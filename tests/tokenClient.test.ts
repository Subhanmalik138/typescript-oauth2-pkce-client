import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import {
  exchangeAuthorizationCode,
  fetchUserInfo,
  refreshAccessToken,
  OAuth2Error,
} from "../src/tokenClient.js";

/**
 * A fake provider: answers /token and /userinfo so the client can be tested
 * end-to-end without any network access.
 */
let server: Server;
let tokenUrl: string;
let userinfoUrl: string;
let lastTokenRequest: { body: URLSearchParams; path: string } | undefined;

before(async () => {
  server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const body = new URLSearchParams(Buffer.concat(chunks).toString("utf-8"));
      lastTokenRequest = { body, path: req.url ?? "" };

      if (req.url === "/token-error") {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "invalid_grant", error_description: "code expired" }));
        return;
      }
      if (req.url === "/token") {
        if (body.get("grant_type") === "authorization_code") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(
            JSON.stringify({
              access_token: "access-1",
              token_type: "Bearer",
              expires_in: 3600,
              refresh_token: "refresh-1",
              scope: "openid profile",
            }),
          );
          return;
        }
        if (body.get("grant_type") === "refresh_token") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(
            JSON.stringify({
              access_token: "access-2",
              token_type: "Bearer",
              expires_in: 3600,
              // no refresh_token: providers may rotate or keep the old one
            }),
          );
          return;
        }
      }
      if (req.url === "/userinfo") {
        if (req.headers.authorization !== "Bearer access-1") {
          res.writeHead(401, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "invalid_token" }));
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ sub: "user-1", name: "Test User" }));
        return;
      }
      res.writeHead(404);
      res.end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("no port");
  tokenUrl = `http://127.0.0.1:${address.port}/token`;
  userinfoUrl = `http://127.0.0.1:${address.port}/userinfo`;
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe("exchangeAuthorizationCode", () => {
  it("posts the code grant with the PKCE verifier and returns tokens", async () => {
    const tokens = await exchangeAuthorizationCode(tokenUrl, {
      clientId: "my-client",
      code: "auth-code",
      redirectUri: "http://127.0.0.1:1234/callback",
      codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    });
    assert.equal(tokens.access_token, "access-1");
    assert.equal(tokens.refresh_token, "refresh-1");
    assert.equal(lastTokenRequest?.body.get("grant_type"), "authorization_code");
    assert.equal(lastTokenRequest?.body.get("code"), "auth-code");
    assert.equal(
      lastTokenRequest?.body.get("code_verifier"),
      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    );
    assert.equal(lastTokenRequest?.body.get("client_id"), "my-client");
  });

  it("surfaces provider errors as OAuth2Error with the description", async () => {
    const errorUrl = tokenUrl.replace("/token", "/token-error");
    await assert.rejects(
      () =>
        exchangeAuthorizationCode(errorUrl, {
          clientId: "my-client",
          code: "bad-code",
          redirectUri: "http://127.0.0.1:1234/callback",
          codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        }),
      (err: unknown) => {
        assert.ok(err instanceof OAuth2Error);
        assert.equal(err.error, "invalid_grant");
        assert.match(err.message, /code expired/);
        return true;
      },
    );
  });

  it("fails clearly when the token endpoint is unreachable", async () => {
    await assert.rejects(
      () =>
        exchangeAuthorizationCode("http://127.0.0.1:1/token", {
          clientId: "my-client",
          code: "x",
          redirectUri: "http://127.0.0.1:1234/callback",
          codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        }),
      /could not reach token endpoint/,
    );
  });
});

describe("refreshAccessToken", () => {
  it("posts the refresh grant and returns the new access token", async () => {
    const tokens = await refreshAccessToken(tokenUrl, {
      clientId: "my-client",
      refreshToken: "refresh-1",
    });
    assert.equal(tokens.access_token, "access-2");
    assert.equal(lastTokenRequest?.body.get("grant_type"), "refresh_token");
    assert.equal(lastTokenRequest?.body.get("refresh_token"), "refresh-1");
  });
});

describe("fetchUserInfo", () => {
  it("sends the bearer token and returns the profile", async () => {
    const profile = (await fetchUserInfo(userinfoUrl, "access-1")) as Record<
      string,
      unknown
    >;
    assert.equal(profile.sub, "user-1");
    assert.equal(profile.name, "Test User");
  });

  it("throws on a 401", async () => {
    await assert.rejects(
      () => fetchUserInfo(userinfoUrl, "wrong-token"),
      /HTTP 401/,
    );
  });
});
