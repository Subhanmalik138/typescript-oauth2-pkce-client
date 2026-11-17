import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { buildAuthorizationUrl } from "../src/authorizationUrl.js";

const BASE = {
  authorizationEndpoint: "https://accounts.example.com/authorize",
  clientId: "my-client",
  redirectUri: "http://127.0.0.1:54321/callback",
  state: "state-123",
  codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
};

describe("buildAuthorizationUrl", () => {
  it("builds a complete authorization URL with S256 by default", () => {
    const url = buildAuthorizationUrl({
      ...BASE,
      scope: ["openid", "profile"],
      nonce: "nonce-456",
    });
    assert.equal(url.origin, "https://accounts.example.com");
    assert.equal(url.pathname, "/authorize");
    assert.equal(url.searchParams.get("response_type"), "code");
    assert.equal(url.searchParams.get("client_id"), "my-client");
    assert.equal(url.searchParams.get("redirect_uri"), "http://127.0.0.1:54321/callback");
    assert.equal(url.searchParams.get("state"), "state-123");
    assert.equal(url.searchParams.get("code_challenge"), BASE.codeChallenge);
    assert.equal(url.searchParams.get("code_challenge_method"), "S256");
    assert.equal(url.searchParams.get("scope"), "openid profile");
    assert.equal(url.searchParams.get("nonce"), "nonce-456");
  });

  it("omits scope when none is requested and passes extra params through", () => {
    const url = buildAuthorizationUrl({
      ...BASE,
      extraParams: { audience: "https://api.example.com", prompt: "consent" },
    });
    assert.equal(url.searchParams.get("scope"), null);
    assert.equal(url.searchParams.get("audience"), "https://api.example.com");
    assert.equal(url.searchParams.get("prompt"), "consent");
  });

  it("rejects a non-http(s) authorization endpoint", () => {
    assert.throws(
      () => buildAuthorizationUrl({ ...BASE, authorizationEndpoint: "ftp://example.com/auth" }),
      /http\(s\)/,
    );
    assert.throws(
      () => buildAuthorizationUrl({ ...BASE, authorizationEndpoint: "not a url" }),
      /invalid authorizationEndpoint/,
    );
  });

  it("rejects missing clientId, redirectUri, state, or challenge", () => {
    assert.throws(() => buildAuthorizationUrl({ ...BASE, clientId: "" }), /clientId/);
    assert.throws(() => buildAuthorizationUrl({ ...BASE, redirectUri: "" }), /redirectUri/);
    assert.throws(() => buildAuthorizationUrl({ ...BASE, state: "" }), /state/);
    assert.throws(() => buildAuthorizationUrl({ ...BASE, codeChallenge: "" }), /codeChallenge/);
  });
});
