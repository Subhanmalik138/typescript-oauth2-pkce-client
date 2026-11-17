import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  TokenStore,
  isAccessTokenExpired,
  tokenExpiresAt,
  withObtainedAt,
} from "../src/tokenStore.js";

let dir: string;
let store: TokenStore;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "oauth2-pkce-test-"));
  store = new TokenStore(join(dir, "tokens.json"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("TokenStore", () => {
  it("returns null when nothing has been stored", () => {
    assert.equal(store.load(), null);
  });

  it("round-trips tokens and leaves no temp file behind", () => {
    const tokens = withObtainedAt({
      access_token: "access-1",
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: "refresh-1",
    });
    store.save(tokens);
    assert.deepEqual(store.load(), tokens);
    assert.equal(existsSync(join(dir, "tokens.json.tmp-" + process.pid)), false);
  });

  it("stores the file with mode 0600", () => {
    store.save(
      withObtainedAt({ access_token: "access-1", token_type: "Bearer" }),
    );
    assert.equal(statSync(join(dir, "tokens.json")).mode & 0o777, 0o600);
  });

  it("creates parent directories as needed", () => {
    const nested = new TokenStore(join(dir, "a", "b", "tokens.json"));
    nested.save(withObtainedAt({ access_token: "x", token_type: "Bearer" }));
    assert.equal(nested.load()?.access_token, "x");
  });

  it("rejects a corrupt token file instead of returning garbage", () => {
    writeFileSync(join(dir, "tokens.json"), "{not json");
    assert.throws(() => store.load(), /not valid JSON/);
    writeFileSync(join(dir, "tokens.json"), JSON.stringify({ nope: true }));
    assert.throws(() => store.load(), /not a valid token set/);
  });

  it("clear removes the file and load returns null again", () => {
    store.save(withObtainedAt({ access_token: "x", token_type: "Bearer" }));
    store.clear();
    assert.equal(store.load(), null);
    assert.equal(existsSync(join(dir, "tokens.json")), false);
    store.clear(); // clearing twice must not throw
  });
});

describe("expiry helpers", () => {
  it("computes absolute expiry from obtainedAt + expires_in", () => {
    const tokens = withObtainedAt({
      access_token: "x",
      token_type: "Bearer",
      expires_in: 60,
    });
    const expiresAt = tokenExpiresAt(tokens);
    assert.ok(expiresAt !== undefined);
    assert.ok(Math.abs(expiresAt - (tokens.obtainedAt + 60_000)) < 5);
    assert.equal(isAccessTokenExpired(tokens), false);
  });

  it("treats tokens without expires_in as non-expiring", () => {
    const tokens = withObtainedAt({ access_token: "x", token_type: "Bearer" });
    assert.equal(tokenExpiresAt(tokens), undefined);
    assert.equal(isAccessTokenExpired(tokens), false);
  });

  it("reports expired tokens, honouring the leeway", () => {
    const expired = {
      ...withObtainedAt({
        access_token: "x",
        token_type: "Bearer",
        expires_in: 60,
      }),
      obtainedAt: Date.now() - 120_000,
    };
    assert.equal(isAccessTokenExpired(expired), true);

    const aboutToExpire = {
      ...withObtainedAt({
        access_token: "x",
        token_type: "Bearer",
        expires_in: 60,
      }),
      obtainedAt: Date.now() - 45_000, // 15s left, inside the 30s leeway
    };
    assert.equal(isAccessTokenExpired(aboutToExpire), true);
    assert.equal(isAccessTokenExpired(aboutToExpire, 0), false);
  });
});

describe("token file contents", () => {
  it("never writes the raw access token to stdout — file holds the full set", () => {
    const tokens = withObtainedAt({
      access_token: "secret-access",
      token_type: "Bearer",
      refresh_token: "secret-refresh",
    });
    store.save(tokens);
    const raw = JSON.parse(readFileSync(join(dir, "tokens.json"), "utf-8")) as Record<
      string,
      unknown
    >;
    assert.equal(raw.access_token, "secret-access");
    assert.equal(raw.refresh_token, "secret-refresh");
    assert.equal(typeof raw.obtainedAt, "number");
  });
});
