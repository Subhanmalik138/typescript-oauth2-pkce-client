import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { startLoopbackListener } from "../src/loopback.js";
import { OAuth2Error } from "../src/tokenClient.js";

describe("startLoopbackListener", () => {
  it("captures the code from a valid redirect and reports the real port", async () => {
    const listener = await startLoopbackListener("expected-state", 5000);
    assert.ok(listener.port > 0);
    assert.equal(
      listener.redirectUri,
      `http://127.0.0.1:${listener.port}/callback`,
    );

    const responsePromise = fetch(
      `${listener.redirectUri}?code=auth-code-123&state=expected-state`,
    );
    const callback = await listener.result;
    assert.deepEqual(callback, { code: "auth-code-123", state: "expected-state" });

    const response = await responsePromise;
    assert.equal(response.status, 200);
    assert.match(await response.text(), /Signed in/);
  });

  it("ignores a state mismatch and still accepts the genuine redirect", async () => {
    const listener = await startLoopbackListener("real-state", 5000);

    const bad = await fetch(
      `${listener.redirectUri}?code=attacker-code&state=wrong-state`,
    );
    assert.equal(bad.status, 400);

    const good = fetch(
      `${listener.redirectUri}?code=real-code&state=real-state`,
    );
    const callback = await listener.result;
    assert.equal(callback.code, "real-code");
    assert.equal((await good).status, 200);
  });

  it("rejects with OAuth2Error when the provider returns an error", async () => {
    const listener = await startLoopbackListener("state-1", 5000);
    const responsePromise = fetch(
      `${listener.redirectUri}?error=access_denied&error_description=user+declined`,
    );
    await assert.rejects(listener.result, (err: unknown) => {
      assert.ok(err instanceof OAuth2Error);
      assert.equal(err.error, "access_denied");
      assert.match(err.message, /user declined/);
      return true;
    });
    assert.equal((await responsePromise).status, 400);
  });

  it("rejects on timeout when nobody completes the login", async () => {
    const listener = await startLoopbackListener("state-1", 150);
    await assert.rejects(listener.result, /timed out/);
  });

  it("ignores a redirect missing code/state and keeps waiting", async () => {
    const listener = await startLoopbackListener("state-1", 5000);
    const probe = await fetch(`${listener.redirectUri}?foo=bar`);
    assert.equal(probe.status, 400);

    const good = fetch(`${listener.redirectUri}?code=c1&state=state-1`);
    const callback = await listener.result;
    assert.equal(callback.code, "c1");
    assert.equal((await good).status, 200);
  });
});
