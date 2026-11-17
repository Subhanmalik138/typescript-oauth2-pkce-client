import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  base64UrlEncode,
  computeCodeChallenge,
  generateCodeVerifier,
  generateState,
} from "../src/pkce.js";

describe("generateCodeVerifier", () => {
  it("defaults to 64 characters from the unreserved alphabet", () => {
    const verifier = generateCodeVerifier();
    assert.equal(verifier.length, 64);
    assert.match(verifier, /^[A-Za-z0-9\-._~]{64}$/);
  });

  it("accepts the RFC 7636 bounds 43 and 128", () => {
    assert.equal(generateCodeVerifier(43).length, 43);
    assert.equal(generateCodeVerifier(128).length, 128);
  });

  it("rejects lengths outside 43-128", () => {
    assert.throws(() => generateCodeVerifier(42), RangeError);
    assert.throws(() => generateCodeVerifier(129), RangeError);
  });

  it("produces different verifiers on every call", () => {
    assert.notEqual(generateCodeVerifier(), generateCodeVerifier());
  });
});

describe("computeCodeChallenge", () => {
  it("matches the RFC 7636 Appendix B test vector", () => {
    // Verifier and challenge straight from RFC 7636, Appendix B.
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    assert.equal(
      computeCodeChallenge(verifier),
      "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    );
  });

  it("is deterministic and 43 chars long (32-byte SHA-256, base64url)", () => {
    const verifier = generateCodeVerifier();
    const challenge = computeCodeChallenge(verifier);
    assert.equal(challenge, computeCodeChallenge(verifier));
    assert.equal(challenge.length, 43);
    assert.match(challenge, /^[A-Za-z0-9\-_]{43}$/);
  });

  it("rejects verifiers that are too short, too long, or use other chars", () => {
    assert.throws(() => computeCodeChallenge("short"), Error);
    assert.throws(() => computeCodeChallenge("a".repeat(129)), Error);
    assert.throws(() => computeCodeChallenge("has space in it ".repeat(3)), Error);
    assert.throws(() => computeCodeChallenge("has+plus/and=equals".repeat(3)), Error);
  });
});

describe("base64UrlEncode", () => {
  it("uses - and _ and strips padding", () => {
    // 0xfb 0xff 0xfe encodes to "+//+" in base64; base64url must be "-__-".
    assert.equal(base64UrlEncode(Buffer.from([0xfb, 0xff, 0xfe])), "-__-");
    assert.equal(base64UrlEncode(Buffer.from("f")), "Zg");
  });
});

describe("generateState", () => {
  it("returns a base64url string, unique per call", () => {
    const state = generateState();
    assert.match(state, /^[A-Za-z0-9\-_]+$/);
    assert.notEqual(state, generateState());
  });

  it("rejects unreasonably short state", () => {
    assert.throws(() => generateState(8), RangeError);
  });
});
