import { createHash, randomBytes } from "node:crypto";

/**
 * PKCE helpers (RFC 7636).
 *
 * A code verifier is a high-entropy random string of 43-128 characters drawn
 * from the unreserved URI alphabet. The challenge sent to the authorization
 * server is base64url(SHA-256(verifier)) — the "S256" method. Because the
 * verifier never travels over the network until the token exchange, an
 * attacker who intercepts the authorization code alone cannot redeem it.
 */

export const VERIFIER_MIN_LENGTH = 43;
export const VERIFIER_MAX_LENGTH = 128;

/** Unreserved characters allowed in a PKCE code verifier (RFC 7636 §4.1). */
const VERIFIER_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

export function generateCodeVerifier(length = 64): string {
  if (
    !Number.isInteger(length) ||
    length < VERIFIER_MIN_LENGTH ||
    length > VERIFIER_MAX_LENGTH
  ) {
    throw new RangeError(
      `code verifier length must be between ${VERIFIER_MIN_LENGTH} and ${VERIFIER_MAX_LENGTH}`,
    );
  }
  const bytes = randomBytes(length);
  let verifier = "";
  for (const byte of bytes) {
    verifier += VERIFIER_ALPHABET.charAt(byte % VERIFIER_ALPHABET.length);
  }
  return verifier;
}

/** Base64url encoding without padding (RFC 7636 §4.2 / RFC 4648 §5). */
export function base64UrlEncode(data: Buffer): string {
  return data
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Derive the S256 code challenge for a verifier.
 * Throws on verifiers outside the 43-128 unreserved-character range.
 */
export function computeCodeChallenge(verifier: string): string {
  if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(verifier)) {
    throw new Error(
      "invalid code verifier: must be 43-128 unreserved characters (A-Z a-z 0-9 - . _ ~)",
    );
  }
  return base64UrlEncode(createHash("sha256").update(verifier, "ascii").digest());
}

/**
 * Generate a CSRF-protection `state` value. It is echoed back by the
 * authorization server on the redirect and must match exactly.
 */
export function generateState(length = 32): string {
  if (!Number.isInteger(length) || length < 16) {
    throw new RangeError("state must be at least 16 random bytes");
  }
  return base64UrlEncode(randomBytes(length));
}
