import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { TokenResponse } from "./tokenClient.js";

/**
 * Token storage: a JSON file holding the latest token set plus the absolute
 * time it was obtained, so expiry can be computed locally without a network
 * round trip. Writes are atomic (temp file + rename) and the file is created
 * with mode 0600 — tokens are credentials and must never be world-readable.
 */

export interface StoredTokens extends TokenResponse {
  /** Unix epoch milliseconds when the tokens were received. */
  obtainedAt: number;
}

export function withObtainedAt(tokens: TokenResponse): StoredTokens {
  const stored: StoredTokens = { ...tokens, obtainedAt: Date.now() };
  return stored;
}

/** Absolute expiry time in epoch ms, or undefined for non-expiring tokens. */
export function tokenExpiresAt(tokens: StoredTokens): number | undefined {
  if (typeof tokens.expires_in !== "number") return undefined;
  return tokens.obtainedAt + tokens.expires_in * 1000;
}

/** True when the access token is expired or will expire within the leeway. */
export function isAccessTokenExpired(
  tokens: StoredTokens,
  leewaySeconds = 30,
): boolean {
  const expiresAt = tokenExpiresAt(tokens);
  if (expiresAt === undefined) return false;
  return Date.now() >= expiresAt - leewaySeconds * 1000;
}

export class TokenStore {
  constructor(private readonly filePath: string) {}

  /** Returns null when no tokens have been stored yet. */
  load(): StoredTokens | null {
    if (!existsSync(this.filePath)) return null;
    let raw: string;
    try {
      raw = readFileSync(this.filePath, "utf-8");
    } catch (err) {
      throw new Error(`cannot read token file ${this.filePath}: ${(err as Error).message}`);
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error(`token file ${this.filePath} is not valid JSON`);
    }
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      typeof (parsed as StoredTokens).access_token !== "string" ||
      typeof (parsed as StoredTokens).obtainedAt !== "number"
    ) {
      throw new Error(`token file ${this.filePath} is not a valid token set`);
    }
    return parsed as StoredTokens;
  }

  save(tokens: StoredTokens): void {
    mkdirSync(dirname(this.filePath), { recursive: true });
    const tmpPath = `${this.filePath}.tmp-${process.pid}`;
    writeFileSync(tmpPath, JSON.stringify(tokens, null, 2), { mode: 0o600 });
    renameSync(tmpPath, this.filePath);
  }

  /** Remove stored tokens (logout). No-op when nothing is stored. */
  clear(): void {
    rmSync(this.filePath, { force: true });
  }
}
