import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/**
 * Provider configuration, loaded from a JSON file:
 *
 *   {
 *     "clientId": "my-public-client",
 *     "authorizationEndpoint": "https://accounts.example.com/authorize",
 *     "tokenEndpoint": "https://accounts.example.com/token",
 *     "userinfoEndpoint": "https://accounts.example.com/userinfo",   // optional
 *     "scopes": ["openid", "profile"],                                // optional
 *     "redirectUri": "http://127.0.0.1:8080/callback",               // optional
 *     "clientSecret": "..."                                           // confidential clients only
 *   }
 *
 * When `redirectUri` is omitted the login command starts a loopback listener
 * on an ephemeral port and uses its address instead.
 */

export interface OAuth2Config {
  clientId: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  userinfoEndpoint?: string | undefined;
  scopes?: string[] | undefined;
  redirectUri?: string | undefined;
  clientSecret?: string | undefined;
}

const REQUIRED_FIELDS = [
  "clientId",
  "authorizationEndpoint",
  "tokenEndpoint",
] as const;

export function loadConfig(configPath: string): OAuth2Config {
  if (!existsSync(configPath)) {
    throw new Error(
      `config file not found: ${configPath} (copy config.example.json and fill in your provider's endpoints)`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(configPath, "utf-8"));
  } catch {
    throw new Error(`config file ${configPath} is not valid JSON`);
  }
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error(`config file ${configPath} must contain a JSON object`);
  }
  const record = parsed as Record<string, unknown>;
  for (const field of REQUIRED_FIELDS) {
    if (typeof record[field] !== "string" || record[field] === "") {
      throw new Error(`config file ${configPath} is missing required field "${field}"`);
    }
  }
  for (const field of ["userinfoEndpoint", "redirectUri", "clientSecret"]) {
    if (record[field] !== undefined && typeof record[field] !== "string") {
      throw new Error(`config field "${field}" must be a string`);
    }
  }
  if (
    record.scopes !== undefined &&
    (!Array.isArray(record.scopes) ||
      !record.scopes.every((s) => typeof s === "string"))
  ) {
    throw new Error(`config field "scopes" must be an array of strings`);
  }
  return record as unknown as OAuth2Config;
}

/** Default token file: ~/.config/oauth2-pkce-client/tokens.json */
export function defaultTokenPath(): string {
  return join(homedir(), ".config", "oauth2-pkce-client", "tokens.json");
}
