#!/usr/bin/env node
/**
 * oauth2-pkce — command line client for the OAuth2 Authorization Code flow
 * with PKCE (RFC 7636) and loopback redirect capture (RFC 8252).
 *
 *   oauth2-pkce --config provider.json login       # interactive browser login
 *   oauth2-pkce --config provider.json token       # print a valid access token
 *   oauth2-pkce --config provider.json refresh     # force a token refresh
 *   oauth2-pkce --config provider.json userinfo    # call the userinfo endpoint
 *   oauth2-pkce --config provider.json logout      # delete stored tokens
 *   oauth2-pkce --config provider.json auth-url    # print the auth URL only
 */
import { createInterface } from "node:readline";
import {
  buildAuthorizationUrl,
  computeCodeChallenge,
  defaultTokenPath,
  exchangeAuthorizationCode,
  fetchUserInfo,
  generateCodeVerifier,
  generateState,
  isAccessTokenExpired,
  loadConfig,
  refreshAccessToken,
  startLoopbackListener,
  TokenStore,
  withObtainedAt,
  type OAuth2Config,
  type StoredTokens,
} from "./index.js";

const USAGE = `Usage: oauth2-pkce --config <provider.json> [--tokens <file>] <command>

Commands:
  login      Open the provider in your browser and store the tokens
  token      Print a valid access token (refreshes it first if expired)
  refresh    Force a refresh of the access token
  userinfo   Fetch the userinfo endpoint with the access token
  logout     Delete the stored tokens
  auth-url   Print the authorization URL without starting a login

Options:
  --config <file>   Provider config (required, see config.example.json)
  --tokens <file>   Token store path (default: ~/.config/oauth2-pkce-client/tokens.json)
  --timeout <sec>   How long login waits for the browser redirect (default: 300)
  --help            Show this help`;

interface CliOptions {
  configPath?: string;
  tokensPath: string;
  timeoutMs: number;
  command?: string;
}

function parseArgs(argv: string[]): CliOptions {
  const options: CliOptions = {
    tokensPath: process.env.OAUTH2_TOKENS ?? defaultTokenPath(),
    timeoutMs: 300_000,
  };
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    if (arg === "--config" || arg === "--tokens" || arg === "--timeout") {
      const value = argv[++i];
      if (value === undefined) throw new Error(`${arg} requires a value`);
      if (arg === "--config") {
        options.configPath = value;
      } else if (arg === "--tokens") {
        options.tokensPath = value;
      } else {
        const seconds = Number(value);
        if (!Number.isFinite(seconds) || seconds <= 0) {
          throw new Error("--timeout must be a positive number of seconds");
        }
        options.timeoutMs = seconds * 1000;
      }
    } else if (arg === "--help" || arg === "-h") {
      console.log(USAGE);
      process.exit(0);
    } else if (arg.startsWith("-")) {
      throw new Error(`unknown option: ${arg}`);
    } else {
      positional.push(arg);
    }
  }
  if (positional.length > 1) {
    throw new Error(`unexpected argument: ${positional.slice(1).join(" ")}`);
  }
  const command = positional[0];
  if (command !== undefined) options.command = command;
  return options;
}

async function readLine(prompt: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    return await new Promise<string>((resolve) => {
      rl.question(prompt, (answer) => resolve(answer.trim()));
    });
  } finally {
    rl.close();
  }
}

/** Load stored tokens or fail with a "run login first" message. */
function requireTokens(store: TokenStore): StoredTokens {
  const tokens = store.load();
  if (!tokens) {
    throw new Error("not logged in — run `login` first");
  }
  return tokens;
}

/**
 * Return a valid access token, refreshing it first when it is expired and a
 * refresh token is available. The refreshed set is persisted.
 */
async function validAccessToken(
  config: OAuth2Config,
  store: TokenStore,
): Promise<string> {
  const tokens = requireTokens(store);
  if (!isAccessTokenExpired(tokens)) return tokens.access_token;
  if (!tokens.refresh_token) {
    throw new Error(
      "access token expired and no refresh token is stored — run `login` again",
    );
  }
  const refreshed = await refreshAccessToken(config.tokenEndpoint, {
    clientId: config.clientId,
    refreshToken: tokens.refresh_token,
    clientSecret: config.clientSecret,
  });
  const merged = withObtainedAt({
    ...refreshed,
    // Some providers omit the refresh token on refresh; keep the old one.
    refresh_token: refreshed.refresh_token ?? tokens.refresh_token,
  });
  store.save(merged);
  return merged.access_token;
}

async function cmdLogin(
  config: OAuth2Config,
  store: TokenStore,
  timeoutMs: number,
): Promise<void> {
  const verifier = generateCodeVerifier();
  const state = generateState();
  const challenge = computeCodeChallenge(verifier);

  let redirectUri = config.redirectUri;
  let listener: Awaited<ReturnType<typeof startLoopbackListener>> | undefined;
  if (!redirectUri) {
    listener = await startLoopbackListener(state, timeoutMs);
    redirectUri = listener.redirectUri;
  }

  const authUrl = buildAuthorizationUrl({
    authorizationEndpoint: config.authorizationEndpoint,
    clientId: config.clientId,
    redirectUri,
    scope: config.scopes,
    state,
    codeChallenge: challenge,
  });

  console.log("Open this URL in your browser to sign in:\n");
  console.log(authUrl.toString());
  console.log("");

  let code: string;
  if (listener) {
    const callback = await listener.result;
    code = callback.code;
  } else {
    const pasted = await readLine(
      "After signing in, paste the full redirect URL here: ",
    );
    const url = new URL(pasted);
    const returnedState = url.searchParams.get("state");
    if (returnedState !== state) {
      throw new Error("state mismatch — the pasted URL is not from this login");
    }
    const error = url.searchParams.get("error");
    if (error) throw new Error(`provider refused the request: ${error}`);
    code = url.searchParams.get("code") ?? "";
    if (!code) throw new Error("no authorization code in the pasted URL");
  }

  const tokens = await exchangeAuthorizationCode(config.tokenEndpoint, {
    clientId: config.clientId,
    code,
    redirectUri,
    codeVerifier: verifier,
    clientSecret: config.clientSecret,
  });
  store.save(withObtainedAt(tokens));
  console.log("Signed in. Tokens stored.");
  if (tokens.scope) console.log(`Granted scopes: ${tokens.scope}`);
}

async function cmdAuthUrl(config: OAuth2Config): Promise<void> {
  if (!config.redirectUri) {
    throw new Error(
      "auth-url needs a fixed redirectUri in the config (login uses an ephemeral loopback port instead)",
    );
  }
  const url = buildAuthorizationUrl({
    authorizationEndpoint: config.authorizationEndpoint,
    clientId: config.clientId,
    redirectUri: config.redirectUri,
    scope: config.scopes,
    state: generateState(),
    codeChallenge: computeCodeChallenge(generateCodeVerifier()),
  });
  console.log(url.toString());
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  if (!options.command) {
    console.log(USAGE);
    process.exit(0);
  }
  if (!options.configPath) {
    throw new Error("--config <provider.json> is required");
  }
  const config = loadConfig(options.configPath);
  const store = new TokenStore(options.tokensPath);

  switch (options.command) {
    case "login":
      await cmdLogin(config, store, options.timeoutMs);
      break;
    case "token":
      console.log(await validAccessToken(config, store));
      break;
    case "refresh": {
      const tokens = requireTokens(store);
      if (!tokens.refresh_token) {
        throw new Error("no refresh token stored — run `login` again");
      }
      const refreshed = await refreshAccessToken(config.tokenEndpoint, {
        clientId: config.clientId,
        refreshToken: tokens.refresh_token,
        clientSecret: config.clientSecret,
      });
      store.save(
        withObtainedAt({
          ...refreshed,
          refresh_token: refreshed.refresh_token ?? tokens.refresh_token,
        }),
      );
      console.log("Access token refreshed.");
      break;
    }
    case "userinfo": {
      if (!config.userinfoEndpoint) {
        throw new Error("userinfoEndpoint is not set in the config");
      }
      const accessToken = await validAccessToken(config, store);
      const profile = await fetchUserInfo(config.userinfoEndpoint, accessToken);
      console.log(JSON.stringify(profile, null, 2));
      break;
    }
    case "logout":
      store.clear();
      console.log("Logged out. Stored tokens deleted.");
      break;
    case "auth-url":
      await cmdAuthUrl(config);
      break;
    default:
      throw new Error(`unknown command: ${options.command}\n\n${USAGE}`);
  }
}

main().catch((err: unknown) => {
  console.error(`error: ${(err as Error).message}`);
  process.exit(1);
});
