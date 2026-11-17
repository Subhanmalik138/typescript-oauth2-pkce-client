# OAuth2 PKCE Client

A zero-dependency TypeScript client for the OAuth2 **Authorization Code flow
with PKCE** (RFC 7636), built for native/desktop CLIs. It generates the
code verifier and S256 challenge, starts a loopback redirect listener
(RFC 8252), exchanges the authorization code for tokens, and refreshes them
when they expire — using only Node's built-ins (`node:crypto`, `node:http`,
global `fetch`).

## The problem

Public clients (CLIs, desktop apps) cannot keep a client secret, so the plain
Authorization Code flow is unsafe for them: anyone who intercepts the code
can redeem it. PKCE fixes that by binding the code to a secret verifier that
only the client knows, and the loopback redirect keeps the whole flow on the
user's own machine — no hosted callback server, no secrets in the repo.

## Design decisions

1. **S256 only, never `plain`.** The challenge is `base64url(SHA-256(verifier))`,
   verified against the RFC 7636 Appendix B test vector in the test suite.
   `plain` exists in the spec but sends the verifier in the clear, defeating
   the point.
2. **Ephemeral loopback port.** The redirect listener binds `127.0.0.1:0` and
   builds the redirect URI from the real port, so no fixed port has to be
   registered with the provider and two logins never collide.
3. **State is validated, not just echoed.** A redirect with a mismatched or
   missing `state` gets a 400 and the listener keeps waiting for the genuine
   callback, so a CSRF probe cannot kill or hijack the login.
4. **Tokens live in a 0600 file, written atomically.** The store records
   `obtainedAt` alongside the token set so expiry is computed locally, and
   writes go through a temp file + rename so a crash can never leave a
   half-written token file. Refresh responses that omit a new refresh token
   keep the old one.

## Usage

```bash
npm install
npm run build

# 1. Copy the example config and fill in your provider's endpoints
cp config.example.json provider.json

# 2. Log in — prints a URL, open it in your browser, sign in
node dist/src/cli.js --config provider.json login

# 3. Get a valid access token (refreshes automatically if expired)
node dist/src/cli.js --config provider.json token

# Other commands
node dist/src/cli.js --config provider.json refresh    # force a refresh
node dist/src/cli.js --config provider.json userinfo   # call userinfo
node dist/src/cli.js --config provider.json logout     # delete stored tokens
node dist/src/cli.js --config provider.json auth-url   # print the auth URL only
```

Config file shape (`config.example.json`):

```json
{
  "clientId": "my-public-client",
  "authorizationEndpoint": "https://accounts.example.com/authorize",
  "tokenEndpoint": "https://accounts.example.com/token",
  "userinfoEndpoint": "https://accounts.example.com/userinfo",
  "scopes": ["openid", "profile", "email"]
}
```

`redirectUri` is optional: omit it and login uses the loopback listener. Set
it (and `clientSecret`) only for confidential clients with a fixed redirect.

Tokens are stored by default at `~/.config/oauth2-pkce-client/tokens.json`;
override with `--tokens <file>` or the `OAUTH2_TOKENS` environment variable.

## As a library

```ts
import {
  generateCodeVerifier,
  computeCodeChallenge,
  generateState,
  buildAuthorizationUrl,
  startLoopbackListener,
  exchangeAuthorizationCode,
  refreshAccessToken,
  TokenStore,
} from "typescript-oauth2-pkce-client";

const verifier = generateCodeVerifier();
const state = generateState();
const listener = await startLoopbackListener(state);
const url = buildAuthorizationUrl({
  authorizationEndpoint: "https://accounts.example.com/authorize",
  clientId: "my-client",
  redirectUri: listener.redirectUri,
  scope: ["openid", "profile"],
  state,
  codeChallenge: computeCodeChallenge(verifier),
});
// ... user visits url, provider redirects to the loopback listener ...
const { code } = await listener.result;
const tokens = await exchangeAuthorizationCode("https://accounts.example.com/token", {
  clientId: "my-client",
  code,
  redirectUri: listener.redirectUri,
  codeVerifier: verifier,
});
new TokenStore("tokens.json").save({ ...tokens, obtainedAt: Date.now() });
```

## Running tests

```bash
npm test
```

35 tests, all against local servers — no network access needed. The token
endpoint and loopback listener are exercised with real HTTP requests to
`127.0.0.1` servers spun up inside the tests.

## Tech stack

- TypeScript (strict, `NodeNext`), Node.js ≥ 20
- Zero runtime dependencies — `node:crypto`, `node:http`, global `fetch`
- `node:test` + `node:assert/strict`

## License

MIT
