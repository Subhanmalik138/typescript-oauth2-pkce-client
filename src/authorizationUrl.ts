/**
 * Build the authorization request URL that starts the flow.
 *
 * The user (or their browser) visits this URL, authenticates with the
 * provider, and is redirected back to `redirectUri` with an authorization
 * code. PKCE parameters and `state` are included so the redirect and the
 * later token exchange can both be verified.
 */

export interface AuthorizationRequest {
  /** Provider's authorization endpoint, e.g. https://accounts.example.com/authorize */
  authorizationEndpoint: string;
  clientId: string;
  /** Must match the redirect URI registered for this client. */
  redirectUri: string;
  /** Scopes requested, space-joined in the URL (e.g. ["openid", "profile"]). */
  scope?: string[] | undefined;
  /** CSRF token generated with generateState(); echoed back on redirect. */
  state: string;
  /** S256 challenge from computeCodeChallenge(). */
  codeChallenge: string;
  codeChallengeMethod?: "S256" | "plain" | undefined;
  /** OpenID Connect nonce, echoed back in the ID token. */
  nonce?: string | undefined;
  /** Any extra provider-specific query parameters. */
  extraParams?: Record<string, string> | undefined;
}

export function buildAuthorizationUrl(request: AuthorizationRequest): URL {
  const {
    authorizationEndpoint,
    clientId,
    redirectUri,
    state,
    codeChallenge,
  } = request;

  if (!authorizationEndpoint) {
    throw new Error("authorizationEndpoint is required");
  }
  let url: URL;
  try {
    url = new URL(authorizationEndpoint);
  } catch {
    throw new Error(`invalid authorizationEndpoint: ${authorizationEndpoint}`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("authorizationEndpoint must use http(s)");
  }
  if (!clientId) throw new Error("clientId is required");
  if (!redirectUri) throw new Error("redirectUri is required");
  if (!state) throw new Error("state is required");
  if (!codeChallenge) throw new Error("codeChallenge is required");

  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set(
    "code_challenge_method",
    request.codeChallengeMethod ?? "S256",
  );
  if (request.scope && request.scope.length > 0) {
    url.searchParams.set("scope", request.scope.join(" "));
  }
  if (request.nonce) url.searchParams.set("nonce", request.nonce);
  if (request.extraParams) {
    for (const [key, value] of Object.entries(request.extraParams)) {
      url.searchParams.set(key, value);
    }
  }
  return url;
}
