/**
 * Token endpoint client: authorization-code exchange, refresh grants and
 * userinfo, using only the global fetch (Node >= 18). All requests are
 * `application/x-www-form-urlencoded` as required by RFC 6749 §2.3.1.
 */

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number | undefined;
  refresh_token?: string | undefined;
  scope?: string | undefined;
  id_token?: string | undefined;
}

export interface TokenExchangeParams {
  clientId: string;
  code: string;
  redirectUri: string;
  codeVerifier: string;
  /** Confidential clients only; public clients omit this. */
  clientSecret?: string | undefined;
}

export interface RefreshParams {
  clientId: string;
  refreshToken: string;
  clientSecret?: string | undefined;
  scope?: string[] | undefined;
}

/** An error returned by the provider, per RFC 6749 §5.2. */
export class OAuth2Error extends Error {
  constructor(
    public readonly error: string,
    public readonly errorDescription?: string,
  ) {
    super(
      errorDescription ? `${error}: ${errorDescription}` : `OAuth2 error: ${error}`,
    );
    this.name = "OAuth2Error";
  }
}

async function postForm(
  tokenEndpoint: string,
  body: URLSearchParams,
): Promise<TokenResponse> {
  let response: Response;
  try {
    response = await fetch(tokenEndpoint, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
      },
      body,
    });
  } catch (err) {
    throw new Error(
      `could not reach token endpoint ${tokenEndpoint}: ${(err as Error).message}`,
    );
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new Error(
      `token endpoint returned HTTP ${response.status} with a non-JSON body`,
    );
  }
  if (!response.ok || !isRecord(payload) || typeof payload.error === "string") {
    if (isRecord(payload) && typeof payload.error === "string") {
      throw new OAuth2Error(
        payload.error,
        typeof payload.error_description === "string"
          ? payload.error_description
          : undefined,
      );
    }
    throw new Error(`token endpoint returned HTTP ${response.status}`);
  }
  if (typeof payload.access_token !== "string" || !payload.access_token) {
    throw new Error("token endpoint response is missing access_token");
  }
  // Build the response explicitly instead of casting the raw JSON: only
  // known fields are kept, and each is type-checked on the way in.
  const tokenResponse: TokenResponse = {
    access_token: payload.access_token,
    token_type:
      typeof payload.token_type === "string" ? payload.token_type : "Bearer",
    ...(typeof payload.expires_in === "number"
      ? { expires_in: payload.expires_in }
      : {}),
    ...(typeof payload.refresh_token === "string"
      ? { refresh_token: payload.refresh_token }
      : {}),
    ...(typeof payload.scope === "string" ? { scope: payload.scope } : {}),
    ...(typeof payload.id_token === "string"
      ? { id_token: payload.id_token }
      : {}),
  };
  return tokenResponse;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/** Exchange the authorization code for tokens (RFC 6749 §4.1.3). */
export async function exchangeAuthorizationCode(
  tokenEndpoint: string,
  params: TokenExchangeParams,
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: params.code,
    redirect_uri: params.redirectUri,
    client_id: params.clientId,
    code_verifier: params.codeVerifier,
  });
  if (params.clientSecret !== undefined) {
    body.set("client_secret", params.clientSecret);
  }
  return postForm(tokenEndpoint, body);
}

/** Redeem a refresh token for a fresh access token (RFC 6749 §6). */
export async function refreshAccessToken(
  tokenEndpoint: string,
  params: RefreshParams,
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: params.refreshToken,
    client_id: params.clientId,
  });
  if (params.clientSecret !== undefined) {
    body.set("client_secret", params.clientSecret);
  }
  if (params.scope && params.scope.length > 0) {
    body.set("scope", params.scope.join(" "));
  }
  return postForm(tokenEndpoint, body);
}

/** Fetch the OpenID Connect userinfo resource with a bearer token. */
export async function fetchUserInfo(
  userinfoEndpoint: string,
  accessToken: string,
): Promise<unknown> {
  const response = await fetch(userinfoEndpoint, {
    headers: {
      authorization: `Bearer ${accessToken}`,
      accept: "application/json",
    },
  });
  if (!response.ok) {
    throw new Error(`userinfo endpoint returned HTTP ${response.status}`);
  }
  return response.json();
}
