import { createServer, type Server } from "node:http";
import { OAuth2Error } from "./tokenClient.js";

/**
 * Loopback redirect listener (RFC 8252 §7.3).
 *
 * Native apps listen on 127.0.0.1 with an ephemeral port so the provider can
 * redirect the browser back to the CLI. The listener validates the returned
 * `state` against the one sent in the authorization request, rejects provider
 * errors, and shuts itself down after the first valid callback (or timeout).
 */

export interface AuthorizationCallback {
  code: string;
  state: string;
}

export interface LoopbackListener {
  /** The ephemeral port the server is listening on. */
  port: number;
  /** The redirect URI to register in the authorization request. */
  redirectUri: string;
  /** Resolves with the authorization code, or rejects on error/timeout. */
  result: Promise<AuthorizationCallback>;
  close(): void;
}

const SUCCESS_PAGE = `<!doctype html>
<html><head><meta charset="utf-8"><title>Signed in</title></head>
<body style="font-family: sans-serif; text-align: center; margin-top: 4em;">
<h1>Signed in</h1><p>You can close this tab and return to the terminal.</p>
</body></html>`;

function errorPage(message: string): string {
  return `<!doctype html>
<html><head><meta charset="utf-8"><title>Sign-in failed</title></head>
<body style="font-family: sans-serif; text-align: center; margin-top: 4em;">
<h1>Sign-in failed</h1><p>${message}</p><p>Return to the terminal and try again.</p>
</body></html>`;
}

/**
 * Start listening on 127.0.0.1:0. Resolves once the server is bound, with the
 * redirect URI built from the real ephemeral port.
 */
export function startLoopbackListener(
  expectedState: string,
  timeoutMs = 5 * 60 * 1000,
): Promise<LoopbackListener> {
  let settled = false;
  let timer: NodeJS.Timeout | undefined;
  let server: Server;

  let resolveResult!: (value: AuthorizationCallback) => void;
  let rejectResult!: (reason: unknown) => void;
  const result = new Promise<AuthorizationCallback>((resolve, reject) => {
    resolveResult = resolve;
    rejectResult = reject;
  });

  const fail = (error: unknown) => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    server.close();
    rejectResult(error);
  };

  const close = () => fail(new Error("loopback listener closed"));

  server = createServer((req, res) => {
    const requestUrl = new URL(req.url ?? "/", "http://127.0.0.1");
    const params = requestUrl.searchParams;

    const providerError = params.get("error");
    if (providerError) {
      res.writeHead(400, { "content-type": "text/html; charset=utf-8" });
      res.end(errorPage(`The provider refused the request: ${providerError}.`));
      fail(
        new OAuth2Error(
          providerError,
          params.get("error_description") ?? undefined,
        ),
      );
      return;
    }

    const code = params.get("code");
    const state = params.get("state");
    if (!code || !state) {
      // A stray request (favicon, probe) must not kill the login.
      res.writeHead(400, { "content-type": "text/html; charset=utf-8" });
      res.end(errorPage("Missing code or state in the redirect."));
      return;
    }
    if (state !== expectedState) {
      res.writeHead(400, { "content-type": "text/html; charset=utf-8" });
      res.end(errorPage("State mismatch — possible CSRF attack. Ignored."));
      return; // keep waiting for the genuine redirect
    }

    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(SUCCESS_PAGE);
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    server.close();
    resolveResult({ code, state });
  });

  server.on("error", fail);

  timer = setTimeout(() => {
    fail(
      new Error(
        `timed out after ${Math.round(timeoutMs / 1000)}s waiting for the browser redirect`,
      ),
    );
  }, timeoutMs);
  timer.unref?.();

  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("could not determine loopback port"));
        return;
      }
      resolve({
        port: address.port,
        redirectUri: `http://127.0.0.1:${address.port}/callback`,
        result,
        close,
      });
    });
    server.on("error", reject);
  });
}
