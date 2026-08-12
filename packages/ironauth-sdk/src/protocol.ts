// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * The OAuth protocol client (issue #115).
 *
 * Authorization URL construction, PKCE, code exchange, refresh, discovery and UserInfo.
 * Pure WebCrypto and pure `fetch`, so it runs unchanged on Node 20+, Deno, Bun, Cloudflare
 * Workers and Vercel Edge.
 *
 * ## PKCE is not optional here
 *
 * {@link authorizationUrl} always emits `code_challenge` with `S256`. There is no switch to
 * turn it off and no `plain` method: `plain` sends the verifier in the authorization
 * request, which defeats the point, and RFC 7636 only keeps it for clients that cannot do
 * SHA-256. Every runtime this package targets can.
 *
 * ## The state and verifier come back to the caller, not into storage
 *
 * This module holds nothing. Where a verifier is kept between the two legs is a decision
 * only the embedding application can make correctly (a cookie, a session, a signed blob),
 * and a core that picked one would be wrong in most of them.
 */

/** What an issuer publishes at its discovery endpoint, narrowed to what is used here. */
export interface DiscoveryDocument {
  readonly issuer: string;
  readonly authorization_endpoint: string;
  readonly token_endpoint: string;
  readonly jwks_uri: string;
  readonly userinfo_endpoint?: string;
  readonly id_token_signing_alg_values_supported?: readonly string[];
}

/** A PKCE pair: the verifier to keep, and the challenge to send. */
export interface PkcePair {
  /** Kept by the caller and presented at the token endpoint. Never sent in leg one. */
  readonly verifier: string;
  /** The S256 challenge sent in the authorization request. */
  readonly challenge: string;
}

/** A token response, narrowed to the members this core reads. */
export interface TokenResponse {
  readonly access_token: string;
  readonly token_type: string;
  readonly expires_in?: number;
  readonly refresh_token?: string;
  readonly id_token?: string;
  readonly scope?: string;
}

/** An OAuth error response, or a transport failure rendered the same way. */
export class ProtocolError extends Error {
  /** The `error` code the server returned, or a local code for a transport failure. */
  readonly code: string;

  constructor(code: string, message?: string) {
    super(message ?? code);
    this.name = 'ProtocolError';
    this.code = code;
  }
}

function base64url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** A cryptographically random base64url string of `bytes` entropy. */
function randomToken(bytes: number): string {
  const buffer = new Uint8Array(bytes);
  crypto.getRandomValues(buffer);
  return base64url(buffer);
}

/**
 * Generate a PKCE pair.
 *
 * The verifier is 32 bytes of CSPRNG output, which is above RFC 7636's floor and well
 * inside its ceiling. S256 only.
 */
export async function generatePkce(): Promise<PkcePair> {
  const verifier = randomToken(32);
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(verifier),
  );
  return { verifier, challenge: base64url(new Uint8Array(digest)) };
}

/** A fresh `state` value, for the caller to store and compare on return. */
export function generateState(): string {
  return randomToken(32);
}

/**
 * Build the authorization URL.
 *
 * `state` is REQUIRED rather than defaulted. A core that generated one silently would let
 * a caller forget to compare it on the way back, and an uncompared state is the same as no
 * state: the CSRF defence is the comparison, not the parameter.
 */
export function authorizationUrl(options: {
  discovery: Pick<DiscoveryDocument, 'authorization_endpoint'>;
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  challenge: string;
  /** Extra parameters, for example `prompt` or `login_hint`. */
  extra?: Record<string, string>;
}): string {
  const url = new URL(options.discovery.authorization_endpoint);
  const parameters: Record<string, string> = {
    response_type: 'code',
    client_id: options.clientId,
    redirect_uri: options.redirectUri,
    scope: options.scope,
    state: options.state,
    code_challenge: options.challenge,
    code_challenge_method: 'S256',
    ...options.extra,
  };
  for (const [name, value] of Object.entries(parameters)) {
    url.searchParams.set(name, value);
  }
  return url.toString();
}

/** Fetch and validate an issuer's discovery document. */
export async function discover(
  issuer: string,
  send: typeof fetch = fetch,
): Promise<DiscoveryDocument> {
  const url = new URL('.well-known/openid-configuration', `${issuer.replace(/\/$/, '')}/`);
  const response = await send(url.toString());
  if (!response.ok) {
    throw new ProtocolError('discovery_failed', `the issuer answered ${response.status}`);
  }
  const document = (await response.json()) as DiscoveryDocument;
  // The document must claim the issuer we asked for. Without this, a redirect or a
  // misconfigured host could hand back another issuer's endpoints and the client would
  // send its code there.
  if (document.issuer !== issuer) {
    throw new ProtocolError(
      'issuer_mismatch',
      `asked ${issuer} and the document claims ${document.issuer}`,
    );
  }
  for (const required of ['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as const) {
    if (typeof document[required] !== 'string' || document[required].length === 0) {
      throw new ProtocolError('discovery_incomplete', `the document has no ${required}`);
    }
  }
  return document;
}

/** POST a form to the token endpoint and read the response. */
async function tokenRequest(
  endpoint: string,
  form: Record<string, string>,
  send: typeof fetch,
): Promise<TokenResponse> {
  const response = await send(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: new URLSearchParams(form).toString(),
  });
  let body: Record<string, unknown>;
  try {
    body = (await response.json()) as Record<string, unknown>;
  } catch {
    throw new ProtocolError('malformed_response', `the endpoint answered ${response.status}`);
  }
  if (!response.ok) {
    const code = typeof body.error === 'string' ? body.error : 'token_request_failed';
    // The server's `error` code travels; its `error_description` does NOT. A description
    // is server-controlled text, and passing it through is how it ends up rendered in a
    // page.
    throw new ProtocolError(code);
  }
  if (typeof body.access_token !== 'string' || typeof body.token_type !== 'string') {
    throw new ProtocolError('malformed_response', 'no access_token in the response');
  }
  return body as unknown as TokenResponse;
}

/**
 * Exchange an authorization code, presenting the PKCE verifier.
 *
 * `redirectUri` is sent again because RFC 6749 section 4.1.3 requires the server to
 * compare it against the one from leg one.
 */
export async function exchangeCode(
  options: {
    discovery: Pick<DiscoveryDocument, 'token_endpoint'>;
    clientId: string;
    redirectUri: string;
    code: string;
    verifier: string;
  },
  send: typeof fetch = fetch,
): Promise<TokenResponse> {
  return tokenRequest(
    options.discovery.token_endpoint,
    {
      grant_type: 'authorization_code',
      code: options.code,
      client_id: options.clientId,
      redirect_uri: options.redirectUri,
      code_verifier: options.verifier,
    },
    send,
  );
}

/** Refresh an access token. */
export async function refresh(
  options: {
    discovery: Pick<DiscoveryDocument, 'token_endpoint'>;
    clientId: string;
    refreshToken: string;
    /** Narrow the scope of the new token. Omitted means unchanged. */
    scope?: string;
  },
  send: typeof fetch = fetch,
): Promise<TokenResponse> {
  const form: Record<string, string> = {
    grant_type: 'refresh_token',
    refresh_token: options.refreshToken,
    client_id: options.clientId,
  };
  if (options.scope !== undefined) {
    form.scope = options.scope;
  }
  return tokenRequest(options.discovery.token_endpoint, form, send);
}

/**
 * Call the UserInfo endpoint.
 *
 * The scheme is the token type the server issued, so a DPoP-bound token is presented as
 * `DPoP` rather than `Bearer`. Hardcoding `Bearer` would present a sender-constrained token
 * as a bearer token, which is what the binding exists to prevent.
 */
export async function userInfo(
  options: {
    discovery: Pick<DiscoveryDocument, 'userinfo_endpoint'>;
    accessToken: string;
    tokenType?: string;
    /** Extra headers, for example a `DPoP` proof. */
    headers?: Record<string, string>;
  },
  send: typeof fetch = fetch,
): Promise<Record<string, unknown>> {
  const endpoint = options.discovery.userinfo_endpoint;
  if (endpoint === undefined) {
    throw new ProtocolError('no_userinfo_endpoint', 'the issuer publishes none');
  }
  const scheme = options.tokenType ?? 'Bearer';
  const response = await send(endpoint, {
    headers: {
      ...options.headers,
      Authorization: `${scheme} ${options.accessToken}`,
      Accept: 'application/json',
    },
  });
  if (!response.ok) {
    throw new ProtocolError('userinfo_failed', `the endpoint answered ${response.status}`);
  }
  return (await response.json()) as Record<string, unknown>;
}
