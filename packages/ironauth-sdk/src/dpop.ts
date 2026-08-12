// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * Client-side DPoP proof generation, RFC 9449 (issue #115).
 *
 * Pure WebCrypto. No `node:` specifiers, no `Buffer`, no Node crypto, so this runs
 * unmodified on Node 20+, Deno, Bun, Cloudflare Workers and Vercel Edge. That constraint is
 * the whole reason this package exists: Workers and Vercel Edge never expose Node's crypto
 * module, and a core that reached for it would be unusable in exactly the runtimes the
 * framework SDKs need it in.
 *
 * ## The private key is non-extractable, deliberately
 *
 * {@link generateProofKey} creates the keypair with `extractable: false`, so page
 * JavaScript cannot read the private key even in the same origin. Stating the limit
 * plainly: this does NOT defeat XSS. A compromised page can ask this key to sign whatever
 * it likes for as long as it runs. What it cannot do is exfiltrate the key and keep signing
 * after the page is gone, which turns a permanent compromise into a bounded one.
 * Hardware-backed key storage is the open frontier and is not available here.
 *
 * Server-side proof validation, nonce issuance and `jkt` confirmation are NOT here; they
 * belong to the server DPoP issue. This module owns the client half only.
 */

/** The JOSE header type RFC 9449 section 4.2 requires on a proof. */
const PROOF_TYP = 'dpop+jwt';

/** The only algorithm this core mints proofs with. */
const PROOF_ALG = 'EdDSA';

/** A DPoP proof keypair, with the public half in the JWK form a proof header carries. */
export interface ProofKey {
  /** The signing key. Non-extractable: it can sign and cannot be read. */
  readonly privateKey: CryptoKey;
  /** The public key as a JWK, embedded in every proof's `jwk` header. */
  readonly publicJwk: JsonWebKey;
}

/** What a proof is bound to. */
export interface ProofRequest {
  /** The HTTP method, matched by the server against the request it arrives on. */
  readonly method: string;
  /**
   * The request URI.
   *
   * Normalized to the `htu` form RFC 9449 section 4.2 defines: scheme, authority and path,
   * with the query and fragment REMOVED. Passing a full URL is fine and expected.
   */
  readonly url: string;
  /**
   * The access token this proof accompanies, when one is presented.
   *
   * Present means the proof carries `ath`, the token's SHA-256 thumbprint, which is what
   * stops a proof captured on one request being replayed alongside a different token.
   */
  readonly accessToken?: string;
  /** A server-issued nonce, echoed when the server has demanded one. */
  readonly nonce?: string;
}

/** Base64url, no padding, from bytes. */
function base64url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Base64url of a UTF-8 string. */
function base64urlText(text: string): string {
  return base64url(new TextEncoder().encode(text));
}

/**
 * The `htu` claim for `url`: scheme, authority and path only.
 *
 * The query and fragment are stripped because RFC 9449 says so, and the reason matters: a
 * server comparing `htu` against its own view of the request would otherwise reject every
 * proof whose query string was reordered or re-encoded in transit by a proxy.
 *
 * @throws {TypeError} when `url` is not absolute.
 */
export function htu(url: string): string {
  const parsed = new URL(url);
  return `${parsed.origin}${parsed.pathname}`;
}

/** SHA-256 of `text`, base64url. */
async function sha256(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return base64url(new Uint8Array(digest));
}

/**
 * Generate a DPoP proof keypair.
 *
 * Ed25519, and non-extractable. Ed25519 is universally available across the target
 * runtimes' WebCrypto, so the EdDSA default costs nothing at the edge.
 */
export async function generateProofKey(): Promise<ProofKey> {
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, false, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  // The proof header carries the PUBLIC key only, and only the members that identify it.
  // Exporting whatever the runtime happened to include would leak `key_ops` and `ext`
  // differences into the signed header, so two runtimes would produce different proofs for
  // the same key and a server pinning the thumbprint would see two distinct keys.
  return {
    privateKey: pair.privateKey,
    publicJwk: {
      kty: publicJwk.kty,
      crv: publicJwk.crv,
      x: publicJwk.x,
    },
  };
}

/**
 * Mint one DPoP proof JWT for `request`.
 *
 * Every proof carries a fresh `jti` and the current `iat`, because a server rejects a
 * replayed one on either.
 */
export async function createProof(key: ProofKey, request: ProofRequest): Promise<string> {
  const header = {
    typ: PROOF_TYP,
    alg: PROOF_ALG,
    jwk: key.publicJwk,
  };
  const payload: Record<string, unknown> = {
    jti: crypto.randomUUID(),
    htm: request.method.toUpperCase(),
    htu: htu(request.url),
    iat: Math.floor(Date.now() / 1000),
  };
  if (request.accessToken !== undefined) {
    payload.ath = await sha256(request.accessToken);
  }
  if (request.nonce !== undefined) {
    payload.nonce = request.nonce;
  }
  const signingInput = `${base64urlText(JSON.stringify(header))}.${base64urlText(
    JSON.stringify(payload),
  )}`;
  const signature = await crypto.subtle.sign(
    { name: 'Ed25519' },
    key.privateKey,
    new TextEncoder().encode(signingInput),
  );
  return `${signingInput}.${base64url(new Uint8Array(signature))}`;
}

/** The `DPoP-Nonce` a server issued, or `undefined` when it issued none. */
export function nonceFrom(response: { headers: Headers }): string | undefined {
  return response.headers.get('DPoP-Nonce') ?? undefined;
}

/**
 * Whether `response` is the server demanding a nonce, per RFC 9449 section 8.
 *
 * A 401 carrying `error="use_dpop_nonce"` in `WWW-Authenticate`, or a 400 on the token
 * endpoint with the same error. Both are answered by ONE retry carrying the nonce; a loop
 * would turn a misbehaving server into a request storm.
 */
export function demandsNonce(response: { status: number; headers: Headers }): boolean {
  if (response.status !== 400 && response.status !== 401) {
    return false;
  }
  const challenge = response.headers.get('WWW-Authenticate') ?? '';
  return (
    challenge.includes('use_dpop_nonce') || response.headers.get('DPoP-Nonce') !== null
  );
}

/**
 * Send `request` with a DPoP proof, retrying ONCE if the server demands a nonce.
 *
 * Exactly one retry. RFC 9449 has the server hand back the nonce it wants, so a second
 * failure is a server that will not be satisfied, and looping on it turns one client into a
 * request storm against an endpoint that is already unhappy.
 */
export async function fetchWithProof(
  key: ProofKey,
  input: string,
  init: RequestInit & { accessToken?: string } = {},
  send: typeof fetch = fetch,
): Promise<Response> {
  const method = (init.method ?? 'GET').toUpperCase();
  const attempt = async (nonce?: string): Promise<Response> => {
    const proof = await createProof(key, {
      method,
      url: input,
      accessToken: init.accessToken,
      nonce,
    });
    const headers = new Headers(init.headers);
    headers.set('DPoP', proof);
    if (init.accessToken !== undefined) {
      // `DPoP` scheme, not `Bearer`: presenting a sender-constrained token as a bearer
      // token is what the whole mechanism exists to stop.
      headers.set('Authorization', `DPoP ${init.accessToken}`);
    }
    return send(input, { ...init, method, headers });
  };

  const first = await attempt();
  if (!demandsNonce(first)) {
    return first;
  }
  const nonce = nonceFrom(first);
  if (nonce === undefined) {
    // The server asked for a nonce and did not supply one. Retrying would send an
    // identical proof and get an identical answer.
    return first;
  }
  return attempt(nonce);
}
