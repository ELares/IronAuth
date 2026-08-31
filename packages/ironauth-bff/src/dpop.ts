// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * DPoP proofs (RFC 9449) for the BFF (issue #116).
 *
 * # Why this file exists
 *
 * IronAuth's stated posture is **DPoP by default for public clients** (issue #124): a client
 * that authenticates with `none` must present a DPoP proof at the token endpoint or the
 * exchange is refused with `invalid_dpop_proof`. This BFF supports public clients -- its
 * `clientSecret` is optional -- and had no DPoP at all, so in that configuration it could not
 * complete a login against IronAuth. Measured against the dev emulator before this was written.
 *
 * # ES256, and only ES256
 *
 * IronAuth accepts `EdDSA ES256` for DPoP. ES256 is what every WebCrypto runtime this package
 * targets can generate and sign with today; Ed25519 support is uneven across the edge runtimes
 * (`packages/ironauth-sdk` verifies Ed25519, which is a different operation from generating a
 * key and signing with it). One algorithm, chosen for portability and stated here, beats a
 * negotiation this package cannot actually carry out.
 *
 * # The key is per SESSION, not per process
 *
 * A DPoP-bound token is bound to the key that proved possession when it was issued, so the key
 * must outlive the request that created it and reach the refresh and the API call. It lives in
 * the session store beside the tokens, which is also where it must NOT be: the private key never
 * reaches the browser, exactly like the tokens.
 *
 * A per-process key would work and be simpler. It would also mean every session on a replica
 * shares one binding, so a token stolen from one session could be replayed by any other, which
 * is most of what DPoP is for.
 */

/** A DPoP key pair as JWKs, so it can be stored and restored from the session store. */
export interface DpopKey {
  /** The private key. NEVER leaves the server. */
  privateJwk: JsonWebKey;
  /** The public key, sent inside each proof's header. */
  publicJwk: JsonWebKey;
}

const ALGORITHM = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const SIGN = { name: 'ECDSA', hash: 'SHA-256' } as const;

function b64url(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = '';
  for (const byte of view) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Generate a fresh DPoP key pair. */
export async function newDpopKey(): Promise<DpopKey> {
  const pair = await crypto.subtle.generateKey(ALGORITHM, true, ['sign', 'verify']);
  const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  return { privateJwk, publicJwk };
}

/**
 * The public JWK exactly as a proof header must carry it.
 *
 * Trimmed to the four members RFC 7638 names for a P-256 thumbprint, in that order. Extra
 * members are not an error, but the thumbprint the server computes is over these, and shipping
 * `key_ops` or `ext` into the header invites a mismatch the day some implementation gets
 * strict about it.
 */
function proofJwk(publicJwk: JsonWebKey): Record<string, string> {
  return {
    crv: publicJwk.crv as string,
    kty: publicJwk.kty as string,
    x: publicJwk.x as string,
    y: publicJwk.y as string,
  };
}

/**
 * Build a DPoP proof for one request.
 *
 * @param key the session's key pair
 * @param htm the HTTP method, uppercase (RFC 9449 section 4.2)
 * @param htu the target URL WITHOUT query or fragment (same section)
 * @param nowSeconds the `iat` to stamp
 * @param accessToken when present, adds the `ath` claim binding the proof to this token
 */
export async function dpopProof(
  key: DpopKey,
  htm: string,
  htu: string,
  nowSeconds: number,
  accessToken?: string,
): Promise<string> {
  // Query and fragment are STRIPPED, not trusted to be absent. RFC 9449 defines htu as the
  // request URI without them, and a caller that passed a URL with `?code=...` would produce a
  // proof the server rejects for a reason that looks nothing like the cause.
  const url = new URL(htu);
  url.search = '';
  url.hash = '';

  const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: proofJwk(key.publicJwk) };
  const payload: Record<string, unknown> = {
    // A fresh, unguessable jti per proof: the server keeps a replay cache keyed on (jkt, jti)
    // and refuses a repeat inside the freshness window.
    jti: b64url(crypto.getRandomValues(new Uint8Array(16))),
    htm,
    htu: url.toString(),
    iat: nowSeconds,
  };
  if (accessToken !== undefined) {
    payload.ath = b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(accessToken)));
  }

  const signingInput =
    `${b64url(new TextEncoder().encode(JSON.stringify(header)))}.` +
    `${b64url(new TextEncoder().encode(JSON.stringify(payload)))}`;
  const privateKey = await crypto.subtle.importKey('jwk', key.privateJwk, ALGORITHM, false, ['sign']);
  // WebCrypto's ECDSA signature is the raw r||s pair, which is exactly what JWS ES256 carries.
  const signature = await crypto.subtle.sign(SIGN, privateKey, new TextEncoder().encode(signingInput));
  return `${signingInput}.${b64url(signature)}`;
}

/** The JWK thumbprint (RFC 7638) of a DPoP key, which is what a bound token's `cnf.jkt` holds. */
export async function thumbprint(publicJwk: JsonWebKey): Promise<string> {
  const members = proofJwk(publicJwk);
  // Lexicographic member order with no whitespace is the whole of RFC 7638's canonical form.
  const canonical = `{"crv":"${members.crv}","kty":"${members.kty}","x":"${members.x}","y":"${members.y}"}`;
  return b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical)));
}
