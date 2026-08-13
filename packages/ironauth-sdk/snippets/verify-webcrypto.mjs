// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * Verify an IronAuth token at the edge, in one file, with no dependencies (issue #118).
 *
 * COPY THIS FILE. That is what it is for. It imports nothing, so it drops into a Cloudflare
 * Worker, a Deno or Bun service, a Node 20+ handler, or a Lambda@Edge function unchanged. It is
 * deliberately NOT an import from `@ironauth/sdk`: a snippet you have to install a package to
 * use is not a snippet, and the whole point of issue #118 is that verifying a token at the edge
 * should cost nothing.
 *
 * NOT SUPPORTED: CloudFront Functions. That tier offers only HMAC and digest primitives, so
 * asymmetric JWT verification is impossible there for any algorithm, and no amount of care in
 * this file changes that. Use Lambda@Edge on AWS, which runs full Node and can run this.
 *
 * Because this file duplicates logic that also lives in the SDK's `verify.ts`, the two are kept
 * honest by running the SAME conformance corpus (`../vectors/verify-vectors.json`). Two
 * implementations that agree on sixteen adversarial vectors are two implementations that agree.
 *
 * ## What this actually checks
 *
 * Signature verification alone is not verification. In order:
 *
 *   1. the token is three base64url segments whose header and claims are JSON;
 *   2. the header's `alg` is in the allow-list YOU pass, taken from the issuer's published
 *      metadata, never from the token;
 *   3. a key with the token's `kid` exists, refetching at most once per cooldown;
 *   4. the signature verifies under that key;
 *   5. and only THEN `iss`, `aud`, `exp` and `nbf`.
 *
 * The ordering is the part to preserve if you edit this. Checking the algorithm before the key
 * means a garbage `alg` costs no upstream fetch, so nobody can drive traffic at the issuer by
 * minting tokens. Checking claims after the signature means a forged token is reported as a bad
 * signature rather than as "expired", which would tell an attacker their forgery was accepted.
 *
 * @example
 *   import { createVerifier } from './verify-webcrypto.mjs';
 *   const verify = createVerifier({
 *     issuer: 'https://auth.example/t/acme/e/prod',
 *     audience: 'my-api',
 *     jwksUri: 'https://auth.example/t/acme/e/prod/jwks.json',
 *     algorithms: ['EdDSA'],           // from the issuer's discovery document
 *   });
 *   const { claims } = await verify(request.headers.get('Authorization')?.slice(7));
 */

/** Why a verification failed. Branch on `error.reason`, never on the message. */
export class VerifyError extends Error {
  constructor(reason, message) {
    super(message ?? reason);
    this.name = 'VerifyError';
    this.reason = reason;
  }
}

/** WebCrypto import and verify parameters per JOSE algorithm. `null` means unsupported. */
function algorithmParameters(alg) {
  switch (alg) {
    case 'EdDSA':
      return { importParams: { name: 'Ed25519' }, verifyParams: { name: 'Ed25519' } };
    case 'ES256':
      return {
        importParams: { name: 'ECDSA', namedCurve: 'P-256' },
        verifyParams: { name: 'ECDSA', hash: 'SHA-256' },
      };
    case 'RS256':
      return {
        importParams: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        verifyParams: { name: 'RSASSA-PKCS1-v1_5' },
      };
    default:
      // `none`, every HS* variant, and anything unrecognised. Returning null rather than
      // throwing keeps the refusal on the same path as every other refusal.
      return null;
  }
}

function decodeSegment(segment) {
  const padded = segment.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function decodeJson(segment) {
  return JSON.parse(new TextDecoder().decode(decodeSegment(segment)));
}

/**
 * The `max-age` a response permits, in seconds, floored at 0 and defaulting to 300.
 *
 * `no-store` and `no-cache` mean zero, so the next lookup refetches. Honouring this is what
 * makes key rotation work without a deploy.
 */
export function maxAgeOf(headers) {
  const control = headers.get('Cache-Control');
  if (control === null) return 300;
  if (/\bno-store\b|\bno-cache\b/i.test(control)) return 0;
  const match = /\bmax-age\s*=\s*(\d+)/i.exec(control);
  if (match === null) return 300;
  return Math.max(0, Number.parseInt(match[1], 10));
}

/**
 * Build a verifier bound to one issuer.
 *
 * `algorithms` MUST come from the issuer's published metadata. Passing the algorithms you
 * happen to expect is the RFC 8725 mistake this parameter exists to prevent; passing the
 * token's own `alg` would be the same mistake with extra steps.
 *
 * One verifier per issuer. Sharing a key cache across issuers would let a key published by one
 * be offered for a token minted by another, which is the confused-deputy shape all of this is
 * guarding against.
 */
export function createVerifier({
  issuer,
  audience,
  jwksUri,
  algorithms,
  skewSeconds = 30,
  refetchCooldownSeconds = 30,
  fetch: send = fetch,
  now = () => Math.floor(Date.now() / 1000),
}) {
  if (!Array.isArray(algorithms) || algorithms.length === 0) {
    throw new TypeError('algorithms must come from the issuer metadata and cannot be empty');
  }

  let keys = [];
  let expiresAt = 0;
  let lastFetchAt = -Infinity;
  let fetchCount = 0;

  async function refresh() {
    lastFetchAt = now();
    fetchCount += 1;
    const response = await send(jwksUri);
    // A JWKS endpoint blipping must not invalidate every token in flight, so keep serving
    // what we already hold.
    if (!response.ok) return;
    const body = await response.json();
    keys = body.keys ?? [];
    expiresAt = now() + maxAgeOf(response.headers);
  }

  function find(kid) {
    if (kid === undefined) {
      // No kid is usable only when the set is unambiguous. Picking the first of several would
      // make verification depend on the order the issuer happened to serve them in.
      return keys.length === 1 ? keys[0] : undefined;
    }
    return keys.find((key) => key.kid === kid);
  }

  async function keyFor(kid) {
    if (now() >= expiresAt) await refresh();
    const found = find(kid);
    if (found !== undefined) return found;
    // An unknown kid means a rotation, OR a token minted to make us fetch. The cooldown
    // separates the two: a real rotation is picked up within one window, and a flood of
    // garbage costs one refetch rather than one per token.
    if (now() - lastFetchAt >= refetchCooldownSeconds) {
      await refresh();
      return find(kid);
    }
    return undefined;
  }

  /** Verify `token`, returning `{ header, claims }` or throwing {@link VerifyError}. */
  async function verify(token) {
    if (typeof token !== 'string') throw new VerifyError('malformed', 'no token supplied');
    const segments = token.split('.');
    if (segments.length !== 3) throw new VerifyError('malformed', 'a JWS has three segments');

    let header;
    let claims;
    try {
      header = decodeJson(segments[0]);
      claims = decodeJson(segments[1]);
    } catch {
      throw new VerifyError('malformed', 'the header or claims are not JSON');
    }

    // FIRST, before any key lookup. A token naming `none` must never reach key resolution, and
    // one naming an algorithm the issuer does not publish must not cause an upstream fetch.
    const alg = typeof header.alg === 'string' ? header.alg : '';
    if (!algorithms.includes(alg)) {
      throw new VerifyError('algorithm_not_allowed', `the issuer does not publish ${alg}`);
    }
    const parameters = algorithmParameters(alg);
    if (parameters === null) {
      throw new VerifyError('algorithm_not_allowed', `${alg} is not supported`);
    }

    const jwk = await keyFor(typeof header.kid === 'string' ? header.kid : undefined);
    if (jwk === undefined) {
      throw new VerifyError('unknown_key', 'no published key matches this token');
    }

    const key = await crypto.subtle.importKey('jwk', jwk, parameters.importParams, false, [
      'verify',
    ]);
    const verified = await crypto.subtle.verify(
      parameters.verifyParams,
      key,
      decodeSegment(segments[2]),
      new TextEncoder().encode(`${segments[0]}.${segments[1]}`),
    );
    if (!verified) throw new VerifyError('bad_signature');

    // Claims only AFTER the signature. Answering "expired" for a forged token would tell an
    // attacker their signature was accepted, which it was not.
    const at = now();
    if (claims.iss !== issuer) throw new VerifyError('wrong_issuer');
    const matches = Array.isArray(claims.aud)
      ? claims.aud.includes(audience)
      : claims.aud === audience;
    if (!matches) throw new VerifyError('wrong_audience');
    if (typeof claims.exp === 'number' && at > claims.exp + skewSeconds) {
      throw new VerifyError('expired');
    }
    if (typeof claims.nbf === 'number' && at + skewSeconds < claims.nbf) {
      throw new VerifyError('not_yet_valid');
    }
    return { header, claims };
  }

  /** How many upstream JWKS fetches this verifier has made. For tests and metrics. */
  verify.fetchCount = () => fetchCount;
  return verify;
}
