// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * Access and ID token verification, pure WebCrypto (issue #115).
 *
 * No `node:` specifiers and no Node crypto, for the reason the DPoP module gives: Workers
 * and Vercel Edge never expose them, and a core that reached for them would be unusable in
 * the runtimes the framework SDKs target.
 *
 * ## The algorithm comes from the issuer, never from the token
 *
 * RFC 8725 section 3.1. The `alg` header of a token is attacker-controlled, so a verifier
 * that trusts it can be talked into `none`, or into verifying an RS256 signature with an
 * HMAC keyed by the public key. The allow-list here is supplied by the CALLER from the
 * issuer's published metadata, and a token whose header names anything else is refused
 * before a key is even looked up.
 *
 * ## Why a JWKS refetch is rate limited
 *
 * An unknown `kid` is the signal for a key rotation, so it triggers a refetch. It is also
 * free for an attacker to produce: a token with a garbage `kid` costs nothing to mint and
 * would otherwise drive one upstream request per attempt. The cooldown means a flood of
 * garbage costs at most one refetch per window.
 */

/** How a verification failed. Distinct variants, because the caller's response differs. */
export type VerifyFailureReason =
  /** The token is not three base64url segments, or the JSON does not parse. */
  | 'malformed'
  /** The header names an algorithm the issuer does not publish. */
  | 'algorithm_not_allowed'
  /** No key with the token's `kid`, even after a refetch. */
  | 'unknown_key'
  /** The signature does not verify under the named key. */
  | 'bad_signature'
  /** `iss` is not the expected issuer. */
  | 'wrong_issuer'
  /** `aud` does not contain the expected audience. */
  | 'wrong_audience'
  /** `exp` is in the past, beyond the permitted skew. */
  | 'expired'
  /** `nbf` is in the future, beyond the permitted skew. */
  | 'not_yet_valid';

/** A verification failure, as a typed error the caller can branch on. */
export class VerifyError extends Error {
  /** Which check failed. */
  readonly reason: VerifyFailureReason;

  constructor(reason: VerifyFailureReason, message?: string) {
    super(message ?? reason);
    this.name = 'VerifyError';
    this.reason = reason;
  }
}

/** What a verified token yielded. */
export interface VerifiedToken {
  /** The decoded header. */
  readonly header: Record<string, unknown>;
  /** The decoded claims. */
  readonly claims: Record<string, unknown>;
}

/** How to verify. */
export interface VerifyOptions {
  /** The exact issuer the token must name. Compared with `===`, never by prefix. */
  readonly issuer: string;
  /** The audience the token must carry. */
  readonly audience: string;
  /**
   * The algorithms the ISSUER publishes. A token naming anything else is refused.
   *
   * Supplied by the caller from discovery metadata rather than defaulted here, so the
   * allow-list is the issuer's statement rather than this library's guess.
   */
  readonly algorithms: readonly string[];
  /** Permitted clock skew in seconds. Small by default; a large one is a liveness hole. */
  readonly skewSeconds?: number;
  /** The current time in seconds, injectable so tests are deterministic. */
  readonly now?: () => number;
}

/** A JSON Web Key Set as fetched. */
interface Jwks {
  readonly keys: readonly JsonWebKey[];
}

/** Decode one base64url segment to bytes. */
function decodeSegment(segment: string): Uint8Array {
  const padded = segment.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

/** Decode one base64url segment to parsed JSON. */
function decodeJson(segment: string): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(decodeSegment(segment))) as Record<
    string,
    unknown
  >;
}

/** The WebCrypto import and verify parameters for a JOSE algorithm. */
function algorithmParameters(alg: string): {
  importParams: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams;
  verifyParams: AlgorithmIdentifier | RsaPssParams | EcdsaParams;
} | null {
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
      // `none`, HS*, and anything unrecognized. Returning null rather than throwing keeps
      // the refusal on the same path as every other refusal.
      return null;
  }
}

/**
 * A JWKS cache that respects `Cache-Control` and rate limits refetches.
 *
 * One instance per issuer. Sharing one across issuers would let a key from one issuer be
 * offered for a token from another, which is the confused-deputy shape this whole module
 * is guarding.
 */
export class JwksCache {
  readonly #uri: string;
  readonly #fetch: typeof fetch;
  readonly #now: () => number;
  readonly #refetchCooldownSeconds: number;
  #keys: readonly JsonWebKey[] = [];
  #expiresAt = 0;
  #lastFetchAt = -Infinity;

  constructor(options: {
    uri: string;
    fetch?: typeof fetch;
    now?: () => number;
    /** The shortest interval between refetches. Defaults to 30 seconds. */
    refetchCooldownSeconds?: number;
  }) {
    this.#uri = options.uri;
    this.#fetch = options.fetch ?? fetch;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1000));
    this.#refetchCooldownSeconds = options.refetchCooldownSeconds ?? 30;
  }

  /** How many upstream fetches this cache has made. For tests and for metrics. */
  fetchCount = 0;

  /** The key with `kid`, fetching or refetching only when it has to. */
  async keyFor(kid: string | undefined): Promise<JsonWebKey | undefined> {
    if (this.#now() >= this.#expiresAt) {
      await this.#refresh();
    }
    const found = this.#find(kid);
    if (found !== undefined) {
      return found;
    }
    // An unknown kid means a rotation, OR a token minted to make us fetch. The cooldown
    // is what separates the two: a real rotation is answered within one window, and a
    // flood of garbage costs one refetch rather than one per token.
    if (this.#now() - this.#lastFetchAt >= this.#refetchCooldownSeconds) {
      await this.#refresh();
      return this.#find(kid);
    }
    return undefined;
  }

  #find(kid: string | undefined): JsonWebKey | undefined {
    if (kid === undefined) {
      // No kid: usable only when the set is unambiguous. Picking the first of several
      // would make verification depend on the order the issuer happened to serve.
      return this.#keys.length === 1 ? this.#keys[0] : undefined;
    }
    return this.#keys.find((key) => (key as { kid?: string }).kid === kid);
  }

  async #refresh(): Promise<void> {
    this.#lastFetchAt = this.#now();
    this.fetchCount += 1;
    const response = await this.#fetch(this.#uri);
    if (!response.ok) {
      // Keep serving what we have. A JWKS endpoint blipping must not invalidate every
      // token in flight.
      return;
    }
    const body = (await response.json()) as Jwks;
    this.#keys = body.keys ?? [];
    this.#expiresAt = this.#now() + maxAgeOf(response.headers);
  }
}

/**
 * The `max-age` a response permits, in seconds, floored at 0 and defaulted to 300.
 *
 * `no-store` and `no-cache` mean zero, so the next lookup refetches.
 */
export function maxAgeOf(headers: Headers): number {
  const control = headers.get('Cache-Control');
  if (control === null) {
    return 300;
  }
  if (/\bno-store\b|\bno-cache\b/i.test(control)) {
    return 0;
  }
  const match = /\bmax-age\s*=\s*(\d+)/i.exec(control);
  if (match === null) {
    return 300;
  }
  return Math.max(0, Number.parseInt(match[1], 10));
}

/**
 * Verify `token` against `keys` under `options`.
 *
 * @throws {VerifyError} naming the first check that failed.
 */
export async function verifyToken(
  token: string,
  keys: JwksCache,
  options: VerifyOptions,
): Promise<VerifiedToken> {
  const segments = token.split('.');
  if (segments.length !== 3) {
    throw new VerifyError('malformed', 'a JWS has three segments');
  }
  let header: Record<string, unknown>;
  let claims: Record<string, unknown>;
  try {
    header = decodeJson(segments[0]);
    claims = decodeJson(segments[1]);
  } catch {
    throw new VerifyError('malformed', 'the header or claims are not JSON');
  }

  // RFC 7515 section 4.1.11: `crit` lists header parameters the recipient MUST understand. This
  // verifier implements NO extensions, so any `crit` at all is unsupported and the token is
  // invalid. Ignoring it is the dangerous reading: an attacker could mark a security-relevant
  // header as critical and have it silently skipped by the very check meant to honour it.
  //
  // Checked BEFORE the key lookup, for the same reason the algorithm is: a token nobody can
  // verify must not cost an upstream fetch.
  if ('crit' in header) {
    throw new VerifyError('malformed', 'the header declares an unsupported crit extension');
  }

  // FIRST, before a key is looked up. A token naming `none` must never reach key
  // resolution, and one naming an algorithm the issuer does not publish must not cause an
  // upstream fetch either.
  const alg = typeof header.alg === 'string' ? header.alg : '';
  if (!options.algorithms.includes(alg)) {
    throw new VerifyError('algorithm_not_allowed', `the issuer does not publish ${alg}`);
  }
  const parameters = algorithmParameters(alg);
  if (parameters === null) {
    throw new VerifyError('algorithm_not_allowed', `${alg} is not supported`);
  }

  const kid = typeof header.kid === 'string' ? header.kid : undefined;
  const jwk = await keys.keyFor(kid);
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
  if (!verified) {
    throw new VerifyError('bad_signature');
  }

  // Claims are checked only AFTER the signature. Answering "expired" for a forged token
  // tells an attacker their signature was accepted, which it was not.
  const now = (options.now ?? (() => Math.floor(Date.now() / 1000)))();
  const skew = options.skewSeconds ?? 30;
  if (claims.iss !== options.issuer) {
    throw new VerifyError('wrong_issuer');
  }
  const audience = claims.aud;
  const audienceMatches = Array.isArray(audience)
    ? audience.includes(options.audience)
    : audience === options.audience;
  if (!audienceMatches) {
    throw new VerifyError('wrong_audience');
  }
  if (typeof claims.exp === 'number' && now > claims.exp + skew) {
    throw new VerifyError('expired');
  }
  if (typeof claims.nbf === 'number' && now + skew < claims.nbf) {
    throw new VerifyError('not_yet_valid');
  }
  return { header, claims };
}
