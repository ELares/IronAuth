// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * Generate the cross-language JWT verification conformance corpus (issue #118).
 *
 * Issue #118 ships verify snippets for Cloudflare Workers, Fastly Compute (Rust), Lambda@Edge
 * and plain WebCrypto, plus official Java and .NET verifier artifacts. Six independent
 * implementations of the same discipline is six chances to disagree, and the disagreements
 * that matter are the REFUSALS: an implementation that accepts `alg: none`, or trusts the
 * token header's `alg` over the issuer's published set, passes every happy-path test anyone
 * writes for it.
 *
 * So the corpus is negative-heavy by design, it is plain JSON with no language bias, and every
 * case carries the REASON it must be refused rather than just a boolean.
 *
 * ## Deterministic on purpose
 *
 * Fixed keys, a fixed `now`, and fixed claims, so regenerating produces byte-identical output
 * and a freshness gate can prove the checked-in corpus matches this generator. A corpus minted
 * with fresh randomness could not be diffed, so drift between it and the generator would be
 * invisible, and a vector quietly weakened during an edit would look like a legitimate change.
 *
 * Ed25519 is deterministic by construction. ECDSA is NOT, so the ES256 vector is PINNED as a
 * constant and re-verified at generation rather than re-signed; see `ES256_PINNED_TOKEN`. That
 * asymmetry is load-bearing, and getting it wrong is how the first version of this generator
 * emitted a different corpus on every run.
 *
 * Times are FIXED CONSTANTS rather than offsets from the clock: a corpus generated relative to
 * "now" starts failing the day the expired vector's window catches up with it, which is a
 * failure that arrives months later with no connection to any change.
 *
 * Run: node scripts/generate-vectors.mjs
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  createSign,
  sign as nodeSign,
  verify as nodeVerify,
} from 'node:crypto';
import { writeFileSync } from 'node:fs';

/** The evaluation instant every vector is judged at. Fixed, never `Date.now()`. */
const NOW = 1_800_000_000;

/** The issuer every valid vector names. */
const ISSUER = 'https://issuer.example/t/tnt_vectors/e/env_vectors';

/** The audience every valid vector names. */
const AUDIENCE = 'cli_vectors';

/** The Ed25519 signing key. Fixed, so the corpus is reproducible. */
const ED25519_PRIVATE = {
  crv: 'Ed25519',
  d: 'n1MNvpTLMUBvq1x67ogaGTrVjBTbn1fmgkxnxfh8rmA',
  x: '6DrtHwAr87lao-pqeXmJ52C3cwl5LMyWRxL6kCQeleU',
  kty: 'OKP',
};
const ED25519_PUBLIC = { kty: 'OKP', crv: 'Ed25519', x: ED25519_PRIVATE.x, kid: 'ed25519-1' };

/** The ES256 key, for the interop escape hatch a client may be pinned to. */
const ES256_PRIVATE = {
  kty: 'EC',
  x: 'm7xOvG92h-OQN-KA6ftI-6pJmxbRsXSfosv7N_aMTfk',
  y: 'cddtFHcRRcW9rTGQQ56sTEgYRPBWQqVfzkbob3ZXlT8',
  crv: 'P-256',
  d: 'tkduxvIi6MVhxflyTzhjuBw38CfSwHSOiWnYPlQpzAY',
};
const ES256_PUBLIC = {
  kty: 'EC',
  crv: 'P-256',
  x: ES256_PRIVATE.x,
  y: ES256_PRIVATE.y,
  kid: 'es256-1',
};

/** An Ed25519 key that is PUBLISHED but never signs anything, for the wrong-key case. */
const ED25519_DECOY_PUBLIC = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'F83SEmSVgKMBLYCoZfCPDHVGDGVoXVfyxRZsGnPPYQE',
  kid: 'ed25519-decoy',
};

/**
 * The ES256 vectors, PINNED rather than regenerated.
 *
 * ECDSA signing is NON-DETERMINISTIC: RFC 6979 deterministic k is not what Node's signer does,
 * so re-minting produces a different signature every run. That would make this corpus
 * un-diffable and the freshness gate a permanent false alarm, which is worse than useless
 * because a real weakening would hide in the noise.
 *
 * So the token is minted ONCE and pinned here. `assertPinnedTokenVerifies` below re-checks it
 * against the published key at generation time, so a pin that is corrupted, truncated, or
 * edited to match a weakened claim fails loudly instead of being trusted because it is a
 * constant.
 *
 * Both ES256 cases share this ONE token deliberately: `alg_not_published_by_the_issuer` is the
 * same bytes as `valid_es256` judged against an issuer publishing EdDSA only. That is what
 * makes it a test of the allow-list rather than of whether ES256 is implemented, and it is only
 * literally true if the two are the same token.
 */
const ES256_PINNED_TOKEN =
  'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImVzMjU2LTEifQ.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlL3QvdG50X3ZlY3RvcnMvZS9lbnZfdmVjdG9ycyIsImF1ZCI6ImNsaV92ZWN0b3JzIiwic3ViIjoidXNyX3ZlY3RvcnMiLCJpYXQiOjE3OTk5OTk5NDAsIm5iZiI6MTc5OTk5OTk0MCwiZXhwIjoxODAwMDAzNjAwfQ.0WpR5-Q9wSdeRt67tpytwckcQNQ9sdXbE-2f3iDJDpAvrca4pfQv_Bayn9CuhjICC0ntzMFYpLUHvupzK7Lgbw';

/** Re-verify a pinned token, so a constant cannot silently become wrong. */
function assertPinnedTokenVerifies(token, jwk) {
  const [header, payload, signature] = token.split('.');
  const ok = nodeVerify(
    'SHA256',
    Buffer.from(`${header}.${payload}`, 'utf8'),
    { key: createPublicKey({ key: jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' },
    Buffer.from(signature, 'base64url'),
  );
  if (!ok) {
    throw new Error(
      'the pinned ES256 token no longer verifies against the published key; it was edited or ' +
        'the key changed, and either way the corpus would ship a vector that proves nothing',
    );
  }
}

function base64url(buffer) {
  return Buffer.from(buffer).toString('base64url');
}

function encodeSegment(value) {
  return base64url(Buffer.from(JSON.stringify(value), 'utf8'));
}

/** Sign a compact JWS with `jwk`, or produce an UNSIGNED one when `alg` is `none`. */
function mint(header, claims, jwk) {
  const signingInput = `${encodeSegment(header)}.${encodeSegment(claims)}`;
  if (header.alg === 'none') {
    // RFC 8725's headline refusal. The empty signature is what the attack looks like.
    return `${signingInput}.`;
  }
  const key = createPrivateKey({ key: jwk, format: 'jwk' });
  let signature;
  if (header.alg === 'EdDSA') {
    signature = nodeSign(null, Buffer.from(signingInput, 'utf8'), key);
  } else {
    // ES256 needs the raw r||s form JOSE requires, not the DER the signer emits by default.
    const signer = createSign('SHA256');
    signer.update(signingInput);
    signature = signer.sign({ key, dsaEncoding: 'ieee-p1363' });
  }
  return `${signingInput}.${base64url(signature)}`;
}

/** The claim set a valid token carries, before any per-case override. */
function baseClaims(overrides = {}) {
  return {
    iss: ISSUER,
    aud: AUDIENCE,
    sub: 'usr_vectors',
    iat: NOW - 60,
    nbf: NOW - 60,
    exp: NOW + 3600,
    ...overrides,
  };
}

const cases = [];

/** Register one vector. `expect` is `"accept"`, or the reason it must be refused. */
function vector(name, token, expect, why) {
  cases.push({ name, token, expect, why });
}

// ---------------------------------------------------------------------------------------------
// Positive controls. Without these the corpus could be satisfied by refusing everything.
// ---------------------------------------------------------------------------------------------

vector(
  'valid_eddsa',
  mint({ alg: 'EdDSA', typ: 'JWT', kid: 'ed25519-1' }, baseClaims(), ED25519_PRIVATE),
  'accept',
  'the default posture: an Ed25519 token from the published key, inside its window',
);

assertPinnedTokenVerifies(ES256_PINNED_TOKEN, ES256_PUBLIC);

vector(
  'valid_es256',
  ES256_PINNED_TOKEN,
  'accept',
  'the documented interop escape hatch for consumers that cannot verify EdDSA',
);

vector(
  'valid_audience_array',
  mint(
    { alg: 'EdDSA', typ: 'JWT', kid: 'ed25519-1' },
    baseClaims({ aud: ['other_client', AUDIENCE] }),
    ED25519_PRIVATE,
  ),
  'accept',
  'aud may be an array, and membership is what counts (RFC 7519 4.1.3)',
);

vector(
  'valid_at_the_expiry_boundary',
  mint({ alg: 'EdDSA', typ: 'JWT', kid: 'ed25519-1' }, baseClaims({ exp: NOW }), ED25519_PRIVATE),
  'accept',
  'exp is "not accepted ON or after" only once skew is exhausted; at exactly now it is live',
);

// ---------------------------------------------------------------------------------------------
// Algorithm confusion. The refusals that separate a verifier from a signature checker.
// ---------------------------------------------------------------------------------------------

vector(
  'alg_none',
  mint({ alg: 'none', typ: 'JWT', kid: 'ed25519-1' }, baseClaims(), null),
  'algorithm_not_allowed',
  'RFC 8725 3.1: an unsigned token must never verify, and must be refused BEFORE key lookup',
);

vector(
  'alg_not_published_by_the_issuer',
  ES256_PINNED_TOKEN,
  'algorithm_not_allowed',
  'the SAME token as valid_es256, judged against an issuer publishing EdDSA only: the ' +
    'allow-list is the issuer metadata, never the token header, so a verifier that reads alg ' +
    'from the token accepts this and is wrong',
  );

vector(
  'alg_hs256_forged_with_the_public_key',
  (() => {
    // The classic confusion: HMAC the signing input with the PUBLIC key bytes as the secret.
    // A verifier that dispatches on the token's `alg` will validate this against its own
    // published key material.
    const header = { alg: 'HS256', typ: 'JWT', kid: 'ed25519-1' };
    const input = `${encodeSegment(header)}.${encodeSegment(baseClaims())}`;
    const secret = Buffer.from(ED25519_PUBLIC.x, 'base64url');
    const mac = createHash('sha256').update(secret).update(input).digest();
    return `${input}.${base64url(mac)}`;
  })(),
  'algorithm_not_allowed',
  'an asymmetric-only issuer must refuse HS* outright, so the public-key-as-HMAC-secret ' +
    'confusion is inexpressible rather than merely unlikely',
);

// ---------------------------------------------------------------------------------------------
// Signature and key binding.
// ---------------------------------------------------------------------------------------------

vector(
  'tampered_payload',
  (() => {
    const token = mint(
      { alg: 'EdDSA', typ: 'JWT', kid: 'ed25519-1' },
      baseClaims(),
      ED25519_PRIVATE,
    );
    const [header, , signature] = token.split('.');
    // Elevate the subject and keep the original signature.
    return `${header}.${encodeSegment(baseClaims({ sub: 'usr_admin' }))}.${signature}`;
  })(),
  'bad_signature',
  'the payload was edited under a signature that still parses; only the check catches it',
);

vector(
  'signed_by_an_unpublished_key',
  mint(
    { alg: 'EdDSA', typ: 'JWT', kid: 'ed25519-decoy' },
    baseClaims(),
    // Signed by the REAL key while naming the decoy's kid, so resolution finds a published key
    // that did not sign this token. A verifier that resolves by kid and forgets to verify, or
    // that falls back to "any key in the set", accepts it.
    ED25519_PRIVATE,
  ),
  'bad_signature',
  'the named key is published but did not sign this token',
);

vector(
  'unknown_kid',
  mint({ alg: 'EdDSA', typ: 'JWT', kid: 'ed25519-absent' }, baseClaims(), ED25519_PRIVATE),
  'unknown_key',
  'no published key matches; a verifier may refetch once but must not fall back to a guess',
);

// ---------------------------------------------------------------------------------------------
// Claim discipline.
// ---------------------------------------------------------------------------------------------

vector(
  'wrong_issuer',
  mint(
    { alg: 'EdDSA', typ: 'JWT', kid: 'ed25519-1' },
    baseClaims({ iss: 'https://issuer.example/t/tnt_vectors/e/env_other' }),
    ED25519_PRIVATE,
  ),
  'wrong_issuer',
  'a sibling environment under the same host: iss is compared EXACTLY, never by prefix, or ' +
    'one environment tokens would be accepted as another',
);

vector(
  'wrong_audience',
  mint(
    { alg: 'EdDSA', typ: 'JWT', kid: 'ed25519-1' },
    baseClaims({ aud: 'another_client' }),
    ED25519_PRIVATE,
  ),
  'wrong_audience',
  'a token minted for a different client of the SAME issuer must not verify here',
);

vector(
  'expired',
  mint(
    { alg: 'EdDSA', typ: 'JWT', kid: 'ed25519-1' },
    baseClaims({ exp: NOW - 3600 }),
    ED25519_PRIVATE,
  ),
  'expired',
  'an hour past expiry, far beyond any sane skew',
);

vector(
  'not_yet_valid',
  mint(
    { alg: 'EdDSA', typ: 'JWT', kid: 'ed25519-1' },
    baseClaims({ nbf: NOW + 3600 }),
    ED25519_PRIVATE,
  ),
  'not_yet_valid',
  'nbf an hour in the future, so a verifier ignoring nbf is caught',
);

// ---------------------------------------------------------------------------------------------
// Structural.
// ---------------------------------------------------------------------------------------------

vector('malformed_two_segments', 'aaaa.bbbb', 'malformed', 'a JWS has three segments');
vector(
  'malformed_not_base64',
  '!!!.!!!.!!!',
  'malformed',
  'segments that do not decode must be refused before anything else is attempted',
);

const corpus = {
  // A note to whoever opens this file, since a generated corpus is exactly the artifact someone
  // hand-edits at 2am.
  $comment:
    'GENERATED by packages/ironauth-sdk/scripts/generate-vectors.mjs (issue #118). Do not ' +
    'edit by hand: scripts/verify-vectors.sh regenerates this file and fails if it differs. ' +
    'Every verifier snippet and SDK in issue #118 is judged against this one corpus.',
  now: NOW,
  issuer: ISSUER,
  audience: AUDIENCE,
  // The allow-list is the ISSUER's published set. `alg_not_published_by_the_issuer` is judged
  // against `algorithmsEddsaOnly` and everything else against `algorithms`, which is what makes
  // that case a test of the allow-list rather than of ES256 support.
  algorithms: ['EdDSA', 'ES256'],
  algorithmsEddsaOnly: ['EdDSA'],
  jwks: { keys: [ED25519_PUBLIC, ES256_PUBLIC, ED25519_DECOY_PUBLIC] },
  cases,
};

const target = new URL('../vectors/verify-vectors.json', import.meta.url);
writeFileSync(target, `${JSON.stringify(corpus, null, 2)}\n`);
process.stdout.write(`wrote ${cases.length} vectors to ${target.pathname}\n`);
