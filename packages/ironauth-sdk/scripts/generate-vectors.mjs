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

/**
 * The RS256 key, for the vector BOTH the TypeScript and Rust verifiers can check.
 *
 * ES256 cannot fill that role: the Rust verifier has no P-256 constructor, so its ES256 vector
 * is only ever exercised as an allowlist refusal. RSA is supported by both, and PKCS#1 v1.5
 * signing is DETERMINISTIC, so unlike ES256 this vector regenerates byte-identically and needs
 * no pinning.
 */
const RS256_PRIVATE = {
  "kty": "RSA",
  "n": "uRAlOVIju8R1E-j2U0730q3q0lQlJ9aB0l-QPkn-YtryolFz6Sf3BWeSWeHwcpeLpwZQXwil3YCs-eypJcOm15CUCTRDP1Yqqwte7DJxwgg3zZBP7nhaVwnhBiXPkB-Bovaj4ec97Q2sgA5uRU_o_e5tqbOvf6dr2GApFM_M0eS3f7JqVItNgYVeYY6kcZVV1RqVQ6PzNlOSbLKYDgNyzDcItB6x9mZAM2KZoeghUdPo2jV1j9ozV26PGPVsLqWHfkel4SbXkmOdMucr0TXOktfQHcR4viOj4Tjoot1RDa3-fwhWTWLhGN3k8Kku__jlFieltvWfGH_U2nJ-4ygRRQ",
  "e": "AQAB",
  "d": "BBSUDYh_GzPAtRis3bdfBXkqNUr_qrozEJVk08rD3iAfu256VMi5zJe1BWBS8ePfg2ZDPWUuawzcQ4JxVFDVC-m3KeDKHspilHTiueh-051kxZaJ_KMQstyX5o_M3MulCxfPEzsLBYAIrqYizkptw7OPHW_FzdW-Lf4oybmvNW2A96tY9Yw3onVvtpiOvnt0cnM-NvdzRcLnsiX_aJifJOcz04NWnkHeE4Q0aiBXoTAheTW6X6gu_RgeOgB8hdzvJQn9-KT6Hgp5sVHU5RQM5GXZ7LSzoAUp2yAczucepX_XLid34kWLXVZE6ZuRqD5DxUDxgcvoWNWQeFOHyVp-fQ",
  "p": "4SczOMEU8srxv7aDN-AeMuwcMamYSDYaCQzGsiNX8NcAo7ri5ZeEEhOyf3HaEiXBgAB4luYMJ1wKKAlsoU4SQR2OTwlboWcO6-JItmCwLCaKdFKTqChQ21i1Qp0ik_BpnET1LvotzSDt6GqHOK235i5TBImqgdXObCBRFbM5Ug8",
  "q": "0mrdr-la3KF7UWtlL3CnsQLqEyH9GSiWHJZdXFVRBgc4vtht6X833ifJoD29UPuSYYbKOxLw1V3gLrOjRh7bBj_stu3ywtVNTIuyy2EeWpfAomIFtKSQuT7_Ud4Oyy161FIN1P2P2YaeRS60yHguNswRFZ5tSACghlUl0ekx62s",
  "dp": "W01aKBmkNRC3F9cbPv1TQbMde8YaSq4lwKW9rV9HuhJ13-9ZM2FN3Ua_i47Pr6w_23hVblu7cfqQ48tukbrnDCDAJKzWy4zPMDiC4_IxfrXiT2ltFzPCFjDS0ECIVRWYvhX4lyQ8joJb93O7gfBwMpd2ctCgpCXfn1k7iGE1TWE",
  "dq": "bDmjBFOV9FzqPJpsVNYwqg7Brk2RDFufudxs8IzBO8SDH0XaYnqYlZ8JSW337as3Qwo9Ad1gGZ5LLDohBHPiW3iNnBkO_78OHwzLTWgKYLYk0mBwZtUtytnoIIeCPGaMAqChlKdGUa-3wAWh3mpR-sVDFEeEFcCcz_sDlM_IaTk",
  "qi": "jOz19soZl-fhG0q7xge35UeizLyJPM6syvDQfJquP89Q2u-kPm1Lawp5BKscwoHQZ0nqmO8xWck3di2XR3BXpN0gtkjqhEiFrYfj2mslCoakHue1D0oUDniRrOtUFuUJvT2g1hzOYdsb7p0LmRfqmb2CPY3cuos-4r4UkT63TPc"
};
const RS256_PUBLIC = {
  kty: 'RSA',
  n: RS256_PRIVATE.n,
  e: RS256_PRIVATE.e,
  kid: 'rsa-1',
};

/**
 * An Ed25519 key that is PUBLISHED but never signs anything, for the wrong-key case.
 *
 * A REAL public key, exported from a generated keypair, and that is load bearing rather than
 * tidy. The previous value was 32 bytes that are not a point on the curve, and the two
 * implementations judged against this corpus disagreed about it: WebCrypto's `importKey` accepts
 * it and the signature check then fails (`bad_signature`, which is what the case asserts), while
 * `ed25519-dalek`'s `VerifyingKey::from_bytes` validates the point and refuses the KEY -- so the
 * Rust snippet reported `unknown_key` and failed a case it implements correctly.
 *
 * The case's own reason is "the named key is published but did not sign this token", and that
 * sentence needs the published thing to actually be a key. Anything else tests point validation
 * on one implementation and key resolution on another.
 */
const ED25519_DECOY_PUBLIC = {
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'HKXZ6AA3cXV3rkGkXABdZYVlYGj74LGGXH7khOzfzzo',
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
  } else if (header.alg === 'RS256') {
    // RSASSA-PKCS1-v1_5, which is what RS256 means and which is deterministic.
    signature = nodeSign('RSA-SHA256', Buffer.from(signingInput, 'utf8'), key);
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
  'valid_rs256',
  mint({ alg: 'RS256', typ: 'JWT', kid: 'rsa-1' }, baseClaims(), RS256_PRIVATE),
  'accept',
  'the one accepted vector BOTH language implementations verify: Rust has no P-256 key type, ' +
    'so ES256 can only ever be an allowlist refusal there, and without this the cross-language ' +
    'agreement would rest on EdDSA alone',
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
// Header injection. Attacks that arrive as a well-formed, correctly signed token.
// ---------------------------------------------------------------------------------------------

/** An Ed25519 key the ATTACKER holds. Never published, and never trusted. */
const ATTACKER_PRIVATE = {
  crv: 'Ed25519',
  d: 'RCoJ8bYWTBpBtBUCzR0y_v3Jm5f-i1YSAg_hVPqfSbA',
  x: 'F83SEmSVgKMBLYCoZfCPDHVGDGVoXVfyxRZsGnPPYQE',
  kty: 'OKP',
};

vector(
  'embedded_jwk_key_injection',
  mint(
    {
      alg: 'EdDSA',
      typ: 'JWT',
      // Names a key the issuer really publishes, so kid resolution "succeeds"...
      kid: 'ed25519-1',
      // ...while the header ALSO carries the attacker's own public key. A verifier that
      // resolves the key from the header rather than from the published set validates this
      // perfectly, because the token is genuinely signed by the key it carries.
      jwk: { kty: 'OKP', crv: 'Ed25519', x: ATTACKER_PRIVATE.x },
    },
    baseClaims({ sub: 'usr_admin' }),
    ATTACKER_PRIVATE,
  ),
  'bad_signature',
  'the header carries the attacker key that signed it while naming a published kid: a verifier ' +
    'trusting the embedded jwk accepts a token minted by anyone, which is the single most ' +
    'damaging JOSE implementation error there is',
);

vector(
  'unknown_crit_header',
  mint(
    {
      alg: 'EdDSA',
      typ: 'JWT',
      kid: 'ed25519-1',
      // RFC 7515 section 4.1.11: a `crit` naming an extension the verifier does not understand
      // MUST cause rejection. Ignoring it lets an attacker mark a security-relevant header as
      // critical and have it silently skipped.
      crit: ['ironauth-not-a-real-extension'],
    },
    baseClaims(),
    ED25519_PRIVATE,
  ),
  'malformed',
  'RFC 7515 4.1.11: an unrecognised `crit` extension must be refused, never ignored',
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
  algorithms: ['EdDSA', 'ES256', 'RS256'],
  algorithmsEddsaOnly: ['EdDSA'],
  jwks: { keys: [ED25519_PUBLIC, ES256_PUBLIC, RS256_PUBLIC, ED25519_DECOY_PUBLIC] },
  cases,
};

const json = `${JSON.stringify(corpus, null, 2)}\n`;
const target = new URL('../vectors/verify-vectors.json', import.meta.url);
writeFileSync(target, json);

// AND THE `.mjs` MIRROR, from the same object in the same run.
//
// That file's own header says "GENERATED from verify-vectors.json by
// scripts/generate-vectors.mjs", and until this line existed that sentence was FALSE: this
// script wrote only the JSON, so the module was hand-maintained while claiming not to be. The
// single thing catching a drift was one assertion in `vectors.test.ts` -- which is a real gate,
// but it tells you the two disagree AFTER someone has hand-edited one of them, rather than
// making that impossible.
//
// Found while adding the Rust snippet: changing the decoy key regenerated the JSON, the module
// kept the old value, and the two went out of step in one command.
const moduleHeader = `// SPDX-License-Identifier: MIT OR Apache-2.0
//
// GENERATED from verify-vectors.json by scripts/generate-vectors.mjs. Do not edit.
//
// # Why a .mjs beside the .json
//
// The conformance corpus has to be readable from code that runs in FIVE runtimes,
// including workerd. A JSON import needs either an import attribute or a bundler rule,
// and support for both varies across those runtimes and across bundler versions, so a
// JSON import in the shared checks would make the portability matrix depend on the very
// thing it exists to test. A plain ES module imports identically everywhere.
//
// The JSON stays canonical: it is what the Rust conformance test and the Node suite read,
// and \`the generated vectors module matches the json corpus\` in verify.test.ts fails if
// this file drifts from it.

export default `;
const moduleTarget = new URL('../vectors/verify-vectors.mjs', import.meta.url);
writeFileSync(moduleTarget, `${moduleHeader}${JSON.stringify(corpus, null, 2)};\n`);

process.stdout.write(
  `wrote ${cases.length} vectors to ${target.pathname} and ${moduleTarget.pathname}\n`,
);
