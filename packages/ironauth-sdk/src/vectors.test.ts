// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * The TypeScript core against the cross-language conformance corpus (issue #118).
 *
 * Issue #118 ships six independent verifiers: Cloudflare Workers, Fastly Compute in Rust,
 * Lambda@Edge, plain WebCrypto, and official Java and .NET artifacts. Six implementations of
 * one discipline is six chances to disagree, and the disagreements that matter are the
 * REFUSALS. A verifier that accepts `alg: none`, or that trusts the token header's `alg` over
 * the issuer's published set, passes every happy-path test anyone writes for it.
 *
 * This file is the TS core's run against that corpus. Every other verifier in #118 runs the
 * SAME JSON, which is the only way "they all agree" is a measured claim rather than a hope.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { JwksCache, VerifyError, verifyToken } from './verify.js';

interface Vector {
  readonly name: string;
  readonly token: string;
  /** `"accept"`, or the `VerifyFailureReason` this token must be refused with. */
  readonly expect: string;
  readonly why: string;
}

interface Corpus {
  readonly now: number;
  readonly issuer: string;
  readonly audience: string;
  readonly algorithms: readonly string[];
  readonly algorithmsEddsaOnly: readonly string[];
  readonly jwks: { readonly keys: readonly JsonWebKey[] };
  readonly cases: readonly Vector[];
}

const corpus = JSON.parse(
  readFileSync(new URL('../vectors/verify-vectors.json', import.meta.url), 'utf8'),
) as Corpus;

/** A cache serving the corpus JWKS, with no network and a counted fetch. */
function corpusKeys(): { keys: JwksCache; fetches: () => number } {
  const send = (async () =>
    new Response(JSON.stringify(corpus.jwks), {
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'max-age=300' },
    })) as unknown as typeof fetch;
  const keys = new JwksCache({
    uri: 'https://issuer.example/jwks',
    fetch: send,
    now: () => corpus.now,
  });
  return { keys, fetches: () => keys.fetchCount };
}

/**
 * The corpus must not be silently emptied or narrowed.
 *
 * A conformance suite that iterates a list is only as good as the list, and a corpus trimmed
 * during an unrelated edit would leave every one of these tests passing over nothing. So the
 * shape is asserted before the cases are run: a floor on the count, and a floor on the number
 * of REFUSAL cases specifically, since those are the ones that separate a verifier from a
 * signature checker and the ones an implementer is tempted to drop.
 */
test('the corpus is populated and negative-heavy', () => {
  assert.ok(corpus.cases.length >= 16, `expected the corpus, found ${corpus.cases.length}`);
  const refusals = corpus.cases.filter((entry) => entry.expect !== 'accept');
  const accepts = corpus.cases.filter((entry) => entry.expect === 'accept');
  assert.ok(accepts.length >= 4, 'without positive controls, refusing everything would pass');
  assert.ok(
    refusals.length >= accepts.length * 2,
    `the corpus must stay negative-heavy: ${refusals.length} refusals to ${accepts.length}`,
  );
  // Every case explains itself. A vector whose reason is missing cannot be reviewed later.
  for (const entry of corpus.cases) {
    assert.ok(entry.why.length > 20, `${entry.name} has no stated reason`);
  }
});

/**
 * Every distinct refusal reason in the corpus is exercised.
 *
 * Pinning the SET, not a count: a corpus that lost its `alg_none` case while gaining two
 * expiry cases would keep the same total and stop testing the single most important refusal
 * in RFC 8725.
 */
test('the corpus covers every refusal reason the verifier can produce', () => {
  const reasons = new Set(
    corpus.cases.filter((entry) => entry.expect !== 'accept').map((entry) => entry.expect),
  );
  for (const required of [
    'algorithm_not_allowed',
    'bad_signature',
    'unknown_key',
    'wrong_issuer',
    'wrong_audience',
    'expired',
    'not_yet_valid',
    'malformed',
  ]) {
    assert.ok(reasons.has(required), `the corpus no longer covers ${required}`);
  }
});

for (const entry of corpus.cases) {
  test(`vector: ${entry.name}`, async () => {
    const { keys } = corpusKeys();
    // The allow-list is the ISSUER's published set. One vector is judged against an
    // EdDSA-only issuer, which is what turns it into a test of the allow-list rather than of
    // whether ES256 happens to be implemented.
    const algorithms =
      entry.name === 'alg_not_published_by_the_issuer'
        ? corpus.algorithmsEddsaOnly
        : corpus.algorithms;
    const options = {
      issuer: corpus.issuer,
      audience: corpus.audience,
      algorithms,
      now: () => corpus.now,
      skewSeconds: 0,
    };

    if (entry.expect === 'accept') {
      const verified = await verifyToken(entry.token, keys, options);
      assert.equal(verified.claims.iss, corpus.issuer, entry.why);
      return;
    }

    await assert.rejects(
      () => verifyToken(entry.token, keys, options),
      (error: VerifyError) => {
        assert.ok(error instanceof VerifyError, `${entry.name} threw ${error}`);
        assert.equal(
          error.reason,
          entry.expect,
          `${entry.name} must be refused as ${entry.expect}: ${entry.why}`,
        );
        return true;
      },
      entry.why,
    );
  });
}

/**
 * A token the issuer does not publish an algorithm for is refused WITHOUT a key lookup.
 *
 * The ordering is the defence, not a detail. A verifier that resolves the key first turns a
 * garbage `alg` into an upstream JWKS fetch, so anyone can drive traffic at the issuer for the
 * cost of minting a token. Counting fetches is the only way to observe that from outside.
 */
test('an algorithm outside the published set costs no key lookup', async () => {
  const { keys, fetches } = corpusKeys();
  const noneToken = corpus.cases.find((entry) => entry.name === 'alg_none');
  assert.ok(noneToken, 'the alg_none vector must exist for this test to mean anything');
  await assert.rejects(
    () =>
      verifyToken(noneToken.token, keys, {
        issuer: corpus.issuer,
        audience: corpus.audience,
        algorithms: corpus.algorithms,
        now: () => corpus.now,
      }),
    (error: VerifyError) => error.reason === 'algorithm_not_allowed',
  );
  assert.equal(fetches(), 0, 'a refused algorithm must not reach the key set');
});
