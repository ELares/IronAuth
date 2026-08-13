// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * The copy-paste WebCrypto snippet against the conformance corpus (issue #118).
 *
 * The snippet deliberately duplicates logic that also lives in `src/verify.ts`, because a
 * sample you must install a package to use is not a sample. Duplication invites drift, so the
 * two are held together by running the SAME sixteen adversarial vectors. Two implementations
 * that agree on `alg: none`, on an HS256 forgery keyed with the public key, and on a token
 * signed by a published-but-wrong key are two implementations that agree.
 *
 * Plain `node:test`, no build step, because the snippet is plain JavaScript on purpose.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { VerifyError, createVerifier, maxAgeOf } from './verify-webcrypto.mjs';

const corpus = JSON.parse(
  readFileSync(new URL('../vectors/verify-vectors.json', import.meta.url), 'utf8'),
);

/** A verifier wired to the corpus, with a counted, network-free JWKS response. */
function verifierFor({ algorithms = corpus.algorithms, cacheControl = 'max-age=300' } = {}) {
  let fetches = 0;
  const send = async () => {
    fetches += 1;
    return new Response(JSON.stringify(corpus.jwks), {
      headers: { 'Content-Type': 'application/json', 'Cache-Control': cacheControl },
    });
  };
  const verify = createVerifier({
    issuer: corpus.issuer,
    audience: corpus.audience,
    jwksUri: 'https://issuer.example/jwks',
    algorithms,
    skewSeconds: 0,
    now: () => corpus.now,
    fetch: send,
  });
  return { verify, fetches: () => fetches };
}

for (const entry of corpus.cases) {
  test(`snippet vector: ${entry.name}`, async () => {
    // One vector is judged against an EdDSA-only issuer, which is what makes it a test of the
    // allow-list rather than of whether ES256 happens to be implemented.
    const algorithms =
      entry.name === 'alg_not_published_by_the_issuer'
        ? corpus.algorithmsEddsaOnly
        : corpus.algorithms;
    const { verify } = verifierFor({ algorithms });

    if (entry.expect === 'accept') {
      const { claims } = await verify(entry.token);
      assert.equal(claims.iss, corpus.issuer, entry.why);
      return;
    }
    await assert.rejects(
      () => verify(entry.token),
      (error) => {
        assert.ok(error instanceof VerifyError, `${entry.name} threw ${error}`);
        assert.equal(error.reason, entry.expect, `${entry.name}: ${entry.why}`);
        return true;
      },
    );
  });
}

/**
 * The corpus must not be silently emptied, or every test above would pass over nothing.
 *
 * The same guard the TS core's run carries. A conformance suite that iterates a list is only
 * as good as the list.
 */
test('the snippet ran the whole corpus', () => {
  assert.ok(corpus.cases.length >= 16, `only ${corpus.cases.length} vectors`);
  const refusals = corpus.cases.filter((entry) => entry.expect !== 'accept');
  assert.ok(refusals.length >= 12, `only ${refusals.length} refusal vectors`);
});

/**
 * A refused algorithm costs NO key lookup.
 *
 * The ordering is a defence, not a detail: a verifier that resolves the key first turns a
 * garbage `alg` into an upstream JWKS request, so anyone can drive traffic at the issuer for
 * the price of minting a token. Counting fetches is the only way to see this from outside.
 */
test('an algorithm outside the published set costs no upstream fetch', async () => {
  const { verify, fetches } = verifierFor();
  const noneToken = corpus.cases.find((entry) => entry.name === 'alg_none');
  await assert.rejects(
    () => verify(noneToken.token),
    (error) => error.reason === 'algorithm_not_allowed',
  );
  assert.equal(fetches(), 0, 'a refused algorithm must not reach the key set');
});

/**
 * An unknown `kid` refetches at most once per cooldown.
 *
 * Without the cooldown, a token with a garbage `kid` costs nothing to mint and one upstream
 * request per attempt, which makes the issuer's JWKS endpoint a free amplification target.
 */
test('a flood of unknown kids is rate limited to one refetch', async () => {
  const { verify, fetches } = verifierFor();
  const unknown = corpus.cases.find((entry) => entry.name === 'unknown_kid');
  for (let attempt = 0; attempt < 5; attempt += 1) {
    await assert.rejects(() => verify(unknown.token), (error) => error.reason === 'unknown_key');
  }
  assert.equal(
    fetches(),
    1,
    'the first lookup populates the cache; the cooldown absorbs every later miss',
  );
});

/**
 * `Cache-Control` is honoured BY THE VERIFIER, not merely parsed correctly.
 *
 * This is the wiring test, and it exists because a mutation that hardcoded the cache lifetime
 * to 300 seconds survived a suite that only exercised `maxAgeOf` on its own. Parsing the
 * directive and then ignoring it is exactly as broken as parsing it wrong, and only a test that
 * counts upstream fetches can tell the difference.
 *
 * The `max-age` case is the control: same verifier, same tokens, one fetch instead of two, so
 * the extra fetch under `no-store` is demonstrably the directive and not something else.
 */
test('the verifier acts on cache-control, not just parses it', async () => {
  const valid = corpus.cases.find((entry) => entry.name === 'valid_eddsa');

  const uncached = verifierFor({ cacheControl: 'no-store' });
  await uncached.verify(valid.token);
  await uncached.verify(valid.token);
  assert.equal(
    uncached.fetches(),
    2,
    'no-store means the next lookup refetches, which is how a rotated key is picked up',
  );

  const cached = verifierFor({ cacheControl: 'max-age=300' });
  await cached.verify(valid.token);
  await cached.verify(valid.token);
  assert.equal(cached.fetches(), 1, 'a live max-age must be reused rather than refetched');
});

/** `Cache-Control` is honoured, which is what lets key rotation work without a deploy. */
test('cache-control is respected', () => {
  assert.equal(maxAgeOf(new Headers({ 'Cache-Control': 'max-age=7' })), 7);
  assert.equal(maxAgeOf(new Headers({ 'Cache-Control': 'no-store' })), 0);
  assert.equal(maxAgeOf(new Headers({ 'Cache-Control': 'private, no-cache' })), 0);
  assert.equal(maxAgeOf(new Headers()), 300, 'a missing directive is a sane default');
  assert.equal(maxAgeOf(new Headers({ 'Cache-Control': 'public' })), 300);
});

/**
 * An empty allow-list is refused at CONSTRUCTION, not at the first verify.
 *
 * A verifier built with no algorithms would refuse every token, which looks like a token
 * problem and is a configuration problem. Failing at startup puts the error where the mistake
 * is.
 */
test('a verifier cannot be built without an algorithm allow-list', () => {
  for (const algorithms of [[], undefined, 'EdDSA']) {
    assert.throws(
      () =>
        createVerifier({
          issuer: corpus.issuer,
          audience: corpus.audience,
          jwksUri: 'https://issuer.example/jwks',
          algorithms,
        }),
      TypeError,
      `algorithms=${JSON.stringify(algorithms)} must be refused`,
    );
  }
});

/** A non-string token is malformed, not a crash. */
test('a missing token is a malformed refusal rather than a throw', async () => {
  const { verify } = verifierFor();
  for (const bad of [undefined, null, 42]) {
    await assert.rejects(() => verify(bad), (error) => error.reason === 'malformed');
  }
});
