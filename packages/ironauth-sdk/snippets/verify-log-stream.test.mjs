// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * The sample consumer against the corpus the Rust signer generated (issue #110 criterion 5).
 *
 * The corpus is not hand written: `cargo run -p ironauth-admin --example log-stream-vectors`
 * emits what the shipped signer actually produces. So this asserts the two implementations
 * agree with each other, not that both agree with somebody's understanding of the format.
 *
 * Every vector carries its own `expect`, so a case that stopped being adversarial -- because
 * the canonical form quietly stopped covering one of its fields -- shows up as a vector that
 * now verifies when the corpus says it must not.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { CANONICAL_VERSION, verifyBatch } from './verify-log-stream.mjs';

const corpus = JSON.parse(
  readFileSync(fileURLToPath(new URL('../vectors/log-stream-vectors.json', import.meta.url))),
);

test('the consumer understands the corpus version', () => {
  assert.equal(
    CANONICAL_VERSION,
    corpus.canonical_version,
    'a consumer on a different canonical version must not silently verify: the version is ' +
      'inside the MAC, so disagreeing here means every vector would fail for the wrong reason',
  );
});

test('the corpus is not all one answer', () => {
  const verify = corpus.vectors.filter((v) => v.expect === 'verify').length;
  const refuse = corpus.vectors.filter((v) => v.expect === 'refuse').length;
  assert.ok(verify > 0, 'a corpus with no accepting vector passes for a verifier that always refuses');
  assert.ok(refuse > 0, 'a corpus with no refusing vector passes for a verifier that always accepts');
});

for (const vector of corpus.vectors) {
  test(`${vector.expect}: ${vector.name}`, async () => {
    const result = await verifyBatch({
      key: corpus.key_utf8,
      signature: vector.signature,
      streamId: vector.stream_id,
      cursorSequence: vector.cursor_sequence,
      cursorId: vector.cursor_id,
      eventCount: vector.event_count,
      eventsJson: vector.events_json,
    });
    assert.equal(result.ok, vector.expect === 'verify', vector.why);
  });
}

test('a replayed position is refused even when the signature is valid', async () => {
  const good = corpus.vectors.find((v) => v.expect === 'verify');
  const shared = {
    key: corpus.key_utf8,
    signature: good.signature,
    streamId: good.stream_id,
    cursorSequence: good.cursor_sequence,
    cursorId: good.cursor_id,
    eventCount: good.event_count,
    eventsJson: good.events_json,
  };

  const first = await verifyBatch({ ...shared, lastVerifiedSequence: good.cursor_sequence - 1 });
  assert.equal(first.ok, true, 'the batch after the last verified position is accepted');
  assert.equal(first.position, good.cursor_sequence, 'it reports the position it verified');

  // The SAME batch, presented again to a consumer that has already applied it. The signature
  // is genuine -- that is the whole point. Only the position catches this.
  const again = await verifyBatch({ ...shared, lastVerifiedSequence: good.cursor_sequence });
  assert.equal(again.ok, false, 'a batch at a position already applied is a replay');
  assert.equal(again.reason, 'replay');
});

test('a malformed signature is refused rather than thrown on', async () => {
  for (const signature of ['', 'zz', 'abc', 'not-hex-at-all', null, 42]) {
    const result = await verifyBatch({
      key: corpus.key_utf8,
      signature,
      streamId: 'lst_conformance',
      cursorSequence: 1,
      cursorId: 'out_00000000',
      eventCount: 1,
      eventsJson: '[]',
    });
    assert.equal(result.ok, false, `${JSON.stringify(signature)} must be refused, not thrown on`);
  }
});

test('a batch verified without a position is refused as such, not as a bad signature', async () => {
  // The failure mode this stops is an integration bug reported as an attack. Without the
  // guard, an omitted position builds the canonical string with the literal `undefined` in
  // it, the HMAC does not match, and the caller is told `bad-signature` -- so an operator
  // wiring up the headers for the first time is told their deployment is forging batches.
  const vector = corpus.vectors.find((v) => v.expect === 'verify');

  const missing = await verifyBatch({
    key: corpus.key_utf8,
    signature: vector.signature,
    streamId: vector.stream_id,
    // cursorSequence omitted
    cursorId: vector.cursor_id,
    eventCount: vector.event_count,
    eventsJson: vector.events_json,
  });
  assert.equal(missing.reason, 'missing-position');
  assert.equal(missing.ok, false);

  // And the same call WITH the position verifies, so the assertion above is about the
  // position rather than about the vector being unverifiable.
  const present = await verifyBatch({
    key: corpus.key_utf8,
    signature: vector.signature,
    streamId: vector.stream_id,
    cursorSequence: vector.cursor_sequence,
    cursorId: vector.cursor_id,
    eventCount: vector.event_count,
    eventsJson: vector.events_json,
  });
  assert.equal(present.ok, true);
});

test('every canonical input is refused by name, and a bad key is refused rather than thrown', async () => {
  // One shape, three inputs: an omitted input must be reported as the integration bug it is,
  // not as `bad-signature`, which reads to an operator as a forged batch. Review found the
  // first version of this guard covered only the position, so the other two still reported an
  // attack when the caller had simply not wired the field.
  const vector = corpus.vectors.find((v) => v.expect === 'verify');
  const good = {
    key: corpus.key_utf8,
    signature: vector.signature,
    streamId: vector.stream_id,
    cursorSequence: vector.cursor_sequence,
    cursorId: vector.cursor_id,
    eventCount: vector.event_count,
    eventsJson: vector.events_json,
  };
  assert.equal((await verifyBatch(good)).ok, true, 'the fixture must verify, or the rest proves nothing');

  for (const [field, reason] of [
    ['streamId', 'missing-position'],
    ['cursorSequence', 'missing-position'],
    ['cursorId', 'missing-position'],
    ['eventCount', 'missing-batch'],
    ['eventsJson', 'missing-batch'],
  ]) {
    const without = { ...good };
    delete without[field];
    const result = await verifyBatch(without);
    assert.equal(result.reason, reason, `omitting ${field} must be reported as ${reason}`);
  }

  // A key that is not key material REFUSES. `crypto.subtle.importKey` throws an uncaught
  // TypeError on each of these, and an unset environment variable is exactly how `undefined`
  // arrives in practice. This file promises malformed input is never a throw.
  for (const key of [undefined, null, 42, {}]) {
    const result = await verifyBatch({ ...good, key });
    assert.equal(result.reason, 'malformed-key', `a ${typeof key} key must refuse, not throw`);
  }
});
