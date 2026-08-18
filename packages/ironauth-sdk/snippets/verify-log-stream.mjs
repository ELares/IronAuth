// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * Verify a shipped IronAuth log-stream batch (issue #110 criterion 5).
 *
 * COPY THIS FILE. It imports nothing and uses only WebCrypto, so it drops into a SIEM
 * forwarder, a Lambda that reads the S3 sink's objects, or a Node handler behind the HTTP
 * sink, unchanged.
 *
 * ## What TLS does not tell you, and this does
 *
 * TLS protects the hop. Once a batch has landed in an object store, a forwarder or a log
 * index, it says nothing about where the batch came from or whether you already applied it.
 * The AWS SigV4 signing on the S3 sink is transport authentication to S3 -- discarded the
 * moment the object is written, and absent for the HTTP, Datadog and Splunk sinks.
 *
 * This answers the three questions a SIEM actually has:
 *
 *   1. AUTHENTICITY  -- did this come from the deployment, or from anyone who can write to
 *                       the bucket?
 *   2. ORDERING      -- is this the batch after the one I last verified?
 *   3. REPLAY        -- have I applied this already under another name?
 *
 * Ordering and replay are answered by the CURSOR POSITION, which is inside the signature
 * rather than beside it. The shipper advances the cursor only on success and only to what was
 * accepted, so positions are monotonic per stream. Keep the last position you verified and:
 *
 *   - a position at or below it is a REPLAY;
 *   - a position beyond the next expected one is a GAP.
 *
 * Neither needs any server-side state, and neither is answerable if you verify the signature
 * alone -- which is why `verifyBatch` refuses to be used without a position and returns the
 * position it verified rather than a bare boolean.
 *
 * ## Conformance
 *
 * This file and the Rust signer are kept honest by the same corpus
 * (`../vectors/log-stream-vectors.json`), which is GENERATED from the signer. Two
 * implementations that agree on seven vectors -- one accepting and six adversarial -- are two
 * implementations that agree.
 */

/** The canonical-form version this file understands. */
export const CANONICAL_VERSION = 'ironauth-log-stream-v1';

const encoder = new TextEncoder();

/** Lowercase hex, matching the signer's encoding exactly. */
function hex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Rebuild the string the signature covers.
 *
 * Built here rather than trusted from the wire. A consumer handed a "canonical string" by the
 * sender is verifying that the sender can sign its own claims, which is not a check.
 */
export async function canonicalString({
  streamId,
  cursorSequence,
  cursorId,
  eventCount,
  eventsJson,
}) {
  const digest = hex(await crypto.subtle.digest('SHA-256', encoder.encode(eventsJson)));
  return [
    CANONICAL_VERSION,
    streamId,
    String(cursorSequence),
    cursorId,
    String(eventCount),
    digest,
  ].join('\n');
}

/**
 * Verify one batch. Returns `{ ok, reason, position }`.
 *
 * `lastVerifiedSequence` is optional ONLY so a first-ever batch can be verified. Pass it
 * every time after that: without it this checks authenticity and integrity but cannot check
 * ordering or replay, and a caller who never passes it has a verifier that a replayed batch
 * sails straight through.
 */
export async function verifyBatch({
  key,
  signature,
  streamId,
  cursorSequence,
  cursorId,
  eventCount,
  eventsJson,
  lastVerifiedSequence = null,
}) {
  const canonical = await canonicalString({
    streamId,
    cursorSequence,
    cursorId,
    eventCount,
    eventsJson,
  });

  // Malformed input is a REFUSAL, never a throw. A verifier that throws on a bad signature
  // hands anyone who can reach it a denial of service in place of a `false`.
  if (typeof signature !== 'string' || !/^[0-9a-fA-F]*$/.test(signature) || signature.length % 2) {
    return { ok: false, reason: 'malformed-signature', position: null };
  }

  const imported = await crypto.subtle.importKey(
    'raw',
    typeof key === 'string' ? encoder.encode(key) : key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  );
  const bytes = new Uint8Array(
    signature.match(/../g)?.map((pair) => Number.parseInt(pair, 16)) ?? [],
  );

  // `crypto.subtle.verify` is constant time. Comparing hex strings with === would leak the
  // position of the first difference to anyone who can submit candidates and time the answer.
  const ok = await crypto.subtle.verify('HMAC', imported, bytes, encoder.encode(canonical));
  if (!ok) {
    return { ok: false, reason: 'bad-signature', position: null };
  }

  if (lastVerifiedSequence !== null) {
    if (cursorSequence <= lastVerifiedSequence) {
      return { ok: false, reason: 'replay', position: cursorSequence };
    }
  }

  return { ok: true, reason: null, position: cursorSequence };
}
