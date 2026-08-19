# Verifying a signed log stream

IronAuth can sign every batch it ships to a SIEM. This is how a consumer checks one, and
where it gets the values it needs to do that.

Signing is per stream and opt in: a stream signs when it names a signing secret
(`signing_secret_name`) and ships unsigned when it does not. An unsigned batch carries
neither header below.

## Why a signature at all

TLS protects the hop. It says nothing about a payload once that payload has landed in an
object store, a forwarder or a log index, which is where a SIEM actually reads it. The AWS
SigV4 signing on the S3 sink is transport authentication to S3: discarded the moment the
object is written, and absent entirely for the HTTP, Datadog and Splunk sinks.

Three questions survive TLS, and the batch signature answers all three:

- **Authenticity.** Did this come from the deployment, or from anyone who can write to the
  bucket?
- **Ordering.** Is this the batch after the one I last verified?
- **Replay.** Have I applied this already, under another name?

## What arrives on the wire

Two headers travel with every signed batch, and a consumer needs **both**:

| header | value |
|---|---|
| `x-ironauth-log-signature` | HMAC-SHA256 of the canonical string, lowercase hex |
| `x-ironauth-log-position` | `<stream id> <cursor sequence> <cursor id>`, space separated |

The S3 sink carries the same two as object metadata, `x-amz-meta-ironauth-log-signature` and
`x-amz-meta-ironauth-log-position`, because an object has no headers once it is written. Both
are inside the SigV4 canonical headers, so neither can be stripped or rewritten in flight: a
position an attacker can rewrite is a gap and replay check the attacker controls.

**The position is not a convenience.** The signature covers the stream id and the cursor
position, and neither is derivable from the payload, so a consumer that has only the body and
the signature cannot rebuild what was signed and cannot verify anything at all. It is also
what makes ordering and replay checkable with no server-side state: keep the last position you
verified, and a position at or below it is a replay while a position beyond the next expected
one is a gap.

## What is signed

```text
ironauth-log-stream-v1
<stream id>
<cursor sequence>
<cursor id>
<event count>
<SHA-256 of the serialized events, lowercase hex>
```

joined with newlines, then HMAC-SHA256 under the stream's signing secret. The count is
redundant for integrity and deliberately present for DIAGNOSIS: a consumer that fails
verification can say whether it received a different number of events or the same number with
different content.

## The verifier

**Use [`packages/ironauth-sdk/snippets/verify-log-stream.mjs`](../packages/ironauth-sdk/snippets/verify-log-stream.mjs).**
It imports nothing and uses only WebCrypto, so it drops into a SIEM forwarder, a Lambda
reading the S3 sink's objects, or a Node handler behind the HTTP sink, unchanged.

Split the position header on spaces to get the three values `verifyBatch` needs:

```js
const [streamId, cursorSequence, cursorId] = positionHeader.split(' ');
const { ok, reason, position } = await verifyBatch({
  key, signature, streamId,
  cursorSequence: Number(cursorSequence),
  cursorId,
  eventCount: events.length,
  eventsJson: bodyAsReceived,
  lastVerifiedSequence,          // pass this every time after the first batch
});
```

Pass `lastVerifiedSequence` on every call after the first. Without it the verifier checks
authenticity and integrity but cannot check ordering or replay, and a replayed batch sails
straight through.

**It is kept in step with the signer by a corpus, not by review.**
`packages/ironauth-sdk/vectors/log-stream-vectors.json` is generated from the shipped signer,
and `scripts/log-stream-vectors.sh` regenerates it in the gate and fails on any diff. Any
change to the canonical form, the algorithm or the hex encoding is a breaking change for every
SIEM already verifying in the field, so it has to be seen rather than merged quietly.

## Vendor sinks reshape the payload

The HTTP and S3 sinks transmit the signed bytes verbatim, so `eventsJson` is the body exactly
as received. The Datadog and Splunk HEC sinks wrap each event, because those APIs require it:

- Datadog: `{"ddsource","service","message":<event>}` per event, in an array
- Splunk HEC: `{"sourcetype","event":<event>}` per event, newline delimited

Both wrappings are deterministic, so unwrap back to the array that was signed before
verifying. **Two details decide whether your unwrapper works.** `serde_json` emits UTF-8
directly and puts no space after `,` or `:`, so a re-serializer that escapes non-ASCII to
`\uXXXX` or pretty-prints produces different bytes, a different digest, and a verification
failure that looks exactly like tampering; one accented character in a username is enough. Key
ORDER needs no handling, because `serde_json` serializes map keys sorted, so the wire bytes are
already in that order and any parser that preserves order through the round trip is fine.
