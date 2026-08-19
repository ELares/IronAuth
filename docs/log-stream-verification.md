# Verifying a signed log stream

IronAuth can sign every batch it ships to a SIEM. This is how a consumer checks one.

Signing is per stream and opt in: a stream signs when it names a signing secret
(`signing_secret_name`), and ships unsigned when it does not. An unsigned batch carries
neither header below.

## Why a signature at all

TLS protects the hop. It says nothing about a payload once that payload has landed in an
object store, a forwarder, or a log index, which is where a SIEM actually reads it. Three
questions survive TLS and a signature answers all three:

- **Authenticity.** Did this batch come from this deployment, or from anyone who could write
  into the bucket the S3 sink writes to?
- **Ordering.** Is this the batch that follows the one I last verified, or has something been
  dropped in between?
- **Replay.** Have I already applied this batch, under a different name?

## What arrives

Two headers travel with every signed batch, and you need both:

| header | value |
|---|---|
| `x-ironauth-log-signature` | HMAC-SHA256 of the canonical string, lowercase hex |
| `x-ironauth-log-position` | `<stream id> <cursor sequence> <cursor id>`, space separated |

The S3 sink carries the same two as object metadata, `x-amz-meta-ironauth-log-signature` and
`x-amz-meta-ironauth-log-position`, because an object has no headers once written. Both are
inside the SigV4 canonical headers, so neither can be stripped or rewritten in flight.

**The position is not a convenience.** The signature covers the stream id and the cursor
position, and neither is derivable from the payload, so a consumer that has only the body and
the signature cannot rebuild what was signed and cannot verify anything. That is also what
makes ordering and replay checkable without any server-side state: record the last sequence
you verified, and refuse anything that is not after it.

## What is signed

```text
ironauth-log-stream-v1
<stream id>
<cursor sequence>
<cursor id>
<event count>
<SHA-256 of the serialized events, lowercase hex>
```

joined with newlines, then HMAC-SHA256 under the stream's signing secret.

The digest is over the events array exactly as IronAuth serialized it. The count is redundant
for integrity, and deliberately present for DIAGNOSIS: a consumer that fails verification can
say whether it received a different number of events or the same number with different
content.

## Vendor sinks reshape the payload

The HTTP and S3 sinks transmit the signed bytes verbatim. The Datadog and Splunk HEC sinks do
not, because those APIs require their own envelopes:

- Datadog wraps each event as `{"ddsource","service","message":<event>}`
- Splunk HEC wraps each as `{"sourcetype","event":<event>}`, newline delimited

Both wrappings are deterministic, so a consumer unwraps them back to the array that was
signed. Verification is possible on every sink; the sample consumer does this for you with
`--sink datadog` or `--sink splunk`.

**If you write your own unwrapper, two details decide whether it works.** serde_json emits
UTF-8 directly and puts no space after `,` or `:`, so a re-serializer that escapes non-ASCII
to `\uXXXX` (Python's `json.dumps` default) or pretty-prints produces different bytes, a
different digest, and a verification failure that looks exactly like tampering. One accented
character in a username is enough. Key ORDER needs no special handling: serde_json sorts map
keys, so the wire bytes are already in that order and any parser that preserves order through
the round trip is fine.

## The sample consumer

[`examples/verify-log-stream.py`](../examples/verify-log-stream.py) is dependency free and
short enough to read before you trust it with your audit trail.

```console
$ ./examples/verify-log-stream.py \
    --secret-file key.bin \
    --body batch.json \
    --position "$X_IRONAUTH_LOG_POSITION" \
    --signature "$X_IRONAUTH_LOG_SIGNATURE" \
    --last-sequence 4241
verified: stream lgs_01J8 at sequence 4242, cursor aud_01J8ZQ
```

It exits 0 when the batch verifies and 1 when it does not, printing the reason either way.
Pass `--last-sequence` to make it check ordering and replay as well as authenticity.

**It is kept honest by a test, not by review.**
`log_sink_conformance::the_published_sample_consumer_verifies_a_batch_this_code_signed` runs
this file as a subprocess over a batch the Rust signer produced, and asserts both that it
accepts a good signature and that it refuses a tampered one. A published verifier that drifts
from the signing code is worse than none, because an operator will trust it.
