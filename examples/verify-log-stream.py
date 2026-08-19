#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Verify a signed IronAuth log-stream batch (issue #110 criterion 5).

This is the SAMPLE CONSUMER. It is deliberately dependency-free and short enough to read
in one sitting, because a SIEM operator has to be able to satisfy themselves that it does
what it says before they trust it with their audit trail.

It answers the three questions TLS cannot answer once a batch has landed in an object
store, a forwarder or a log index:

  authenticity  did this batch come from the deployment that holds the signing secret
  ordering      is this the batch that follows the one I last verified
  replay        have I already applied this batch under a different name

WHAT IS SIGNED

  ironauth-log-stream-v1
  <stream id>
  <cursor sequence>
  <cursor id>
  <event count>
  <SHA-256 of the serialized events, lowercase hex>

joined with newlines, and HMAC-SHA256'd with the stream's signing secret. The digest is
over the events array exactly as IronAuth serialized it, which is what the HTTP and S3
sinks transmit verbatim.

VENDOR SINKS RESHAPE THE PAYLOAD, and this is the one place a consumer has to do work:
the Datadog sink wraps each event as {"ddsource","service","message":<event>} and the
Splunk HEC sink wraps each as {"sourcetype","event":<event>}, newline delimited. Pass
--sink datadog or --sink splunk and this unwraps them back to the array that was signed.
The unwrapping is deterministic, so verification is possible on every sink; it is not
guesswork.

USAGE

  verify-log-stream.py --secret-file key.bin --body batch.json \
      --position "$X_IRONAUTH_LOG_POSITION" --signature "$X_IRONAUTH_LOG_SIGNATURE"

exits 0 when the batch verifies, 1 when it does not, and prints the reason either way.
"""

import argparse
import hashlib
import hmac
import json
import sys

CANONICAL_VERSION = "ironauth-log-stream-v1"


def events_from(body: str, sink: str) -> str:
    """The events array as IronAuth serialized it, whatever the sink wrapped it in."""
    if sink == "raw":
        # HTTP and S3 transmit the signed bytes verbatim. Re-serializing would risk
        # changing separators or key order, so the body is used exactly as received.
        return body
    if sink == "datadog":
        return json.dumps([entry["message"] for entry in json.loads(body)], separators=(",", ":"))
    if sink == "splunk":
        events = [json.loads(line)["event"] for line in body.splitlines() if line.strip()]
        return json.dumps(events, separators=(",", ":"))
    raise SystemExit(f"unknown sink {sink!r}")


def canonical_string(stream_id: str, sequence: int, cursor_id: str, events_json: str) -> str:
    count = len(json.loads(events_json))
    digest = hashlib.sha256(events_json.encode("utf-8")).hexdigest()
    return "\n".join(
        [CANONICAL_VERSION, stream_id, str(sequence), cursor_id, str(count), digest]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--secret-file", required=True, help="the stream's signing secret, raw bytes")
    parser.add_argument("--body", required=True, help="the batch body as received")
    parser.add_argument("--position", required=True, help="x-ironauth-log-position header value")
    parser.add_argument("--signature", required=True, help="x-ironauth-log-signature header value")
    parser.add_argument("--sink", default="raw", choices=["raw", "datadog", "splunk"])
    parser.add_argument("--last-sequence", type=int, default=None,
                        help="the sequence you last verified, to check ordering and replay")
    args = parser.parse_args()

    with open(args.secret_file, "rb") as handle:
        key = handle.read()
    with open(args.body, "r", encoding="utf-8") as handle:
        body = handle.read()

    # "<stream id> <sequence> <cursor id>", split positionally: all three are opaque ids.
    parts = args.position.split(" ")
    if len(parts) != 3:
        print(f"malformed position header: {args.position!r}", file=sys.stderr)
        return 1
    stream_id, sequence, cursor_id = parts[0], int(parts[1]), parts[2]

    canonical = canonical_string(stream_id, sequence, cursor_id, events_from(body, args.sink))
    expected = hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, args.signature):
        print("SIGNATURE MISMATCH: this batch was not signed by that secret, or it was altered",
              file=sys.stderr)
        return 1

    # Ordering and replay are the reason the position is signed rather than merely sent.
    if args.last_sequence is not None:
        if sequence <= args.last_sequence:
            print(f"REPLAY: sequence {sequence} is not after {args.last_sequence}", file=sys.stderr)
            return 1

    print(f"verified: stream {stream_id} at sequence {sequence}, cursor {cursor_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
