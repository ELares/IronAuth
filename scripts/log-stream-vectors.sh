#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Regenerate the log-stream signature conformance corpus and fail if it moved (issue #110).
#
# The corpus is what the SHIPPED signer produces, so a change to the canonical form, the
# algorithm or the hex encoding shows up here as a diff a reviewer reads. That diff IS the
# compatibility check: a consumer in the field verifies against the old form, so any change to
# what is signed is a breaking change to every SIEM integration, and it must not be possible
# to make one without somebody seeing it.
set -euo pipefail

CORPUS="packages/ironauth-sdk/vectors/log-stream-vectors.json"

cargo run --quiet -p ironauth-admin --example log-stream-vectors > "$CORPUS"
echo "log-stream-vectors: $CORPUS regenerated"

if ! git diff --exit-code "$CORPUS" >/dev/null 2>&1; then
    echo "log-stream-vectors: the committed corpus is STALE."
    echo "  The signer's output changed. Review the diff: anything here is a BREAKING change"
    echo "  for every consumer already verifying batches in the field, and needs a canonical"
    echo "  version bump rather than a quiet edit."
    git --no-pager diff -- "$CORPUS" || true
    exit 1
fi
echo "log-stream-vectors: clean"
