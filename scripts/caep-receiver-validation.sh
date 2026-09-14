#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The CAEP events this build emits are accepted by an INDEPENDENT receiver (issue #144
# criterion 1).
#
# > caep.dev (or an equivalent public receiver) accepts and validates emitted events; the
# > validation evidence is captured.
#
# Two steps, and the split is the point. `caep_receiver_corpus` mints one SET per CAEP event type
# this build emits, through the same mapping functions the fan-out calls, and writes each beside
# the JWKS its environment publishes. `validate-caep-receiver.py` then judges them with rules
# written from the interoperability profile, in a second implementation: PyJWT does the
# signature, and everything about the EVENT -- one member under `events`, a resolvable subject
# format, a second-scale `event_timestamp`, an object body -- is checked by code that shares no
# line with the emitter.
#
# WHY NOT THE PUBLIC SERVICE. A gate that posted to somebody else's receiver would fail when that
# service was down, say nothing when it changed, and send this deployment's events to a third
# party on every pull request. What it would buy is an INDEPENDENT judgement, and that is what
# the validator is.
#
# THE EVIDENCE IS THE REPORT the validator writes: which event types were accepted, under which
# algorithm, and how many negative controls each rejected. It is printed here so a CI log carries
# it, which is what "captured" means for a check that must not depend on a third party.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

if ! python3 -c "import jwt" >/dev/null 2>&1; then
    echo "caep-receiver-validation: PyJWT is not installed." >&2
    echo "  python3 -m pip install -r deploy/conformance/requirements-set.txt" >&2
    echo "  (CI installs the same file with --require-hashes; see .github/workflows/ci.yml)" >&2
    exit 1
fi

# A FRESH DIRECTORY EVERY RUN, for the reason the sibling gate gives: pointing the validator at a
# path that survived a previous run is how an event type dropped from the emitter goes on being
# validated from leftovers.
corpus="$(mktemp -d "${TMPDIR:-/tmp}/caep-receiver-corpus.XXXXXX")"
trap 'rm -rf "$corpus"' EXIT

CAEP_RECEIVER_CORPUS_DIR="$corpus" \
    cargo test -p ironauth-oidc --features testing --test caep_receiver_corpus -- --nocapture

python3 scripts/validate-caep-receiver.py "$corpus"

echo
echo "caep-receiver-validation: the captured evidence"
cat "$corpus/validation-report.json"
