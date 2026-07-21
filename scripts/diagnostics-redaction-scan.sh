#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Diagnostics structural redaction corpus (issue #91).
#
# The admin diagnostics sink (the M9 flow inspector's client-authentication failure
# records) must be structurally INCAPABLE of holding a secret: no field of any
# diagnostic struct can carry an assertion body, a client secret, a token value, or a
# JWKS private key, so a secret is UNREPRESENTABLE rather than scrubbed after the
# fact. This gate runs the hostile-corpus test that proves it: a corpus stuffs known
# secret / token / assertion / JWKS-private sentinels into every secret-bearing input,
# the safe-field extraction builds a diagnostic from each, every diagnostic record is
# serialized (its Debug, its reason, its expected hint, and every field), and the test
# asserts NO sentinel substring appears anywhere. A regression that lifts a secret into
# a diagnostic field (a new field, or an extraction that reads a secret position) fails
# this gate LOUDLY, exactly as the pii-encryption-scan gate does for plaintext PII
# columns. It is a plain cargo test (no database), so it runs in any lane.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

echo "diagnostics-redaction: running the hostile sentinel corpus against the diagnostic record"
cargo test --quiet -p ironauth-oidc --lib \
  client_auth::tests::diagnostics_redaction_corpus_leaks_no_secret_sentinel -- --exact

echo "diagnostics-redaction: clean (no secret sentinel can reach a serialized diagnostic record)"
