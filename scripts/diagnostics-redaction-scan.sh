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

# The M9 policy decision trace and token size record types (issue #91) carry the SAME
# structural redaction guarantee: their safe field builders accept only typed safe fields
# (an acr, a signal name and level, a connector slug, a bounded failure kind, a byte size,
# a client id), so a claim value, a token, or a secret is unrepresentable. This is the
# sibling corpus that proves it for those record types.
echo "diagnostics-redaction: running the hostile sentinel corpus against the policy trace record"
cargo test --quiet -p ironauth-oidc --lib \
  policy_trace::tests::redaction_corpus_leaks_no_secret_sentinel -- --exact

# The M9 flow inspector projection (issue #91, PR4) carries the SAME structural redaction
# guarantee: the flow context view has no field for the flow submit token (it is not even on
# the persisted state) and no field for the recovery identifier PII (reduced to a boolean), and
# a hostile risk signal name folds to the bounded vocabulary, so a secret is unrepresentable in
# an observe or dry run projection. This is the sibling corpus that proves it for the inspector.
echo "diagnostics-redaction: running the hostile sentinel corpus against the flow inspector projection"
cargo test --quiet -p ironauth-oidc --lib \
  flow::inspect::tests::redaction_corpus_leaks_no_secret_sentinel -- --exact

echo "diagnostics-redaction: clean (no secret sentinel can reach a serialized diagnostic record)"
