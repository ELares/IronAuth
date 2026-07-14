#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Covenant lint (issue #23): NO metering, counting-for-billing, or quota hook may
# exist anywhere on the machine-to-machine (client-credentials) ISSUANCE PATH. M2M
# token issuance must never be metered, counted for billing, or quota-gated (a
# stated covenant of the M2M path); token-caching guidance is published as docs
# instead (docs/design/M2M-TOKEN-CACHING.md).
#
# This asserts the covenant by construction: the one module that implements the
# issuance path (crates/ironauth-oidc/src/client_credentials.rs) must contain NO
# metering/billing/quota hook. A `metrics::counter!`, a billing/quota/meter symbol,
# or a rate-limit hook appearing there would fail the build. The security AUDIT row
# the issuance writes is explicitly NOT a meter (it is who/what/when for revocation
# and forensics), so `audit`/`Action::TokenIssue` are not flagged.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# The single module that implements the M2M issuance path.
ISSUANCE_PATH='crates/ironauth-oidc/src/client_credentials.rs'

if [ ! -f "$ISSUANCE_PATH" ]; then
  echo "no-m2m-metering: expected issuance-path module not found: $ISSUANCE_PATH"
  exit 1
fi

# Forbidden hooks: any metrics counter/gauge/histogram macro, or a
# billing/metering/quota/rate-limit symbol. Word-boundaried and case-insensitive so
# a renamed spelling (Meter, QuotaGuard, bill_for, chargeUsage) is still caught. A
# genuine false positive may carry "no-m2m-metering-allow: <reason>" on the line.
FORBIDDEN='metrics::(counter|gauge|histogram)|counter!|gauge!|histogram!|\b(meter|metering|billing|billable|quota|chargeable|usage_count|rate_limit|ratelimit)\b'

# Scan CODE, not prose: a comment-only line (the covenant documentation itself names
# these words) is excluded. grep emits "<lineno>:<content>"; drop lines whose content
# begins with a Rust line/doc comment marker. A metering hook in real code (even with
# a trailing comment) is not comment-only, so it is still caught.
hits=$(grep -niE "$FORBIDDEN" "$ISSUANCE_PATH" \
  | grep -vE '^[0-9]+:[[:space:]]*//' \
  | grep -v 'no-m2m-metering-allow' \
  || true)

if [ -n "$hits" ]; then
  echo "no-m2m-metering: a metering/billing/quota hook is on the M2M issuance path:"
  echo "$hits"
  echo
  echo "The client-credentials issuance path must carry NO metering, counting-for-billing,"
  echo "or quota hook (a covenant of the M2M path). Publish token-caching guidance as docs"
  echo "instead. If this is a genuine false positive, add 'no-m2m-metering-allow: <reason>'."
  exit 1
fi

echo "no-m2m-metering: clean (no metering/billing/quota hook on the M2M issuance path)"
