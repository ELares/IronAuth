#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Covenant lint (issue #23): NO metering, counting-for-billing, or quota hook may
# exist anywhere on the machine-to-machine (client-credentials) ISSUANCE PATH. M2M
# token issuance must never be metered, counted for billing, or quota-gated (a
# stated covenant of the M2M path); token-caching guidance is published as docs
# instead (docs/design/M2M-TOKEN-CACHING.md).
#
# This asserts the covenant by construction over the WHOLE M2M issuance path, which
# spans three modules: the request handler
# (crates/ironauth-oidc/src/client_credentials.rs, scanned in full) PLUS the two
# CC-specific mint helpers and the persistence helper that only the M2M path uses:
#   - tokens.rs::mint_client_credentials_access_token
#   - tokens.rs::build_client_credentials_access_token_claims
#   - repository.rs::issue_client_credentials
# A `metrics::counter!`, a billing/quota/meter symbol, or a rate-limit hook appearing
# in any of them would fail the build. To avoid false-positives on the unrelated code
# those two shared modules also contain, only the CC-named function REGIONS (a `fn`
# whose name contains `client_credentials`, through its body's closing brace) are
# scanned there. The security AUDIT row the issuance writes is explicitly NOT a meter
# (it is who/what/when for revocation and forensics), so `audit`/`Action::TokenIssue`
# are not flagged.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# The request handler (scanned in full) and the two modules whose CC-named function
# regions are also on the issuance path.
HANDLER='crates/ironauth-oidc/src/client_credentials.rs'
TOKENS='crates/ironauth-oidc/src/tokens.rs'
REPO='crates/ironauth-store/src/repository.rs'

for path in "$HANDLER" "$TOKENS" "$REPO"; do
  if [ ! -f "$path" ]; then
    echo "no-m2m-metering: expected issuance-path module not found: $path"
    exit 1
  fi
done

# Emit, for every `fn *client_credentials*` in $1, the signature line through the
# body's closing brace, each line tagged `path:lineno:content` so a hit points at the
# real location. Brace-depth tracking is sufficient here: it scopes the scan to the
# CC helpers without dragging in the unrelated code the shared modules also hold.
extract_cc_regions() {
  awk '
    !in_fn {
      if ($0 ~ /fn +[A-Za-z0-9_]*client_credentials[A-Za-z0-9_]*/) {
        in_fn = 1; depth = 0; opened = 0
      } else {
        next
      }
    }
    in_fn {
      print FILENAME ":" NR ":" $0
      o = gsub(/\{/, "{"); c = gsub(/\}/, "}")
      depth += o - c
      if (o > 0) opened = 1
      if (opened && depth <= 0) in_fn = 0
    }
  ' "$1"
}

# The scan corpus, uniformly tagged `path:lineno:content`: the whole handler module
# plus only the CC-specific function regions of the mint and persistence modules.
corpus="$(
  {
    awk '{ print FILENAME ":" NR ":" $0 }' "$HANDLER"
    extract_cc_regions "$TOKENS"
    extract_cc_regions "$REPO"
  }
)"

# Forbidden hooks: any metrics counter/gauge/histogram macro, or a
# billing/metering/quota/rate-limit symbol. Word-boundaried and case-insensitive so
# a renamed spelling (Meter, QuotaGuard, bill_for, chargeUsage) is still caught. A
# genuine false positive may carry "no-m2m-metering-allow: <reason>" on the line.
FORBIDDEN='metrics::(counter|gauge|histogram)|counter!|gauge!|histogram!|\b(meter|metering|billing|billable|quota|chargeable|usage_count|rate_limit|ratelimit)\b'

# Scan CODE, not prose: a comment-only line (the covenant documentation itself names
# these words) is excluded. Each corpus line is `path:lineno:content`; drop lines whose
# CONTENT begins with a Rust line/doc comment marker. A metering hook in real code
# (even with a trailing comment) is not comment-only, so it is still caught.
hits=$(printf '%s\n' "$corpus" \
  | grep -iE "$FORBIDDEN" \
  | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' \
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
