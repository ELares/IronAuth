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
# The VERIFICATION path (issue #99, criterion 5), scanned in full. Metering issuance
# bills a customer once per token; metering VERIFICATION taxes every request an API
# gateway makes against a cached one, which is the worse of the two and is why the
# criterion names both. Introspection is where a verification counter would live.
INTROSPECT='crates/ironauth-oidc/src/introspection.rs'

for path in "$HANDLER" "$TOKENS" "$REPO" "$INTROSPECT"; do
  if [ ! -f "$path" ]; then
    echo "no-m2m-metering: expected issuance-path module not found: $path"
    exit 1
  fi
done

# Emit every line of the named `impl` block in $1, tagged `path:lineno:content`.
#
# The API-KEY verification path (issue #99, criterion 5) lives in `ApiKeyRepo::verify`, whose
# function name carries no distinguishing token, so the CC extractor below cannot reach it: it
# matches on `fn *client_credentials*` and `verify` does not. Scanning by IMPL BLOCK is what
# covers it, and it covers every method added to that repository later without anyone having to
# remember to extend a name pattern.
#
# This is the gap that made criterion 5 only half enforced. `introspection.rs` was already
# scanned in full for the token verification path, and the api_keys verification path added in
# PR #627 was not scanned at all: the covenant held by construction (the table has no counter
# and no `last_used_at`) and nothing stopped a later edit from adding one.
extract_impl_region() {
  awk -v want="$2" '
    !in_impl {
      if ($0 ~ "^impl +" want "(<|\\b)") { in_impl = 1; depth = 0; opened = 0 } else { next }
    }
    in_impl {
      print FILENAME ":" NR ":" $0
      o = gsub(/\{/, "{"); c = gsub(/\}/, "}")
      depth += o - c
      if (o > 0) opened = 1
      if (opened && depth <= 0) in_impl = 0
    }
  ' "$1"
}

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
    awk '{ print FILENAME ":" NR ":" $0 }' "$INTROSPECT"
    extract_cc_regions "$TOKENS"
    extract_cc_regions "$REPO"
    extract_impl_region "$REPO" "ApiKeyRepo"
    extract_impl_region "$REPO" "ActingApiKeyRepo"
  }
)"

# Forbidden hooks: any metrics counter/gauge/histogram macro, or a
# billing/metering/quota/rate-limit symbol, case-insensitive.
#
# The boundary is `[^A-Za-z0-9]`, NOT `\b`. This is the whole difference between a covenant
# and a covenant-shaped comment: `_` is a word character, so `\bquota\b` cannot match
# `monthly_quota`, `\bmeter\b` cannot match `usage_meter`, and `\bbillable\b` cannot match
# `_billable`. Every snake_case spelling, which is to say every spelling this codebase actually
# uses, walked straight through.
#
# The previous comment claimed `bill_for` and `chargeUsage` were caught. Neither was: the list
# held `billing`/`billable` but not `bill`, and `chargeable` but not `charge`.
#
# `chargeUsage` needs a second pass. A camelCase join has no non-alphanumeric character at the
# seam, so no boundary can express it, and dropping the boundary entirely is not an option:
# `parameter` contains `meter`. CAMEL below is therefore matched case-SENSITIVELY, on a
# lowercase letter followed by a capitalised stem, which is precise enough to carry no false
# positives and catches the spelling a Rust or TypeScript author would actually write.
#
# A genuine false positive may carry "no-m2m-metering-allow: <reason>" on the line.
BOUNDARY_L='(^|[^A-Za-z0-9])'
BOUNDARY_R='([^A-Za-z0-9]|$)'
STEMS='meter|metering|billing|billable|bill|quota|chargeable|charge|usage_count|usage|rate_limit|ratelimit'
FORBIDDEN="metrics::(counter|gauge|histogram)|counter!|gauge!|histogram!|${BOUNDARY_L}(${STEMS})${BOUNDARY_R}"
# The camelCase seam, case SENSITIVE: `chargeUsage`, `requestQuota`, `perCallBilling`.
CAMEL='[a-z](Meter|Metering|Billing|Billable|Bill|Quota|Chargeable|Charge|Usage|RateLimit)'

# Scan CODE, not prose: a comment-only line (the covenant documentation itself names
# these words) is excluded. Each corpus line is `path:lineno:content`; drop lines whose
# CONTENT begins with a Rust line/doc comment marker. A metering hook in real code
# (even with a trailing comment) is not comment-only, so it is still caught.
hits=$(printf '%s\n' "$corpus" \
  | grep -iE "$FORBIDDEN" \
  | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' \
  | grep -v 'no-m2m-metering-allow' \
  || true)
# The camelCase pass is separate because it is the ONE pattern that must not be
# case-folded: `-i` would make `[a-z](Usage)` match `chargeusage` and, worse,
# `parameter`-shaped words through the lowercase stems.
camel_hits=$(printf '%s\n' "$corpus" \
  | grep -E "$CAMEL" \
  | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' \
  | grep -v 'no-m2m-metering-allow' \
  || true)
if [ -n "$camel_hits" ]; then
  hits="$(printf '%s\n%s' "$hits" "$camel_hits" | grep -v '^$' || true)"
fi

if [ -n "$hits" ]; then
  echo "no-m2m-metering: a metering/billing/quota hook is on the M2M issuance or"
  echo "                 verification path:"
  echo "$hits"
  echo
  echo "The client-credentials issuance path must carry NO metering, counting-for-billing,"
  echo "or quota hook (a covenant of the M2M path). Publish token-caching guidance as docs"
  echo "instead. If this is a genuine false positive, add 'no-m2m-metering-allow: <reason>'."
  exit 1
fi

# The SCHEMA half (issue #99, criterion 5): "confirmed by schema and code audit". A
# counter that is merely DORMANT sits in a table passing every code scan, waiting to be
# switched on, so the shipped DDL of the tables these paths write is read too. Read from
# the migrations rather than a live database because the question is what the project
# SHIPS; a live check would also pass on a deployment somebody altered by hand.
# A COLUMN pattern, not the code one. `$FORBIDDEN` is word-boundaried, which is right
# for code and wrong here: column names are snake_case compounds, and `\bquota\b` does
# NOT match inside `monthly_quota` because `_` is a word character. A mutation adding
# exactly that column survived the word-boundaried pattern, so this one matches the stem
# anywhere in an identifier.
#
# `last_used` is in the list and is the subtlest entry. It is not billing and it is not a
# counter, so it reads as harmless operational telemetry, which is exactly why migration
# 0123's header argues at length for leaving it out: a monotonically written column on the
# VERIFICATION path is a write amplification on every authenticated request and the first
# step toward usage accounting. That argument lived in a comment and was enforced nowhere.
# Planting `last_used_at` on `api_keys` survived this scan until the stem was added.
FORBIDDEN_COLUMN='(meter|metering|billing|billable|quota|chargeable|usage_count|seat_count|last_used|rate_limit|ratelimit)'

# `api_keys` (issue #99) is the table criterion 5 most obviously concerns and it was NOT
# here: the schema half was added before the table existed and nobody extended the list.
# Its migration argues at length that `last_used_at` is deliberately absent because a
# monotonically written column on the verification path is the first step toward usage
# accounting. That argument was in a comment and enforced nowhere.
M2M_TABLES='service_accounts opaque_access_tokens api_keys'
schema_hits=""
for table in $M2M_TABLES; do
  ddl_file=$(grep -l "CREATE TABLE ${table}" crates/ironauth-store/migrations/*.sql | head -1)
  if [ -z "$ddl_file" ]; then
    echo "no-m2m-metering: no migration declares ${table}, so the schema half of this"
    echo "                 audit is reading nothing. Point it at the migration that does."
    exit 1
  fi
  ddl=$(awk -v t="CREATE TABLE ${table}" '
    index($0, t) { inside = 1 }
    inside { print FILENAME ":" NR ":" $0 }
    inside && /^\);/ { inside = 0 }
  ' "$ddl_file")
  # Non-vacuity: the extracted block must look like a scoped table body, or the
  # extraction silently matched nothing and the scan below proves nothing.
  if ! printf '%s\n' "$ddl" | grep -q 'tenant_id'; then
    echo "no-m2m-metering: the extracted ${table} DDL does not look like a table body,"
    echo "                 so the schema scan proved nothing."
    exit 1
  fi
  found=$(printf '%s\n' "$ddl" \
    | grep -iE "$FORBIDDEN_COLUMN" \
    | grep -vE '^[^:]+:[0-9]+:[[:space:]]*--' \
    | grep -v 'no-m2m-metering-allow' \
    || true)
  [ -n "$found" ] && schema_hits="${schema_hits}${found}\n"
done

if [ -n "$schema_hits" ]; then
  echo "no-m2m-metering: a metering/billing/quota COLUMN is on an M2M table:"
  printf '%b' "$schema_hits"
  echo
  echo "A counter in the schema passes every code scan while it sits unused, then becomes"
  echo "a bill the day something reads it. Metering M2M is a product decision to make"
  echo "deliberately, not one that arrives in a migration."
  exit 1
fi

echo "no-m2m-metering: clean (no metering hook on the M2M issuance or verification path,"
echo "                 and no metering column on the M2M tables)"
