#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The local merge gate: run everything CI runs that can run locally, in the
# same order. Green here should mean green in CI for the fmt, clippy, test,
# invariant, dash, and compatibility lanes; cargo-deny and the MSRV and musl
# lanes run in CI (install cargo-deny locally to close that gap too).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

echo "==> fmt"
cargo fmt --all --check

echo "==> msrv audit (no dependency declares a rust-version above the workspace MSRV)"
./scripts/msrv-audit.sh

echo "==> clippy (pedantic, -D warnings)"
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "==> test"
# The ironauth-store isolation tests need a real Postgres via DATABASE_URL.
# with-test-db.sh runs against DATABASE_URL if set (a CI service), else brings up
# a throwaway local cluster and tears it down. All other tests are unaffected.
scripts/with-test-db.sh cargo test --workspace --all-features

echo "==> invariant lints"
scripts/invariant-lints.sh

echo "==> query audit (no scoped-table SQL outside the repository module)"
scripts/query-audit.sh
echo "==> scoped table registration (every forced-RLS table in the migrations is in the query audit list)"
scripts/scoped-table-registration.sh
echo "==> audit foreign key claims (no comment asserts an audit_log foreign key that does not exist)"
scripts/audit-fk-claim-scan.sh
echo "==> test registration (every tests/*.rs file has a [[test]] entry; autotests are off)"
scripts/test-registration.sh

echo "==> independently publishable crates"
scripts/publishable-crates.sh

# The freshness and audit lanes CI runs that this gate did not.
#
# Main went RED for three consecutive commits because two new message ids made
# packages/reference-app/src/contract/messages.gen.ts stale. Every one of those commits
# passed this gate. A local gate that is a strict subset of CI teaches you to trust a green
# that does not mean what it looks like, and the gap is invisible until something lands.
#
# `comm -23` over the script names in .github/workflows/ci.yml and this file is how the six
# missing ones were found; keep them in step.
echo "==> route audit (server routes against the published contract)"
scripts/route-audit.sh

echo "==> admin SPA route audit"
scripts/admin-spa-route-audit.sh

echo "==> reference app bindings freshness (generated from the published contract)"
scripts/reference-app-bindings.sh

echo "==> journey transcript replay"
scripts/journey-replay.sh

echo "==> admin SPA embed freshness"
scripts/admin-spa-embed.sh

echo "==> admin SPA bindings freshness (generated from the OpenAPI document)"
# The precondition is the LOCAL npm bin, not a global one.
#
# The first version of this guard tested `command -v openapi-typescript`, which is the wrong
# question: `scripts/admin-spa-bindings.sh` runs `npm run codegen` from `packages/admin-spa`,
# so it uses `node_modules/.bin`. With the dependencies installed the script succeeds while
# that guard still reports absent, and the gate would have skipped a check it could run. A
# skip that fires when the tool IS available is worse than the silent skip this block replaced,
# because the announcement makes it look considered.
#
# The skip now names the command that removes it. An announced skip nobody can act on is only
# half the value.
if [ -x packages/admin-spa/node_modules/.bin/openapi-typescript ]; then
    scripts/admin-spa-bindings.sh
else
    echo "admin-spa-bindings: SKIPPED, packages/admin-spa dependencies are not installed."
    echo "                    Run: (cd packages/admin-spa && npm install)  [CI runs this check]"
fi
echo "==> idempotent write audit (no admin handler splits two store writes behind one Idempotency-Key)"
scripts/idempotent-write-audit.sh

echo "==> classification lint (every resource type is classified; all three classes used)"
scripts/classification-lint.sh
echo "==> pii encryption (every classified PII/secret column is envelope-encrypted)"
scripts/pii-encryption-scan.sh
echo "==> diagnostics redaction corpus (a sentinel in any free-form diagnostic field would be seen)"
scripts/diagnostics-redaction-scan.sh

echo "==> canonicalization seam (every identifier comparison routes through the one seam)"
scripts/canonicalization-seam.sh

echo "==> hashing pool boundary (every request-path hash routes through the admission-controlled pool)"
scripts/hashing-pool-boundary.sh

echo "==> http audit (ironauth-fetch is the only outbound HTTP path)"
scripts/http-audit.sh

echo "==> jose audit (ironauth-jose is the only JOSE verification path)"
scripts/jose-audit.sh

echo "==> no M2M metering (no metering/billing/quota hook on the client-credentials path)"
scripts/no-m2m-metering.sh

echo "==> dash scan"
scripts/dash-scan.sh

echo "==> discovery scan (no static discovery JSON; generated at serve time)"
scripts/discovery-scan.sh

echo "==> rfc9700 scan (every OAuth endpoint bound to a conformance test)"
scripts/rfc9700-scan.sh
echo "==> conformance harness static checks (results gate, matrix, plan config, digest pins, fail-closed wiring, downgrade confinement)"
scripts/conformance-check.sh

echo "==> compatibility matrix freshness"
scripts/compat-matrix.sh
git diff --exit-code docs/COMPATIBILITY.md

echo "==> config schema freshness"
scripts/config-schema.sh
git diff --exit-code docs/config-schema.json docs/CONFIG.md

echo "==> connector schema freshness (definition + capability matrix)"
scripts/connector-schema.sh
git diff --exit-code docs/connector-schema.json docs/capability-matrix.schema.json

echo "==> flow schema freshness (flow object schema + message id registry)"
scripts/flow-schema.sh
git diff --exit-code docs/flow-schema.json docs/flow-messages.json

echo "==> journey schema freshness (published journey artifact contract)"
scripts/journey-schema.sh
git diff --exit-code docs/journey-schema.json

echo "==> flow golden corpus freshness (rendered flow shape, all journeys x both transports)"
scripts/flow-golden.sh
git diff --exit-code docs/flow-golden.json

echo "==> openapi freshness (served management spec vs committed artifact)"
scripts/openapi-check.sh

echo "==> fuzz matrix freshness (every registered fuzz target has a CI matrix row)"
scripts/fuzz-matrix-freshness.sh

if command -v cargo-deny >/dev/null 2>&1; then
  echo "==> cargo deny"
  cargo deny check
else
  echo "==> cargo deny skipped (not installed; CI enforces it)"
fi

echo "gate: all local checks green"
