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

echo "==> http audit (ironauth-fetch is the only outbound HTTP path)"
scripts/http-audit.sh

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

echo "==> openapi freshness (served management spec vs committed artifact)"
scripts/openapi-check.sh

if command -v cargo-deny >/dev/null 2>&1; then
  echo "==> cargo deny"
  cargo deny check
else
  echo "==> cargo deny skipped (not installed; CI enforces it)"
fi

echo "gate: all local checks green"
