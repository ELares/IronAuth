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

echo "==> event catalog freshness (generated from the audit action registry)"
# Issue #108. The catalog is DERIVED from the action list, so a new event type cannot land
# without appearing in it, and a payload schema edited under an unchanged version shows up
# as a diff a reviewer reads: that diff IS the compatibility check.
scripts/event-catalog.sh

echo "==> JWT verification conformance corpus freshness (issue #118)"
# The ONE corpus every verifier in issue #118 is judged against (the TS core today; the
# Workers, Fastly, Lambda@Edge, Java and .NET verifiers as they land). Deterministic, so a
# diff here is always a real change, and a REMOVED refusal vector is what this catches:
# dropping the alg_none case would make every verifier go green on an unsigned token.
scripts/verify-vectors.sh

echo "==> terraform provider coverage (generated from the OpenAPI document)"
# Issue #51 criterion 6. A pure python lane over the committed spec, so it needs neither Go
# nor tofu and runs everywhere.
scripts/provider-coverage.sh

echo "==> event producer coverage (every management write announces itself)"
# Issue #108 criterion 6, which the owner replaced "the registry counts at least 100 event
# types" with: a COUNT is satisfied by registering types nothing emits, which is the fiction
# the registry's own rule forbids. A RATCHET on the uncovered set, like the provider coverage
# above, because a check that fails from its first commit gets disabled rather than fixed.
scripts/producer-coverage.py

echo "==> SDK check() middleware (issue #100, criterion 6)"
# The uniform authorization `check()`: one call resolving via token claims, via IronAuth's
# AuthZEN PDP, or via a customer PDP, by configuration. It is a fail-CLOSED authorization
# primitive, so its tests are the kind worth running on every gate.
#
# It lives in its OWN package rather than in the reference app because route-audit.sh
# forbids that app from performing a network call outside `api.ts` or naming a URL outside
# `endpoints.ts`, which is exactly what an SDK calling an operator-configured PDP does. The
# lint caught that and was right; see packages/ironauth-sdk/README.md.
#
# Same precondition shape as the admin-SPA lane, and the same reason: the runner is the LOCAL
# `tsc`, so testing for a global one would skip a check the tree can actually run. The skip
# names the command that removes it.
if [ -x packages/ironauth-sdk/node_modules/.bin/tsc ]; then
    (cd packages/ironauth-sdk && npm test --silent)
else
    echo "sdk check(): SKIPPED, packages/ironauth-sdk dependencies are not installed."
    echo "             Run: (cd packages/ironauth-sdk && npm install)  [CI runs this check]"
fi

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

echo "==> dormant module scan (a public surface nothing calls)"
scripts/dormant-module-scan.sh

echo "==> SDK portability scan (no Node-only imports in runtime-portable sources)"
scripts/sdk-portability-scan.sh

echo "==> dash scan"
scripts/dash-scan.sh

echo "==> emulator doc freshness (the documented CI recipe's OTP code matches CI's pin)"
scripts/emulator-doc-freshness.sh

echo "==> no plaintext credentials (no login path writes a token to a file)"
scripts/no-plaintext-credentials.sh

echo "==> event registry compatibility (a breaking payload change bumps its version)"
scripts/event-registry-compat.py

echo "==> SDK policy (the published policy still matches the SDKs that exist)"
scripts/sdk-policy-check.py

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
# Drift says the spec is CURRENT; this says it is generator-ready (issue #122).
scripts/openapi-lint.sh
# The spec-diff changelog generator must itself be correct (issue #122).
python3 scripts/openapi-changelog.py --self-test
# The published wire-format contract must still describe the code (issue #122).
python3 scripts/sdk-contract.py --check
# The generated management SDKs must still match the published contract (issue #122).
python3 scripts/gen-management-sdks.py --check
# And they must still COMPILE, which a freshness check cannot show.
( cd sdks/go && go build ./... )
python3 -c "import importlib.util,sys; s=importlib.util.spec_from_file_location('c','sdks/python/ironauth_management/client_gen.py'); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)"
# The events-vs-webhooks guidance must still match the code it quotes (issue #107).
python3 scripts/events-vs-webhooks.py --check
# Metering must stay off the login and token-issuance paths (issue #107).
scripts/metering-off-hot-path.sh

echo "==> fuzz matrix freshness (every registered fuzz target has a CI matrix row)"
scripts/fuzz-matrix-freshness.sh

if command -v cargo-deny >/dev/null 2>&1; then
  echo "==> cargo deny"
  cargo deny check
else
  echo "==> cargo deny skipped (not installed; CI enforces it)"
fi

# The IRONBUS lane of the dual-mode async matrix (issue #104, criterion 6).
#
# CI runs this against a broker it installs. Locally a broker is optional, so the lane
# is run only when IRONBUS_ADDR points at one, and its ABSENCE is announced rather than
# silent. That is the difference this gate's own header is about: a local gate that is
# quietly a subset of CI teaches you to trust a green that does not mean what it looks
# like. The workspace run above already compiles this lane under --all-features; without
# a broker its cases skip, so what is missing locally is the live-broker assertion and
# nothing else.
if [ -n "${IRONBUS_ADDR:-}" ]; then
  echo "==> outbox ironbus lane (IRONBUS_ADDR=$IRONBUS_ADDR)"
  scripts/with-test-db.sh cargo test -p ironauth-store --features testing,ironbus \
    --test outbox --test outbox_ironbus
else
  echo "==> outbox ironbus lane SKIPPED (set IRONBUS_ADDR to a broker to run it; CI always does)"
fi

echo "gate: all local checks green"
