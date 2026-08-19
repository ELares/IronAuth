#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The local merge gate: run everything CI runs that can run locally, in the
# same order. Green here should mean green in CI for the fmt, clippy, test,
# invariant, dash, and compatibility lanes; cargo-deny and the MSRV and musl
# lanes run in CI (install cargo-deny locally to close that gap too).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# FAILURES ARE ACCUMULATED, not fatal on the spot, and this is the whole point of the
# rewrite. `set -e` plus a flat sequence meant the FIRST failing check killed the run, so
# everything after it silently never executed. When scripts/scoped-table-registration.sh
# started failing, this gate announced 7 banners and exited -- 6 checks actually completed,
# so every "green local gate" claimed after that was about a ninth of a gate. Three CI breaks
# (rfc9700-scan, event-catalog freshness, dash-scan) sat in the ~44 announced checks it never
# reached, and were found only by replaying the CI job by hand.
#
# The banner count is not the whole story either: the file holds 66 executable commands, 14
# of which were assertions with no banner of their own (a 15th, `git rev-parse`, is setup) --
# which is exactly how the six
# `git diff --exit-code` freshness checks came to be the LAST things still able to kill this
# script after its first rewrite.
#
# A gate that stops at the first failure also makes the WRONG tradeoff for its user: you fix
# one thing, re-run the whole expensive suite, and discover the next one. Reporting every
# failure at the end costs one run instead of N.
#
# `set -e` stays ON: the `if !` context suppresses errexit for the condition only, so a
# failure inside a check is caught here while an unexpected error anywhere else still aborts.
GATE_FAILURES=()

# WHETHER THE RUN REACHED THE END, and the lanes it could not run.
#
# The trap alone is not enough, and the first version of this rewrite proved it. On a signal
# death `$?` inside the trap is the status of the last COMPLETED command, not the signal, so
# a Ctrl-C during a long check left `rc=0` and an empty failure list, and the summary printed
# `gate: all local checks green` after 35 of 66 checks. The process still exited 130, so the
# STATUS was right and only the text lied -- which is the worse half, because a multi-hour
# run is read from `gate.log` afterwards and the last line is what a reader takes away.
#
# On main this could not happen, for an uninteresting reason: the green line was the script's
# last statement, so an interrupted run never reached it. Moving the summary into a trap is
# what created the hole, so this flag is part of that move rather than an extra.
#
# SKIPPED lanes are ledgered for the same reason one step milder: on a fresh clone with no
# node dependencies, 62 of 66 checks run and the summary said "all local checks green" with
# no qualification. This file's own header warns that "a local gate that is quietly a subset
# of CI teaches you to trust a green that does not mean what it looks like."
GATE_COMPLETED=0
GATE_SKIPPED=()

# Record a lane this machine could not run. `$1` is the lane, `$2` how to enable it.
skipped() {
  GATE_SKIPPED+=("$1 ($2)")
}

# The summary prints from a TRAP, not from the tail of the script.
#
# A tail-printed summary is lost the moment anything aborts -- and the first version of this
# rewrite left 16 commands unwrapped, so a failure in any of them killed the run AND discarded
# every failure already collected. The report was least available exactly when it mattered
# most. On EXIT the summary prints whatever was gathered, however the script ended.
gate_summary() {
  local rc=$?
  if ((${#GATE_FAILURES[@]} > 0)); then
    # stdout, like every other line this script prints. Splitting the summary onto stderr
    # would drop it from `scripts/gate.sh > gate.log`, which is how a multi-hour run is
    # actually captured -- the failure list is the one part of the log that must survive.
    echo ""
    echo "gate: ${#GATE_FAILURES[@]} check(s) FAILED:"
    printf '  - %s\n' "${GATE_FAILURES[@]}"
    # A non-zero rc from an abort is preserved; a clean exit with failures recorded becomes 1.
    if ((rc == 0)); then rc=1; fi
  fi

  # LAST, deliberately. An interrupted run's failure list is a PARTIAL accounting, so the
  # caveat has to be the thing at the bottom of the log rather than a line above a list that
  # reads as complete.
  if ((GATE_COMPLETED == 0)); then
    echo ""
    echo "gate: INCOMPLETE -- the run ended before the last check."
    echo "      Every check after the interruption never ran, so any list above is a"
    echo "      PARTIAL accounting. This is not a green gate."
    if ((rc == 0)); then rc=1; fi
  elif ((rc == 0)); then
    if ((${#GATE_SKIPPED[@]} > 0)); then
      echo "gate: all local checks green, ${#GATE_SKIPPED[@]} lane(s) SKIPPED here (CI runs them):"
      printf '  - %s\n' "${GATE_SKIPPED[@]}"
    else
      echo "gate: all local checks green"
    fi
  fi
  exit "$rc"
}
trap gate_summary EXIT

run() {
  local label="$1"
  shift
  echo "==> $label"
  if ! "$@"; then
    GATE_FAILURES+=("$label")
    echo "    FAILED: $label  (continuing -- every failure is reported at the end)"
  fi
}

# A PREREQUISITE: if this fails, the cargo-dependent checks below are noise, so stop.
#
# Scoped to a real COMPILE, deliberately. An earlier version gated on clippy, which exits
# non-zero identically for `error[E0308]` and for one pedantic style lint on a tree that
# compiles perfectly -- so a missing `#[must_use]` skipped every later check and reinstated
# the fix-one-thing-rerun-everything loop this rewrite exists to remove, for what is by far
# clippy's most common failure mode.
#
# The scope is also narrower than it looks. Counted on this file: 66 checks, 63 of them below
# this prerequisite. FIFTEEN of those 63 reach cargo -- two on gate.sh's own lines and
# thirteen through leaf scripts that shell out to it -- or seventeen when cargo-deny and the
# ironbus lane are both available. The remaining 46 to 48 are grep and python scans that
# never needed a compiling tree.
#
# So the honest claim is "about a quarter of the checks below would report the same root
# cause", and the reason to stop is that those fifteen are also the slow ones: they would
# spend the gate's full wall-clock re-proving one compile error.
#
# RE-DERIVED rather than adjusted. An earlier version said "18 of the 51", where 51 was a
# leftover denominator from the banner count this rewrite replaced. Correcting a fraction
# without re-deriving what it divides by is how a wrong number survives a correction.
#
# IT ALSO COSTS SOMETHING, on every green run, which is the common case. `cargo check` and
# `cargo clippy` do not share fingerprints, so clippy re-checks what this just checked. The
# cost is bounded to the workspace crates rather than the dependency graph (measured:
# dependencies are reused, only the workspace crate recompiles), so it is a second pass over
# our own code and not a second build. That is the trade: a bounded fixed cost on every green
# run, against not spending the gate's full wall-clock re-proving one compile error on a red
# one. Worth stating rather than presenting this as free.
run_required() {
  local label="$1"
  shift
  echo "==> $label"
  if ! "$@"; then
    GATE_FAILURES+=("$label (prerequisite -- later checks were skipped)")
    echo "    FAILED: $label"
    echo "    This is a PREREQUISITE: the cargo-dependent checks after it need a compiling"
    echo "    tree, so the gate stops rather than re-proving one root cause 15 times."
    exit 1
  fi
}


run "fmt" cargo fmt --all --check

run "msrv audit (no dependency declares a rust-version above the workspace MSRV)" ./scripts/msrv-audit.sh

run_required "workspace compiles" cargo check --workspace --all-targets --all-features
run "clippy (pedantic, -D warnings)" cargo clippy --workspace --all-targets --all-features -- -D warnings

# The ironauth-store isolation tests need a real Postgres via DATABASE_URL.
# with-test-db.sh runs against DATABASE_URL if set (a CI service), else brings up
# a throwaway local cluster and tears it down. All other tests are unaffected.
run "test" scripts/with-test-db.sh cargo test --workspace --all-features

run "invariant lints" scripts/invariant-lints.sh

run "query audit (no scoped-table SQL outside the repository module)" scripts/query-audit.sh
run "scoped table registration (every forced-RLS table in the migrations is in the query audit list)" scripts/scoped-table-registration.sh
run "audit foreign key claims (no comment asserts an audit_log foreign key that does not exist)" scripts/audit-fk-claim-scan.sh
run "test registration (every tests/*.rs file has a [[test]] entry; autotests are off)" scripts/test-registration.sh

run "independently publishable crates" scripts/publishable-crates.sh

# The freshness and audit lanes CI runs that this gate did not.
#
# Main went RED for three consecutive commits because two new message ids made
# packages/reference-app/src/contract/messages.gen.ts stale. Every one of those commits
# passed this gate. A local gate that is a strict subset of CI teaches you to trust a green
# that does not mean what it looks like, and the gap is invisible until something lands.
#
# `comm -23` over the script names in .github/workflows/ci.yml and this file is how the six
# missing ones were found; keep them in step.
run "route audit (server routes against the published contract)" scripts/route-audit.sh

run "admin SPA route audit" scripts/admin-spa-route-audit.sh

run "reference app bindings freshness (generated from the published contract)" scripts/reference-app-bindings.sh

# Issue #108. The catalog is DERIVED from the action list, so a new event type cannot land
# without appearing in it, and a payload schema edited under an unchanged version shows up
# as a diff a reviewer reads: that diff IS the compatibility check.
run "event catalog freshness (generated from the audit action registry)" scripts/event-catalog.sh

# The ONE corpus every verifier in issue #118 is judged against (the TS core today; the
# Workers, Fastly, Lambda@Edge, Java and .NET verifiers as they land). Deterministic, so a
# diff here is always a real change, and a REMOVED refusal vector is what this catches:
# dropping the alg_none case would make every verifier go green on an unsigned token.
run "JWT verification conformance corpus freshness (issue #118)" scripts/verify-vectors.sh

# Generated from the shipped signer, so a change to what a batch signature covers surfaces as
# a diff rather than as a SIEM that stops verifying in the field.
run "log-stream signature corpus freshness (issue #110)" scripts/log-stream-vectors.sh

# Issue #51 criterion 6. A pure python lane over the committed spec, so it needs neither Go
# nor tofu and runs everywhere.
run "terraform provider coverage (generated from the OpenAPI document)" scripts/provider-coverage.sh

# Issue #108 criterion 6, which the owner replaced "the registry counts at least 100 event
# types" with: a COUNT is satisfied by registering types nothing emits, which is the fiction
# the registry's own rule forbids. A RATCHET on the uncovered set, like the provider coverage
# above, because a check that fails from its first commit gets disabled rather than fixed.
run "event producer coverage (every management write announces itself)" scripts/producer-coverage.py

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
    run "SDK check() middleware (issue #100, criterion 6)" \
        bash -c 'cd packages/ironauth-sdk && npm test --silent'
else
    echo "sdk check(): SKIPPED, packages/ironauth-sdk dependencies are not installed."
    echo "             Run: (cd packages/ironauth-sdk && npm install)  [CI runs this check]"
    skipped "SDK check() middleware" "cd packages/ironauth-sdk && npm install"
fi

run "journey transcript replay" scripts/journey-replay.sh

run "admin SPA embed freshness" scripts/admin-spa-embed.sh

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
    run "admin SPA bindings freshness (generated from the OpenAPI document)" scripts/admin-spa-bindings.sh
else
    echo "admin-spa-bindings: SKIPPED, packages/admin-spa dependencies are not installed."
    echo "                    Run: (cd packages/admin-spa && npm install)  [CI runs this check]"
    skipped "admin SPA bindings freshness" "cd packages/admin-spa && npm install"
fi
run "idempotent write audit (no admin handler splits two store writes behind one Idempotency-Key)" scripts/idempotent-write-audit.sh

run "classification lint (every resource type is classified; all three classes used)" scripts/classification-lint.sh
run "pii encryption (every classified PII/secret column is envelope-encrypted)" scripts/pii-encryption-scan.sh
run "diagnostics redaction corpus (a sentinel in any free-form diagnostic field would be seen)" scripts/diagnostics-redaction-scan.sh

run "canonicalization seam (every identifier comparison routes through the one seam)" scripts/canonicalization-seam.sh

run "hashing pool boundary (every request-path hash routes through the admission-controlled pool)" scripts/hashing-pool-boundary.sh

run "http audit (ironauth-fetch is the only outbound HTTP path)" scripts/http-audit.sh

run "jose audit (ironauth-jose is the only JOSE verification path)" scripts/jose-audit.sh

run "no M2M metering (no metering/billing/quota hook on the client-credentials path)" scripts/no-m2m-metering.sh

run "dormant module scan (a public surface nothing calls)" scripts/dormant-module-scan.sh

run "SDK portability scan (no Node-only imports in runtime-portable sources)" scripts/sdk-portability-scan.sh

run "dash scan" scripts/dash-scan.sh

run "emulator doc freshness (the documented CI recipe's OTP code matches CI's pin)" scripts/emulator-doc-freshness.sh

run "no plaintext credentials (no login path writes a token to a file)" scripts/no-plaintext-credentials.sh

run "event registry compatibility (a breaking payload change bumps its version)" scripts/event-registry-compat.py

run "SDK policy (the published policy still matches the SDKs that exist)" scripts/sdk-policy-check.py

run "discovery scan (no static discovery JSON; generated at serve time)" scripts/discovery-scan.sh

run "rfc9700 scan (every OAuth endpoint bound to a conformance test)" scripts/rfc9700-scan.sh
run "conformance harness static checks (results gate, matrix, plan config, digest pins, fail-closed wiring, downgrade confinement)" scripts/conformance-check.sh

run "compatibility matrix freshness" scripts/compat-matrix.sh
run "compat matrix is committed fresh" git diff --exit-code docs/COMPATIBILITY.md

run "config schema freshness" scripts/config-schema.sh
run "config schema is committed fresh" git diff --exit-code docs/config-schema.json docs/CONFIG.md

run "connector schema freshness (definition + capability matrix)" scripts/connector-schema.sh
run "connector schema is committed fresh" git diff --exit-code docs/connector-schema.json docs/capability-matrix.schema.json

run "flow schema freshness (flow object schema + message id registry)" scripts/flow-schema.sh
run "flow schema is committed fresh" git diff --exit-code docs/flow-schema.json docs/flow-messages.json

run "journey schema freshness (published journey artifact contract)" scripts/journey-schema.sh
run "journey schema is committed fresh" git diff --exit-code docs/journey-schema.json

run "flow golden corpus freshness (rendered flow shape, all journeys x both transports)" scripts/flow-golden.sh
run "flow golden is committed fresh" git diff --exit-code docs/flow-golden.json

run "openapi freshness (served management spec vs committed artifact)" scripts/openapi-check.sh
# Drift says the spec is CURRENT; this says it is generator-ready (issue #122).
run "openapi lint (generator-ready)" scripts/openapi-lint.sh
# The spec-diff changelog generator must itself be correct (issue #122).
run "openapi changelog self-test" python3 scripts/openapi-changelog.py --self-test
# The published wire-format contract must still describe the code (issue #122).
run "sdk contract freshness" python3 scripts/sdk-contract.py --check
# The generated management SDKs must still match the published contract (issue #122).
run "generated management SDKs freshness" python3 scripts/gen-management-sdks.py --check
# And they must still COMPILE, which a freshness check cannot show.
run "Go SDK builds" bash -c 'cd sdks/go && go build ./...'
run "Python SDK imports" python3 -c "import importlib.util,sys; s=importlib.util.spec_from_file_location('c','sdks/python/ironauth_management/client_gen.py'); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)"
# The events-vs-webhooks guidance must still match the code it quotes (issue #107).
run "events-vs-webhooks guidance" python3 scripts/events-vs-webhooks.py --check
# Metering must stay off the login and token-issuance paths (issue #107).
run "metering stays off the hot path" scripts/metering-off-hot-path.sh

run "fuzz matrix freshness (every registered fuzz target has a CI matrix row)" scripts/fuzz-matrix-freshness.sh

if command -v cargo-deny >/dev/null 2>&1; then
  run "cargo deny" cargo deny check
else
  echo "==> cargo deny skipped (not installed; CI enforces it)"
  skipped "cargo deny" "cargo install cargo-deny"
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
  run "outbox ironbus lane (IRONBUS_ADDR=$IRONBUS_ADDR)" \
    scripts/with-test-db.sh cargo test -p ironauth-store --features testing,ironbus \
    --test outbox --test outbox_ironbus
else
  echo "==> outbox ironbus lane SKIPPED (set IRONBUS_ADDR to a broker to run it; CI always does)"
  skipped "outbox ironbus lane" "set IRONBUS_ADDR to a broker"
fi

# THE LAST STATEMENT, and it has to stay last.
#
# This is what tells the trap the difference between a run that finished and one that was
# killed. Anything placed below it would execute on a run the flag has already declared
# complete, so new checks go ABOVE.
GATE_COMPLETED=1

# The EXIT trap prints the summary and decides the status.
