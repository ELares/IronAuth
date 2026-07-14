#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# One-command local reproduction and CI entry point for the OIDF conformance
# harness (issue #37). It brings the stack up, selects the profiles for a
# trigger (or one named profile) from profile-matrix.yaml, generates each plan's
# runner config from that same matrix, drives each plan with the OIDF Python
# runner, normalizes the per-module results, and fails on any non-PASS through
# parse_results.py.
#
# Local, one profile against a local server (the documented single command):
#     ./run-conformance.sh --profile oidcc-basic-certification-test-plan --up
#
# The merge-gate subset, or the full nightly matrix:
#     ./run-conformance.sh --trigger merge-gate --up
#     ./run-conformance.sh --trigger nightly --up
#
# THIS SCRIPT FAILS CLOSED. It exits 0 ONLY when it has actually driven at least
# one plan through the live suite and the results gate passed every module. Every
# other outcome is a NON-ZERO exit:
#
#   - the OIDF runner (run-test-plan.py) is not on PATH        -> exit 1
#   - the profile selection is empty                           -> exit 1
#   - the profile selector itself failed                       -> exit 1
#   - a plan config cannot be generated                        -> exit 1 (set -e)
#   - any module is not a PASS, or the run is vacuously empty  -> exit 1
#
# A harness that cannot run the suite must NEVER report the suite as green. The
# single escape hatch, --allow-missing-runner, exists for a LOCAL dry run of the
# selection and orchestration logic; it REFUSES TO RUN IN CI (guard below), it
# says loudly that nothing was verified, and no workflow in this repo passes it.
#
# WHAT NEEDS THE PROVISIONED RUNNER (owner/infra): the live suite images pinned
# in SUITE_VERSION (real digests), the suite's trust of the OP CA, and the OIDF
# runner (run-test-plan.py) on PATH or vendored. See docs/conformance/RUNBOOK.md.
set -euo pipefail
cd "$(dirname "$0")"

TRIGGER=""
PROFILE=""
BRING_UP=0
ALLOW_MISSING_RUNNER=0
RESULTS_DIR="results"
COMPOSE=(docker compose --env-file SUITE_VERSION -f docker-compose.yml)

# The throwaway cert credential. gen-plan-config.py reads it from the ENVIRONMENT
# (the matrix names the variable), so the password never lands in a generated
# config file. seed.sh declares the same default; drift between the two is caught
# by crates/ironauth-oidc/tests/conformance_seed.rs.
export CERT_USER_PASSWORD="${CERT_USER_PASSWORD:-conformance-cert-password}"

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --trigger) TRIGGER="$2"; shift 2 ;;
        --profile) PROFILE="$2"; shift 2 ;;
        --up)      BRING_UP=1; shift ;;
        --allow-missing-runner) ALLOW_MISSING_RUNNER=1; shift ;;
        -h|--help) usage 0 ;;
        *) echo "unknown argument: $1" >&2; usage 1 ;;
    esac
done

if [ -z "$TRIGGER" ] && [ -z "$PROFILE" ]; then
    echo "specify --trigger <merge-gate|nightly> or --profile <id>" >&2
    exit 2
fi

# --allow-missing-runner is a LOCAL dry-run affordance. In CI it would be exactly
# the fail-open this harness exists to prevent (a green run that drove nothing),
# so it is refused there outright.
if [ "$ALLOW_MISSING_RUNNER" -eq 1 ] && [ "${CI:-}" = "true" ]; then
    echo "run-conformance: --allow-missing-runner is a LOCAL dry-run flag and is" >&2
    echo "run-conformance: REFUSED in CI: a CI run that drives no plan must be RED," >&2
    echo "run-conformance: never a vacuous pass. Provision the runner instead." >&2
    exit 2
fi

# Print the enabled profiles for the selection, and the deferred ones, from the
# matrix. One enabled profile id per line on stdout; human notes on stderr. A
# non-zero exit means the SELECTOR failed, which must abort the run.
select_profiles() {
    python3 - "$TRIGGER" "$PROFILE" <<'PY'
import sys, yaml
trigger, profile = sys.argv[1], sys.argv[2]
matrix = yaml.safe_load(open("profile-matrix.yaml"))
enabled, deferred = [], []
for p in matrix["profiles"]:
    if profile:
        if p["id"] != profile:
            continue
    elif trigger not in p.get("triggers", []):
        continue
    if p.get("enabled", False):
        enabled.append(p["id"])
    else:
        deferred.append((p["id"], p.get("blocked_by", "unspecified")))
for pid, blocked in deferred:
    sys.stderr.write(f"not-yet-enabled: {pid} (blocked by {blocked})\n")
if profile and not enabled and not deferred:
    sys.stderr.write(f"error: profile {profile} is not in the matrix\n")
    sys.exit(3)
print("\n".join(enabled))
PY
}

if [ "$BRING_UP" -eq 1 ]; then
    echo "==> generating the OP self-signed CA and cert"
    ./gen-certs.sh
    echo "==> bringing the stack up (pinned by digest via SUITE_VERSION)"
    "${COMPOSE[@]}" up -d --wait
    echo "==> seeding the deterministic operator/tenant/environment/user"
    ./seed.sh
fi

mkdir -p "$RESULTS_DIR"

# Capture the selector's EXIT STATUS explicitly. `mapfile -t P < <(select_profiles)`
# threw it away, so a CRASHED selector read as "no profiles" and passed; and
# mapfile is bash 4 only, which breaks the documented one-command reproduction on
# stock macOS bash 3.2. A command substitution plus a portable read loop fixes
# both at once.
selected=""
if ! selected="$(select_profiles)"; then
    echo "run-conformance: the profile SELECTOR failed (see the error above)." >&2
    echo "run-conformance: a broken selector is a harness bug, not an empty run;" >&2
    echo "run-conformance: refusing to continue." >&2
    exit 1
fi

PROFILES=()
while IFS= read -r line; do
    if [ -n "$line" ]; then
        PROFILES+=("$line")
    fi
done <<EOF
$selected
EOF

if [ "${#PROFILES[@]}" -eq 0 ]; then
    echo "run-conformance: the selection matched NO enabled profile." >&2
    if [ -n "$PROFILE" ]; then
        echo "run-conformance: profile '$PROFILE' is in the matrix but is not enabled." >&2
    else
        echo "run-conformance: trigger '$TRIGGER' selected no enabled profile." >&2
    fi
    echo "run-conformance: a selection that drives nothing is a harness bug, not a" >&2
    echo "run-conformance: pass. Fix the matrix or the selection and re-run." >&2
    exit 1
fi

# The live drive needs the OIDF runner. Without it NOTHING is verified, so this
# is a hard failure: exiting green here is exactly the vacuous pass this gate
# exists to prevent.
if ! command -v run-test-plan.py >/dev/null 2>&1; then
    echo "run-conformance: the OIDF runner (run-test-plan.py) is NOT on PATH." >&2
    echo "run-conformance: it drives every plan, so nothing can be verified without" >&2
    echo "run-conformance: it. Provision it from the pinned suite release and install" >&2
    echo "run-conformance: requirements.txt (see docs/conformance/RUNBOOK.md)." >&2
    if [ "$ALLOW_MISSING_RUNNER" -eq 1 ]; then
        echo "run-conformance: --allow-missing-runner: DRY RUN. The profiles below were" >&2
        echo "run-conformance: SELECTED BUT NOT DRIVEN. NOTHING was verified. This is" >&2
        echo "run-conformance: not a conformance pass and must never be read as one." >&2
        for plan in "${PROFILES[@]}"; do
            echo "run-conformance:   would drive: $plan" >&2
        done
        exit 0
    fi
    exit 1
fi

# Drive each enabled profile with the OIDF runner and normalize its results. The
# plan config is GENERATED from the matrix (issuer, discovery URL, login), so the
# issuer the suite exact-string-matches has exactly one definition (#194).
overall=0
for plan in "${PROFILES[@]}"; do
    echo "==> profile: $plan"
    out="$RESULTS_DIR/$plan.json"
    config="$RESULTS_DIR/$plan.config.json"

    # Both abort the run on failure (set -e): a plan that cannot be configured is
    # a plan that cannot be certified, and must never be silently skipped.
    python3 gen-plan-config.py --profile "$plan" --out "$config"
    plan_spec="$(python3 gen-plan-config.py --profile "$plan" --print-plan)"

    # LIVE DRIVE. run-test-plan.py exports per-module status/result. A failing
    # plan must not abort the loop (the results gate below reports it module by
    # module), so its exit status is deliberately not fatal here; a MISSING export
    # still fails closed, because normalize_runner_export.py then errors under
    # set -e.
    run-test-plan.py \
        --export-dir "$RESULTS_DIR/$plan.suite" \
        "$plan_spec" "$config" \
        || true
    python3 normalize_runner_export.py "$RESULTS_DIR/$plan.suite" > "$out"

    if ! python3 parse_results.py "$out" --waivers warning-waivers.json; then
        overall=1
    fi
done

exit "$overall"
