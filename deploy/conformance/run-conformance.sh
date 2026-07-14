#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# One-command local reproduction and CI entry point for the OIDF conformance
# harness (issue #37). It brings the stack up, selects the profiles for a
# trigger (or one named profile) from profile-matrix.yaml, drives each with the
# OIDF Python runner, normalizes the per-module results, and fails on any
# non-PASS through parse_results.py.
#
# Local, one profile against a local server (the documented single command):
#     ./run-conformance.sh --profile oidcc-basic-certification-test-plan --up
#
# The merge-gate subset, or the full nightly matrix:
#     ./run-conformance.sh --trigger merge-gate --up
#     ./run-conformance.sh --trigger nightly --up
#
# WHAT NEEDS THE PROVISIONED RUNNER (owner/infra): the live suite images pinned
# in SUITE_VERSION (real digests), the suite's trust of the OP CA, and the OIDF
# runner (run-test-plan.py) on PATH or vendored. Until those exist the selection,
# orchestration, and results-gating logic here are exercised, but the live drive
# step reports that the runner is not provisioned rather than faking a pass.
set -euo pipefail
cd "$(dirname "$0")"

TRIGGER=""
PROFILE=""
BRING_UP=0
RESULTS_DIR="results"
COMPOSE=(docker compose --env-file SUITE_VERSION -f docker-compose.yml)

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --trigger) TRIGGER="$2"; shift 2 ;;
        --profile) PROFILE="$2"; shift 2 ;;
        --up)      BRING_UP=1; shift ;;
        -h|--help) usage 0 ;;
        *) echo "unknown argument: $1" >&2; usage 1 ;;
    esac
done

if [ -z "$TRIGGER" ] && [ -z "$PROFILE" ]; then
    echo "specify --trigger <merge-gate|nightly> or --profile <id>" >&2
    exit 2
fi

# Print the enabled profiles for the selection, and the deferred ones, from the
# matrix. Emits one enabled profile id per line on fd 3; human notes on stderr.
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
mapfile -t PROFILES < <(select_profiles)

if [ "${#PROFILES[@]}" -eq 0 ]; then
    echo "no enabled profiles selected (see the not-yet-enabled notes above)"
    exit 0
fi

# Drive each enabled profile with the OIDF runner and normalize results. The
# runner (run-test-plan.py) is invoked with the plan id and a generated config
# whose issuer comes from the matrix (exact-string match, no trailing slash).
overall=0
for plan in "${PROFILES[@]}"; do
    echo "==> profile: $plan"
    out="$RESULTS_DIR/$plan.json"
    if command -v run-test-plan.py >/dev/null 2>&1; then
        # LIVE DRIVE (provisioned runner). run-test-plan.py exports per-module
        # status/result; normalize its export into the shape parse_results.py
        # consumes. Archive the raw suite log alongside for certification
        # submission (see docs/conformance/RUNBOOK.md).
        run-test-plan.py \
            --export-dir "$RESULTS_DIR/$plan.suite" \
            "$plan" ./plan-config.json \
            || true
        python3 normalize_runner_export.py "$RESULTS_DIR/$plan.suite" > "$out"
    else
        echo "runner not provisioned: skipping the LIVE drive of $plan" >&2
        echo "  (provision the OIDF runner + suite digests, then re-run; see RUNBOOK)" >&2
        continue
    fi
    if ! python3 parse_results.py "$out" --waivers warning-waivers.json; then
        overall=1
    fi
done

exit "$overall"
