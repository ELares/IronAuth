#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Always-on static checks for the OIDF conformance harness (issue #37). These run
# on every PR WITHOUT the provisioned live runner, so the wiring cannot rot even
# while the runner is owner-gated. They cover everything that is locally
# verifiable:
#
#   1. the results gate's own unit tests (parse_results.py / normalize),
#   2. the JSON files (waivers, fixtures) are well formed,
#   3. the profile matrix and compose YAML parse and have the expected shape
#      (deep check when PyYAML is present; a structural fallback otherwise),
#   4. every compose image is pinned BY DIGEST via SUITE_VERSION, never a tag,
#   5. the cert-only downgrades are present in the cert config and ABSENT from
#      the shipped default (a fast complement to the Rust confinement test),
#   6. `docker compose config` parses (only when docker is available).
#
# The live suite run itself (against a provisioned deployment) is a separate,
# owner-gated lane; see .github/workflows/ci.yml and docs/conformance/RUNBOOK.md.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

conf="deploy/conformance"
fail=0
note() { echo "conformance-check: $*"; }

# 1. Results-gate unit tests (standard-library only; always runnable).
note "results-gate unit tests"
( cd "$conf" && python3 test_parse_results.py >/dev/null 2>&1 ) \
    || { echo "conformance-check: results-gate unit tests FAILED"; fail=1; }

# 2. JSON files well formed.
note "json well-formedness"
for f in "$conf"/warning-waivers.json "$conf"/fixtures/*.json; do
    python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$f" \
        || { echo "conformance-check: invalid JSON: $f"; fail=1; }
done

# 3. Matrix + compose YAML. Deep-parse with PyYAML when present; else a
#    dependency-free structural fallback so the check stays green everywhere.
if python3 -c "import yaml" >/dev/null 2>&1; then
    note "matrix + compose YAML (deep parse, PyYAML present)"
    python3 - "$conf" <<'PY' || fail=1
import sys, yaml
conf = sys.argv[1]
matrix = yaml.safe_load(open(f"{conf}/profile-matrix.yaml"))
assert isinstance(matrix.get("profiles"), list) and matrix["profiles"], "no profiles"
issuer = matrix["op"]["issuer"]
assert not issuer.endswith("/"), "issuer must not have a trailing slash (#194)"
enabled = [p for p in matrix["profiles"] if p.get("enabled")]
gated = [p for p in matrix["profiles"] if not p.get("enabled")]
assert enabled, "no enabled profiles"
for p in gated:
    assert p.get("blocked_by"), f"deferred profile {p['id']} must name blocked_by"
mg = [p["id"] for p in enabled if "merge-gate" in p.get("triggers", [])]
assert len(mg) >= 4, f"expected the 4 OP profiles on the merge gate, got {mg}"
yaml.safe_load(open(f"{conf}/docker-compose.yml"))
print(f"matrix ok: {len(enabled)} enabled, {len(gated)} deferred, {len(mg)} on merge-gate")
PY
else
    note "PyYAML absent: structural fallback (deep YAML parse skipped)"
    grep -q '^profiles:' "$conf/profile-matrix.yaml" \
        || { echo "conformance-check: profile-matrix.yaml missing 'profiles:'"; fail=1; }
    grep -Eq 'issuer:[[:space:]]*"[^"]*[^/]"' "$conf/profile-matrix.yaml" \
        || { echo "conformance-check: matrix issuer missing or has a trailing slash"; fail=1; }
    grep -Eq 'blocked_by:' "$conf/profile-matrix.yaml" \
        || { echo "conformance-check: no deferred (blocked_by) profiles found"; fail=1; }
fi

# 4. Every compose image var is pinned by digest in SUITE_VERSION.
note "image digest pinning (SUITE_VERSION)"
for var in $(grep -oE '\$\{[A-Z_]+_IMAGE' "$conf/docker-compose.yml" | tr -d '${' | sort -u); do
    line="$(grep -E "^${var}=" "$conf/SUITE_VERSION" || true)"
    if [ -z "$line" ]; then
        echo "conformance-check: compose image \$$var is not pinned in SUITE_VERSION"; fail=1
    elif ! printf '%s' "$line" | grep -q '@sha256:'; then
        echo "conformance-check: $var is not pinned BY DIGEST (needs @sha256:)"; fail=1
    fi
done
# No compose service may pin an image by a bare mutable tag: an image line whose
# value begins with something other than a compose variable is a literal ref.
if grep -E '^[[:space:]]*image:[[:space:]]+[^$[:space:]]' "$conf/docker-compose.yml" \
    | grep -v '@sha256:' | grep -q .; then
    echo "conformance-check: a compose image uses a literal (non-digest) reference"; fail=1
fi

# 5. Cert-only downgrade confinement (fast complement to the Rust test).
note "downgrade confinement (cert on, default off)"
cert="$conf/ironauth.toml"
default="deploy/ironauth.toml"
for key in enable_response_type_id_token enable_response_type_code_id_token \
           enable_response_type_none enable_response_mode_form_post registration_enabled; do
    grep -Eq "^[[:space:]]*${key}[[:space:]]*=[[:space:]]*true" "$cert" \
        || { echo "conformance-check: cert config must set $key = true"; fail=1; }
    if grep -Eq "^[[:space:]]*${key}[[:space:]]*=[[:space:]]*true" "$default"; then
        echo "conformance-check: DEFAULT config must NOT set $key = true (downgrade leaked)"; fail=1
    fi
done

# 6. Compose config parses, only when docker is available.
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    note "docker compose config"
    ( cd "$conf" && docker compose --env-file SUITE_VERSION -f docker-compose.yml config >/dev/null ) \
        || { echo "conformance-check: docker compose config FAILED"; fail=1; }
else
    note "docker absent: 'docker compose config' skipped (CI/owner runner covers it)"
fi

if [ "$fail" -ne 0 ]; then
    echo "conformance-check: FAILED"
    exit 1
fi
echo "conformance-check: clean"
