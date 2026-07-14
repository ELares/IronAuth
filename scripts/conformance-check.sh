#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# ALWAYS-ON static checks for the OIDF conformance harness (issue #37). These run
# in the ordinary lint lane on EVERY PR, with no repository variable gating them
# and WITHOUT the provisioned live runner. They are the part of the harness that
# really enforces today; the live suite drive is owner-gated and, until it is
# provisioned, enforces nothing (docs/conformance/README.md says so plainly).
# Everything statically verifiable is therefore checked HERE:
#
#   1. the results gate's own unit tests (parse_results.py / normalize),
#   2. the JSON files (waivers, fixtures) are well formed,
#   3. the profile matrix and compose YAML parse and have the expected shape,
#   4. EVERY image reference anywhere under deploy/conformance is pinned BY
#      DIGEST, never a mutable tag (compose files AND shell scripts),
#   5. the runner's plan config can actually be GENERATED from the matrix and has
#      the right shape (its absence used to be a latent run-time failure),
#   6. the cert-only downgrades are present in the cert config and ABSENT from
#      the shipped default (a fast complement to the Rust confinement test),
#   7. the harness cannot fail OPEN: no workflow may pass --allow-missing-runner,
#      and run-conformance.sh must stay bash 3.2 portable (no mapfile),
#   8. `docker compose config` parses (only when docker is available).
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

# 3. Matrix + compose YAML. Deep-parse with PyYAML (CI installs it from the
#    hash-pinned requirements.txt); a dependency-free structural fallback keeps
#    the check usable on a developer box that has no PyYAML.
have_yaml=0
if python3 -c "import yaml" >/dev/null 2>&1; then
    have_yaml=1
fi

if [ "$have_yaml" -eq 1 ]; then
    note "matrix + compose YAML (deep parse)"
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

# 4. EVERY image reference under deploy/conformance is pinned BY DIGEST.
#
#    This used to look only at docker-compose.yml, which left the "every image is
#    pinned by digest, never a mutable tag" claim BLIND to the rest of the
#    harness: seed.sh ran `docker run alpine:3.20` (a mutable tag, plus a package
#    installed from the network at run time) and nothing noticed. The scan now
#    covers every file in the directory, shell scripts included, so the claim is
#    true of the whole harness rather than of one file.
note "image digest pinning (every file under $conf)"

# 4a. Every compose image var resolves to a digest pin in SUITE_VERSION.
for var in $(grep -oE '\$\{[A-Z_]+_IMAGE' "$conf/docker-compose.yml" | tr -d '${' | sort -u); do
    line="$(grep -E "^${var}=" "$conf/SUITE_VERSION" || true)"
    if [ -z "$line" ]; then
        echo "conformance-check: compose image \$$var is not pinned in SUITE_VERSION"; fail=1
    elif ! printf '%s' "$line" | grep -q '@sha256:'; then
        echo "conformance-check: $var is not pinned BY DIGEST (needs @sha256:)"; fail=1
    fi
done

# 4b. No YAML `image:` key anywhere under the harness may use a literal tag. A
#     value that does not start with a compose variable is a literal reference,
#     and a literal reference must carry a digest.
literal_images="$(grep -rEn '^[[:space:]]*image:[[:space:]]+[^$[:space:]]' "$conf" \
    | grep -v '@sha256:' || true)"
if [ -n "$literal_images" ]; then
    echo "conformance-check: an image: key uses a literal (non-digest) reference:"
    printf '%s\n' "$literal_images"
    fail=1
fi

# 4c. No `docker run` anywhere under the harness may execute an un-pinned image.
#     A container that runs inside the gate lane is code the gate trusts, so it is
#     pinned exactly like every other image.
docker_runs="$(grep -rEn 'docker[[:space:]]+run([[:space:]]|$)' "$conf" \
    | grep -v '@sha256:' || true)"
if [ -n "$docker_runs" ]; then
    echo "conformance-check: a 'docker run' uses an un-pinned (non-digest) image:"
    printf '%s\n' "$docker_runs"
    echo "conformance-check: pin it by digest, or do not run a container here."
    fail=1
fi

# 5. The runner's plan config must be GENERATABLE from the matrix, with the right
#    shape. run-conformance.sh hands this file to the OIDF runner; it used to be
#    referenced but never produced, so a live run would have died on a missing
#    file with nothing catching it beforehand. Rendering it on every PR makes that
#    a RED STATIC CHECK instead of a latent runtime failure.
if [ "$have_yaml" -eq 1 ]; then
    note "plan config generates from the matrix, with the right shape"
    if [ ! -f "$conf/gen-plan-config.py" ]; then
        echo "conformance-check: $conf/gen-plan-config.py is MISSING"; fail=1
    fi
    tmp_cfg="$(mktemp -d)"
    trap 'rm -rf "$tmp_cfg"' EXIT
    python3 - "$conf" "$tmp_cfg" <<'PY' || fail=1
import json, os, subprocess, sys
import yaml

conf, tmp = sys.argv[1], sys.argv[2]
matrix = yaml.safe_load(open(f"{conf}/profile-matrix.yaml"))
env = dict(os.environ)
# The generator refuses to render without the login credential in the
# environment (the password is deliberately not written into the matrix), so
# supply the throwaway cert value for this shape check.
env.setdefault(matrix["op"]["login"]["password_env"], "conformance-cert-password")

enabled = [p for p in matrix["profiles"] if p.get("enabled")]
for profile in enabled:
    out = os.path.join(tmp, f"{profile['id']}.json")
    subprocess.run(
        [sys.executable, "gen-plan-config.py", "--profile", profile["id"], "--out", out],
        cwd=conf, env=env, check=True,
    )
    with open(out, encoding="utf-8") as handle:
        config = json.load(handle)
    for key in ("alias", "description", "server", "client", "browser", "variant"):
        assert key in config, f"{profile['id']}: plan config is missing '{key}'"
    issuer = matrix["op"]["issuer"]
    assert config["server"]["issuer"] == issuer, f"{profile['id']}: issuer drifted"
    assert config["server"]["discoveryUrl"] == matrix["op"]["well_known"][0], (
        f"{profile['id']}: discoveryUrl is not the matrix well_known form"
    )
    assert config["variant"] == dict(profile.get("variant", {})), (
        f"{profile['id']}: the variant block does not match the matrix"
    )
    # The plan spec the runner is actually invoked with must name the plan.
    spec = subprocess.run(
        [sys.executable, "gen-plan-config.py", "--profile", profile["id"], "--print-plan"],
        cwd=conf, env=env, check=True, capture_output=True, text=True,
    ).stdout.strip()
    assert spec.startswith(profile["id"]), f"{profile['id']}: bad plan spec {spec}"

# A DISABLED profile must never render a config: it is never driven.
disabled = [p for p in matrix["profiles"] if not p.get("enabled")]
if disabled:
    probe = subprocess.run(
        [sys.executable, "gen-plan-config.py", "--profile", disabled[0]["id"],
         "--out", os.path.join(tmp, "should-not-exist.json")],
        cwd=conf, env=env, capture_output=True, text=True,
    )
    assert probe.returncode != 0, (
        f"gen-plan-config rendered a config for the DISABLED profile {disabled[0]['id']}"
    )
print(f"plan config ok: {len(enabled)} enabled profiles render a valid config")
PY
else
    note "PyYAML absent: plan-config generation check skipped (CI installs PyYAML)"
fi

# 5b. The committed Argon2id hash for the cert user. seed.sh installs this instead
#     of computing one inside a network container; the Rust test
#     crates/ironauth-oidc/tests/conformance_seed.rs proves it actually verifies
#     against the committed password with the product's real verifier.
note "committed cert password hash"
if ! grep -q '^\$argon2id\$' "$conf/cert-user-password.phc" 2>/dev/null; then
    echo "conformance-check: $conf/cert-user-password.phc is missing or is not an Argon2id PHC string"
    fail=1
fi

# 6. Cert-only downgrade confinement (fast complement to the Rust test).
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
# registration_mode = "open" is ANONYMOUS (unauthenticated) DCR: one of the very
# downgrades the cert config turns on, so it belongs in the confinement set. It is
# a string rather than a bool, so it needs its own comparison.
grep -Eq '^[[:space:]]*registration_mode[[:space:]]*=[[:space:]]*"open"' "$cert" \
    || { echo "conformance-check: cert config must set registration_mode = \"open\""; fail=1; }
if grep -Eq '^[[:space:]]*registration_mode[[:space:]]*=[[:space:]]*"open"' "$default"; then
    echo "conformance-check: DEFAULT config must NOT set registration_mode = \"open\" (open DCR leaked)"
    fail=1
fi

# 7. The harness cannot fail OPEN.
note "fail-closed wiring"
# 7a. --allow-missing-runner is a LOCAL dry-run flag: it drives zero plans and
#     still exits 0. run-conformance.sh refuses it when CI=true; this makes even
#     writing it into a workflow a red check.
if grep -rn -- '--allow-missing-runner' .github/workflows/ >/dev/null 2>&1; then
    echo "conformance-check: a workflow passes --allow-missing-runner. That flag drives"
    echo "conformance-check: NO plan and must never appear in CI (it is a local dry run)."
    fail=1
fi
# 7b. bash 3.2 portability: mapfile/readarray are bash 4 only, stock macOS ships
#     3.2, and the one-command local reproduction is an acceptance criterion of
#     this issue. (mapfile also swallowed the selector's exit status, which is how
#     a crashed selector could read as a pass.)
# The pattern skips comment lines, so run-conformance.sh can still EXPLAIN why it
# does not use mapfile without tripping its own check.
if grep -qE '^[^#]*(mapfile|readarray)' "$conf/run-conformance.sh"; then
    echo "conformance-check: run-conformance.sh uses mapfile/readarray (bash 4 only)."
    echo "conformance-check: stock macOS bash is 3.2; use a portable read loop."
    fail=1
fi

# 8. Compose config parses, only when docker is available.
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
