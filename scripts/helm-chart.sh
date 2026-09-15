#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The Helm chart gate (issue #151).
#
# `helm lint` checks that a chart is well formed. It says nothing about whether
# the chart deploys IronAuth CORRECTLY, and the properties that matter here are
# exactly the ones lint cannot see:
#
#   - the pod runs non-root with a read-only root filesystem and no capabilities
#     (criterion 2), so a template edit that drops one fails here rather than in
#     someone's cluster;
#   - the accelerators are ABSENT by default (criterion 6) -- not merely disabled
#     but rendering no endpoint, no environment variable, no dangling reference;
#   - the rendered config lands in a SECRET and not a ConfigMap, because
#     database.url carries the credential inline and the schema gives it no
#     environment indirection;
#   - the management plane has no Service, so health, readiness and metrics are
#     not published to every in-cluster caller;
#   - probes address the management port, which is the only place /healthz and
#     /readyz are served.
#
# Each assertion is made against RENDERED output, because a value is not a
# property: `readOnlyRootFilesystem: true` in values.yaml proves nothing if no
# template reads it.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

CHART=charts/ironauth

if ! command -v helm >/dev/null 2>&1; then
    echo "helm-chart: helm is not installed." >&2
    echo "  This gate renders the chart and asserts properties of the output; without helm it" >&2
    echo "  can assert nothing, and a check that passes by skipping is worse than no check." >&2
    echo "  Install helm (a single static binary: https://get.helm.sh) and re-run." >&2
    exit 1
fi

# Values every render needs. The chart refuses to render without them by design,
# which is itself asserted below.
BASE=(--set server.publicUrl=https://id.example.com
      --set database.url=postgres://ironauth:secret@pg:5432/ironauth)

fail() { echo "helm-chart: $*" >&2; exit 1; }

echo "helm-chart: helm lint"
helm lint "$CHART" "${BASE[@]}" >/dev/null || fail "helm lint failed"

echo "helm-chart: rendering the default install"
DEFAULT=$(helm template ironauth "$CHART" "${BASE[@]}")

# --- criterion 2: non-root, read-only root filesystem, no capabilities --------
python3 - "$DEFAULT" <<'PY'
import sys, yaml
docs = [d for d in yaml.safe_load_all(sys.argv[1]) if d]
deploys = [d for d in docs if d.get("kind") == "Deployment"]
assert len(deploys) == 1, f"expected one Deployment, got {len(deploys)}"
spec = deploys[0]["spec"]["template"]["spec"]

pod = spec.get("securityContext", {})
assert pod.get("runAsNonRoot") is True, "pod securityContext must set runAsNonRoot: true"
assert pod.get("runAsUser", 0) != 0, "pod must not run as uid 0"
assert pod.get("seccompProfile", {}).get("type") == "RuntimeDefault", "seccompProfile must be RuntimeDefault"

containers = spec["containers"]
assert len(containers) == 1, f"expected one container, got {len(containers)}"
c = containers[0]
sc = c.get("securityContext", {})
assert sc.get("readOnlyRootFilesystem") is True, "container must set readOnlyRootFilesystem: true"
assert sc.get("allowPrivilegeEscalation") is False, "container must set allowPrivilegeEscalation: false"
assert sc.get("privileged") is False, "container must not be privileged"
assert sc.get("capabilities", {}).get("drop") == ["ALL"], "container must drop ALL capabilities"

# A read-only root with nowhere to write is a pod that crashes on first use, so
# the writable mount is part of the property, not a detail.
mounts = {m["mountPath"] for m in c.get("volumeMounts", [])}
assert "/tmp" in mounts, "readOnlyRootFilesystem is set but /tmp is not writable"

# --- probes address the management plane -------------------------------------
mgmt = next((p for p in c["ports"] if p["name"] == "management"), None)
assert mgmt is not None, "no management port"
for probe, path in (("livenessProbe", "/healthz"), ("readinessProbe", "/readyz")):
    p = c.get(probe)
    assert p is not None, f"{probe} is missing"
    assert p["httpGet"]["port"] == "management", f"{probe} must address the management port"
    assert p["httpGet"]["path"] == path, f"{probe} must probe {path}"

# --- the config is a Secret, never a ConfigMap -------------------------------
assert not [d for d in docs if d.get("kind") == "ConfigMap"], (
    "the rendered config must not be a ConfigMap: database.url carries the credential inline"
)
secrets = [d for d in docs if d.get("kind") == "Secret"]
assert len(secrets) == 1, f"expected one Secret, got {len(secrets)}"
toml = secrets[0]["stringData"]["ironauth.toml"]
assert "postgres://ironauth:secret@pg:5432" in toml, "the DSN must reach the process in the config file"

# --- the management plane has no Service -------------------------------------
services = [d for d in docs if d.get("kind") == "Service"]
assert len(services) == 1, f"expected one Service, got {len(services)}"
ports = services[0]["spec"]["ports"]
assert all(p["targetPort"] != "management" for p in ports), (
    "the management plane must not be published through a Service"
)

# --- HA shape by default -----------------------------------------------------
assert deploys[0]["spec"]["replicas"] >= 2, "the default install must be multi-replica"
assert [d for d in docs if d.get("kind") == "PodDisruptionBudget"], "the default install needs a PDB"
assert spec.get("topologySpreadConstraints"), "replicas must be spread across nodes"

# --- criterion 6: accelerators ABSENT by default ------------------------------
rendered = sys.argv[1]
# THE PROTOCOL SURFACE IS OFF BY DEFAULT TOO, and for the same reason as the accelerators:
# a default install mounts nothing it was not asked to mount. Asserted in the config file
# rather than by a flag name, because `[oidc]` absent is what makes `oidc.enabled` false.
for needle in ("IRONBUS", "ironbus_addr", "[outbox]", "[oidc]",
              "bootstrap_operator_token", "IRONAUTH_BOOTSTRAP_OPERATOR_TOKEN"):
    assert needle not in rendered, (
        f"the default install mentions {needle!r}: an accelerator that is off must be absent, "
        "not merely disabled"
    )
# The chart must not offer an IronCache value, and the reason is narrower than it was.
#
# It used to be that the server had no config surface for IronCache at all. It has one now
# (`[hot_state] ironcache_addr`), and readiness reports the accelerator tier from it. What
# has not changed is that NO READ goes through the accelerator: `ironauth-hot` is not a
# dependency of any crate that serves a request. So a chart value would still configure
# something that accelerates nothing, which is what this assertion is for.
#
# The assertion is unchanged; only its justification is. Delete this check when a read path
# consults the accelerator AND the chart renders a [hot_state] section, not before.
for forbidden in ("ironcache", "IRONCACHE", "IronCache"):
    assert forbidden not in rendered, (
        f"the chart renders {forbidden!r}, but no read path consults the accelerator: "
        "ironauth-hot is not a dependency of any crate that serves a request, so a chart "
        "value would configure something that accelerates nothing"
    )
print("  default install: all assertions hold")
PY

# --- criterion 6, the other direction: enabled means wired -------------------
echo "helm-chart: rendering with IronBus enabled"
ENABLED=$(helm template ironauth "$CHART" "${BASE[@]}" \
    --set ironbus.enabled=true --set ironbus.addr=bus.svc:4222)
python3 - "$ENABLED" <<'PY'
import sys, yaml
docs = [d for d in yaml.safe_load_all(sys.argv[1]) if d]
# Asserted against the CONFIG FILE, not against an environment variable.
#
# The first version of this gate checked that the Deployment set
# IRONAUTH_IRONBUS_ADDR -- a name the chart itself invented and that nothing in the
# server reads. Config::from_toml_str is a plain toml::from_str with no environment
# overlay, so an env var named after a setting reaches nothing. The check passed by
# construction: its expectation came from the template it was checking.
toml = next(d for d in docs if d.get("kind") == "Secret")["stringData"]["ironauth.toml"]
assert "[outbox]" in toml, f"no [outbox] section in the rendered config:\n{toml}"
assert 'ironbus_addr = "bus.svc:4222"' in toml, f"ironbus_addr not set:\n{toml}"
PY

# --- the OIDC provider, both directions --------------------------------------
#
# This exists because the chart COULD NOT MOUNT THE PROVIDER AT ALL: values.yaml had no
# `oidc` key, so the rendered config never carried an `[oidc]` section, `oidc.enabled`
# stayed at its false default, and a chart install produced replicas that answered
# /healthz, /readyz and /metrics and served no protocol surface.
#
# Nothing caught it. This script asserted properties of what the chart DOES render, and
# the defect was a section it never rendered; the kind install job then reported three
# Ready replicas, because `/readyz` opens a TCP connection to the database and speaks no
# protocol. A gate that only checks what is present cannot see what is missing, so the
# absence is now named above and the presence is asserted here.
echo "helm-chart: rendering with the OIDC provider enabled"
OIDC=$(helm template ironauth "$CHART" "${BASE[@]}" --set oidc.enabled=true)
python3 - "$OIDC" <<'PY'
import sys, yaml
docs = [d for d in yaml.safe_load_all(sys.argv[1]) if d]
toml = next(d for d in docs if d.get("kind") == "Secret")["stringData"]["ironauth.toml"]
assert "[oidc]" in toml, f"no [oidc] section with oidc.enabled=true:\n{toml}"
assert "enabled = true" in toml, f"[oidc] present but not enabled:\n{toml}"

# NO ENVIRONMENT VARIABLE THE SERVER DOES NOT READ. Asserted on THIS render, where the chart
# is expected to set none, because that is the render where the property holds.
#
# A change to this file displaced these lines into the operator-token render, where the chart
# sets IRONAUTH_BOOTSTRAP_OPERATOR_TOKEN on purpose. The assertion then failed, and had it
# been "fixed" by widening the exclusion list it would have stopped asserting anything: an
# exclusion per variable is a list that grows to match whatever the chart happens to set.
c = next(d for d in docs if d.get("kind") == "Deployment")["spec"]["template"]["spec"]["containers"][0]
env = {e["name"] for e in (c.get("env") or []) if e["name"] != "IRONAUTH_MASTER_KEY"}
assert not env, (
    f"the chart sets {env}, but the server reads its configuration from the TOML file "
    "only. An environment variable named after a setting reaches nothing."
)
PY

# --- the operator credential never appears in rendered output -----------------
#
# The bootstrap operator token authorizes tenant CRUD, so it is the one credential a
# chart must never render. The config schema says so in its own words ("use the
# `file`/`env` secret indirection, never a literal"), and a chart that offered a literal
# would put an operator credential into `helm get manifest`, into any GitOps repository
# holding the values, and into every CI log that renders the chart.
#
# So the value names a SECRET and the assertions below are in three parts: the rendered
# config carries the indirection, the Deployment carries the env var pointing at the
# named Secret, and the TOKEN ITSELF appears nowhere. The third is the one that matters;
# the first two only describe the mechanism that makes it true.
echo "helm-chart: rendering with a bootstrap operator token"
# The sentinel goes in through a values path the chart does not read, so it is inert today
# and becomes the tripwire the moment one is added.
SENTINEL="SENTINEL-OPERATOR-TOKEN-MUST-NOT-RENDER"
BOOTSTRAP=$(helm template ironauth "$CHART" "${BASE[@]}" \
    --set admin.controlDatabaseUrl=postgres://ironauth_control@db/ironauth \
    --set admin.bootstrapOperatorToken.existingSecret=operator-credentials \
    --set admin.bootstrapOperatorToken.key=token \
    --set-string "admin.bootstrapOperatorToken.value=$SENTINEL")
python3 - "$BOOTSTRAP" "$SENTINEL" <<'PY'
import sys, yaml
rendered = sys.argv[1]
SENTINEL = sys.argv[2]
docs = [d for d in yaml.safe_load_all(rendered) if d]
toml = next(d for d in docs if d.get("kind") == "Secret")["stringData"]["ironauth.toml"]
assert 'bootstrap_operator_token = { env = "IRONAUTH_BOOTSTRAP_OPERATOR_TOKEN" }' in toml, (
    f"the config must carry the indirection, not a literal:\n{toml}"
)

deployment = next(d for d in docs if d.get("kind") == "Deployment")
container = deployment["spec"]["template"]["spec"]["containers"][0]
env = {e["name"]: e for e in container.get("env", [])}
ref = env.get("IRONAUTH_BOOTSTRAP_OPERATOR_TOKEN")
assert ref is not None, f"no env var for the token: {list(env)}"
source = ref["valueFrom"]["secretKeyRef"]
assert source["name"] == "operator-credentials", source
assert source["key"] == "token", source

# EXACTLY THE ONE INTENDED VARIABLE on this render, rather than "not none". A bare
# `assert ref is not None` would pass while the chart also set three others.
assert set(env) == {"IRONAUTH_BOOTSTRAP_OPERATOR_TOKEN"}, env

# THE ASSERTION THE OTHER TWO EXIST FOR, and the first version of it could not fail.
#
# It grepped the output for "bootstrapOperatorToken.value" and "op-secret". The first is a
# VALUES KEY PATH, and helm renders values, never key paths, so it cannot appear under any
# template. The second is a Rust unit-test literal that this render never supplies. Worse,
# the render passed no token literal at all, so there was nothing in the input that could
# have leaked into the output: vacuous on both axes, and it was the assertion the PR
# description called the important one.
#
# The sentinel below is supplied through the exact path a future author would add
# (`--set admin.bootstrapOperatorToken.value=...`). Today the chart ignores it and the
# sentinel cannot appear. The day someone renders that value into the config or the
# Deployment, this fails.
assert "operator-credentials" in rendered, "the Secret name is expected to appear"
assert SENTINEL not in rendered, (
    f"a token literal reached the rendered manifests: {SENTINEL!r} was supplied as "
    "admin.bootstrapOperatorToken.value and the chart rendered it. The operator credential "
    "must reach the process through the environment, never through a manifest."
)

PY

# --- the chart refuses configurations that cannot work -----------------------
echo "helm-chart: refusals"
refuse() {
    local description="$1"; shift
    if helm template ironauth "$CHART" "$@" >/dev/null 2>&1; then
        fail "the chart rendered $description, and should have refused"
    fi
}
refuse "without server.publicUrl" --set database.url=postgres://u@p/db
refuse "without a database" --set server.publicUrl=https://id.example.com
refuse "with ironbus enabled and no address" "${BASE[@]}" --set ironbus.enabled=true
echo "  three invalid configurations refused"

# --- the chart deploys the version it claims ---------------------------------
APP_VERSION=$(python3 -c "import yaml; print(yaml.safe_load(open('$CHART/Chart.yaml'))['appVersion'])")
# Read from the CRATE, because [workspace.package] has no version key: it carries only
# edition, rust-version, license and repository. The first version of this check looked
# there, got the empty string, and was skipped by its own `-n` guard on every run --
# while Chart.yaml and the README both claimed it was enforced. A bound satisfied by the
# empty string, guarding a claim made in two other files.
CRATE_VERSION=$(python3 - <<'PY'
import pathlib, re, sys
text = pathlib.Path("crates/ironauth/Cargo.toml").read_text()
package = re.search(r"\[package\](.*?)(\n\[|\Z)", text, re.S)
match = re.search(r'^\s*version\s*=\s*"([^"]+)"', package.group(1) if package else "", re.M)
if not match:
    sys.exit(1)
print(match.group(1))
PY
) || fail "could not read the version from crates/ironauth/Cargo.toml.
  Not skipped: a version check that cannot find a version must fail, or it passes
  every run while asserting nothing."
[ -n "$CRATE_VERSION" ] || fail "the version read from crates/ironauth/Cargo.toml is empty"
if [ "$APP_VERSION" != "$CRATE_VERSION" ]; then
    fail "Chart.yaml appVersion is $APP_VERSION but crates/ironauth is $CRATE_VERSION.
  The chart's default image tag falls back to appVersion, so a mismatch deploys a
  different build than the chart claims and labels the pods with the wrong version."
fi
echo "helm-chart: appVersion $APP_VERSION matches the crate"

echo "helm-chart: clean"
