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
for needle in ("IRONCACHE", "IRONBUS", "ironcache", "ironbus"):
    assert needle not in rendered, (
        f"the default install mentions {needle!r}: an accelerator that is off must be absent, "
        "not merely disabled"
    )
print("  default install: all assertions hold")
PY

# --- criterion 6, the other direction: enabled means wired -------------------
echo "helm-chart: rendering with the accelerators enabled"
ENABLED=$(helm template ironauth "$CHART" "${BASE[@]}" \
    --set ironcache.enabled=true --set ironcache.endpoint=cache.svc:6379 \
    --set ironbus.enabled=true --set ironbus.addr=bus.svc:4222)
python3 - "$ENABLED" <<'PY'
import sys, yaml
docs = [d for d in yaml.safe_load_all(sys.argv[1]) if d]
c = next(d for d in docs if d.get("kind") == "Deployment")["spec"]["template"]["spec"]["containers"][0]
env = {e["name"]: e.get("value") for e in c.get("env", [])}
assert env.get("IRONAUTH_IRONCACHE_ENDPOINT") == "cache.svc:6379", f"ironcache not wired: {env}"
assert env.get("IRONAUTH_IRONBUS_ADDR") == "bus.svc:4222", f"ironbus not wired: {env}"
print("  enabled install: both accelerators wired")
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
refuse "with ironcache enabled and no endpoint" "${BASE[@]}" --set ironcache.enabled=true
refuse "with ironbus enabled and no address" "${BASE[@]}" --set ironbus.enabled=true
echo "  four invalid configurations refused"

# --- the chart deploys the version it claims ---------------------------------
APP_VERSION=$(python3 -c "import yaml,sys; print(yaml.safe_load(open('$CHART/Chart.yaml'))['appVersion'])")
CRATE_VERSION=$(python3 - <<'PY'
import pathlib, re
text = pathlib.Path("Cargo.toml").read_text()
workspace = re.search(r"\[workspace\.package\](.*?)(\n\[|\Z)", text, re.S)
section = workspace.group(1) if workspace else text
match = re.search(r'^\s*version\s*=\s*"([^"]+)"', section, re.M)
print(match.group(1) if match else "")
PY
)
if [ -n "$CRATE_VERSION" ] && [ "$APP_VERSION" != "$CRATE_VERSION" ]; then
    fail "Chart.yaml appVersion is $APP_VERSION but the workspace is $CRATE_VERSION.
  A chart whose default image tag is not the release it ships with deploys a
  different build than it claims, which is the kind of drift nobody notices
  until the wrong version is serving."
fi

echo "helm-chart: clean"
