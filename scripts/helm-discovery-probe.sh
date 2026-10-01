#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# One GET through the disposable Helm job's public Service. Keep the HTTP response
# separate from kubectl's attach/deletion messages and preserve failed evidence.
set -euo pipefail

: "${TENANT:?bootstrapped tenant is required}"
: "${ENVIRONMENT:?bootstrapped environment is required}"
: "${EXPECTED_PUBLIC_URL:?configured public URL is required}"
namespace=default
probe="ironauth-discovery-${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:?}"
evidence=target/helm-discovery
mkdir -p "$evidence"
uid=

kube() { kubectl --request-timeout=15s "$@"; }

cleanup() {
  result=$?
  trap - EXIT
  if [ -n "$uid" ]; then
    kube get pod "$probe" -n "$namespace" -o json >"$evidence/pod.final.json" 2>"$evidence/pod-final.stderr" || true
    printf '{"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"uid":"%s"}}\n' "$uid" >"$evidence/delete-options.json"
    if ! kube delete --raw "/api/v1/namespaces/$namespace/pods/$probe" -f "$evidence/delete-options.json" >"$evidence/delete.json" 2>"$evidence/delete.stderr"; then
      echo "discovery probe cleanup failed; retained the UID and response evidence" >&2
      result=1
    fi
  fi
  printf '%s\n' "$result" >"$evidence/probe-exit.txt"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Create refuses a pre-existing name. The deadline is a backstop if this runner is
# lost; the normal EXIT trap deletes only the UID returned by this create.
kube run "$probe" -n "$namespace" --restart=Never --image=curlimages/curl:8.10.1 \
  --overrides='{"spec":{"activeDeadlineSeconds":180,"automountServiceAccountToken":false}}' \
  --command --dry-run=client -o json -- sh -c 'sleep 150' >"$evidence/pod.request.json"
kube create -f "$evidence/pod.request.json" -o json >"$evidence/pod.created.json"
uid=$(jq -er '.metadata.uid | select(type == "string" and length > 0)' "$evidence/pod.created.json")
kubectl --request-timeout=65s wait -n "$namespace" --for=condition=Ready "pod/$probe" --timeout=60s >"$evidence/ready.txt" 2>"$evidence/ready.stderr"
current_uid=$(kube get pod "$probe" -n "$namespace" -o jsonpath='{.metadata.uid}')
test "$current_uid" = "$uid"

# Exactly one request: HTTP refusal, curl failure, and lost output stay failures.
# curl writes only bounded public discovery metadata, never credentials or config.
set +e
# Expand the curl argument and exit code inside the probe Pod, not this shell.
# shellcheck disable=SC2016
kube exec -n "$namespace" "$probe" -- sh -c '
  curl --silent --show-error --connect-timeout 2 --max-time 10 --max-filesize 65536 \
    --dump-header /tmp/discovery.headers --output /tmp/discovery.body \
    --write-out "%{http_code}\n" "$1" \
    >/tmp/discovery.status 2>/tmp/discovery.curl-stderr
  code=$?
  printf "%s\n" "$code" >/tmp/discovery.curl-exit
' sh "http://ironauth:8443/t/$TENANT/e/$ENVIRONMENT/.well-known/openid-configuration" \
  >"$evidence/exec.stdout" 2>"$evidence/exec.stderr"
exec_exit=$?
printf '%s\n' "$exec_exit" >"$evidence/exec-exit.txt"
capture_failed=0
for part in headers body status curl-exit curl-stderr; do
  kube exec -n "$namespace" "$probe" -- cat "/tmp/discovery.$part" \
    >"$evidence/$part" 2>"$evidence/$part.capture-stderr"
  captured=$?
  printf '%s=%s\n' "$part" "$captured" >>"$evidence/capture-status.txt"
  if [ "$captured" -ne 0 ]; then capture_failed=1; fi
done
set -e
test "$exec_exit" -eq 0
test "$capture_failed" -eq 0
test "$(cat "$evidence/curl-exit")" = 0
test "$(cat "$evidence/status")" = 200
base=${EXPECTED_PUBLIC_URL%/}
issuer="$base/t/$TENANT/e/$ENVIRONMENT"
jq -s -e --arg base "$base" --arg issuer "$issuer" '
  length == 1 and (.[0] | type == "object" and .issuer == $issuer and
  .jwks_uri == ($issuer + "/jwks.json") and
  .authorization_endpoint == ($base + "/authorize") and
  .token_endpoint == ($base + "/token"))
' "$evidence/body" >"$evidence/assertions.txt"
echo "discovery answered with the exact bootstrapped issuer and endpoints"
