#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# A workload obtains an IronAuth access token from its AMBIENT OIDC token, with zero stored
# secrets (issue #126 criterion 1).
#
# The criterion names GitHub Actions specifically, and the reason it names a JOB rather than a
# fixture is the part worth testing: an Actions job holds no secret at all. It asks the runner
# for a token, and everything after that has to work from a signature the deployment can verify
# against a key set it has never seen before. A test that mints its own GitHub-SHAPED token
# proves the mapping logic and cannot prove that.
#
# Driven by environment so CI and a local run differ only in their inputs:
#
#   IRONAUTH_EXTERNAL_ISSUER    the workload platform's issuer  (required)
#   IRONAUTH_EXTERNAL_SUBJECT   the `sub` to map                (required)
#   IRONAUTH_ASSERTION          the ambient token itself        (required)
#   IRONAUTH_EXTERNAL_JWKS_URI  where the platform publishes its keys, OR
#   IRONAUTH_EXTERNAL_JWKS      an inline key set (a local run, where a loopback jwks_uri
#                               would be refused by the SSRF guard -- correctly)
#
# ZERO STORED SECRETS is asserted rather than described: the presenting client is the seeded
# PUBLIC client, which has no secret to store, and the only credential in the whole exchange is
# the assertion the platform minted moments ago.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

if [ -z "${IRONAUTH_EXTERNAL_JWKS_URI:-}" ] && [ -z "${IRONAUTH_EXTERNAL_JWKS:-}" ]; then
    echo "workload-github: set IRONAUTH_EXTERNAL_JWKS_URI or IRONAUTH_EXTERNAL_JWKS" >&2
    exit 1
fi

WORK="$(mktemp -d -t ironauth-workload-XXXXXX)"
cleanup() {
    if [ -f "${WORK}/emulator.pid" ]; then
        kill "$(cat "${WORK}/emulator.pid")" 2>/dev/null || true
    fi
    rm -rf "${WORK}"
}
trap cleanup EXIT

echo "workload-github: starting the emulator"
cargo run --quiet -p ironauth --bin ironauth -- dev --bind 127.0.0.1:18134 --seed 1 \
    > "${WORK}/emulator.log" 2>&1 &
echo $! > "${WORK}/emulator.pid"

ISSUER=""
for _ in $(seq 1 900); do
    if ! kill -0 "$(cat "${WORK}/emulator.pid")" 2>/dev/null; then
        echo "workload-github: the emulator exited before serving; its log:" >&2
        tail -20 "${WORK}/emulator.log" >&2
        exit 1
    fi
    ISSUER=$(grep -o 'issuer http://[^ ]*' "${WORK}/emulator.log" 2>/dev/null | head -1 | sed 's/issuer //' || true)
    if [ -n "${ISSUER}" ] && curl -sf -o /dev/null "${ISSUER}/.well-known/openid-configuration"; then
        break
    fi
    sleep 0.2
done

CLIENT_ID=$(grep -o 'client_id [^ ]*' "${WORK}/emulator.log" | head -1 | sed 's/client_id //' || true)
IDENTITY=$(grep -o 'machine identity [^ ]*' "${WORK}/emulator.log" | head -1 | sed 's/machine identity //' || true)
MANAGEMENT=$(grep -o 'server.management.addr":"Some(127.0.0.1:[0-9]*' "${WORK}/emulator.log" \
    | head -1 | grep -oE '127.0.0.1:[0-9]+' || true)
TENANT=$(printf '%s' "${ISSUER}" | sed -E 's#.*/t/([^/]+)/e/.*#\1#')
ENVIRONMENT=$(printf '%s' "${ISSUER}" | sed -E 's#.*/e/([^/]+)$#\1#')
if [ -z "${ISSUER}" ] || [ -z "${CLIENT_ID}" ] || [ -z "${IDENTITY}" ] || [ -z "${MANAGEMENT}" ]; then
    echo "workload-github: the emulator never reported everything this needs" >&2
    tail -20 "${WORK}/emulator.log" >&2
    exit 1
fi
BASE="http://${MANAGEMENT}/v1/tenants/${TENANT}/environments/${ENVIRONMENT}"
OPERATOR='authorization: Bearer ironauth-dev-operator-token-not-for-production'

# THE AMBIENT TOKEN, fetched HERE rather than by the caller, because its `aud` has to be the
# issuer this emulator just generated. A caller could not have known that value before the
# server started, which is the ordering problem that made the first version of this script take
# the assertion as an input and then need the audience to have been guessed.
if [ -z "${IRONAUTH_ASSERTION:-}" ]; then
    if [ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] || [ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]; then
        echo "workload-github: no IRONAUTH_ASSERTION, and no GitHub Actions OIDC token to ask for." >&2
        echo "  In Actions this needs 'permissions: id-token: write'. Outside it, set" >&2
        echo "  IRONAUTH_ASSERTION to a token some platform minted for this audience." >&2
        exit 1
    fi
    # ZERO STORED SECRETS: this is the whole point. The runner hands the job a token because
    # of WHO IT IS, and nothing in this repository holds a credential for it.
    IRONAUTH_ASSERTION=$(curl -sf \
        -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
        "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "${ISSUER}")" \
        | python3 -c 'import json,sys;print(json.load(sys.stdin)["value"])')
    echo "workload-github: obtained the runner's ambient OIDC token"
fi

# ITS OWN CLAIMS decide what gets registered. An operator does not invent the issuer and
# subject; they read them off the platform's token, which is what this does.
CLAIMS=$(printf '%s' "${IRONAUTH_ASSERTION}" | python3 -c '
import base64, json, sys
payload = sys.stdin.read().strip().split(".")[1]
payload += "=" * (-len(payload) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(payload))))')
IRONAUTH_EXTERNAL_ISSUER="${IRONAUTH_EXTERNAL_ISSUER:-$(printf '%s' "${CLAIMS}" | python3 -c 'import json,sys;print(json.load(sys.stdin)["iss"])')}"
IRONAUTH_EXTERNAL_SUBJECT="${IRONAUTH_EXTERNAL_SUBJECT:-$(printf '%s' "${CLAIMS}" | python3 -c 'import json,sys;print(json.load(sys.stdin)["sub"])')}"
export IRONAUTH_EXTERNAL_ISSUER IRONAUTH_EXTERNAL_SUBJECT
echo "workload-github: the workload identifies as ${IRONAUTH_EXTERNAL_SUBJECT} at ${IRONAUTH_EXTERNAL_ISSUER}"

# THE TRUST ANCHOR. Everything an operator has to say about a platform they do not run: who it
# claims to be, and where its keys are.
if [ -n "${IRONAUTH_EXTERNAL_JWKS_URI:-}" ]; then
    ANCHOR=$(printf '{"issuer":"%s","jwks_uri":"%s"}' "${IRONAUTH_EXTERNAL_ISSUER}" "${IRONAUTH_EXTERNAL_JWKS_URI}")
else
    # The inline key set travels as a STRING, not as a nested object: the surface stores the
    # document verbatim so the bytes an operator registered are the bytes verified against.
    ANCHOR=$(python3 -c '
import json, os
print(json.dumps({
    "issuer": os.environ["IRONAUTH_EXTERNAL_ISSUER"],
    "jwks": os.environ["IRONAUTH_EXTERNAL_JWKS"],
}))')
fi
STATUS=$(curl -s -o "${WORK}/anchor.json" -w '%{http_code}' -X POST "${BASE}/external-issuers" \
    -H "${OPERATOR}" -H 'content-type: application/json' -H 'Idempotency-Key: workload-anchor' \
    -d "${ANCHOR}")
if [ "${STATUS}" != "201" ]; then
    echo "workload-github: registering the trust anchor answered ${STATUS}:" >&2
    cat "${WORK}/anchor.json" >&2
    exit 1
fi
echo "workload-github: trust anchor registered for ${IRONAUTH_EXTERNAL_ISSUER}"

# THE SUBJECT MAPPING. Which external workload is which local principal. Nothing is
# auto-provisioned: a subject with no mapping gets no token, which is the property
# `an_unmapped_subject_is_rejected_and_never_auto_provisioned` pins.
MAPPING=$(IRONAUTH_IDENTITY="${IDENTITY}" python3 -c '
import json, os
print(json.dumps({
    "issuer": os.environ["IRONAUTH_EXTERNAL_ISSUER"],
    "external_subject": os.environ["IRONAUTH_EXTERNAL_SUBJECT"],
    "principal": os.environ["IRONAUTH_IDENTITY"],
}))')
STATUS=$(curl -s -o "${WORK}/mapping.json" -w '%{http_code}' \
    -X POST "${BASE}/subject-mappings" \
    -H "${OPERATOR}" -H 'content-type: application/json' -H 'Idempotency-Key: workload-mapping' \
    -d "${MAPPING}")
if [ "${STATUS}" != "201" ]; then
    echo "workload-github: mapping the subject answered ${STATUS}:" >&2
    cat "${WORK}/mapping.json" >&2
    exit 1
fi
echo "workload-github: ${IRONAUTH_EXTERNAL_SUBJECT} mapped to ${IDENTITY}"

# THE EXCHANGE. The public client presents the ambient assertion; no secret anywhere.
# FROM DISCOVERY, never `${ISSUER}/token`. An IronAuth issuer carries a per-environment path
# while its endpoints sit at the host root, so concatenation builds a URL that 404s -- which is
# exactly what this script did on its first run, and the same defect the BFF shipped with.
TOKEN_ENDPOINT=$(curl -sf "${ISSUER}/.well-known/openid-configuration" \
    | python3 -c 'import json,sys;print(json.load(sys.stdin)["token_endpoint"])')
STATUS=$(curl -s -o "${WORK}/token.json" -w '%{http_code}' -X POST "${TOKEN_ENDPOINT}" \
    --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' \
    --data-urlencode "assertion=${IRONAUTH_ASSERTION}" \
    --data-urlencode "client_id=${CLIENT_ID}")
if [ "${STATUS}" != "200" ]; then
    echo "workload-github: the exchange answered ${STATUS}:" >&2
    cat "${WORK}/token.json" >&2
    exit 1
fi

IRONAUTH_IDENTITY="${IDENTITY}" python3 - "${WORK}/token.json" <<'PY'
import base64, json, os, sys

tokens = json.load(open(sys.argv[1], encoding="utf-8"))
access = tokens.get("access_token")
if not access:
    sys.exit(f"the exchange returned no access token: {sorted(tokens)}")

# THE TOKEN IS THE MAPPED IDENTITY, not the presenting client. Without this the whole run
# would pass against a grant that ignored the mapping and resolved the presenter instead --
# which is the exact defect `workload_federation.rs` records having measured.
payload = access.split(".")[1]
payload += "=" * (-len(payload) % 4)
claims = json.loads(base64.urlsafe_b64decode(payload))
expected = os.environ["IRONAUTH_IDENTITY"]
if claims.get("sub") != expected:
    sys.exit(f"the token was issued as {claims.get('sub')}, not the mapped identity {expected}")
print(f"workload-github: exchanged for an access token as {expected}")
PY

echo "workload-github: OK"
