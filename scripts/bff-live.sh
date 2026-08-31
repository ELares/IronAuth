#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The BFF against a REAL IronAuth (issue #116).
#
# # Why a live lane exists at all
#
# Every other test in `@ironauth/bff` answers from a fake, and a fake is written by the same
# person as the code, from the same understanding. It therefore agrees with the code's mistakes.
# The one in this package replied 200 to ANY url it was given, which is why two defects that made
# a real login impossible passed every test the package had:
#
#   1. endpoints were built by concatenation (`${issuer}/token`). An IronAuth issuer carries a
#      `/t/<tenant>/e/<environment>` path while its endpoints sit at the host root, so that URL
#      is a 404. MEASURED: 404 against the emulator, where the discovered endpoint answers.
#   2. no DPoP proof was ever sent. IronAuth's posture is DPoP-by-default for PUBLIC clients
#      (issue #124), and this BFF supports public clients, so the exchange was refused outright
#      with `invalid_dpop_proof`.
#
# Both are invisible to a fake and obvious to a real server. That is the whole argument for this
# lane: it is the only test here that neither the code's author nor the fake's author gets to
# define the answer to.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

BIND="127.0.0.1:${IRONAUTH_LIVE_PORT:-18141}"
WORK="$(mktemp -d -t ironauth-bff-live-XXXXXX)"
LOG="${WORK}/emulator.log"

cleanup() {
    if [ -f "${WORK}/emulator.pid" ]; then
        kill "$(cat "${WORK}/emulator.pid")" 2>/dev/null || true
    fi
    rm -rf "${WORK}"
}
trap cleanup EXIT

echo "bff-live: building the BFF"
(cd packages/ironauth-bff && npm run build >/dev/null)

echo "bff-live: starting the emulator on ${BIND}"
cargo run --quiet -p ironauth --bin ironauth -- dev --bind "${BIND}" --seed 1 > "${LOG}" 2>&1 &
echo $! > "${WORK}/emulator.pid"

# Waiting for the log line is NOT enough: it is printed while the listener is still coming up.
# The loop asks DISCOVERY to answer, which is true only once the server is serving, and checks
# the emulator is still alive each time round so a failed start is its own error immediately.
ISSUER=""
for _ in $(seq 1 900); do
    if ! kill -0 "$(cat "${WORK}/emulator.pid")" 2>/dev/null; then
        echo "bff-live: the emulator exited before serving; its log:" >&2
        tail -20 "${LOG}" >&2
        exit 1
    fi
    # `|| true` because of `pipefail`: until the emulator writes its banner the grep finds
    # nothing and exits 1, which under `set -e` aborts the whole script one iteration into a
    # loop whose entire purpose is to wait. Measured: the script exited silently every run.
    ISSUER=$(grep -o 'issuer http://[^ ]*' "${LOG}" 2>/dev/null | head -1 | sed 's/issuer //' || true)
    if [ -n "${ISSUER}" ] && curl -sf -o /dev/null "${ISSUER}/.well-known/openid-configuration"; then
        break
    fi
    sleep 0.2
done
CLIENT_ID=$(grep -o 'client_id [^ ]*' "${LOG}" | head -1 | sed 's/client_id //' || true)
if [ -z "${ISSUER}" ] || [ -z "${CLIENT_ID}" ]; then
    echo "bff-live: the emulator never reported an issuer and client" >&2
    tail -20 "${LOG}" >&2
    exit 1
fi

# The seeded client is PUBLIC (`token_endpoint_auth_method` of `none`), which is exactly the
# configuration that makes DPoP mandatory. Running the live lane against a confidential client
# would pass without any of this working.
echo "bff-live: driving a real login against ${ISSUER}"
node packages/ironauth-bff/live.mjs "${ISSUER}" "${CLIENT_ID}"
