#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The AppAuth mobile path, verified (issue #116 criterion 7).
#
# Two halves, and each proves something the other cannot:
#
#   BUILD    the Android sample assembles into a real APK against the real AppAuth library,
#            and the merged manifest carries the redirect scheme. A sample that does not
#            build is documentation of something that does not exist.
#
#   FLOW     the DOCUMENTED CONFIGURATION completes a real token exchange, in the shape
#            AppAuth sends it: a PUBLIC client, PKCE, a loopback redirect, and NO DPoP
#            PROOF. With a CONTROL: before the exemption is granted, the identical exchange
#            must be REFUSED. Without that control the flow half would pass on a server that
#            never required DPoP at all, and would prove nothing about the configuration the
#            guide tells people to apply.
#
# Why the exemption is needed at all: AppAuth has no DPoP support (measured -- unpack
# `net.openid:appauth` and grep its classes), IronAuth requires DPoP from public clients by
# default, and a mobile app is a public client.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

WORK="$(mktemp -d -t ironauth-mobile-XXXXXX)"
cleanup() {
    if [ -f "${WORK}/emulator.pid" ]; then
        kill "$(cat "${WORK}/emulator.pid")" 2>/dev/null || true
    fi
    rm -rf "${WORK}"
}
trap cleanup EXIT

# ---------------------------------------------------------------- the build half

if [ -z "${ANDROID_HOME:-}" ] && [ -z "${ANDROID_SDK_ROOT:-}" ]; then
    # A HARD failure, not a skip: a gate that prints "no SDK, skipping" is green on every
    # machine that cannot run it.
    echo "mobile-verify: no ANDROID_HOME or ANDROID_SDK_ROOT (install the Android SDK)" >&2
    exit 1
fi
GRADLE="${GRADLE_BIN:-gradle}"
if ! command -v "${GRADLE}" >/dev/null 2>&1; then
    echo "mobile-verify: no gradle on PATH (set GRADLE_BIN)" >&2
    exit 1
fi

echo "mobile-verify: building the Android sample"
(cd clients/mobile/android && "${GRADLE}" --no-daemon -q :app:assembleDebug)
APK="clients/mobile/android/app/build/outputs/apk/debug/app-debug.apk"
test -f "${APK}" || { echo "mobile-verify: no APK was produced" >&2; exit 1; }

# THE MERGED MANIFEST, not the source one. `appAuthRedirectScheme` is a placeholder the
# library's manifest interpolates, so the only place its value is observable is after the
# merge. Checking the source would check that we wrote the property, not that it reached the
# receiver that has to match it.
MERGED="clients/mobile/android/app/build/intermediates/merged_manifests/debug/processDebugMainManifest/AndroidManifest.xml"
if [ ! -f "${MERGED}" ]; then
    MERGED="$(find clients/mobile/android/app/build -name AndroidManifest.xml -path '*merged*' | head -1)"
fi
grep -q 'android:scheme="dev.ironauth.sample"' "${MERGED}" || {
    echo "mobile-verify: the merged manifest declares no dev.ironauth.sample redirect receiver" >&2
    exit 1
}
echo "mobile-verify: APK built, and the merged manifest carries the redirect scheme"

# ---------------------------------------------------------------- the iOS half, such as it is
#
# `swiftc -parse` and NOT a build, because building for iOS needs Xcode and this gate runs
# where the Android SDK is. Stated precisely because the difference matters: parsing catches
# syntax errors and nothing else -- it does not resolve `import AppAuth`, so it cannot tell you
# whether a method name is real or an argument label is right. The macOS CI lane compiles these
# files against the actual AppAuth package; this step is the cheap check that runs everywhere.
if command -v swiftc >/dev/null 2>&1; then
    swiftc -parse clients/mobile/ios/Sources/IronAuthSignIn/*.swift
    echo "mobile-verify: the iOS sources parse (SYNTAX only; the macOS lane compiles them)"
else
    echo "mobile-verify: no swiftc here, so the iOS sources are unchecked in this run"
fi

# ---------------------------------------------------------------- the flow half

echo "mobile-verify: starting the emulator"
cargo run --quiet -p ironauth --bin ironauth -- dev --bind 127.0.0.1:18136 --seed 1 \
    > "${WORK}/emulator.log" 2>&1 &
echo $! > "${WORK}/emulator.pid"

ISSUER=""
for _ in $(seq 1 900); do
    if ! kill -0 "$(cat "${WORK}/emulator.pid")" 2>/dev/null; then
        echo "mobile-verify: the emulator exited before serving; its log:" >&2
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
MANAGEMENT=$(grep -o 'server.management.addr":"Some(127.0.0.1:[0-9]*' "${WORK}/emulator.log" \
    | head -1 | grep -oE '127.0.0.1:[0-9]+' || true)
TENANT=$(printf '%s' "${ISSUER}" | sed -E 's#.*/t/([^/]+)/e/.*#\1#')
ENVIRONMENT=$(printf '%s' "${ISSUER}" | sed -E 's#.*/e/([^/]+)$#\1#')
if [ -z "${ISSUER}" ] || [ -z "${CLIENT_ID}" ] || [ -z "${MANAGEMENT}" ]; then
    echo "mobile-verify: the emulator never reported an issuer, client and management port" >&2
    tail -20 "${WORK}/emulator.log" >&2
    exit 1
fi

# THE CONTROL FIRST, on an unmodified client: no proof, no tokens.
echo "mobile-verify: the control -- an AppAuth-shaped exchange before the exemption"
STATUS=$(scripts/lib/mobile-flow.sh "${ISSUER}" "${CLIENT_ID}" "${WORK}" || true)
if [ "${STATUS}" = "200" ]; then
    echo "mobile-verify: an AppAuth-shaped exchange SUCCEEDED with no exemption and no proof." >&2
    echo "  The DPoP-by-default posture is not being enforced, so the rest of this gate would" >&2
    echo "  pass without proving anything about the documented configuration." >&2
    exit 1
fi
grep -q 'invalid_dpop_proof' "${WORK}/token.json" || {
    echo "mobile-verify: the control was refused, but not for the DPoP reason:" >&2
    cat "${WORK}/token.json" >&2
    exit 1
}
echo "mobile-verify: refused with invalid_dpop_proof, as the posture requires"

# NOW the documented configuration.
echo "mobile-verify: granting the per-client bearer exemption through the management API"
curl -sf -X PUT \
    "http://${MANAGEMENT}/v1/tenants/${TENANT}/environments/${ENVIRONMENT}/clients/${CLIENT_ID}/bearer-tokens" \
    -H 'authorization: Bearer ironauth-dev-operator-token-not-for-production' \
    -H 'content-type: application/json' \
    -d '{"allowed":true}' -o "${WORK}/grant.json"
grep -q '"allow_bearer_tokens":true' "${WORK}/grant.json" || {
    echo "mobile-verify: the grant did not take:" >&2
    cat "${WORK}/grant.json" >&2
    exit 1
}

echo "mobile-verify: the same exchange, with the exemption granted"
STATUS=$(scripts/lib/mobile-flow.sh "${ISSUER}" "${CLIENT_ID}" "${WORK}")
if [ "${STATUS}" != "200" ]; then
    echo "mobile-verify: the documented configuration still cannot complete a login:" >&2
    cat "${WORK}/token.json" >&2
    exit 1
fi
python3 - "${WORK}/token.json" <<'PY'
import json, sys

tokens = json.load(open(sys.argv[1], encoding="utf-8"))
for required in ("access_token", "id_token", "refresh_token"):
    if required not in tokens:
        sys.exit(f"the token response carries no {required}: {sorted(tokens)}")
# `Bearer` is the POINT here: the exemption is what makes an unbound token issuable, and a
# DPoP-typed response would mean something else granted this exchange.
if tokens.get("token_type") != "Bearer":
    sys.exit(f"expected an unbound Bearer token, got {tokens.get('token_type')}")
print("mobile-verify: signed in with an unbound Bearer token, exactly as AppAuth would")
PY

echo "mobile-verify: OK"
