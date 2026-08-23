#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Drive a COMPLETE RFC 8628 device authorization against the emulator, offline (issue #120).
#
# WHAT THIS DOES AND DOES NOT COVER. It exercises the SERVER side of the headless login: the
# grant starts, the code is approved from a second device, and a token is issued. It does NOT
# run `ironauth login`, which criterion 1 names, and that is not an omission I can close here:
# the CLI builds its endpoints by appending `/device_authorization` and `/token` to `--issuer`
# (crates/ironauth/src/login.rs:310 and :356), while both routes are served at the DEPLOYMENT
# ROOT and an IronAuth issuer is scoped (`.../t/{tenant}/e/{environment}`). Feeding the CLI
# the issuer this very emulator prints therefore answers HTTP 404. Measured, and reported on
# the issue. The fix is discovery-based endpoint resolution in the CLI, which needs a GET
# helper the shared apply client does not have, so it is its own change.
#
# The device grant is the one flow whose whole premise is that the device cannot open a
# browser, so a test that drives it through a browser proves nothing about the case it exists
# for. This script never opens one: it starts the grant, approves the user code over the
# emulator's own approval surface as the "second device" would, and then polls the token
# endpoint exactly as a conforming client does.
#
# It asserts the POLL SEQUENCE and not just the final token. A grant that returned a token
# immediately would satisfy an end-state check while breaking the contract every RFC 8628
# client is written against, which is `authorization_pending` until approval and a token
# after. Both halves are checked here.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

PORT="${PORT:-18120}"
SEED="${SEED:-1}"
BIN="${BIN:-./target/debug/ironauth}"
LOG="$(mktemp -t ironauth-device-XXXXXX)"
COOKIE_JAR="$(mktemp -t ironauth-device-jar-XXXXXX)"

if [ ! -x "$BIN" ]; then
  echo "dev-device-login: $BIN is not built. Run: cargo build -p ironauth --bin ironauth" >&2
  exit 1
fi

# ONE handler for everything. `trap ... EXIT` REPLACES any previous EXIT trap rather than
# adding to it, so a second `trap` for the cookie jar would silently drop this one and leave
# the emulator, and the throwaway Postgres cluster it brought up, running after every run.
cleanup() {
  [ -n "${DEV_PID:-}" ] && kill "$DEV_PID" 2>/dev/null
  sleep 2
  rm -f "$LOG" "$COOKIE_JAR"
}
trap cleanup EXIT INT TERM

env -u DATABASE_URL "$BIN" dev --bind "127.0.0.1:${PORT}" --seed "$SEED" > "$LOG" 2>&1 &
DEV_PID=$!

issuer=""
client_id=""
operator=""
for _ in $(seq 1 300); do
  if ! kill -0 "$DEV_PID" 2>/dev/null; then
    echo "dev-device-login: the emulator exited before serving. Log:" >&2
    tail -20 "$LOG" >&2
    exit 1
  fi
  [ -z "$issuer" ] && issuer=$(grep -o 'issuer http://[^ ]*' "$LOG" 2>/dev/null | head -1 | sed 's/issuer //')
  [ -z "$client_id" ] && client_id=$(grep -o 'client_id [^ ]*' "$LOG" 2>/dev/null | head -1 | sed 's/client_id //')
  [ -z "$operator" ] && operator=$(grep -o 'operator token [^ ]*' "$LOG" 2>/dev/null | head -1 | sed 's/operator token //')
  if [ -n "$issuer" ] && curl -sf -o /dev/null "${issuer}/.well-known/openid-configuration"; then
    break
  fi
  sleep 0.1
done

if [ -z "$issuer" ] || [ -z "$client_id" ]; then
  echo "dev-device-login: emulator never reported an issuer and a client. Log:" >&2
  tail -20 "$LOG" >&2
  exit 1
fi

# The protocol endpoints live at the DEPLOYMENT ROOT while the verification page is scoped, so
# both bases are needed. `/device_authorization` resolves the tenant and environment from the
# client id rather than from the path, and `/token` from the device code it is handed, which is
# what lets a headless device hold one URL.
base="${issuer%/t/*}"

# 1. START the grant, as the headless device does. A public client, so no secret travels.
#
#    `openid` IS requested, because a CLI login wants an identity token and nothing refuses it:
#    the sensitive denylist is `offline_access`, `admin` and `management`, and the
#    unverified-sensitive-scope gate additionally needs a QUARANTINED client, which the seeded
#    one is not. An earlier revision sent no scope and explained that with that gate, which
#    cannot fire here. What actually refused this flow before was the third-party
#    admin-consent gate, and it is scope-independent: dropping the scope never helped, and
#    classifying the seeded client first-party is what fixed it.
start=$(curl -s --max-time 20 -X POST "${base}/device_authorization" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "client_id=${client_id}" --data-urlencode 'scope=openid')

device_code=$(printf '%s' "$start" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("device_code",""))' 2>/dev/null)
user_code=$(printf '%s' "$start" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("user_code",""))' 2>/dev/null)
# The server's own advertised polling floor, honoured rather than guessed. RFC 8628 lets the
# endpoint answer `slow_down` to a client that polls faster than `interval`, and it does: a
# script that ignored this would fail here for a reason that has nothing to do with the flow.
interval=$(printf '%s' "$start" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("interval",5))' 2>/dev/null)

if [ -z "$device_code" ] || [ -z "$user_code" ]; then
  echo "dev-device-login: the grant did not start. Response: ${start}" >&2
  echo "  unauthorized_client here means the seeded client lacks the device_code grant." >&2
  exit 1
fi

# 2. POLL BEFORE APPROVAL. This must be `authorization_pending`, and asserting it is the
#    point: a grant that issued a token here would pass an end-state check while breaking
#    every RFC 8628 client, which polls precisely because it expects to be told to wait.
pending=$(curl -s --max-time 20 -X POST "${base}/token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
  --data-urlencode "device_code=${device_code}" --data-urlencode "client_id=${client_id}")
pending_error=$(printf '%s' "$pending" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("error",""))' 2>/dev/null)

if [ "$pending_error" != "authorization_pending" ]; then
  echo "dev-device-login: expected authorization_pending before approval, got: ${pending}" >&2
  exit 1
fi

# 3. APPROVE, as the user does on their SECOND device: sign in, then walk the verification
#    page. There is no operator shortcut and deliberately so, because the cross-device BCP
#    requires an explicit human approval and the page enforces it. Merely opening the
#    prefilled link does not resolve the code; the confirmation carries a per-flow handle
#    that has to come back with the decision.
device_path="${issuer}/device"
# `return_to` is REQUIRED, not decorative: the login handler parses it to recover which client
# the session is being established for, and refuses with 400 without one. Any valid resume
# target for the seeded client does, since the device approval that follows only needs the
# session cookie this establishes.
resume="/authorize?response_type=code&client_id=${client_id}&redirect_uri=${DEV_REDIRECT_URI:-http://127.0.0.1/callback}&scope=openid"
login_status=$(curl -s --max-time 20 -o /dev/null -w '%{http_code}' -c "$COOKIE_JAR" \
  -X POST "${base}/login" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "identifier=${DEV_USER:-dev@example.test}" \
  --data-urlencode "password=${DEV_PASSWORD:-dev-password-not-for-production}" \
  --data-urlencode "return_to=${resume}")
if [ "$login_status" != "200" ] && [ "$login_status" != "303" ] && [ "$login_status" != "302" ]; then
  echo "dev-device-login: the approving user could not sign in (${login_status})" >&2
  tail -20 "$LOG" >&2
  exit 1
fi

# Submit the user code to resolve it, and read the per-flow handle off the confirmation.
confirm=$(curl -s --max-time 20 -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
  -X POST "$device_path" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "user_code=${user_code}")
device_code_id=$(printf '%s' "$confirm" | python3 -c '
import re, sys
html = sys.stdin.read()
m = re.search(r"name=\"device_code_id\"[^>]*value=\"([^\"]+)\"", html) or \
    re.search(r"value=\"([^\"]+)\"[^>]*name=\"device_code_id\"", html)
print(m.group(1) if m else "")
')
if [ -z "$device_code_id" ]; then
  echo "dev-device-login: the confirmation page carried no flow handle." >&2
  echo "  This is what a signed-out approver also sees, so check the login above." >&2
  exit 1
fi

approve_status=$(curl -s --max-time 20 -o /dev/null -w '%{http_code}' -b "$COOKIE_JAR" \
  -X POST "$device_path" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode 'decision=allow' \
  --data-urlencode "device_code_id=${device_code_id}" \
  --data-urlencode "user_code=${user_code}")
if [ "$approve_status" != "200" ]; then
  echo "dev-device-login: approval answered ${approve_status}" >&2
  tail -20 "$LOG" >&2
  exit 1
fi

# 4. POLL AFTER APPROVAL, and get the token the CLI would store. Waiting out the advertised
#    interval first, exactly as a conforming client does between polls.
sleep "$((interval + 1))"
issued=$(curl -s --max-time 20 -X POST "${base}/token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
  --data-urlencode "device_code=${device_code}" --data-urlencode "client_id=${client_id}")
access_token=$(printf '%s' "$issued" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null)

if [ -z "$access_token" ]; then
  echo "dev-device-login: no access token after approval. Response: ${issued}" >&2
  exit 1
fi

# The ID token. Asserted because it is the half a CLI login stores to know WHO signed in, and
# an access token alone would satisfy a token check while leaving the identity half
# unexercised. NOT attributed to the requested scope: `mint_device_tokens` emits it
# unconditionally on this endpoint, so `openid` is what a real client sends rather than what
# makes this field appear.
id_token=$(printf '%s' "$issued" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id_token",""))' 2>/dev/null)
if [ -z "$id_token" ]; then
  echo "dev-device-login: the device grant returned no id_token. Response: ${issued}" >&2
  exit 1
fi

echo "dev-device-login: OK (server-side device flow: pending before approval, token"
echo "                  after, approved from a second device, no browser involved)"
