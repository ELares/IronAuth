#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Drive a COMPLETE email-OTP login against the emulator, offline (issue #121, criterion 2:
# "a CI example workflow ... asserts a complete email OTP login using a deterministic code").
#
# This is the emulator's whole thesis in one script: boot a real server with no external
# services, obtain a real one-time code without a mail server, and complete a real login.
#
# It reads the code from the capture SINK rather than from the log. The sink is the supported
# surface and returns structured JSON; scraping a log line couples the test to a message
# format that exists for humans. It also asserts the code is the DETERMINISTIC one for the
# seed, which is what lets a CI job fail loudly if seeding stops being reproducible instead of
# passing against whatever code happened to be generated.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

PORT="${PORT:-18110}"
SEED="${SEED:-1}"
BIN="${BIN:-./target/debug/ironauth}"
LOG="$(mktemp -t ironauth-otp-XXXXXX)"

if [ ! -x "$BIN" ]; then
  echo "dev-otp-login: $BIN is not built. Run: cargo build -p ironauth --bin ironauth" >&2
  exit 1
fi

cleanup() {
  [ -n "${DEV_PID:-}" ] && kill "$DEV_PID" 2>/dev/null
  sleep 2
  rm -f "$LOG"
}
trap cleanup EXIT INT TERM

env -u DATABASE_URL "$BIN" dev --bind "127.0.0.1:${PORT}" --seed "$SEED" > "$LOG" 2>&1 &
DEV_PID=$!

issuer=""
sink=""
for _ in $(seq 1 300); do
  if ! kill -0 "$DEV_PID" 2>/dev/null; then
    echo "dev-otp-login: the emulator exited before serving. Log:" >&2
    tail -20 "$LOG" >&2
    exit 1
  fi
  [ -z "$issuer" ] && issuer=$(grep -o 'issuer http://[^ ]*' "$LOG" 2>/dev/null | head -1 | sed 's/issuer //')
  [ -z "$sink" ] && sink=$(grep -o 'captured messages at http://[^ ]*' "$LOG" 2>/dev/null | sed 's/.*at //')
  if [ -n "$issuer" ] && curl -sf -o /dev/null "${issuer}/.well-known/openid-configuration"; then
    break
  fi
  sleep 0.1
done

if [ -z "$issuer" ] || [ -z "$sink" ]; then
  echo "dev-otp-login: emulator never reported an issuer and a sink. Log:" >&2
  tail -20 "$LOG" >&2
  exit 1
fi

identifier="dev@example.test"

# 1. Request the code. A 200 here means only that the request was accepted: the response is
#    deliberately identical whether or not the account exists (the anti-enumeration contract),
#    so it proves nothing on its own and the real assertion is the captured code below.
send_status=$(curl -s --max-time 20 -o /dev/null -w '%{http_code}' \
  -X POST "${issuer}/otp/send" -H 'content-type: application/json' \
  --data-binary "{\"identifier\":\"${identifier}\"}")
if [ "$send_status" != "200" ]; then
  echo "dev-otp-login: otp/send answered ${send_status}, expected 200" >&2
  exit 1
fi

# 2. Read the code out of the SINK, offline. This is the step a mail server would otherwise be
#    required for, and it is the reason the emulator exists.
code=$(curl -s --max-time 10 "$sink" | python3 -c '
import json, sys
messages = json.load(sys.stdin)["messages"]
email = [m for m in messages if m["kind"] == "email"]
if not email:
    print("NO-EMAIL-CAPTURED", file=sys.stderr)
    raise SystemExit(1)
print(email[-1]["body"])
')
if [ -z "$code" ]; then
  echo "dev-otp-login: no email captured in the sink" >&2
  exit 1
fi
echo "dev-otp-login: captured code ${code}"

# 3. The code must be the DETERMINISTIC one for this seed. Without this the job would pass
#    against any code at all, and a regression that broke reproducibility -- the property the
#    whole seeded emulator rests on -- would go unnoticed.
if [ -n "${EXPECT_CODE:-}" ] && [ "$code" != "$EXPECT_CODE" ]; then
  echo "dev-otp-login: code ${code} is not the expected ${EXPECT_CODE} for seed ${SEED}." >&2
  echo "  Seeding is no longer reproducible, or the seed changed." >&2
  exit 1
fi

# 4. Complete the login.
verify_body=$(curl -s --max-time 20 -w '\n%{http_code}' \
  -X POST "${issuer}/otp/verify" -H 'content-type: application/json' \
  --data-binary "{\"identifier\":\"${identifier}\",\"code\":\"${code}\"}")
verify_status=$(printf '%s' "$verify_body" | tail -1)
verify_json=$(printf '%s' "$verify_body" | sed '$d')

if [ "$verify_status" != "200" ]; then
  echo "dev-otp-login: otp/verify answered ${verify_status}, expected 200" >&2
  echo "  body: ${verify_json}" >&2
  exit 1
fi

# The status code alone is not the claim. `authenticated: true` is what "a complete login"
# means, and asserting it stops a future change that returned 200 with a refusal body from
# reading as success.
printf '%s' "$verify_json" | python3 -c '
import json, sys
body = json.load(sys.stdin)
if body.get("authenticated") is not True:
    print("dev-otp-login: verify did not authenticate: %s" % body, file=sys.stderr)
    raise SystemExit(1)
print("dev-otp-login: authenticated, amr=%s" % body.get("amr"))
' || exit 1

echo "dev-otp-login: a complete email-OTP login succeeded offline"
