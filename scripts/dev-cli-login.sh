#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Drive `ironauth login` ITSELF, headless, end to end against the emulator (issue #120,
# criterion 1: "`ironauth login` completes successfully on a headless box (device flow, code
# displayed, approval from a second device)").
#
# # How this differs from dev-device-login.sh, and why both exist
#
# `dev-device-login.sh` drives the SERVER side with curl: it starts a grant, approves it, and
# asserts the poll sequence. It proves the protocol. It does NOT run the CLI, so it says nothing
# about whether `ironauth login` displays the code, polls correctly, or stores what it receives.
#
# This runs THE ACTUAL BINARY. It reads the user code off the CLI's own stdout -- which is the
# criterion's "code displayed" -- approves it from a separate session as the second device, and
# waits for the process to exit. Then it asserts the credential really landed by running `login`
# again and requiring the already-signed-in short circuit, and removes it with `logout`.
#
# # THE BLOCKER THIS REMOVES
#
# `dev-device-login.sh` records why it could not do this: "The ubuntu runner this job uses has no
# Secret Service ... so driving the CLI here would fail on the keychain rather than on anything
# the device flow does. Making that possible needs a headless credential store, which is its own
# change."
#
# That is no longer true, and it was the note rather than the code that was out of date. The
# `keychain` job now brings a real Secret Service up on the ubuntu runner and round-trips a
# credential through it on all three platforms. The same six lines work here, so the CLI can be
# driven on a headless host with the credential store it actually ships -- which is a stronger
# result than a headless store would have been, because a store built for CI proves nothing
# about the one users get.
#
# The Secret Service is the CALLER's to provide (the CI job does it in a step of its own, and a
# developer's desktop already has one). This script only refuses clearly if there is none.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

PORT="${PORT:-18121}"
SEED="${SEED:-1}"
BIN="${BIN:-./target/debug/ironauth}"
LOG="$(mktemp -t ironauth-cli-login-XXXXXX)"
CLI_OUT="$(mktemp -t ironauth-cli-out-XXXXXX)"
COOKIE_JAR="$(mktemp -t ironauth-cli-jar-XXXXXX)"
# UNIQUE PER RUN, so a leftover credential from an interrupted run cannot make the
# already-signed-in assertion below pass without this run having signed in at all.
ACCOUNT="${ACCOUNT:-ironauth-cli-login-$$}"

if [ ! -x "$BIN" ]; then
  echo "dev-cli-login: $BIN is not built. Run: cargo build -p ironauth --bin ironauth" >&2
  exit 1
fi

cleanup() {
  [ -n "${LOGIN_PID:-}" ] && kill "$LOGIN_PID" 2>/dev/null
  [ -n "${DEV_PID:-}" ] && kill "$DEV_PID" 2>/dev/null
  # Best effort: remove the credential even when an assertion failed, so a red run does not
  # leave one in the keychain of whatever machine ran it.
  "$BIN" logout --account "$ACCOUNT" >/dev/null 2>&1
  sleep 2
  rm -f "$LOG" "$CLI_OUT" "$COOKIE_JAR"
}
trap cleanup EXIT INT TERM

env -u DATABASE_URL "$BIN" dev --bind "127.0.0.1:${PORT}" --seed "$SEED" > "$LOG" 2>&1 &
DEV_PID=$!

issuer=""
client_id=""
for _ in $(seq 1 600); do
  if ! kill -0 "$DEV_PID" 2>/dev/null; then
    echo "dev-cli-login: the emulator exited before serving. Log:" >&2
    tail -20 "$LOG" >&2
    exit 1
  fi
  [ -z "$issuer" ] && issuer=$(grep -o 'issuer http://[^ ]*' "$LOG" 2>/dev/null | head -1 | sed 's/issuer //')
  [ -z "$client_id" ] && client_id=$(grep -o 'client_id [^ ]*' "$LOG" 2>/dev/null | head -1 | sed 's/client_id //')
  if [ -n "$issuer" ] && curl -sf -o /dev/null "${issuer}/.well-known/openid-configuration"; then
    break
  fi
  sleep 0.1
done

if [ -z "$issuer" ] || [ -z "$client_id" ]; then
  echo "dev-cli-login: emulator never reported an issuer and a client. Log:" >&2
  tail -20 "$LOG" >&2
  exit 1
fi

# The protocol endpoints live at the DEPLOYMENT ROOT while the verification page is scoped.
base="${issuer%/t/*}"

# 1. RUN THE CLI.
#
#    `--issuer` takes the SCOPED issuer, not the deployment root. The CLI does discovery at
#    `<issuer>/.well-known/openid-configuration` and derives the root itself for
#    `/device_authorization` and `/token` -- which is the fix #120 already landed, and passing
#    the root here instead answers 404 on discovery. (Measured: the first version of this script
#    passed `$base` and got exactly that.)
#
#    FLOW_FLAG defaults to `--device` so this runs anywhere. CI sets it EMPTY on the headless
#    Linux runner, which is the stronger assertion: with no display the CLI must CHOOSE the
#    device flow, and the check below reads its own announcement of that choice rather than
#    assuming it. Clearing the display variables is not enough on macOS, where the host signals
#    report a browser regardless -- so a developer running this on a desktop forces the flow and
#    the runner proves the choice.
FLOW_FLAG="${FLOW_FLAG---device}"
# shellcheck disable=SC2086
env -u DISPLAY -u BROWSER -u WAYLAND_DISPLAY \
  "$BIN" login --issuer "$issuer" --client-id "$client_id" --account "$ACCOUNT" $FLOW_FLAG \
  > "$CLI_OUT" 2>&1 &
LOGIN_PID=$!

# 2. READ THE CODE OFF THE CLI'S OWN OUTPUT. This is the criterion's "code displayed": taking it
#    from the server instead would test the server again and leave the CLI's display untested,
#    which is the whole difference between this script and the one beside it.
user_code=""
for _ in $(seq 1 600); do
  if ! kill -0 "$LOGIN_PID" 2>/dev/null; then
    echo "dev-cli-login: the CLI exited before displaying a code. Output:" >&2
    cat "$CLI_OUT" >&2
    exit 1
  fi
  # BOTH SPELLINGS. The CLI says "enter the code" when it printed a bare verification URI and
  # "check the page shows this code" when it printed the complete one, and which it does depends
  # on what the server offered. A scrape that knew only one form would pass on one deployment
  # and hang on the other -- which is exactly what the first version of this script did.
  user_code=$(grep -oE '(enter the code|shows this code): [A-Z0-9-]+' "$CLI_OUT" 2>/dev/null \
    | head -1 | sed -E 's/.*code: //')
  [ -n "$user_code" ] && break
  sleep 0.1
done

if [ -z "$user_code" ]; then
  echo "dev-cli-login: the CLI never displayed a user code. Output:" >&2
  cat "$CLI_OUT" >&2
  exit 1
fi

# THE FLOW IT ACTUALLY USED, read from the CLI's own announcement. On the headless runner
# FLOW_FLAG is empty, so this is the assertion that the CHOICE was the device flow rather than
# something forced -- criterion 3's fallback reached from the direction that matters.
if ! grep -q 'device flow' "$CLI_OUT"; then
  echo "dev-cli-login: the CLI did not use the device flow. Output:" >&2
  cat "$CLI_OUT" >&2
  exit 1
fi

if ! grep -q 'Waiting for approval' "$CLI_OUT"; then
  echo "dev-cli-login: the CLI displayed a code but never said it was waiting. Output:" >&2
  cat "$CLI_OUT" >&2
  exit 1
fi

# 3. APPROVE FROM A SECOND DEVICE. A separate cookie jar, so this really is a different session
#    and not the CLI's own -- the CLI holds none, which is the premise of the whole flow.
device_path="${issuer}/device"
resume="/authorize?response_type=code&client_id=${client_id}&redirect_uri=${DEV_REDIRECT_URI:-http://127.0.0.1/callback}&scope=openid"
login_status=$(curl -s --max-time 20 -o /dev/null -w '%{http_code}' -c "$COOKIE_JAR" \
  -X POST "${base}/login" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "identifier=${DEV_USER:-dev@example.test}" \
  --data-urlencode "password=${DEV_PASSWORD:-dev-password-not-for-production}" \
  --data-urlencode "return_to=${resume}")
case "$login_status" in
  200|302|303) ;;
  *)
    echo "dev-cli-login: the approving user could not sign in (${login_status})" >&2
    tail -20 "$LOG" >&2
    exit 1
    ;;
esac

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
  echo "dev-cli-login: the confirmation page carried no flow handle." >&2
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
  echo "dev-cli-login: approval answered ${approve_status}" >&2
  tail -20 "$LOG" >&2
  exit 1
fi

# 4. THE CLI FINISHES ON ITS OWN. Bounded, because a poller that never noticed the approval
#    would otherwise hang this job until the runner's own timeout, reported as an infrastructure
#    problem rather than as the CLI defect it would be.
deadline=$((SECONDS + 120))
while kill -0 "$LOGIN_PID" 2>/dev/null; do
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "dev-cli-login: the CLI did not finish within 120s of approval. Output:" >&2
    cat "$CLI_OUT" >&2
    exit 1
  fi
  sleep 0.5
done
wait "$LOGIN_PID"
login_rc=$?
LOGIN_PID=""
if [ "$login_rc" != "0" ]; then
  echo "dev-cli-login: \`ironauth login\` exited ${login_rc}. Output:" >&2
  cat "$CLI_OUT" >&2
  tail -20 "$LOG" >&2
  exit 1
fi

# 5. THE CREDENTIAL REALLY LANDED, asserted through the CLI's own read path rather than by
#    trusting the exit code. A `login` that printed success and stored nothing would satisfy
#    step 4 completely.
second=$("$BIN" login --issuer "$issuer" --client-id "$client_id" --account "$ACCOUNT" 2>&1)
if ! printf '%s' "$second" | grep -q 'already signed in'; then
  echo "dev-cli-login: a second login did not short circuit, so nothing was stored:" >&2
  printf '%s\n' "$second" >&2
  exit 1
fi

# 6. AND `logout` REMOVES IT (criterion 5, end to end rather than over the store seam).
out=$("$BIN" logout --account "$ACCOUNT" 2>&1)
if ! printf '%s' "$out" | grep -q 'removed stored credentials'; then
  echo "dev-cli-login: logout did not report a removal: ${out}" >&2
  exit 1
fi
# And the CREDENTIAL IS GONE, not merely reported gone. A `login` after a real logout starts a
# fresh flow and blocks waiting for approval, so it is run in the background, given a moment to
# reach the point where it would have short circuited, and then killed. What is asserted is the
# ABSENCE of the short-circuit line -- if the credential survived, that line appears within
# milliseconds and long before the timeout.
after_out="$(mktemp -t ironauth-cli-after-XXXXXX)"
env -u DISPLAY -u BROWSER -u WAYLAND_DISPLAY \
  "$BIN" login --issuer "$issuer" --client-id "$client_id" --account "$ACCOUNT" --device \
  > "$after_out" 2>&1 &
AFTER_PID=$!
sleep 5
kill "$AFTER_PID" 2>/dev/null
wait "$AFTER_PID" 2>/dev/null
if grep -q 'already signed in' "$after_out"; then
  echo "dev-cli-login: the credential survived logout:" >&2
  cat "$after_out" >&2
  rm -f "$after_out"
  exit 1
fi
# It got as far as starting a new grant, which is the positive half: an absence of the
# short-circuit line would also be produced by a `login` that failed immediately for some
# unrelated reason.
if ! grep -qE 'enter the code:|To sign in, visit' "$after_out"; then
  echo "dev-cli-login: the post-logout login neither short circuited nor started a flow:" >&2
  cat "$after_out" >&2
  rm -f "$after_out"
  exit 1
fi
rm -f "$after_out"

echo "dev-cli-login: OK -- ironauth login completed headlessly, stored a credential, and logout removed it"
