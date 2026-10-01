#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Drive the CORE-FLOW BATTERY against the emulator (issue #163's acceptance
# criterion: "core flows (discovery, code+PKCE login, token issuance, JWKS
# fetch by a co-located RP, admin API call) pass" in a no-egress environment).
#
# The lane runs this IMMEDIATELY AFTER the no-egress inspection (dev-no-egress
# asserts a live process makes no off-machine connections over a window in
# which it serves discovery and JWKS), so the battery lands inside that window:
# the flows an operator runs in an air-gapped enclave are the ones proven here.
#
# Everything is loopback: the server, the RP-style loopback listener that
# catches the authorization code, and the management plane. No DNS, no egress.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

PORT="${PORT:-18112}"
SEED="${SEED:-1}"
BIN="${BIN:-./target/debug/ironauth}"

if [ ! -x "$BIN" ]; then
  echo "dev-core-flows: $BIN is not built. Run: cargo build -p ironauth --bin ironauth" >&2
  exit 1
fi

LOG="$(mktemp -t ironauth-core-flows-XXXXXX)"
CAPTURE="$(mktemp -t ironauth-core-flows-capture-XXXXXX)"
COOKIES="$(mktemp -t ironauth-core-flows-cookies-XXXXXX)"
LISTENER_OUT="$(mktemp -t ironauth-core-flows-listener-XXXXXX)"

cleanup() {
  [ -n "${DEV_PID:-}" ] && kill "$DEV_PID" 2>/dev/null
  [ -n "${LISTENER_PID:-}" ] && kill "$LISTENER_PID" 2>/dev/null
  sleep 2
  rm -f "$LOG" "$CAPTURE" "$COOKIES" "$LISTENER_OUT"
}
trap cleanup EXIT INT TERM

env -u DATABASE_URL "$BIN" dev --bind "127.0.0.1:${PORT}" --seed "$SEED" > "$LOG" 2>&1 &
DEV_PID=$!

issuer=""
client_id=""
management=""
operator_token=""
for _ in $(seq 1 300); do
  if ! kill -0 "$DEV_PID" 2>/dev/null; then
    echo "dev-core-flows: the emulator exited before serving. Log:" >&2
    tail -20 "$LOG" >&2
    exit 1
  fi
  [ -z "$issuer" ] && issuer=$(grep -o 'issuer http://[^ ]*' "$LOG" | head -1 | sed 's/issuer //')
  [ -z "$client_id" ] && client_id=$(grep -o 'client_id [^ ]*' "$LOG" | head -1 | sed 's/client_id //')
  [ -z "$management" ] && management=$(grep -o 'management http://[^ ]*' "$LOG" | head -1 | sed 's/management //')
  [ -z "$operator_token" ] && operator_token=$(grep -o 'operator token [^ ]*' "$LOG" | head -1 | sed 's/operator token //')
  if [ -n "$issuer" ] && curl -sf -o /dev/null "${issuer}/.well-known/openid-configuration"; then
    break
  fi
  sleep 0.1
done

for var in issuer client_id management operator_token; do
  if [ -z "${!var}" ]; then
    echo "dev-core-flows: the emulator never reported ${var}. Log:" >&2
    tail -20 "$LOG" >&2
    exit 1
  fi
done

# 1. Discovery (the waiting loop above already asserted a 200; assert the
#    DOCUMENT parses and names an issuer, so a dead-but-200 surface fails).
curl --fail --silent --show-error --max-time 10 \
  "${issuer}/.well-known/openid-configuration" \
  | python3 -c '
import json, sys
doc = json.load(sys.stdin)
if not doc.get("issuer"):
    print("dev-core-flows: discovery lacks an issuer", file=sys.stderr)
    raise SystemExit(1)
assert "authorization_endpoint" in doc and "token_endpoint" in doc
print("dev-core-flows: discovery parses, issuer %s" % doc["issuer"])
' || exit 1

# 2. JWKS fetch (the co-located RP's key material), asserted as a real key set.
curl --fail --silent --show-error --max-time 10 "${issuer}/jwks.json" \
  | python3 -c '
import json, sys
doc = json.load(sys.stdin)
keys = doc.get("keys")
if not isinstance(keys, list) or not keys:
    print("dev-core-flows: jwks.json has no keys", file=sys.stderr)
    raise SystemExit(1)
print("dev-core-flows: jwks.json served %d keys" % len(keys))
' || exit 1

# 3. A complete email-OTP login (the session the browser flow rides).
send_status=$(curl -s --max-time 20 -o /dev/null -w '%{http_code}' \
  -X POST "${issuer}/otp/send" -H 'content-type: application/json' \
  --data-binary "{\"identifier\":\"dev@example.test\"}")
if [ "$send_status" != "200" ]; then
  echo "dev-core-flows: otp/send answered ${send_status}, expected 200" >&2
  exit 1
fi
if ! curl --fail --silent --show-error --max-time 10 "$(grep -o 'captured messages at http://[^ ]*' "$LOG" | head -1 | sed 's/.*at //')" --output "$CAPTURE"; then
  echo "dev-core-flows: capture sink did not answer" >&2
  exit 1
fi
code=$(python3 -c '
import json, sys
messages = json.load(open(sys.argv[1], encoding="utf-8"))["messages"]
email = [m for m in messages if m["kind"] == "email"]
if not email:
    print("NO-EMAIL-CAPTURED", file=sys.stderr)
    raise SystemExit(1)
print(email[-1]["body"])
' "$CAPTURE")
if [ -z "$code" ]; then
  echo "dev-core-flows: no email captured in the sink" >&2
  exit 1
fi
# The code must be the DETERMINISTIC one for this seed (reproducibility is the
# property the whole seeded emulator rests on).
if [ -n "${EXPECT_CODE:-}" ] && [ "$code" != "$EXPECT_CODE" ]; then
  echo "dev-core-flows: code ${code} is not the expected ${EXPECT_CODE} for seed ${SEED}." >&2
  exit 1
fi
verify_status=$(curl -s --max-time 20 -o /dev/null -w '%{http_code}' \
  -c "$COOKIES" -b "$COOKIES" \
  -X POST "${issuer}/otp/verify" -H 'content-type: application/json' \
  --data-binary "{\"identifier\":\"dev@example.test\",\"code\":\"${code}\"}")
if [ "$verify_status" != "200" ]; then
  echo "dev-core-flows: otp/verify answered ${verify_status}, expected 200" >&2
  exit 1
fi

# 4. The code+PKCE authorization: the session rides the cookie jar, the PKCE
#    pair is generated locally (the verifier never leaves the RP), and the
#    loopback listener catches the code the way a co-located RP would.
pkce=$(python3 -c '
import secrets, hashlib, base64, json
verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
json.dump({"verifier": verifier, "challenge": challenge}, open("'"$LISTENER_OUT"'.pkce", "w"))
print(challenge)
')
state="dev-core-flows-${SEED}"

cat > "$(dirname "$LISTENER_OUT")/core-flows-listener.py" <<'PYEOF'
import http.server, json, sys, urllib.parse
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        with open(sys.argv[1], "w", encoding="utf-8") as f:
            json.dump(params, f)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"dev-core-flows: code captured")
    def log_message(self, *_):
        pass
http.server.HTTPServer(("127.0.0.1", 80), Handler).handle_request()
PYEOF
python3 "$(dirname "$LISTENER_OUT")/core-flows-listener.py" "$LISTENER_OUT" &
LISTENER_PID=$!
sleep 1

auth_status=$(curl -s --max-time 30 -o /dev/null -w '%{http_code}' \
  -c "$COOKIES" -b "$COOKIES" -L \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=${client_id}" \
  --data-urlencode "redirect_uri=http://127.0.0.1/callback" \
  --data-urlencode "scope=openid" \
  --data-urlencode "state=${state}" \
  --data-urlencode "code_challenge=${pkce}" \
  --data-urlencode "code_challenge_method=S256" \
  --get "${issuer}/authorize" 2>&1)
# -L does not follow to a listener that already answered; the code arrives on
# the listener regardless. Assert the listener caught it.
for _ in $(seq 1 50); do
  [ -s "$LISTENER_OUT" ] && break
  sleep 0.1
done
if [ ! -s "$LISTENER_OUT" ]; then
  echo "dev-core-flows: the loopback listener never received the authorization code (authorize answered ${auth_status})." >&2
  exit 1
fi
[ -n "$LISTENER_PID" ] && kill "$LISTENER_PID" 2>/dev/null
LISTENER_PID=""
python3 -c "
import json, sys
params = json.load(open('$LISTENER_OUT', encoding='utf-8'))
params = {k: v[0] for k, v in params.items()}
if params.get('state') != '$state':
    print('dev-core-flows: state mismatch in the callback', file=sys.stderr)
    raise SystemExit(1)
if 'code' not in params:
    print('dev-core-flows: the callback carried no code: %s' % params, file=sys.stderr)
    raise SystemExit(1)
print('dev-core-flows: authorization code captured, state matched')
" || exit 1

# 5. Token issuance: the code + the verifier at the token endpoint. The
#    assertion is the ACCESS TOKEN ITSELF: a three-part JWT, which is the
#    "token issuance" the criterion names.
code_value=$(python3 -c "
import json
params = json.load(open('$LISTENER_OUT', encoding='utf-8'))
params = {k: v[0] for k, v in params.items()}
print(params['code'])
")
token_body=$(curl -s --max-time 20 \
  -X POST "${issuer}/token" -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=${code_value}" \
  --data-urlencode "redirect_uri=http://127.0.0.1/callback" \
  --data-urlencode "client_id=${client_id}" \
  --data-urlencode "code_verifier=$(python3 -c "import json; print(json.load(open('$LISTENER_OUT.pkce'))['verifier'])")")
printf '%s' "$token_body" | python3 -c '
import json, sys
body = json.load(sys.stdin)
if "access_token" not in body:
    print("dev-core-flows: token endpoint returned no access token: %s" % body, file=sys.stderr)
    raise SystemExit(1)
parts = body["access_token"].split(".")
if len(parts) != 3:
    print("dev-core-flows: access token is not a JWT", file=sys.stderr)
    raise SystemExit(1)
print("dev-core-flows: an access token was issued (%d bytes)" % len(body["access_token"]))
' || exit 1

# 6. The admin API call: the seeded operator token against the management
#    plane, a real authenticated management call.
me_status=$(curl -s --max-time 20 -o "$LISTENER_OUT.me" -w '%{http_code}' \
  "${management}/v1/me" -H "Authorization: Bearer ${operator_token}")
if [ "$me_status" != "200" ]; then
  echo "dev-core-flows: the admin API call answered ${me_status}, expected 200" >&2
  cat "$LISTENER_OUT.me" >&2
  exit 1
fi
python3 -c "
import json, sys
body = json.load(open('$LISTENER_OUT.me', encoding='utf-8'))
if not body:
    print('dev-core-flows: /v1/me returned an empty body', file=sys.stderr)
    raise SystemExit(1)
print('dev-core-flows: the admin API answered as %s' % list(body.keys()))
" || exit 1

echo "dev-core-flows: the core-flow battery passed: discovery, JWKS, code+PKCE login, token issuance, admin API"
rm -f "$LISTENER_OUT.pkce" "$LISTENER_OUT.me" "$(dirname "$LISTENER_OUT")/core-flows-listener.py"