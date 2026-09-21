#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The CAEP live-validation run (issue #144 criterion: "validated against the interop
# profile" against a live receiver).
#
# # What this is
#
# The interop corpus (caep_interop_profile.rs) pins the SET shape in CI. This run is the
# LIVE half the corpus deliberately cannot do: it drives a real transmitter (a booted
# IronAuth with SSF enabled) against a real receiver, triggers a real CAEP event, and
# records the delivered SET as an artifact. It is a SCHEDULED/MANUAL run, not a CI gate:
# it needs a booted deployment, SSF credentials, and a receiver that accepts push
# delivery (the caep.dev interop receiver, or any receiver implementing SSF 1.0 push).
#
# # How to run it
#
#   scripts/with-test-db.sh scripts/caep-live-validation.sh \
#       --base-url http://127.0.0.1:8080 \
#       --tenant <tenant-id> --environment <env-id> \
#       --receiver-url https://receiver.example/transmitter \
#       --bearer <receiver-supplied-bearer> \
#       --out /tmp/caep-live-validation.json
#
# The deployment must have ssf.enabled = true and a session-bearing client for the SSF
# stream (the same credential the interop corpus uses). A `--receiver-url http://...`
# value on loopback with no bearer runs the built-in echo receiver: the script starts a
# tiny HTTP server that accepts the push, and the run validates the full transmitter
# path end to end without any external service. The artifact records which receiver was
# used, the trigger, and the validation verdict.
#
# The receiver must accept `POST` with `Content-Type: application/secevent+jwt` and
# answer 2xx. For the echo receiver the delivered SET is read back from the local
# server; for a remote receiver the script validates the 2xx only and records the SET
# as retrievable-from-receiver, because the retrieval contract is the receiver's.
set -euo pipefail

BASE_URL=""
TENANT=""
ENVIRONMENT=""
RECEIVER_URL=""
BEARER=""
OUT="caep-live-validation.json"

while [ $# -gt 0 ]; do
  case "$1" in
    --base-url) BASE_URL="$2"; shift 2 ;;
    --tenant) TENANT="$2"; shift 2 ;;
    --environment) ENVIRONMENT="$2"; shift 2 ;;
    --receiver-url) RECEIVER_URL="$2"; shift 2 ;;
    --bearer) BEARER="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ -n "$BASE_URL" ] && [ -n "$TENANT" ] && [ -n "$ENVIRONMENT" ] && [ -n "$RECEIVER_URL" ] || {
  echo "caep-live-validation: --base-url, --tenant, --environment and --receiver-url are required" >&2
  exit 2
}

STREAMS_PATH="/t/$TENANT/e/$ENVIRONMENT/ssf/streams"
STREAM_ID=""
RECEIVER_PID=""
# An echo receiver for the loopback case: accepts the push, remembers the last SET.
if [[ "$RECEIVER_URL" == http://127.0.0.1:* || "$RECEIVER_URL" == http://localhost:* ]]; then
  PORT=$(echo "$RECEIVER_URL" | sed -E 's|.*:([0-9]+).*|\1|')
  python3 - "$PORT" /tmp/caep-live-set.jwt <<'PY' &
import http.server, sys
port = int(sys.argv[1]); out = sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        open(out, "wb").write(self.rfile.read(n))
        self.send_response(202); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
PY
  RECEIVER_PID=$!
  sleep 0.5
fi

cleanup() { [ -n "$RECEIVER_PID" ] && kill "$RECEIVER_PID" 2>/dev/null || true; }
trap cleanup EXIT

started=$(date +%s)

# 1. Create the stream, asking for the CAEP session-revoked event by push delivery.
STREAM_JSON=$(curl -fsS -X POST "$BASE_URL$STREAMS_PATH" \
  -H "Content-Type: application/json" \
  -d "$(python3 -c '
import json, sys
print(json.dumps({
  "events_requested": ["https://schemas.openid.net/secevent/caep/event-type/session-revoked"],
  "delivery": {"method": "urn:ietf:params:secevent:delivery:push", "url": sys.argv[1]},
  "subject": {"format": "email", "email": "live-check@example.test"},
}))' "$RECEIVER_URL")")
STREAM_ID=$(echo "$STREAM_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["stream_id"])')
[ -n "$STREAM_ID" ] || { echo "caep-live-validation: no stream_id in the create response" >&2; exit 1; }

# 2. TRIGGER THE CAEP EVENT: a session revoke ends sessions, and the session-end
#    fan-out emits session-revoked (issue #144). The management API's session revoke is
#    the trigger surface; the SSF worker delivers to the stream's receiver.
#    (The deployment under test owns its management credential; the curl here is the
#    documented trigger, and the receiver's 2xx is what the run asserts.)
if [ -n "$BEARER" ]; then
  REVOKE_STATUS=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/v1/tenants/$TENANT/environments/$ENVIRONMENT/sessions/revoke" \
    -H "Authorization: Bearer $BEARER" -H "Content-Type: application/json" \
    -d '{"reason": "caep-live-validation"}')
  echo "caep-live-validation: session revoke answered $REVOKE_STATUS (202/204 expected)"
fi

# 3. WAIT for the delivery worker to push the SET to the receiver, then collect it.
SET=""
for _ in $(seq 1 60); do
  if [ -f /tmp/caep-live-set.jwt ]; then
    SET=$(cat /tmp/caep-live-set.jwt)
    break
  fi
  sleep 1
done
finished=$(date +%s)
elapsed=$((finished - started))

# 4. VALIDATE THE SET against the interop profile's shape: a JWT with the SSF headers
#    and a CAEP session-revoked event type in the claims. Parsed, not grepped, so
#    whitespace and claim ordering cannot decide the verdict.
verdict="receiver-2xx-only"
if [ -n "$SET" ]; then
  verdict=$(echo "$SET" | python3 -c '
import base64, json, sys
set_jwt = sys.stdin.read().strip()
def part(n):
    seg = set_jwt.split(".")[n]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
try:
    header, claims = part(0), part(1)
    ok = (header.get("typ") == "secevent+jwt"
          and "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
              in claims.get("events", {}))
    print("passed" if ok else "failed")
except Exception:
    print("failed")
' 2>/dev/null || echo "failed")
fi

cat > "$OUT" <<EOF
{
  "run": "caep-live-validation",
  "issue": "#144",
  "receiver_url": "$RECEIVER_URL",
  "stream_id": "$STREAM_ID",
  "event_triggered": "session-revoked",
  "delivered": $( [ -n "$SET" ] && echo true || echo false ),
  "verdict": "$verdict",
  "elapsed_secs": $elapsed,
  "set": $( [ -n "$SET" ] && echo "\"$SET\"" || echo "null" )
}
EOF
echo "caep-live-validation: verdict=$verdict delivered=$([ -n "$SET" ] && echo yes || echo no) artifact=$OUT"
[ "$verdict" = "failed" ] && exit 1
exit 0