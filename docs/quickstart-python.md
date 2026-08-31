# Quickstart: authenticate a user from Python

Sign a real user in from a Python backend and verify the token you get, against a local IronAuth
that needs no account and no network.

**Budget: under 15 minutes**, and CI proves it -- `scripts/quickstart.sh python` runs the commands
below **verbatim** and fails if they stop working or take too long. There is no second copy of
these steps anywhere; the gate reads this file.

You need Python 3.11+ and a checkout of this repository.

## 1. Install the one dependency

```bash quickstart
python3 -m venv "$QS_DIR/venv"
"$QS_DIR/venv/bin/pip" install --quiet --disable-pip-version-check cryptography
export PY="$QS_DIR/venv/bin/python"
```

A virtual environment rather than a bare `pip install`, because many Python installations are
externally managed and refuse one -- and because a quickstart should not be the thing that
modifies a reader's system Python.

`cryptography` is used for exactly one thing: verifying the Ed25519 signature on the token you
get. Everything else in the example is standard library. It is a hard requirement rather than an
optional extra, and the example refuses to run without it -- a quickstart that printed "skipping
signature verification" would teach that the signature is optional.

## 2. Start a local IronAuth

```bash quickstart
cargo run --quiet -p ironauth --bin ironauth -- dev --bind 127.0.0.1:18130 --seed 1 > "$QS_DIR/emulator.log" 2>&1 &
echo $! > "$QS_DIR/emulator.pid"
```

It brings up its own throwaway Postgres, seeds a tenant, an environment, a client and a user, and
serves offline. `docs/EMULATOR.md` has the details.

## 3. Wait for it, and read what it seeded

```bash quickstart
for _ in $(seq 1 900); do
  if ! kill -0 "$(cat "$QS_DIR/emulator.pid")" 2>/dev/null; then
    echo "the emulator exited before serving; its log:" >&2
    tail -20 "$QS_DIR/emulator.log" >&2
    exit 1
  fi
  ISSUER=$(grep -o 'issuer http://[^ ]*' "$QS_DIR/emulator.log" 2>/dev/null | head -1 | sed 's/issuer //')
  if [ -n "$ISSUER" ] && curl -sf -o /dev/null "$ISSUER/.well-known/openid-configuration"; then break; fi
  sleep 0.2
done
export ISSUER
export CLIENT_ID=$(grep -o 'client_id [^ ]*' "$QS_DIR/emulator.log" | head -1 | sed 's/client_id //')
test -n "$ISSUER" && test -n "$CLIENT_ID"
```

Waiting for the log line is not enough: it is printed while the listener is still coming up. The
loop asks **discovery** to answer, which is the first thing that is true only once the server is
actually serving.

It also checks that the emulator is still alive each time round. Without that, an emulator that
failed to start turns into three minutes of polling and then a confusing "ISSUER is empty" --
rather than the emulator's own error, immediately.

The issuer is per environment, so it carries the tenant and environment in its path. That is why
a token from one environment is never valid in another.

## 4. Sign a user in with the device flow

The device flow is the one that needs no browser on the machine running it, which is what makes
it the quickstart: your terminal is the device, and the approval happens over HTTP.

```bash quickstart
"$PY" docs/examples/quickstart_python.py > "$QS_DIR/out.txt"
cat "$QS_DIR/out.txt"
```

`docs/examples/quickstart_python.py` is about ninety lines and worth reading: it starts the grant,
polls the token endpoint honouring `authorization_pending`, and then **verifies** the ID token
against the environment's published JWKS rather than trusting it because it arrived over TLS.

## 5. Check what you got

```bash quickstart
grep -q 'quickstart: signed in as ' "$QS_DIR/out.txt"
```

You should see the subject the token names. That line is what CI asserts, so if you see it, the
quickstart worked.

## 6. Stop the emulator

```bash quickstart
kill "$(cat "$QS_DIR/emulator.pid")" 2>/dev/null || true
```

## What to do next

- **Verifying tokens** is the thing to get right first. The example verifies the signature, the
  issuer, the audience and the expiry, and pins the algorithm to what the issuer publishes --
  never to what the token's own header claims. `docs/edge-verification.md` explains why that
  last one is the whole ballgame.
- **A browser app** should not do any of this in the browser. Read `docs/bff.md`.
