# Quickstart: sign a user in from a React SPA

Sign a real user into a **plain Vite + React single-page app**, with every token held server-side
and nothing in the browser but an opaque, `HttpOnly` cookie. Against a local IronAuth that needs
no account and no network.

**Budget: under 15 minutes**, and CI proves it -- `scripts/quickstart.sh react` runs the commands
below **verbatim** and fails if they stop working or take too long. There is no second copy of
these steps anywhere; the gate reads this file.

You need Node 20+ and a checkout of this repository.

## Why a SPA needs a server at all

A single-page app cannot hold tokens safely. Anything JavaScript can read, an XSS can read, so a
token anywhere the browser's own code can reach it is one injected script away from full account
takeover -- which is why the OAuth for Browser-Based Apps BCP puts a **backend for frontend**
first among its architectures. [`docs/bff.md`](bff.md) is where that reasoning lives, including
which browser storage is and is not acceptable.

So the app you build here is a React bundle plus a small server that owns the tokens. The server
is 40 lines of `node:http`. The point is that it is **not a framework**: the same
`@ironauth/bff` package drives the Next.js guide, and here it drives a bare Node server.

## 1. Start a local IronAuth

```bash quickstart
REPO=$(pwd)
cargo run --quiet -p ironauth --bin ironauth -- dev --bind 127.0.0.1:18138 --seed 1 > "$QS_DIR/emulator.log" 2>&1 &
echo $! > "$QS_DIR/emulator.pid"
```

## 2. Wait for it, and read what it seeded

```bash quickstart
for _ in $(seq 1 900); do
  if ! kill -0 "$(cat "$QS_DIR/emulator.pid")" 2>/dev/null; then
    echo "the emulator exited before serving; its log:" >&2
    tail -20 "$QS_DIR/emulator.log" >&2
    exit 1
  fi
  ISSUER=$(grep -o 'issuer http://[^ ]*' "$QS_DIR/emulator.log" 2>/dev/null | head -1 | sed 's/issuer //' || true)
  if [ -n "$ISSUER" ] && curl -sf -o /dev/null "$ISSUER/.well-known/openid-configuration"; then break; fi
  sleep 0.2
done
export ISSUER
export CLIENT_ID=$(grep -o 'client_id [^ ]*' "$QS_DIR/emulator.log" | head -1 | sed 's/client_id //')
test -n "$ISSUER" && test -n "$CLIENT_ID"
```

## 3. Create a plain Vite React app

```bash quickstart
cd "$QS_DIR"
npm create vite@latest app -- --template react-ts > "$QS_DIR/create.log" 2>&1
cd "$QS_DIR/app"
npm install > "$QS_DIR/install.log" 2>&1
```

Nothing is pre-seeded. This is what `npm create vite` gives anybody.

## 4. Install the BFF

```bash quickstart
(cd "$REPO/packages/ironauth-bff" && npm run build >/dev/null && npm pack --pack-destination "$QS_DIR" >/dev/null)
npm install "$(ls "$QS_DIR"/ironauth-bff-*.tgz)" >> "$QS_DIR/install.log" 2>&1
```

## 5. Write the server

```bash quickstart
cat > server.mjs <<'JS'
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';

import {
  MemorySessionStore,
  assertHardened,
  callback,
  login,
  logout,
  nodeAdapter,
  userinfo,
} from '@ironauth/bff';

const ORIGIN = process.env.APP_ORIGIN ?? 'http://127.0.0.1:3100';

// MemorySessionStore is for development: a restart signs everybody out and a second replica
// shares none of the first's sessions. Point it at Redis before you ship.
const store = new MemorySessionStore();

const config = {
  issuer: process.env.IRONAUTH_ISSUER,
  clientId: process.env.IRONAUTH_CLIENT_ID,
  // Path `/callback` on 127.0.0.1. RFC 8252 loopback matching is PORT-agnostic but exact
  // everywhere else, so the seeded client accepts this without any registration step.
  redirectUri: `${ORIGIN}/callback`,
  scope: 'openid',
  apiBase: process.env.IRONAUTH_ISSUER,
  sessionMaxAgeSeconds: 3600,
  store,
};

// The BFF is framework-agnostic: it turns a request into a DECISION, and the adapter turns that
// decision into a response. `nodeAdapter` is the one for a bare `node:http` server.
const routes = {
  '/auth/login': nodeAdapter((request) => login(config, request), ORIGIN),
  '/callback': nodeAdapter((request) => callback(config, request), ORIGIN),
  '/auth/me': nodeAdapter((request) => userinfo(config, request), ORIGIN),
  '/auth/logout': nodeAdapter((request) => logout(config, request), ORIGIN),
};

const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' };

createServer(async (req, res) => {
  const path = new URL(req.url, ORIGIN).pathname;
  const route = routes[path];
  if (route) {
    await route(req, res);
    return;
  }
  // Everything else is the built SPA. `normalize` plus the prefix check keeps `../` out, which
  // matters the moment this serves anything from a real disk.
  const file = normalize(join('dist', path === '/' ? 'index.html' : path));
  if (!file.startsWith('dist')) {
    res.statusCode = 403;
    res.end('no');
    return;
  }
  try {
    const body = await readFile(file);
    res.setHeader('content-type', TYPES[extname(file)] ?? 'application/octet-stream');
    res.end(body);
  } catch {
    res.statusCode = 404;
    res.end('not found');
  }
}).listen(3100, '127.0.0.1', () => console.log('listening'));
JS
```

## 6. Write the React side

The whole client-side auth API is `fetch('/auth/me')`. There is no token to store, no expiry to
track, and no refresh to schedule: the server does all of it behind the session cookie.

```bash quickstart
cat > src/App.tsx <<'TSX'
import { useEffect, useState } from 'react';

type Me = { claims: Record<string, unknown> };

export default function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [signedOut, setSignedOut] = useState(false);

  useEffect(() => {
    // Same origin, so the cookie rides along. There is nothing to put in an Authorization
    // header, which is the entire point: this code CANNOT leak a token, because it never has one.
    fetch('/auth/me')
      .then((response) => (response.ok ? response.json() : Promise.reject(response.status)))
      .then(setMe)
      .catch(() => setSignedOut(true));
  }, []);

  if (signedOut) {
    return <a href="/auth/login">Sign in</a>;
  }
  if (!me) {
    return <p>Loading...</p>;
  }
  return (
    <main>
      <h1>Signed in</h1>
      <pre>{JSON.stringify(me.claims, null, 2)}</pre>
    </main>
  );
}
TSX
npx vite build > "$QS_DIR/build.log" 2>&1 || { tail -30 "$QS_DIR/build.log"; exit 1; }
IRONAUTH_ISSUER="$ISSUER" IRONAUTH_CLIENT_ID="$CLIENT_ID" node server.mjs > "$QS_DIR/server.log" 2>&1 &
echo $! > "$QS_DIR/server.pid"
for _ in $(seq 1 120); do
  curl -sf -o /dev/null http://127.0.0.1:3100/ && break
  sleep 0.5
done
# THE SERVER WE STARTED, not merely a server. If the port was already taken, node exits on
# EADDRINUSE while the process holding it answers happily -- and the whole run then tests
# somebody else's server. Measured: a leaked server from an earlier run made a deliberately
# broken guide pass.
kill -0 "$(cat "$QS_DIR/server.pid")" 2>/dev/null || {
  echo "the app server exited; its log:" >&2
  cat "$QS_DIR/server.log" >&2
  exit 1
}
curl -sf -o /dev/null http://127.0.0.1:3100/
```

## 7. Sign in

A person would click "Sign in" and type the seeded credentials. This does the same thing with
`curl`, so CI can prove the login really completes rather than that the page renders.

```bash quickstart
cd "$QS_DIR"
rm -f jar.txt
APP=http://127.0.0.1:3100
NEXT_URL=$(curl -s -c jar.txt -b jar.txt -o /dev/null -w '%{redirect_url}' "$APP/auth/login?return_to=/")
for _ in 1 2 3 4 5 6 7 8; do
  case "$NEXT_URL" in "$APP/callback"*) break;; esac
  CODE=$(curl -s -c jar.txt -b jar.txt -o page.html -w '%{http_code}' "$NEXT_URL")
  if [ "$CODE" = "303" ] || [ "$CODE" = "302" ]; then
    NEXT_URL=$(curl -s -c jar.txt -b jar.txt -o /dev/null -w '%{redirect_url}' "$NEXT_URL")
    continue
  fi
  ACTION=$(grep -oE '<form[^>]*action="[^"]*"' page.html | head -1 | sed 's/.*action="//;s/"//')
  RETURN_TO=$(python3 -c "import html,re;print(html.unescape(re.search(r'name=\"return_to\" value=\"([^\"]*)\"',open('page.html',encoding='utf-8').read()).group(1)))")
  ORIGIN=$(printf '%s' "$NEXT_URL" | sed -E 's#(https?://[^/]+).*#\1#')
  if grep -q 'name="password"' page.html; then
    NEXT_URL=$(curl -s -c jar.txt -b jar.txt -o /dev/null -w '%{redirect_url}' -X POST "$ORIGIN$ACTION" \
      --data-urlencode "return_to=$RETURN_TO" \
      --data-urlencode 'identifier=dev@example.test' \
      --data-urlencode 'password=dev-password-not-for-production')
  else
    NEXT_URL=$(curl -s -c jar.txt -b jar.txt -o /dev/null -w '%{redirect_url}' -X POST "$ORIGIN$ACTION" \
      --data-urlencode "return_to=$RETURN_TO" -d 'decision=allow')
  fi
done
curl -s -c jar.txt -b jar.txt -D headers.txt -o /dev/null "$NEXT_URL"
echo "signed in"
```

## 8. What the SPA can see, and what it cannot

```bash quickstart
cd "$QS_DIR"
curl -s -b jar.txt "$APP/auth/me" -o me.json -w 'auth/me %{http_code}\n'
python3 - <<'PY'
import json, pathlib, sys

claims = json.loads(pathlib.Path('me.json').read_text(encoding='utf-8'))
subject = claims.get('claims', {}).get('sub', '')
if not subject.startswith('usr_'):
    sys.exit(f'/auth/me did not identify the user: {claims}')

# Checked over the WHOLE response rather than by looking for one field name: the tokens are what
# this architecture exists to keep out of the browser, and a nested copy would be just as leaked.
body = json.dumps(claims)
for secret in ('access_token', 'refresh_token', 'privateJwk'):
    if secret in body:
        sys.exit(f'{secret} reached the browser: {body}')

# HttpOnly IS the defence for a SPA. Everything else here is arrangement; this attribute is what
# makes an injected script unable to read the session, so it is asserted rather than assumed.
headers = pathlib.Path('headers.txt').read_text(encoding='utf-8')
cookie_lines = [line for line in headers.splitlines() if line.lower().startswith('set-cookie:')]
session = [line for line in cookie_lines if 'ironauth_bff' in line]
if len(session) != 1:
    sys.exit(f'expected one session cookie on the callback, found {len(session)}')
if 'HttpOnly' not in session[0]:
    sys.exit('the session cookie is readable from JavaScript, which defeats the whole architecture')
if 'SameSite=Lax' not in session[0] and 'SameSite=Strict' not in session[0]:
    sys.exit(f'the session cookie has no restrictive SameSite: {session[0]}')
print('signed in; cookie is HttpOnly and SameSite, and no token reached the browser')
PY
```

## 9. The built bundle carries no token handling

```bash quickstart
cd "$QS_DIR/app"
# The SPA source never mentions a token, so the BUNDLE must not either. This is a weak check on
# its own -- a bundle can be innocent while a server leaks -- but it catches the specific
# regression where someone "simplifies" the client by having it fetch tokens directly.
# The BUNDLE MUST EXIST first. `grep dist/assets/*.js` over an empty glob finds nothing and
# reports success, so without this the check passes hardest when there is no bundle at all.
BUNDLES=$(ls dist/assets/*.js 2>/dev/null | wc -l | tr -d ' ')
test "$BUNDLES" -ge 1 || { echo "no built bundle to inspect, so this check would pass vacuously"; exit 1; }
if grep -rqE 'access_token|refresh_token' dist/assets/*.js; then
  echo "the built bundle references tokens; a SPA in this architecture never should"
  exit 1
fi
echo "$BUNDLES bundle(s) inspected, none references a token"
```

## 10. Stop everything

```bash quickstart
kill "$(cat "$QS_DIR/server.pid")" 2>/dev/null || true
kill "$(cat "$QS_DIR/emulator.pid")" 2>/dev/null || true
echo "stopped"
```

## What you just proved

- A **plain Vite React SPA** signs a real user in, with a 40-line `node:http` server and no
  framework.
- The same `@ironauth/bff` package drives this and the Next.js guide, which is what
  "framework-agnostic" means when it is measured rather than claimed.
- The session cookie is **`HttpOnly`**, so an injected script cannot read it, and the client code
  cannot leak a token because it never holds one.
