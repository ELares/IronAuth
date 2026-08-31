# Quickstart: sign a user in from Next.js

Sign a real user into a **clean Next.js App Router project**, with every token held server-side and
nothing but an opaque session cookie in the browser. Against a local IronAuth that needs no account
and no network.

**Budget: under 15 minutes**, and CI proves it -- `scripts/quickstart.sh nextjs` runs the commands
below **verbatim** and fails if they stop working or take too long. There is no second copy of
these steps anywhere; the gate reads this file.

You need Node 20+ and a checkout of this repository.

## 1. Start a local IronAuth

```bash quickstart
REPO=$(pwd)
cargo run --quiet -p ironauth --bin ironauth -- dev --bind 127.0.0.1:18139 --seed 1 > "$QS_DIR/emulator.log" 2>&1 &
echo $! > "$QS_DIR/emulator.pid"
```

It brings up its own throwaway Postgres, seeds a tenant, an environment, a client and a user, and
serves offline. `docs/EMULATOR.md` has the details.

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

Waiting for the log line is not enough: it is printed while the listener is still coming up. The
loop asks **discovery** to answer, which is true only once the server is serving.

The seeded client is **public** -- it has no secret. That matters more than it looks: IronAuth
requires DPoP for public clients, so the login below is sender-constrained end to end without you
configuring anything.

## 3. Create a clean App Router project

```bash quickstart
cd "$QS_DIR"
npx --yes create-next-app@latest app --ts --app --no-tailwind --no-eslint --no-src-dir --no-turbopack --import-alias "@/*" --use-npm > "$QS_DIR/create.log" 2>&1
cd "$QS_DIR/app"
```

Nothing is pre-seeded here. This is what `create-next-app` gives anybody.

## 4. Install the BFF

```bash quickstart
(cd "$REPO/packages/ironauth-bff" && npm run build >/dev/null && npm pack --pack-destination "$QS_DIR" >/dev/null)
npm install "$(ls "$QS_DIR"/ironauth-bff-*.tgz)" > "$QS_DIR/install.log" 2>&1
```

`@ironauth/bff` is not published yet, so this packs it from the repository and installs the
tarball -- the same artifact a registry would serve.

## 5. Add the routes

The BFF is framework-agnostic: it turns a request into a decision, and `fetchAdapter` turns that
decision into a `Response`. An App Router route handler is three lines.

```bash quickstart
mkdir -p lib app/auth/login app/auth/me app/callback
cat > lib/ironauth.ts <<'TS'
import { MemorySessionStore, type BffConfig } from '@ironauth/bff';

// ONE store for the process. MemorySessionStore is for development: a restart signs everybody
// out and a second replica shares none of the first's sessions. Point it at Redis before you
// ship anything.
const store = new MemorySessionStore();

export const config: BffConfig = {
  issuer: process.env.IRONAUTH_ISSUER!,
  clientId: process.env.IRONAUTH_CLIENT_ID!,
  // Path `/callback` on 127.0.0.1. RFC 8252 loopback matching is PORT-agnostic but exact
  // everywhere else, so the seeded client accepts this without any registration step.
  redirectUri: 'http://127.0.0.1:3000/callback',
  scope: 'openid',
  apiBase: process.env.IRONAUTH_ISSUER!,
  sessionMaxAgeSeconds: 3600,
  store,
};
TS
cat > app/auth/login/route.ts <<'TS'
import { fetchAdapter, login } from '@ironauth/bff';
import { config } from '@/lib/ironauth';

export const GET = fetchAdapter((request) => login(config, request));
TS
cat > app/callback/route.ts <<'TS'
import { callback, fetchAdapter } from '@ironauth/bff';
import { config } from '@/lib/ironauth';

export const GET = fetchAdapter((request) => callback(config, request));
TS
cat > app/auth/me/route.ts <<'TS'
import { fetchAdapter, userinfo } from '@ironauth/bff';
import { config } from '@/lib/ironauth';

export const GET = fetchAdapter((request) => userinfo(config, request));
TS
```

## 6. Add a prefetch-heavy page

Next prefetches every `<Link>` in the viewport. That is worth pointing at deliberately, because
a session cookie that grew with the session would be sent on every one of those requests, and
"my auth cookie broke my CDN" is a real failure mode.

```bash quickstart
cat > app/page.tsx <<'TSX'
import Link from 'next/link';

// Twenty links, all prefetched. The point of the page is the traffic it generates.
export default function Home() {
  return (
    <main>
      <h1>Prefetch-heavy sample</h1>
      <a href="/auth/login">Sign in</a>
      <ul>
        {Array.from({ length: 20 }, (_, index) => (
          <li key={index}>
            <Link href={`/auth/me?n=${index}`} prefetch>
              link {index}
            </Link>
          </li>
        ))}
      </ul>
    </main>
  );
}
TSX
npx next build > "$QS_DIR/build.log" 2>&1 || { tail -30 "$QS_DIR/build.log"; exit 1; }
IRONAUTH_ISSUER="$ISSUER" IRONAUTH_CLIENT_ID="$CLIENT_ID" npx next start -H 127.0.0.1 -p 3000 > "$QS_DIR/next.log" 2>&1 &
echo $! > "$QS_DIR/next.pid"
for _ in $(seq 1 120); do
  curl -sf -o /dev/null http://127.0.0.1:3000/ && break
  sleep 0.5
done
# The page is FETCHED and counted, not just built. Otherwise "prefetch-heavy sample app" is a
# claim about a file nothing in this run ever opens, and the twenty links could quietly become
# two without any check noticing.
curl -sf http://127.0.0.1:3000/ -o "$QS_DIR/home.html"
# DISTINCT targets, not occurrences. Next emits each href more than once (the anchor and the
# RSC payload), so counting matches reported 40 links on a page that has 20 -- a number that
# passed the check while being wrong, which is the worse kind of green.
LINKS=$(grep -oE '/auth/me\?n=[0-9]+' "$QS_DIR/home.html" | sort -u | wc -l | tr -d ' ')
test "$LINKS" -ge 20 || { echo "the sample page rendered $LINKS distinct prefetch links, not 20"; exit 1; }
echo "the sample page renders $LINKS distinct prefetched links"
```

## 7. Sign in

A person would click "Sign in" and type the seeded credentials. This does the same thing with
`curl`, so CI can prove the login really completes rather than that the pages render.

```bash quickstart
cd "$QS_DIR"
rm -f jar.txt
APP=http://127.0.0.1:3000
NEXT_URL=$(curl -s -c jar.txt -b jar.txt -o /dev/null -w '%{redirect_url}' "$APP/auth/login?return_to=/dashboard")
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
LANDED=$(curl -s -c jar.txt -b jar.txt -o /dev/null -w '%{redirect_url}' "$NEXT_URL")
test "$LANDED" = "$APP/dashboard" || { echo "the callback did not return to /dashboard, got: $LANDED"; exit 1; }
echo "signed in, returned to $LANDED"
```

The browser was sent back to `/dashboard`, which is where step 7 asked to go: `return_to` survived
the whole round trip.

## 8. Check the session, and what the browser is holding

```bash quickstart
cd "$QS_DIR"
curl -s -b jar.txt "$APP/auth/me" -o me.json -w 'auth/me %{http_code}\n'
python3 - <<'PY'
import json, pathlib, re, sys

claims = json.loads(pathlib.Path('me.json').read_text(encoding='utf-8'))
subject = claims.get('claims', {}).get('sub', '')
if not subject.startswith('usr_'):
    sys.exit(f'/auth/me did not identify the user: {claims}')

# The tokens must NOT be here. This is the property the whole architecture exists for, so it is
# checked over the WHOLE response rather than by looking for one field name.
body = json.dumps(claims)
for secret in ('access_token', 'refresh_token', 'privateJwk'):
    if secret in body:
        sys.exit(f'{secret} reached the browser: {body}')

# And the cookie is opaque and small. 4096 bytes is the per-cookie limit browsers and proxies
# converge on; a session cookie anywhere near it is one claim away from being dropped.
# curl writes HttpOnly cookies with a `#HttpOnly_` prefix, so skipping every `#` line drops
# exactly the cookies that matter here -- the session cookie IS HttpOnly, which is the point.
def jar_cookies(text):
    for line in text.splitlines():
        line = line[len('#HttpOnly_'):] if line.startswith('#HttpOnly_') else line
        if line and not line.startswith('#'):
            yield line.split('\t')

# The APP's cookie specifically. Cookies ignore ports, so on loopback the jar also holds
# IronAuth's own `__Host-ironauth_session` from the login pages -- same host, different service.
# In production those are different hosts; here they are not, and asserting "one ironauth cookie"
# would be asserting something about the test setup rather than about the app.
jar = pathlib.Path('jar.txt').read_text(encoding='utf-8')
app_cookies = [c for c in jar_cookies(jar) if 'ironauth_bff' in c[5]]
if len(app_cookies) != 1:
    sys.exit(f'expected exactly one app session cookie, found {[c[5] for c in app_cookies]}')
size = len(app_cookies[0][5]) + len(app_cookies[0][6]) + 1
if size > 512:
    sys.exit(f'the session cookie is {size} bytes, which is not opaque-and-small')
print(f'one opaque session cookie, {size} bytes, no tokens in the browser')
PY
```

## 9. The prefetch-heavy page changes none of that

```bash quickstart
cd "$QS_DIR"
BEFORE=$(grep -c ironauth_bff jar.txt || true)   # the APP's cookie; the jar also holds IronAuth's own
for n in $(seq 0 19); do
  curl -s -b jar.txt -c jar.txt -o /dev/null \
    -H 'purpose: prefetch' -H 'next-router-prefetch: 1' \
    "$APP/auth/me?n=$n"
done
AFTER=$(grep -c ironauth_bff jar.txt || true)
test "$BEFORE" = "$AFTER" || { echo "prefetching changed the cookie jar: $BEFORE -> $AFTER"; exit 1; }
python3 - <<'PY'
import pathlib, sys

def jar_cookies(text):
    for line in text.splitlines():
        line = line[len('#HttpOnly_'):] if line.startswith('#HttpOnly_') else line
        if line and not line.startswith('#'):
            yield line.split('\t')

jar = pathlib.Path('jar.txt').read_text(encoding='utf-8')
app_cookies = [c for c in jar_cookies(jar) if 'ironauth_bff' in c[5]]
if len(app_cookies) != 1:
    sys.exit(f'twenty prefetches left {len(app_cookies)} app cookies: {[c[5] for c in app_cookies]}')

# CHUNKING HAS A SHAPE, and this is it: a library that splits an oversized cookie emits numbered
# siblings. Naming the shape means the check fails on the mechanism rather than on a size that
# might merely have crept up.
chunks = [c[5] for c in app_cookies if any(c[5].endswith(f'.{n}') or c[5].endswith(f'-{n}') for n in range(10))]
if chunks:
    sys.exit(f'the session cookie was chunked: {chunks}')
print(f'after 20 prefetches: still one cookie, {len(app_cookies[0][5]) + len(app_cookies[0][6]) + 1} bytes, no chunks')
PY
```

Twenty prefetches, one cookie, same size. **Nothing chunks**, because the cookie carries an opaque
id and never grows with the session: the tokens and claims stay in the store on the server.

## 10. Stop everything

```bash quickstart
kill "$(cat "$QS_DIR/next.pid")" 2>/dev/null || true
kill "$(cat "$QS_DIR/emulator.pid")" 2>/dev/null || true
echo "stopped"
```

## What you just proved

- A **clean App Router project** signs a real user in through IronAuth, with three route handlers.
- Every token is **server-side**. The browser holds an opaque id and nothing else.
- The login is **DPoP-bound** without configuration, because the seeded client is public and the
  BFF sender-constrains public clients by default.
- The session cookie stays **one small cookie** under prefetch pressure, so chunking never arises.
