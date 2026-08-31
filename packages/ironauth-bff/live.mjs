// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * The BFF against a REAL IronAuth (issue #116).
 *
 * Every other test in this package answers from a fake. A fake is written by the same person as
 * the code, from the same understanding, so it agrees with the code's mistakes: the previous one
 * replied 200 to any URL it was given, which is exactly why a BFF that built `${issuer}/token`
 * (a 404 against a real IronAuth) and sent no DPoP proof (refused outright for a public client)
 * passed everything it had.
 *
 * This drives the real emulator. It plays the browser: it takes the BFF's redirect, walks the
 * login and consent pages the way a person would, hands the callback back to the BFF, and then
 * checks the session works. Nothing here is stubbed.
 *
 *   node live.mjs <issuer> <client_id>
 */
import { callback, login, userinfo, thumbprint, MemorySessionStore, SESSION_COOKIE } from './dist/index.js';

const [issuer, clientId] = process.argv.slice(2);
if (!issuer || !clientId) {
  console.error('usage: node live.mjs <issuer> <client_id>');
  process.exit(2);
}

const REDIRECT_URI = 'http://127.0.0.1:3000/callback';
const USER = 'dev@example.test';
const PASSWORD = 'dev-password-not-for-production';

const failures = [];
let checked = 0;
function check(what, condition, detail = '') {
  checked++;
  if (!condition) {
    failures.push(`${what}${detail ? ` -- ${detail}` : ''}`);
  }
}

/** A cookie jar, because the login and consent pages are a session on the IdP. */
const jar = new Map();
function jarHeader() {
  return [...jar].map(([name, value]) => `${name}=${value}`).join('; ');
}
function rememberCookies(response) {
  for (const line of response.headers.getSetCookie?.() ?? []) {
    const [pair] = line.split(';');
    const index = pair.indexOf('=');
    jar.set(pair.slice(0, index).trim(), pair.slice(index + 1).trim());
  }
}

/** Fetch without following redirects, keeping the jar. */
async function hop(url, init = {}) {
  const response = await fetch(url, {
    ...init,
    redirect: 'manual',
    headers: { ...(init.headers ?? {}), cookie: jarHeader() },
  });
  rememberCookies(response);
  return response;
}

/** The `return_to` hidden field an interaction page carries. */
function returnTo(html) {
  const match = /name="return_to" value="([^"]*)"/.exec(html);
  if (!match) {
    throw new Error('no return_to on the interaction page');
  }
  return match[1]
    .replaceAll('&amp;', '&')
    .replaceAll('&quot;', '"')
    .replaceAll('&#39;', "'")
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>');
}

const store = new MemorySessionStore();
const config = {
  issuer,
  clientId,
  // NO clientSecret: the seeded client is PUBLIC, which is what makes DPoP mandatory here and
  // what the old code could not do at all.
  redirectUri: REDIRECT_URI,
  scope: 'openid',
  apiBase: `${new URL(issuer).origin}`,
  sessionMaxAgeSeconds: 3600,
  store,
};

// 1. The BFF starts the flow.
const started = await login(config, {
  method: 'GET',
  url: 'http://127.0.0.1:3000/auth/login?return_to=/dashboard',
  headers: new Headers(),
});
check('login returns a redirect', started.kind === 'redirect', `got ${started.kind}`);
const bffCookie = /(?:^|;\s*)([^=]+)=([^;]*)/.exec(started.setCookie ?? '');
check('login sets the BFF session cookie', started.setCookie?.includes(SESSION_COOKIE) === true);

// The authorize URL must come from DISCOVERY, so it is NOT under the issuer's environment path.
check(
  'the authorize endpoint is not built by concatenating the issuer',
  !started.location.startsWith(`${issuer}/authorize`),
  started.location,
);

// 2. Play the browser: walk to the code.
let next = started.location;
let landed;
for (let step = 0; step < 8; step++) {
  const response = await hop(next);
  if (response.status >= 300 && response.status < 400) {
    const location = new URL(response.headers.get('location'), next).toString();
    if (location.startsWith(REDIRECT_URI)) {
      landed = location;
      break;
    }
    next = location;
    continue;
  }
  const html = await response.text();
  const action = new URL(/<form[^>]*action="([^"]*)"/.exec(html)[1], next).toString();
  const form = new URLSearchParams({ return_to: returnTo(html) });
  if (html.includes('name="password"')) {
    form.set('identifier', USER);
    form.set('password', PASSWORD);
  } else {
    form.set('decision', 'allow');
  }
  const posted = await hop(action, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  });
  next = new URL(posted.headers.get('location'), action).toString();
  if (next.startsWith(REDIRECT_URI)) {
    landed = next;
    break;
  }
}
check('the browser reached the redirect_uri with a code', landed?.includes('code=') === true, landed);

// 3. Hand the callback back to the BFF. THIS is the exchange that needs DPoP.
const done = await callback(config, {
  method: 'GET',
  url: landed,
  headers: new Headers({ cookie: `${bffCookie[1]}=${bffCookie[2]}` }),
});
check(
  'the code exchange succeeded against the REAL token endpoint',
  done.kind === 'redirect',
  done.kind === 'upstream_error' ? `${done.status}: ${done.detail}` : done.kind,
);
check('the browser is returned to where it started', done.location === '/dashboard', done.location);

// STOP HERE IF THE EXCHANGE FAILED. Everything below reads the session the exchange created, so
// continuing produces a crash inside a cookie regex -- which is a true failure reported as a
// stack trace about the wrong line. Measured: with DPoP disabled, this script used to die at
// `sessionCookie[1]` instead of saying the code exchange was refused.
if (done.kind !== 'redirect' || !done.setCookie) {
  console.error('FAIL: the BFF does not work against a real IronAuth');
  failures.forEach((failure) => console.error(`  - ${failure}`));
  console.error('  - the login did not establish a session, so the checks below could not run');
  process.exit(1);
}

// 4. The session works, and the tokens never left the server.
const sessionCookie = /(?:^|;\s*)([^=]+)=([^;]*)/.exec(done.setCookie);
const who = await userinfo(config, {
  method: 'GET',
  url: 'http://127.0.0.1:3000/auth/me',
  headers: new Headers({ cookie: `${sessionCookie[1]}=${sessionCookie[2]}` }),
});
check('the session identifies the user', who.kind === 'json', who.kind);
if (who.kind === 'json') {
  // The claims are NESTED under `claims`, which is the shape the frontend actually receives.
  check(
    'the claims name the seeded subject',
    typeof who.body.claims?.sub === 'string' && who.body.claims.sub.startsWith('usr_'),
    JSON.stringify(who.body),
  );
  // Checked over the WHOLE serialised body, not one property: the tokens are what this
  // architecture exists to keep out of the browser, and a nested copy would be just as leaked.
  const serialised = JSON.stringify(who.body);
  check(
    'no token is readable from the browser',
    !serialised.includes('access_token') && !serialised.includes('refresh_token') && !serialised.includes('privateJwk'),
    serialised,
  );
}

// 5b. THE SERVER BOUND THE TOKEN TO OUR KEY, asserted rather than inferred.
//
// The callback refuses a mismatch, so a passing login already implies this. Implying is not
// measuring: if the server stopped emitting `cnf` altogether the check would go quiet and this
// script would still be green, having stopped testing the binding at all.
{
  const record = await store.getSession(sessionCookie[2]);
  const [, claims] = record.accessToken.split('.');
  const cnf = JSON.parse(Buffer.from(claims, 'base64url').toString('utf8')).cnf;
  check('the access token carries a cnf.jkt', typeof cnf?.jkt === 'string', JSON.stringify(cnf));
  check(
    'the token is bound to the key this session proved possession of',
    cnf?.jkt === (await thumbprint(record.dpopKey.publicJwk)),
    `${cnf?.jkt} vs our key`,
  );
}

// 5. The session record really is DPoP-bound. Without this the login could have succeeded on a
// server that did not require a proof, and the binding would be untested.
const record = await store.getSession(sessionCookie[2]);
check('the session holds a DPoP key', record?.dpopKey?.privateJwk !== undefined);
check('the DPoP key is EC P-256', record?.dpopKey?.publicJwk?.crv === 'P-256');

if (checked < 13) {
  failures.push(`only ${checked} checks ran`);
}
if (failures.length > 0) {
  console.error('FAIL: the BFF does not work against a real IronAuth');
  failures.forEach((failure) => console.error(`  - ${failure}`));
  process.exit(1);
}
console.log(`bff live: ${checked} checks against a real IronAuth OK`);
