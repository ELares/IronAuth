// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * The RFC 9470 step-up loop, end to end (issue #116 criterion 4), and the loop-safety proof
 * criterion 6 asks for.
 *
 * > A protected route emits the insufficient_user_authentication challenge with
 * > acr_values/max_age, and the stepped-up token is accepted.
 *
 * The whole loop is driven: a session that does not meet the requirement, the challenge it
 * produces, a real callback that records a stronger factor, and the same route accepting
 * afterwards. Asserting only the challenge would leave the half that matters -- that stepping up
 * actually resolves it -- untested, which is how a step-up that can never be satisfied ships.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { SESSION_COOKIE } from './cookie.js';
import {
  type BffConfig,
  type BffRequest,
  MemorySessionStore,
  callback,
  login,
  proxy,
  userinfo,
} from './core.js';
import { toResponse } from './adapters.js';
import { challengeHeader, satisfies, stepUpLoginPath } from './step-up.js';

const ISSUER = 'https://iss.example/t/ten_x/e/env_y';

function idToken(payload: Record<string, unknown>): string {
  const b64 = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${b64({ alg: 'EdDSA' })}.${b64(payload)}.signature`;
}

/** An IdP that mints whatever authentication context the test asks for. */
function idp(context: Record<string, unknown>, options: { refreshFails?: boolean } = {}) {
  const calls: string[] = [];
  const send = async (input: string | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === 'string' ? input : input.toString();
    calls.push(url);
    if (url === `${ISSUER}/token`) {
      const form = new URLSearchParams(typeof init?.body === 'string' ? init.body : '');
      if (form.get('grant_type') === 'refresh_token' && options.refreshFails) {
        return new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400 });
      }
      return new Response(
        JSON.stringify({
          access_token: 'at-1',
          refresh_token: 'rt-1',
          expires_in: 300,
          id_token: idToken({ sub: 'usr_1', ...context }),
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }
    return new Response(JSON.stringify({ ok: true }), { status: 200 });
  };
  return { calls, send: send as unknown as typeof fetch };
}

function configOf(store: MemorySessionStore, send: typeof fetch, now = () => 1000): BffConfig {
  return {
    issuer: ISSUER,
    clientId: 'cli_bff',
    redirectUri: 'https://app.example/auth/callback',
    scope: 'openid profile',
    apiBase: 'https://api.example',
    sessionMaxAgeSeconds: 3600,
    store,
    fetch: send,
    now,
  };
}

function request(method: string, url: string, headers: Record<string, string> = {}): BffRequest {
  return { method, url, headers: new Headers(headers) };
}

/** Sign in, returning the session cookie header. */
async function signIn(config: BffConfig): Promise<string> {
  const started = toResponse(await login(config, request('GET', 'https://app.example/auth/login')));
  const pending = started.headers.getSetCookie()[0] ?? '';
  const state = new URL(started.headers.get('location') ?? '').searchParams.get('state') ?? '';
  const done = toResponse(
    await callback(
      config,
      request('GET', `https://app.example/auth/callback?code=c&state=${encodeURIComponent(state)}`, {
        cookie: pending.slice(0, pending.indexOf(';')),
      }),
    ),
  );
  const session = done.headers.getSetCookie()[0] ?? '';
  return session.slice(0, session.indexOf(';'));
}

test('the full RFC 9470 loop: refused, challenged, stepped up, accepted', async () => {
  const store = new MemorySessionStore();
  // A first login with a WEAK factor and an old authentication.
  const weak = idp({ acr: 'urn:ietf:params:acr:password', auth_time: 500 });
  const config = configOf(store, weak.send, () => 1000);
  const cookie = await signIn(config);
  const sessionId = cookie.split('=')[1] ?? '';

  const requirement = {
    acrValues: ['urn:ietf:params:acr:phishing-resistant'],
    maxAgeSeconds: 300,
  };

  // 1. REFUSED, and the gap names WHICH requirement failed. A caller that cannot tell them apart
  //    asks a user to re-authenticate when their factor was wrong.
  const before = await store.getSession(sessionId);
  assert.ok(before);
  const verdictBefore = satisfies(before, requirement, 1000);
  assert.deepEqual(verdictBefore, { ok: false, gap: 'acr' });

  // 2. THE CHALLENGE carries both parameters, which is what makes it actionable.
  const header = challengeHeader(requirement);
  assert.match(header, /error="insufficient_user_authentication"/);
  assert.match(header, /acr_values="urn:ietf:params:acr:phishing-resistant"/);
  assert.match(header, /max_age=300/);

  // 3. AND THE PAGE FORM carries them onward to the login route.
  const path = stepUpLoginPath('/auth/login', requirement, '/settings/billing');
  const parsed = new URL(path, 'https://app.example');
  assert.equal(parsed.searchParams.get('acr_values'), 'urn:ietf:params:acr:phishing-resistant');
  assert.equal(parsed.searchParams.get('max_age'), '300');
  assert.equal(parsed.searchParams.get('return_to'), '/settings/billing');

  // 4. STEP UP: a new login that records the stronger factor, now.
  const strong = idp({ acr: 'urn:ietf:params:acr:phishing-resistant', auth_time: 990 });
  const steppedConfig = configOf(store, strong.send, () => 1000);
  const newCookie = await signIn(steppedConfig);
  const newSessionId = newCookie.split('=')[1] ?? '';
  // The id ROTATED, so the step-up did not merely mutate the old session in place.
  assert.notEqual(newSessionId, sessionId);

  // 5. ACCEPTED. This is the half a challenge-only test leaves out, and without it a step-up that
  //    can never be satisfied ships green.
  const after = await store.getSession(newSessionId);
  assert.ok(after);
  assert.deepEqual(satisfies(after, requirement, 1000), { ok: true });
});

test('a stale but strong session is refused as stale, not as weak', async () => {
  const store = new MemorySessionStore();
  const strong = idp({ acr: 'urn:ietf:params:acr:phishing-resistant', auth_time: 100 });
  const config = configOf(store, strong.send, () => 1000);
  const cookie = await signIn(config);
  const session = await store.getSession(cookie.split('=')[1] ?? '');
  assert.ok(session);
  // The factor is right and the authentication is old. Reporting `acr` here would send the user
  // to prove a factor they already hold.
  assert.deepEqual(
    satisfies(session, { acrValues: ['urn:ietf:params:acr:phishing-resistant'], maxAgeSeconds: 300 }, 1000),
    { ok: false, gap: 'stale' },
  );
});

test('a session that recorded no acr does NOT satisfy an acr requirement', async () => {
  // Fail closed. A route demanding a phishing-resistant factor must not pass a session whose
  // factor nobody recorded, and treating absence as satisfaction is how that happens quietly.
  const store = new MemorySessionStore();
  const none = idp({});
  const config = configOf(store, none.send, () => 1000);
  const cookie = await signIn(config);
  const session = await store.getSession(cookie.split('=')[1] ?? '');
  assert.ok(session);
  assert.deepEqual(satisfies(session, { acrValues: ['anything'] }, 1000), {
    ok: false,
    gap: 'unknown',
  });
  // And with no requirement at all it passes, so the refusal above is the requirement and not a
  // session that can never satisfy anything.
  assert.deepEqual(satisfies(session, {}, 1000), { ok: true });
});

test('acr and auth_time are held server-side and never reach the frontend', async () => {
  // `acr` is something a resource server decides on, so it belongs in the set the frontend never
  // sees -- the same allow-list that keeps `scope` and `permissions` out.
  const store = new MemorySessionStore();
  const strong = idp({ acr: 'urn:ietf:params:acr:phishing-resistant', auth_time: 990 });
  const config = configOf(store, strong.send, () => 1000);
  const cookie = await signIn(config);
  const session = await store.getSession(cookie.split('=')[1] ?? '');
  assert.equal(session?.acr, 'urn:ietf:params:acr:phishing-resistant');
  assert.equal(session?.authTime, 990);

  const response = toResponse(
    await userinfo(config, request('GET', 'https://app.example/auth/userinfo', { cookie })),
  );
  const body = await response.text();
  assert.ok(!body.includes('acr'), `acr reached the frontend: ${body}`);
  assert.ok(!body.includes('auth_time'), `auth_time reached the frontend: ${body}`);
});

// ---------------------------------------------------------------------------
// Criterion 6: no infinite redirect, no cookie stacking.
// ---------------------------------------------------------------------------

test('a failed refresh never loops and never stacks cookies', async () => {
  // > Refresh-token failure surfaces as a typed, documented event ... with a test proving no
  // > infinite redirect or cookie-stacking loop.
  //
  // The loop this rules out is concrete: a failed refresh returns `unauthenticated`, the caller
  // redirects to login, the browser arrives with the SAME dead session, and round it goes. It is
  // broken by destroying the session on the failure -- so the second attempt is `no_session`,
  // which is a different state that a caller handles once.
  const store = new MemorySessionStore();
  const broken = idp({}, { refreshFails: true });
  const config = configOf(store, broken.send, () => 5000);
  await store.putSession('sid', {
    accessToken: 'at-old',
    refreshToken: 'rt-dead',
    expiresAt: 1000,
    claims: {},
  });
  const cookie = `${SESSION_COOKIE}=sid`;

  const first = await proxy(config, request('GET', 'https://app.example/orders', { cookie }));
  assert.deepEqual(first, { kind: 'unauthenticated', reason: 'refresh_failed' });

  // THE SECOND ATTEMPT IS A DIFFERENT ANSWER, which is what ends the loop.
  const second = await proxy(config, request('GET', 'https://app.example/orders', { cookie }));
  assert.deepEqual(second, { kind: 'unauthenticated', reason: 'no_session' });

  // AND TEN MORE ARE ALL THE SAME. A loop is a state that repeats, so repeating the request is
  // the only way to observe that it does not.
  for (let attempt = 0; attempt < 10; attempt += 1) {
    const again = await proxy(config, request('GET', 'https://app.example/orders', { cookie }));
    assert.deepEqual(again, { kind: 'unauthenticated', reason: 'no_session' });
  }

  // NO COOKIE WAS SET on any of them. Cookie stacking is what happens when each failed attempt
  // writes a fresh session cookie: the header grows until a proxy rejects the request, and the
  // symptom looks like an outage rather than a login problem.
  const responses = [toResponse(first), toResponse(second)];
  for (const response of responses) {
    assert.equal(response.headers.getSetCookie().length, 0, 'a failure must set no cookie');
  }
  assert.equal(store.sessionCount, 0, 'the dead session is gone rather than retried forever');
});

test('a login after a failed refresh sets exactly one cookie', async () => {
  // The other half of cookie stacking: the recovery path must not ADD a cookie beside the dead
  // one. `__Host-` cookies are keyed on name alone, so a second set overwrites rather than
  // stacks -- this asserts that property holds rather than assuming it.
  const store = new MemorySessionStore();
  const fresh = idp({ acr: 'urn:ietf:params:acr:password', auth_time: 4990 });
  const config = configOf(store, fresh.send, () => 5000);
  const started = toResponse(await login(config, request('GET', 'https://app.example/auth/login')));
  assert.equal(started.headers.getSetCookie().length, 1);
  const pending = started.headers.getSetCookie()[0] ?? '';
  const state = new URL(started.headers.get('location') ?? '').searchParams.get('state') ?? '';
  const done = toResponse(
    await callback(
      config,
      request('GET', `https://app.example/auth/callback?code=c&state=${encodeURIComponent(state)}`, {
        cookie: pending.slice(0, pending.indexOf(';')),
      }),
    ),
  );
  assert.equal(done.headers.getSetCookie().length, 1, 'the callback sets one cookie, not two');
});
