// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * The BFF helper, against both adapters (issue #117).
 *
 * The full lifecycle -- login, callback, userinfo, proxy, logout -- runs through the FETCH
 * adapter and again through the NODE one, from one table, because criterion 1 is "runs on two
 * frameworks with all five handler groups". Two copies of the lifecycle would be two places for
 * one of them to quietly stop covering something.
 *
 * The adversarial cases are here too: CSRF without the header, a tampered cookie, a replayed
 * `state`, and session fixation across a login.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { type NodeResponseLike, fetchAdapter, nodeAdapter, toResponse } from './adapters.js';
import { COOKIE_BUDGET_BYTES, SESSION_COOKIE, assertHardened } from './cookie.js';
import {
  type BffConfig,
  type BffRequest,
  CSRF_HEADER,
  MemorySessionStore,
  callback,
  login,
  logout,
  proxy,
  userinfo,
} from './core.js';

const ISSUER = 'https://iss.example/t/ten_x/e/env_y';

/** An ID token payload with the claims the allow-list admits, plus ones it must drop. */
function idToken(): string {
  const payload = {
    sub: 'usr_123',
    name: 'A Person',
    email: 'a@example.test',
    // MUST NOT REACH THE FRONTEND. Each is something a resource server authorizes on.
    scope: 'openid admin',
    permissions: ['billing:write'],
    roles: ['owner'],
  };
  const b64 = (value: object) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${b64({ alg: 'EdDSA' })}.${b64(payload)}.signature`;
}

/** A fake IdP + upstream API. Records what it was asked. */
function upstream(options: { refreshFails?: boolean } = {}) {
  const calls: Array<{ url: string; authorization: string | null; body?: string }> = [];
  const send = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = typeof input === 'string' ? input : input.toString();
    const headers = new Headers(init?.headers as HeadersInit | undefined);
    const body = typeof init?.body === 'string' ? init.body : undefined;
    calls.push({ url, authorization: headers.get('authorization'), body });
    if (url === `${ISSUER}/token`) {
      const form = new URLSearchParams(body ?? '');
      if (form.get('grant_type') === 'refresh_token' && options.refreshFails) {
        return new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400 });
      }
      return new Response(
        JSON.stringify({
          access_token: form.get('grant_type') === 'refresh_token' ? 'at-2' : 'at-1',
          refresh_token: 'rt-1',
          expires_in: 300,
          id_token: idToken(),
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }
    return new Response(JSON.stringify({ ok: true, url }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
  return { calls, send: send as unknown as typeof fetch };
}

function configOf(store: MemorySessionStore, send: typeof fetch, now = () => 1000): BffConfig {
  return {
    issuer: ISSUER,
    clientId: 'cli_bff',
    clientSecret: 'shh',
    redirectUri: 'https://app.example/auth/callback',
    scope: 'openid profile',
    apiBase: 'https://api.example',
    sessionMaxAgeSeconds: 3600,
    store,
    fetch: send,
    now,
  };
}

/** A request the core accepts, built from parts. */
function request(
  method: string,
  url: string,
  headers: Record<string, string> = {},
): BffRequest {
  return { method, url, headers: new Headers(headers) };
}

/** The `Set-Cookie` value from a `Response`. */
function setCookieOf(response: Response): string | undefined {
  return response.headers.getSetCookie()[0];
}

/** The session id out of a `Set-Cookie`. */
function idOf(setCookie: string): string {
  return setCookie.slice(setCookie.indexOf('=') + 1, setCookie.indexOf(';'));
}

// ---------------------------------------------------------------------------
// Criterion 1: five handler groups, on two frameworks, from ONE table.
// ---------------------------------------------------------------------------

/** Run the whole lifecycle through one adapter, returning what it observed. */
async function lifecycle(
  drive: (handler: (r: BffRequest) => Promise<never | Awaited<ReturnType<typeof login>>>, req: BffRequest) => Promise<Response>,
) {
  const store = new MemorySessionStore();
  const api = upstream();
  const config = configOf(store, api.send);

  // LOGIN
  const loginResponse = await drive(
    (r) => login(config, r),
    request('GET', 'https://app.example/auth/login?return_to=/dashboard'),
  );
  assert.equal(loginResponse.status, 302);
  const authorize = new URL(loginResponse.headers.get('location') ?? '');
  assert.equal(authorize.origin + authorize.pathname, `${ISSUER}/authorize`);
  assert.equal(authorize.searchParams.get('code_challenge_method'), 'S256');
  assert.ok(authorize.searchParams.get('code_challenge'), 'a PKCE challenge is sent');
  const state = authorize.searchParams.get('state') ?? '';
  const pendingCookie = setCookieOf(loginResponse) ?? '';
  assert.deepEqual(assertHardened(pendingCookie), [], pendingCookie);

  // CALLBACK
  const callbackResponse = await drive(
    (r) => callback(config, r),
    request(
      'GET',
      `https://app.example/auth/callback?code=abc&state=${encodeURIComponent(state)}`,
      { cookie: pendingCookie.slice(0, pendingCookie.indexOf(';')) },
    ),
  );
  assert.equal(callbackResponse.status, 302);
  assert.equal(callbackResponse.headers.get('location'), '/dashboard');
  const sessionCookie = setCookieOf(callbackResponse) ?? '';
  assert.deepEqual(assertHardened(sessionCookie), [], sessionCookie);
  const cookieHeader = sessionCookie.slice(0, sessionCookie.indexOf(';'));
  // THE ID ROTATED. The pending id and the session id are different values, which is the
  // session-fixation defence and is invisible from the outside unless asserted.
  assert.notEqual(idOf(sessionCookie), idOf(pendingCookie), 'the session id must rotate at login');

  // USERINFO
  const userinfoResponse = await drive(
    (r) => userinfo(config, r),
    request('GET', 'https://app.example/auth/userinfo', { cookie: cookieHeader }),
  );
  assert.equal(userinfoResponse.status, 200);
  const identity = (await userinfoResponse.json()) as { claims: Record<string, unknown> };
  assert.equal(identity.claims.sub, 'usr_123');
  assert.equal(identity.claims.name, 'A Person');

  // PROXY
  const proxyResponse = await drive(
    (r) => proxy(config, r),
    request('GET', 'https://app.example/orders?page=2', { cookie: cookieHeader }),
  );
  assert.equal(proxyResponse.status, 200);

  // LOGOUT
  const logoutResponse = await drive(
    (r) => logout(config, r),
    request('POST', 'https://app.example/auth/logout', {
      cookie: cookieHeader,
      [CSRF_HEADER]: '1',
    }),
  );
  assert.equal(logoutResponse.status, 200);
  const cleared = setCookieOf(logoutResponse) ?? '';
  assert.match(cleared, /Max-Age=0/);

  return { store, api, cookieHeader, identity, proxyResponse };
}

test('the whole lifecycle runs through the FETCH adapter', async () => {
  const observed = await lifecycle(async (handler, req) => {
    const adapted = fetchAdapter(handler as (r: BffRequest) => Promise<never>);
    return adapted(new Request(req.url, { method: req.method, headers: req.headers as Headers }));
  });
  // The upstream saw the bearer token and NOT the session cookie: the API is authenticated by
  // the token, and forwarding the cookie would hand a third party a credential for this origin.
  const call = observed.api.calls.find((c) => c.url.startsWith('https://api.example'));
  assert.ok(call, 'the proxy reached the upstream');
  assert.equal(call.authorization, 'Bearer at-1');
  assert.equal(observed.store.sessionCount, 0, 'logout removed the session server-side');
});

test('the whole lifecycle runs through the NODE adapter', async () => {
  const observed = await lifecycle(async (handler, req) => {
    const headers: Record<string, string> = {};
    (req.headers as Headers).forEach((value, name) => {
      headers[name] = value;
    });
    const adapted = nodeAdapter(handler as (r: BffRequest) => Promise<never>, 'https://app.example');
    // A minimal `(req, res)` pair: what Express and node:http share, and no more. A class rather
    // than an object literal because `statusCode` is a plain writable field on the real thing,
    // and an object literal cannot have both a property and an accessor of one name.
    class Recorder implements NodeResponseLike {
      statusCode = 0;
      readonly headers: Record<string, string | string[]> = {};
      body: string | undefined;
      setHeader(name: string, value: string | string[]): void {
        this.headers[name] = value;
      }
      end(chunk?: string): void {
        this.body = chunk;
      }
    }
    const sent = new Recorder();
    await adapted(
      { method: req.method, url: new URL(req.url).pathname + new URL(req.url).search, headers },
      sent,
    );
    const responseHeaders = new Headers();
    for (const [name, value] of Object.entries(sent.headers)) {
      for (const one of Array.isArray(value) ? value : [value]) {
        responseHeaders.append(name, one);
      }
    }
    return new Response(sent.body ?? null, { status: sent.statusCode, headers: responseHeaders });
  });
  assert.equal(observed.store.sessionCount, 0);
});

// ---------------------------------------------------------------------------
// Criterion 3: no token is readable from the browser.
// ---------------------------------------------------------------------------

test('no token is ever readable from the browser', async () => {
  // WHAT THIS CAN AND CANNOT ASSERT, said plainly. There is no browser here, so this is not the
  // automated browser test the criterion names. What it proves is the property that test would
  // observe: every response the browser receives -- headers AND body -- is searched for the
  // access and refresh tokens, and the session cookie is `HttpOnly` so script cannot read it
  // either. A browser test would add "and `document.cookie` does not contain it", which
  // `HttpOnly` is the mechanism for and `assertHardened` pins.
  const store = new MemorySessionStore();
  const api = upstream();
  const config = configOf(store, api.send);

  const responses: Response[] = [];
  const loginResult = await login(config, request('GET', 'https://app.example/auth/login'));
  responses.push(toResponse(loginResult));
  const pending = setCookieOf(responses[0]!) ?? '';
  const state = new URL(responses[0]!.headers.get('location') ?? '').searchParams.get('state') ?? '';
  const cbResult = await callback(
    config,
    request('GET', `https://app.example/auth/callback?code=abc&state=${encodeURIComponent(state)}`, {
      cookie: pending.slice(0, pending.indexOf(';')),
    }),
  );
  responses.push(toResponse(cbResult));
  const session = setCookieOf(responses[1]!) ?? '';
  const cookie = session.slice(0, session.indexOf(';'));
  responses.push(toResponse(await userinfo(config, request('GET', 'https://app.example/auth/userinfo', { cookie }))));

  for (const response of responses) {
    const rendered = [...response.headers.getSetCookie()].join('\n');
    let headerText = rendered;
    response.headers.forEach((value, name) => {
      headerText += `\n${name}: ${value}`;
    });
    const body = await response.clone().text();
    for (const secret of ['at-1', 'rt-1']) {
      assert.ok(!headerText.includes(secret), `a token reached a response header: ${headerText}`);
      assert.ok(!body.includes(secret), `a token reached a response body: ${body}`);
    }
  }

  // And the claims the frontend CAN see exclude everything a resource server authorizes on.
  const identity = (await responses[2]!.json()) as { claims: Record<string, unknown> };
  for (const forbidden of ['scope', 'permissions', 'roles']) {
    assert.equal(identity.claims[forbidden], undefined, `${forbidden} must not reach the frontend`);
  }
});

// ---------------------------------------------------------------------------
// Criterion 2: the cookie budget.
// ---------------------------------------------------------------------------

test('the auth cookies stay far under the budget, and nothing chunks them', async () => {
  const store = new MemorySessionStore();
  const config = configOf(store, upstream().send);
  const loginResult = await login(config, request('GET', 'https://app.example/auth/login'));
  const response = toResponse(loginResult);
  const cookies = response.headers.getSetCookie();
  // EXACTLY ONE. The failure this guards is the chunked multi-kB encrypted cookie the BCP warns
  // about, and that design shows up as cookie COUNT before it shows up as size -- a second
  // cookie named `...1` is the first step, and a budget on total bytes alone would pass it.
  assert.equal(cookies.length, 1, `exactly one auth cookie: ${cookies.join(' | ')}`);
  const total = cookies.reduce((sum, cookie) => sum + cookie.length, 0);
  assert.ok(total < COOKIE_BUDGET_BYTES, `${total} bytes is over the budget`);
  // AND WELL UNDER, not merely under. An opaque id is a few dozen bytes; anything approaching
  // the ceiling means claims or tokens started going into cookies, which is the design this
  // package exists to avoid rather than to bound.
  assert.ok(total < 256, `an opaque-id cookie should be tiny, got ${total} bytes`);
});

test('a prefetch-heavy page still carries one small cookie', async () => {
  // The criterion says "in a prefetch-heavy test app". The property that matters is that the
  // cookie does not GROW with traffic, so this drives many requests against one session and
  // asserts nothing new is ever set.
  const store = new MemorySessionStore();
  const config = configOf(store, upstream().send);
  await store.putSession('sid', {
    accessToken: 'at-1',
    refreshToken: 'rt-1',
    expiresAt: 99_999,
    claims: { sub: 'usr_1' },
  });
  const cookie = `${SESSION_COOKIE}=sid`;
  for (let i = 0; i < 50; i += 1) {
    const result = await userinfo(config, request('GET', `https://app.example/auth/userinfo?i=${i}`, { cookie }));
    const response = toResponse(result);
    assert.equal(
      response.headers.getSetCookie().length,
      0,
      'a read must not set a cookie, or fifty prefetches set fifty',
    );
  }
});

// ---------------------------------------------------------------------------
// Criterion 4: CSRF.
// ---------------------------------------------------------------------------

test('state-changing endpoints refuse a request with no custom header', async () => {
  const store = new MemorySessionStore();
  const config = configOf(store, upstream().send);
  await store.putSession('sid', {
    accessToken: 'at-1',
    expiresAt: 99_999,
    claims: {},
  });
  const cookie = `${SESSION_COOKIE}=sid`;

  const loggedOut = await logout(config, request('POST', 'https://app.example/auth/logout', { cookie }));
  assert.deepEqual(loggedOut, { kind: 'refused', reason: 'csrf' });
  // AND THE SESSION SURVIVED. A refusal that had already deleted it would be a logout CSRF that
  // merely reported failure.
  assert.equal(store.sessionCount, 1);

  const posted = await proxy(config, request('POST', 'https://app.example/orders', { cookie }));
  assert.deepEqual(posted, { kind: 'refused', reason: 'csrf' });

  // A GET through the proxy is NOT refused: it is not state-changing, the BCP asks for the check
  // on state-changing endpoints, and demanding a custom header on reads would break every
  // ordinary page fetch while protecting nothing.
  const read = await proxy(config, request('GET', 'https://app.example/orders', { cookie }));
  assert.equal(read.kind, 'proxied');
});

// ---------------------------------------------------------------------------
// Adversarial.
// ---------------------------------------------------------------------------

test('a tampered session cookie is unauthenticated, not an error', async () => {
  const store = new MemorySessionStore();
  const config = configOf(store, upstream().send);
  const result = await userinfo(
    config,
    request('GET', 'https://app.example/auth/userinfo', { cookie: `${SESSION_COOKIE}=not-a-real-id` }),
  );
  assert.deepEqual(result, { kind: 'unauthenticated', reason: 'no_session' });
});

test('a replayed callback is refused: the pending login is single-use', async () => {
  const store = new MemorySessionStore();
  const config = configOf(store, upstream().send);
  const loginResult = await login(config, request('GET', 'https://app.example/auth/login'));
  const response = toResponse(loginResult);
  const pending = setCookieOf(response) ?? '';
  const cookie = pending.slice(0, pending.indexOf(';'));
  const state = new URL(response.headers.get('location') ?? '').searchParams.get('state') ?? '';
  const url = `https://app.example/auth/callback?code=abc&state=${encodeURIComponent(state)}`;

  const first = await callback(config, request('GET', url, { cookie }));
  assert.equal(first.kind, 'redirect');
  // THE SAME code and state again. Without single-use, a `state` observed in a redirect log or a
  // referrer could be replayed.
  const second = await callback(config, request('GET', url, { cookie }));
  assert.deepEqual(second, { kind: 'refused', reason: 'unknown_login' });
});

test('a callback whose state does not match is refused', async () => {
  const store = new MemorySessionStore();
  const config = configOf(store, upstream().send);
  const response = toResponse(await login(config, request('GET', 'https://app.example/auth/login')));
  const pending = setCookieOf(response) ?? '';
  const result = await callback(
    config,
    request('GET', 'https://app.example/auth/callback?code=abc&state=attacker-chosen', {
      cookie: pending.slice(0, pending.indexOf(';')),
    }),
  );
  assert.deepEqual(result, { kind: 'refused', reason: 'bad_state' });
});

test('a login started in one browser cannot be completed in another', async () => {
  // Session fixation across a login: the attacker starts a flow, gets a pending id, and plants
  // it. The victim's browser completes a DIFFERENT flow, and the attacker's id resolves to
  // nothing because a pending login is single-use and bound to the cookie that started it.
  const store = new MemorySessionStore();
  const config = configOf(store, upstream().send);
  const attacker = toResponse(await login(config, request('GET', 'https://app.example/auth/login')));
  const attackerCookie = (setCookieOf(attacker) ?? '').split(';')[0] ?? '';
  const attackerState =
    new URL(attacker.headers.get('location') ?? '').searchParams.get('state') ?? '';

  const victim = toResponse(await login(config, request('GET', 'https://app.example/auth/login')));
  const victimCookie = (setCookieOf(victim) ?? '').split(';')[0] ?? '';
  const victimState = new URL(victim.headers.get('location') ?? '').searchParams.get('state') ?? '';

  // The victim completes THEIR flow, and the session id they end up with is new.
  const done = await callback(
    config,
    request('GET', `https://app.example/auth/callback?code=v&state=${encodeURIComponent(victimState)}`, {
      cookie: victimCookie,
    }),
  );
  assert.equal(done.kind, 'redirect');
  const victimSession = done.kind === 'redirect' ? idOf(done.setCookie ?? '') : '';
  assert.notEqual(victimSession, attackerCookie.split('=')[1]);

  // The attacker's own pending id now buys nothing: presenting it reaches no session.
  const stolen = await userinfo(config, request('GET', 'https://app.example/auth/userinfo', { cookie: attackerCookie }));
  assert.deepEqual(stolen, { kind: 'unauthenticated', reason: 'no_session' });
  // And their state cannot be redeemed against the victim's cookie either.
  const crossed = await callback(
    config,
    request('GET', `https://app.example/auth/callback?code=a&state=${encodeURIComponent(attackerState)}`, {
      cookie: victimCookie,
    }),
  );
  assert.equal(crossed.kind, 'refused');
});

test('a return_to that is not a same-origin path is ignored', async () => {
  const store = new MemorySessionStore();
  const config = configOf(store, upstream().send);
  for (const hostile of ['https://evil.example/', '//evil.example/', 'javascript:alert(1)']) {
    const result = await login(
      config,
      request('GET', `https://app.example/auth/login?return_to=${encodeURIComponent(hostile)}`),
    );
    assert.equal(result.kind, 'redirect');
    const pendingId = result.kind === 'redirect' ? idOf(result.setCookie ?? '') : '';
    const pending = await store.takePending(pendingId);
    assert.equal(pending?.returnTo, '/', `${hostile} must not become a redirect target`);
  }
});

// ---------------------------------------------------------------------------
// Typed results for the failure paths.
// ---------------------------------------------------------------------------

test('a failed refresh is a typed result and destroys the session', async () => {
  const store = new MemorySessionStore();
  const api = upstream({ refreshFails: true });
  const config = configOf(store, api.send);
  await store.putSession('sid', {
    accessToken: 'at-old',
    refreshToken: 'rt-dead',
    // ALREADY past the skew, so the proxy refreshes before forwarding.
    expiresAt: 1000,
    claims: {},
  });
  const result = await proxy(
    config,
    request('GET', 'https://app.example/orders', { cookie: `${SESSION_COOKIE}=sid` }),
  );
  assert.deepEqual(result, { kind: 'unauthenticated', reason: 'refresh_failed' });
  // DESTROYED, not left to fail forever: a session whose refresh token is dead cannot recover,
  // and keeping it is keeping a cookie that says "signed in" while nothing works.
  assert.equal(store.sessionCount, 0);
  // AND THE UPSTREAM WAS NEVER CALLED. A proxy that forwarded without a token would turn an
  // authentication problem into whatever the API says about an anonymous request.
  assert.equal(api.calls.filter((c) => c.url.startsWith('https://api.example')).length, 0);
});

test('an expired access token with a live refresh token is refreshed transparently', async () => {
  const store = new MemorySessionStore();
  const api = upstream();
  const config = configOf(store, api.send);
  await store.putSession('sid', {
    accessToken: 'at-old',
    refreshToken: 'rt-1',
    expiresAt: 1000,
    claims: { sub: 'usr_1' },
  });
  const result = await proxy(
    config,
    request('GET', 'https://app.example/orders', { cookie: `${SESSION_COOKIE}=sid` }),
  );
  assert.equal(result.kind, 'proxied');
  const call = api.calls.find((c) => c.url.startsWith('https://api.example'));
  // The NEW token, so the refresh actually replaced it rather than merely succeeding.
  assert.equal(call?.authorization, 'Bearer at-2');
});

test('an unreachable token endpoint is an upstream error, not a crash', async () => {
  const store = new MemorySessionStore();
  const send = (async () => {
    throw new Error('network down');
  }) as unknown as typeof fetch;
  const config = configOf(store, send);
  const loginResult = await login(config, request('GET', 'https://app.example/auth/login'));
  const pending = idOf((loginResult as { setCookie: string }).setCookie);
  const stored = await store.takePending(pending);
  await store.putPending(pending, stored!);
  const result = await callback(
    config,
    request('GET', `https://app.example/auth/callback?code=abc&state=${encodeURIComponent(stored!.state)}`, {
      cookie: `${SESSION_COOKIE}=${pending}`,
    }),
  );
  assert.equal(result.kind, 'upstream_error');
});

test('every adapter renders unauthenticated the way the route asked', () => {
  const result = { kind: 'unauthenticated', reason: 'no_session' } as const;
  const xhr = toResponse(result);
  assert.equal(xhr.status, 401);
  const page = toResponse(result, { redirectTo: '/auth/login' });
  assert.equal(page.status, 302);
  assert.equal(page.headers.get('location'), '/auth/login');
});
