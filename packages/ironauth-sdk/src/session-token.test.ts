// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * Fault injection for the session JWT client (issue #119 criterion 6).
 *
 * > Re-mint failure in SDKs degrades to a stateful session check, never a silent signed-out
 * > state, covered by a fault-injection test.
 *
 * Every test here breaks the mint in a different way and asserts the same two things: the
 * stateful check WAS consulted, and the answer was not `signed-out`. The first half is what
 * makes the second half meaningful -- a client that returned `degraded` without asking anyone
 * would pass an assertion about the status alone while having no idea whether the user is signed
 * in.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { SessionTokenClient, readSessionTokenMode } from './session-token.js';

const TOKENIZE = 'https://iss.example/t/ten_a/e/env_a/session/tokenize?tokenize_as=orders';
const CHECK = 'https://iss.example/t/ten_a/e/env_a/account/sessions';

/** A fake `fetch` driven by a per-URL handler, recording every call. */
function server(handlers: {
  tokenize: () => Promise<Response> | Response;
  check?: () => Promise<Response> | Response;
}) {
  const calls: string[] = [];
  const send = async (input: string | URL | Request): Promise<Response> => {
    const url = typeof input === 'string' ? input : input.toString();
    calls.push(url);
    if (url === TOKENIZE) {
      return handlers.tokenize();
    }
    if (url === CHECK) {
      assert.ok(handlers.check, 'the stateful check was called with no handler configured');
      return handlers.check();
    }
    throw new Error(`unexpected url ${url}`);
  };
  return { calls, send: send as unknown as typeof fetch };
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function clientOf(send: typeof fetch, now: () => number = () => 1000) {
  return new SessionTokenClient({
    tokenizeUrl: TOKENIZE,
    sessionCheckUrl: CHECK,
    fetch: send,
    now,
  });
}

test('a successful mint yields a token and never touches the stateful check', async () => {
  const s = server({ tokenize: () => json({ token: 'jwt.a.b', expires_in: 60 }) });
  const client = clientOf(s.send);
  const state = await client.current();
  assert.equal(state.status, 'active');
  assert.equal(state.status === 'active' && state.token, 'jwt.a.b');
  assert.equal(state.status === 'active' && state.expiresAt, 1060);
  assert.equal(client.checkCount, 0, 'a working mint must cost no extra request');
  assert.deepEqual(s.calls, [TOKENIZE]);
});

test('a THROWN fetch degrades and never signs the user out', async () => {
  // The #9114 shape exactly: offline, DNS, CORS, an aborted request. It says nothing about the
  // session, and a client that read it as "signed out" would log out a valid user.
  const s = server({
    tokenize: () => {
      throw new Error('network down');
    },
    check: () => json({ sessions: [] }),
  });
  const client = clientOf(s.send);
  const state = await client.current();
  assert.equal(state.status, 'degraded');
  assert.equal(state.status === 'degraded' && state.reason, 'mint_unreachable');
  assert.equal(client.checkCount, 1, 'the stateful check must actually have been asked');
  assert.deepEqual(s.calls, [TOKENIZE, CHECK]);
});

test('a 500 from the mint degrades and never signs the user out', async () => {
  const s = server({
    tokenize: () => json({ error: 'server_error' }, 500),
    check: () => json({ sessions: [] }),
  });
  const client = clientOf(s.send);
  const state = await client.current();
  assert.equal(state.status, 'degraded');
  assert.equal(client.checkCount, 1);
});

test('a 2xx body the client cannot use degrades, and says so distinctly', async () => {
  // A DIFFERENT reason from unreachable, because the operator's next action differs: this one is
  // a version skew between the SDK and the server, and telling someone their network is down
  // would send them to look at the wrong thing.
  const s = server({
    tokenize: () => json({ token: 42, expires_in: 'soon' }),
    check: () => json({ sessions: [] }),
  });
  const client = clientOf(s.send);
  const state = await client.current();
  assert.equal(state.status, 'degraded');
  assert.equal(state.status === 'degraded' && state.reason, 'mint_malformed');
  assert.equal(client.checkCount, 1);
});

test('a 401 from the MINT is not enough to sign anyone out', async () => {
  // The mint and the stateful check read the same cookie through the same guard, so they should
  // agree. When they do not, this resolves toward "still signed in": the direction that does not
  // throw away a session over a disagreement that is a bug somewhere.
  const s = server({
    tokenize: () => json({ error: 'unauthenticated' }, 401),
    check: () => json({ sessions: [] }),
  });
  const client = clientOf(s.send);
  const state = await client.current();
  assert.equal(state.status, 'degraded', 'only the stateful check may sign a user out');
  assert.equal(client.checkCount, 1);
});

test('BOTH failing still does not sign the user out', async () => {
  // Two failed requests are evidence of a network problem, not of a session ending. This is the
  // case a naive implementation gets wrong, because "we could not find out" looks locally
  // indistinguishable from "the answer is no".
  const s = server({
    tokenize: () => {
      throw new Error('network down');
    },
    check: () => {
      throw new Error('network down');
    },
  });
  const client = clientOf(s.send);
  const state = await client.current();
  assert.equal(state.status, 'degraded');
  assert.equal(state.status === 'degraded' && state.reason, 'stateful_check_unreachable');
});

test('a 500 from the stateful check is not an answer either', async () => {
  const s = server({
    tokenize: () => json({ error: 'server_error' }, 500),
    check: () => json({ error: 'server_error' }, 500),
  });
  const client = clientOf(s.send);
  const state = await client.current();
  assert.equal(state.status, 'degraded');
  assert.equal(state.status === 'degraded' && state.reason, 'stateful_check_unreachable');
});

test('an explicit 401 from the stateful check IS a signed-out user', async () => {
  // The one path to signed-out in the whole module. Without this test every other assertion here
  // would be satisfied by a client that can never say signed-out at all, which would be a
  // different bug in the other direction.
  const s = server({
    tokenize: () => json({ error: 'unauthenticated' }, 401),
    check: () => json({ error: 'unauthenticated' }, 401),
  });
  const client = clientOf(s.send);
  const state = await client.current();
  assert.equal(state.status, 'signed-out');
});

test('a cached token is reused until the refresh skew, then re-minted', async () => {
  let now = 1000;
  let issued = 0;
  const s = server({
    tokenize: () => {
      issued += 1;
      return json({ token: `jwt.${issued}`, expires_in: 60 });
    },
  });
  const client = clientOf(s.send, () => now);
  assert.equal((await client.current()).status, 'active');
  assert.equal(client.mintCount, 1);
  // Well inside the window: no second mint.
  now = 1040;
  const reused = await client.current();
  assert.equal(reused.status === 'active' && reused.token, 'jwt.1');
  assert.equal(client.mintCount, 1, 'a live token must not be re-minted');
  // Inside the 10s skew before expiry (1060): re-mint BEFORE it is invalid, not after, because a
  // token used at the instant it expires is one some verifier rejects for clock skew.
  now = 1051;
  const refreshed = await client.current();
  assert.equal(refreshed.status === 'active' && refreshed.token, 'jwt.2');
  assert.equal(client.mintCount, 2);
});

test('a rotation mid-flight re-mints, and a failed re-mint still does not sign anyone out', async () => {
  // The caller sees the resource server reject a token (a key rotated, the audience moved) and
  // calls `invalidate`. The client cannot observe that rejection itself, because verification
  // happens at the resource server.
  let broken = false;
  const s = server({
    tokenize: () => {
      if (broken) {
        throw new Error('rotation in progress');
      }
      return json({ token: 'jwt.old', expires_in: 60 });
    },
    check: () => json({ sessions: [] }),
  });
  const client = clientOf(s.send);
  assert.equal((await client.current()).status, 'active');

  broken = true;
  client.invalidate();
  const state = await client.current();
  assert.equal(state.status, 'degraded', 'a rotation must never log a user out');
  assert.equal(client.checkCount, 1);
});

test('an expiring token is dropped before the mint, so a failure never serves a stale one', async () => {
  // If the client kept serving the cached token after a failed re-mint, a recoverable degrade
  // would become an authorization error at the resource server that the caller cannot explain.
  let now = 1000;
  let broken = false;
  const s = server({
    tokenize: () => {
      if (broken) {
        throw new Error('down');
      }
      return json({ token: 'jwt.old', expires_in: 60 });
    },
    check: () => json({ sessions: [] }),
  });
  const client = clientOf(s.send, () => now);
  await client.current();
  now = 1055;
  broken = true;
  const state = await client.current();
  assert.equal(state.status, 'degraded');
  assert.notEqual(state.status, 'active');
});

test('the token-mode reader fails to DISABLED on every fault', async () => {
  // Failing to disabled sends the caller to the stateful check, which is always correct and
  // merely slower. An SDK that cannot read its configuration must do the correct slow thing.
  const url = 'https://iss.example/t/ten_a/e/env_a/session/token-mode';
  const cases: Array<[string, () => Promise<Response> | Response]> = [
    ['thrown', () => { throw new Error('down'); }],
    ['non-2xx', () => json({}, 500)],
    ['unparseable', () => new Response('{', { status: 200 })],
    ['enabled without a template', () => json({ enabled: true, ttl_seconds: 60, jwks_uri: 'u' })],
    ['enabled without a ttl', () => json({ enabled: true, template: 't', jwks_uri: 'u' })],
    ['enabled without a jwks uri', () => json({ enabled: true, template: 't', ttl_seconds: 60 })],
  ];
  for (const [label, handler] of cases) {
    const send = (async () => handler()) as unknown as typeof fetch;
    const mode = await readSessionTokenMode(url, { fetch: send });
    assert.equal(mode.enabled, false, `${label} must report disabled`);
  }
});

test('a fresh environment reports disabled, and a configured one reports its template', async () => {
  const url = 'https://iss.example/t/ten_a/e/env_a/session/token-mode';
  const off = (async () => json({ enabled: false })) as unknown as typeof fetch;
  assert.deepEqual(await readSessionTokenMode(url, { fetch: off }), { enabled: false });

  const on = (async () =>
    json({
      enabled: true,
      template: 'orders',
      ttl_seconds: 60,
      audience: 'https://orders.example',
      jwks_uri: 'https://iss.example/t/ten_a/e/env_a/session-tokens/orders/jwks.json',
    })) as unknown as typeof fetch;
  const mode = await readSessionTokenMode(url, { fetch: on });
  assert.equal(mode.enabled, true);
  assert.equal(mode.template, 'orders');
  assert.equal(mode.ttlSeconds, 60);
});
