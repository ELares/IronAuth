// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import test from 'node:test';

import { generateProofKey } from './dpop.js';
import { NonceCache } from './dpop-store.js';

import {
  ProtocolError,
  authorizationUrl,
  discover,
  exchangeCode,
  generatePkce,
  generateState,
  refresh,
  userInfo,
} from './protocol.js';

const ISSUER = 'https://issuer.example';

const DISCOVERY = {
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/authorize`,
  token_endpoint: `${ISSUER}/token`,
  jwks_uri: `${ISSUER}/jwks`,
  userinfo_endpoint: `${ISSUER}/userinfo`,
};

/** A fake `fetch` whose calls are recorded and BOUNDED. */
function responder(handler: (input: string, init?: RequestInit) => Response) {
  const calls: Array<{ input: string; init?: RequestInit }> = [];
  const send = (async (input: string, init?: RequestInit): Promise<Response> => {
    calls.push({ input, init });
    if (calls.length > 10) {
      throw new Error('the client looped');
    }
    return handler(input, init);
  }) as unknown as typeof fetch;
  return { calls, send };
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

test('the authorization url always carries an S256 challenge', () => {
  const url = new URL(
    authorizationUrl({
      discovery: DISCOVERY,
      clientId: 'cli_1',
      redirectUri: 'https://app.example/callback',
      scope: 'openid profile',
      state: 'st',
      challenge: 'ch',
    }),
  );
  assert.equal(url.searchParams.get('response_type'), 'code');
  assert.equal(url.searchParams.get('code_challenge'), 'ch');
  assert.equal(
    url.searchParams.get('code_challenge_method'),
    'S256',
    'plain sends the verifier in leg one, which defeats PKCE; there is no switch for it',
  );
  assert.equal(url.searchParams.get('state'), 'st');
});

test('extra parameters are carried but cannot overwrite the protocol ones', () => {
  const url = new URL(
    authorizationUrl({
      discovery: DISCOVERY,
      clientId: 'cli_1',
      redirectUri: 'https://app.example/callback',
      scope: 'openid',
      state: 'st',
      challenge: 'ch',
      extra: { prompt: 'login' },
    }),
  );
  assert.equal(url.searchParams.get('prompt'), 'login');
  assert.equal(url.searchParams.get('response_type'), 'code');
});

test('the pkce challenge is the S256 digest of the verifier', async () => {
  const pair = await generatePkce();
  // Computed by a DIFFERENT implementation than the module uses, so this is a
  // cross-implementation check rather than the test repeating the code.
  const expected = createHash('sha256').update(pair.verifier).digest('base64url');
  assert.equal(pair.challenge, expected);
  assert.notEqual(pair.verifier, pair.challenge, 'the challenge is not the verifier');
});

test('pkce verifiers and states do not repeat', async () => {
  const verifiers = new Set<string>();
  const states = new Set<string>();
  for (let attempt = 0; attempt < 32; attempt += 1) {
    verifiers.add((await generatePkce()).verifier);
    states.add(generateState());
  }
  assert.equal(verifiers.size, 32, 'a repeated verifier would make PKCE replayable');
  assert.equal(states.size, 32);
});

test('discovery refuses a document claiming a different issuer', async () => {
  const { send } = responder(() => json({ ...DISCOVERY, issuer: 'https://evil.example' }));
  await assert.rejects(
    () => discover(ISSUER, send),
    (error: ProtocolError) => error.code === 'issuer_mismatch',
    'a document naming another issuer would send the code to that issuer',
  );
});

test('discovery refuses a document missing an endpoint it will be asked for', async () => {
  for (const missing of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) {
    const document: Record<string, unknown> = { ...DISCOVERY };
    delete document[missing];
    const { send } = responder(() => json(document));
    await assert.rejects(
      () => discover(ISSUER, send),
      (error: ProtocolError) => error.code === 'discovery_incomplete',
      `${missing} must be required`,
    );
  }
});

test('discovery builds the well-known path without doubling a slash', async () => {
  const { calls, send } = responder(() => json(DISCOVERY));
  await discover(`${ISSUER}/`, send).catch(() => undefined);
  assert.equal(calls[0].input, `${ISSUER}/.well-known/openid-configuration`);
});

test('the code exchange presents the verifier and repeats the redirect uri', async () => {
  const { calls, send } = responder(() => json({ access_token: 'at', token_type: 'DPoP' }));
  const tokens = await exchangeCode(
    {
      discovery: DISCOVERY,
      clientId: 'cli_1',
      redirectUri: 'https://app.example/callback',
      code: 'the-code',
      verifier: 'the-verifier',
    },
    send,
  );
  assert.equal(tokens.access_token, 'at');
  const body = new URLSearchParams(String(calls[0].init?.body));
  assert.equal(body.get('grant_type'), 'authorization_code');
  assert.equal(body.get('code_verifier'), 'the-verifier');
  assert.equal(
    body.get('redirect_uri'),
    'https://app.example/callback',
    'RFC 6749 4.1.3 has the server compare this against leg one',
  );
});

/**
 * The server's `error` code travels; its `error_description` does not.
 *
 * A description is server-controlled text. Passing it through is how it ends up rendered
 * in somebody's page.
 */
test('a token error surfaces the code and never the server description', async () => {
  const { send } = responder(() =>
    json(
      {
        error: 'invalid_grant',
        error_description: '<script>alert(1)</script> the code was already used',
      },
      400,
    ),
  );
  await assert.rejects(
    () =>
      exchangeCode(
        {
          discovery: DISCOVERY,
          clientId: 'c',
          redirectUri: 'https://app.example/cb',
          code: 'c',
          verifier: 'v',
        },
        send,
      ),
    (error: ProtocolError) => {
      assert.equal(error.code, 'invalid_grant');
      assert.ok(
        !error.message.includes('script'),
        `the server description must not travel: ${error.message}`,
      );
      return true;
    },
  );
});

test('a 200 with no access token is a malformed response, not a success', async () => {
  const { send } = responder(() => json({ token_type: 'Bearer' }));
  await assert.rejects(
    () =>
      exchangeCode(
        {
          discovery: DISCOVERY,
          clientId: 'c',
          redirectUri: 'https://app.example/cb',
          code: 'c',
          verifier: 'v',
        },
        send,
      ),
    (error: ProtocolError) => error.code === 'malformed_response',
  );
});

test('refresh sends the grant and omits scope unless narrowed', async () => {
  const { calls, send } = responder(() => json({ access_token: 'at2', token_type: 'DPoP' }));
  await refresh({ discovery: DISCOVERY, clientId: 'c', refreshToken: 'rt' }, send);
  let body = new URLSearchParams(String(calls[0].init?.body));
  assert.equal(body.get('grant_type'), 'refresh_token');
  assert.equal(body.get('scope'), null, 'an absent scope must not become an empty one');

  await refresh(
    { discovery: DISCOVERY, clientId: 'c', refreshToken: 'rt', scope: 'openid' },
    send,
  );
  body = new URLSearchParams(String(calls[1].init?.body));
  assert.equal(body.get('scope'), 'openid');
});

/**
 * UserInfo presents the token under the type the SERVER issued.
 *
 * Hardcoding `Bearer` would present a DPoP-bound token as a bearer token, which is exactly
 * what the binding exists to prevent.
 */
test('userinfo uses the issued token type, not a hardcoded Bearer', async () => {
  const { calls, send } = responder(() => json({ sub: 'usr_1' }));
  await userInfo(
    {
      discovery: DISCOVERY,
      accessToken: 'at',
      tokenType: 'DPoP',
      headers: { DPoP: 'proof' },
    },
    send,
  );
  const headers = new Headers(calls[0].init?.headers);
  assert.equal(headers.get('Authorization'), 'DPoP at');
  assert.equal(headers.get('DPoP'), 'proof');

  await userInfo({ discovery: DISCOVERY, accessToken: 'at' }, send);
  assert.equal(new Headers(calls[1].init?.headers).get('Authorization'), 'Bearer at');
});

test('userinfo refuses when the issuer publishes no endpoint', async () => {
  const { send } = responder(() => json({}));
  await assert.rejects(
    () => userInfo({ discovery: {}, accessToken: 'at' }, send),
    (error: ProtocolError) => error.code === 'no_userinfo_endpoint',
  );
});

/**
 * The portability guard: no Node-only imports in the runtime-portable modules.
 *
 * This is the constraint the whole package exists for, and it is the one that rots
 * silently: a `node:crypto` import added for convenience compiles, passes every test on
 * Node, and fails only on Workers, where nobody runs the suite. The scan is the cheap
 * standing check; the five-runtime CI matrix is the expensive one and is still owed.
 */
test('the portable modules import nothing Node-only', () => {
  const directory = new URL('.', import.meta.url).pathname;
  const sources = readdirSync(directory.replace(/dist\/?$/, 'src/'))
    .filter((name) => name.endsWith('.ts') && !name.endsWith('.test.ts'));
  assert.ok(sources.length >= 3, `expected the portable modules, found ${sources.length}`);
  for (const name of sources) {
    const body = readFileSync(
      `${directory.replace(/dist\/?$/, 'src/')}${name}`,
      'utf8',
    );
    for (const forbidden of ["'node:", '"node:', 'require(', 'Buffer.']) {
      assert.ok(
        !body.includes(forbidden),
        `${name} uses ${forbidden}, which does not exist on Workers or Vercel Edge`,
      );
    }
  }
});

// ---------------------------------------------------------------------------------------------
// DPoP binding on the protocol calls (issue #134).
// ---------------------------------------------------------------------------------------------

/** Decode a compact JWS payload without verifying it: the tests only read what was sent. */
function proofPayload(proof: string): Record<string, unknown> {
  return JSON.parse(
    atob(proof.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')),
  ) as Record<string, unknown>;
}

test('the code exchange attaches a proof bound to the token endpoint', async () => {
  const key = await generateProofKey();
  const { calls, send } = responder(() => json({ access_token: 'at', token_type: 'DPoP' }));
  await exchangeCode(
    {
      discovery: DISCOVERY,
      clientId: 'cli_1',
      redirectUri: 'https://app.example/cb',
      code: 'c',
      verifier: 'v',
      dpop: { key },
    },
    send,
  );
  const proof = new Headers(calls[0].init?.headers).get('DPoP');
  assert.ok(proof, 'a proof must be attached');
  const payload = proofPayload(proof);
  assert.equal(payload.htm, 'POST');
  assert.equal(payload.htu, `${ISSUER}/token`);
  assert.equal(
    payload.ath,
    undefined,
    'there is no access token yet, so a proof carrying one would be malformed',
  );
});

test('an absent binding leaves the request byte-identical to the bearer path', async () => {
  const { calls, send } = responder(() => json({ access_token: 'at', token_type: 'Bearer' }));
  await exchangeCode(
    {
      discovery: DISCOVERY,
      clientId: 'cli_1',
      redirectUri: 'https://app.example/cb',
      code: 'c',
      verifier: 'v',
    },
    send,
  );
  assert.equal(
    new Headers(calls[0].init?.headers).get('DPoP'),
    null,
    'no binding means no proof, so the plain OAuth path is untouched',
  );
});

test('refresh attaches a proof, which a bound family requires to rotate', async () => {
  const key = await generateProofKey();
  const { calls, send } = responder(() => json({ access_token: 'at2', token_type: 'DPoP' }));
  await refresh(
    { discovery: DISCOVERY, clientId: 'c', refreshToken: 'rt', dpop: { key } },
    send,
  );
  const proof = new Headers(calls[0].init?.headers).get('DPoP');
  assert.ok(proof);
  assert.equal(proofPayload(proof).htu, `${ISSUER}/token`);
});

/**
 * A bound UserInfo call presents `DPoP`, never `Bearer`, and the proof carries the token's
 * `ath`.
 *
 * Both halves matter. Presenting a sender-constrained token as a bearer token is what the
 * binding exists to prevent, and a proof without `ath` is one a resource server correctly
 * refuses because nothing ties it to the token it arrived with.
 */
test('userinfo binds the proof to the exact token it presents', async () => {
  const key = await generateProofKey();
  const { calls, send } = responder(() => json({ sub: 'usr_1' }));
  await userInfo(
    { discovery: DISCOVERY, accessToken: 'the-token', tokenType: 'Bearer', dpop: { key } },
    send,
  );
  const headers = new Headers(calls[0].init?.headers);
  assert.equal(
    headers.get('Authorization'),
    'DPoP the-token',
    'a binding overrides tokenType: Bearer would defeat the whole mechanism',
  );
  const payload = proofPayload(headers.get('DPoP') ?? '');
  assert.equal(payload.htu, `${ISSUER}/userinfo`);
  assert.equal(payload.htm, 'GET');
  const expected = createHash('sha256').update('the-token').digest('base64url');
  assert.equal(payload.ath, expected, 'ath is the SHA-256 of the presented token');
});

/**
 * The nonce learned on one call is carried by the next.
 *
 * Without the shared cache each call relearns it from a challenge, so a compliant server costs
 * two round trips per request forever. The assertion counts calls exactly, because "fewer"
 * would still pass if the second call challenged again.
 */
test('a shared nonce cache spares later protocol calls the challenge', async () => {
  const key = await generateProofKey();
  const nonces = new NonceCache();
  let calls = 0;
  const send = (async (_input: string, init?: RequestInit): Promise<Response> => {
    calls += 1;
    const proof = new Headers(init?.headers).get('DPoP') ?? '';
    if (proofPayload(proof).nonce === undefined) {
      return new Response('{"error":"use_dpop_nonce"}', {
        status: 400,
        headers: { 'DPoP-Nonce': 'n1', 'Content-Type': 'application/json' },
      });
    }
    return new Response('{"access_token":"at","token_type":"DPoP"}', {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }) as unknown as typeof fetch;

  const options = {
    discovery: DISCOVERY,
    clientId: 'c',
    redirectUri: 'https://app.example/cb',
    code: 'c',
    verifier: 'v',
    dpop: { key, nonces },
  };
  await exchangeCode(options, send);
  assert.equal(calls, 2, 'the first call challenges and retries');
  await exchangeCode(options, send);
  assert.equal(calls, 3, 'the second carries the nonce up front: one request, no challenge');
});
