// SPDX-License-Identifier: MIT OR Apache-2.0

/*
 * Every test here bounds its fake `fetch` call count where a loop is possible, for the
 * reason recorded in `dpop.test.ts`: a runaway loop HANGS the runner rather than failing
 * it, and a hang reports nothing.
 */

import assert from 'node:assert/strict';
import test from 'node:test';

import { JwksCache, VerifyError, maxAgeOf, verifyToken } from './verify.js';

const ISSUER = 'https://issuer.example';
const AUDIENCE = 'api://resource';
const NOW = 1_700_000_000;

function base64url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function encode(value: unknown): string {
  return base64url(new TextEncoder().encode(JSON.stringify(value)));
}

/** A signing key plus the public JWK a JWKS would publish. */
async function signingKey(kid: string) {
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const exported = await crypto.subtle.exportKey('jwk', pair.publicKey);
  return {
    privateKey: pair.privateKey,
    jwk: { kty: exported.kty, crv: exported.crv, x: exported.x, kid, alg: 'EdDSA' },
  };
}

async function mint(
  key: { privateKey: CryptoKey },
  header: Record<string, unknown>,
  claims: Record<string, unknown>,
): Promise<string> {
  const input = `${encode(header)}.${encode(claims)}`;
  const signature = await crypto.subtle.sign(
    { name: 'Ed25519' },
    key.privateKey,
    new TextEncoder().encode(input),
  );
  return `${input}.${base64url(new Uint8Array(signature))}`;
}

function goodClaims(overrides: Record<string, unknown> = {}) {
  return { iss: ISSUER, aud: AUDIENCE, exp: NOW + 300, nbf: NOW - 10, ...overrides };
}

/** A JWKS server whose call count is BOUNDED, so a refetch loop fails rather than hangs. */
function jwksServer(keys: unknown[], cacheControl = 'max-age=300') {
  const state = { calls: 0 };
  const send = async (): Promise<Response> => {
    state.calls += 1;
    if (state.calls > 20) {
      throw new Error(`refetched ${state.calls} times; the cooldown is gone`);
    }
    return new Response(JSON.stringify({ keys }), {
      status: 200,
      headers: { 'Cache-Control': cacheControl, 'Content-Type': 'application/json' },
    });
  };
  return { state, send: send as unknown as typeof fetch };
}

function cacheOf(server: { send: typeof fetch }, now: () => number, cooldown = 30) {
  return new JwksCache({
    uri: 'https://issuer.example/jwks',
    fetch: server.send,
    now,
    refetchCooldownSeconds: cooldown,
  });
}

const options = {
  issuer: ISSUER,
  audience: AUDIENCE,
  algorithms: ['EdDSA'],
  now: () => NOW,
};

test('a well-formed token from a published key verifies', async () => {
  const key = await signingKey('k1');
  const server = jwksServer([key.jwk]);
  const token = await mint(key, { alg: 'EdDSA', kid: 'k1' }, goodClaims());
  const verified = await verifyToken(token, cacheOf(server, () => NOW), options);
  assert.equal(verified.claims.iss, ISSUER);
  assert.equal(verified.header.kid, 'k1');
});

/**
 * RS256 verification, via WebCrypto only.
 *
 * The issue asks for Ed25519 AND RS256 to both work with no Node crypto, and until now only
 * Ed25519 was exercised: `algorithmParameters` listed RS256 and nothing proved the mapping
 * was right. A wrong hash or a wrong import algorithm there fails only at runtime, for the
 * deployments that configured RS256.
 */
test('an RS256 token verifies through WebCrypto alone', async () => {
  const pair = (await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
  const exported = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const jwk = { kty: exported.kty, n: exported.n, e: exported.e, kid: 'rsa-1', alg: 'RS256' };
  const server = jwksServer([jwk]);

  const input = `${encode({ alg: 'RS256', kid: 'rsa-1' })}.${encode(goodClaims())}`;
  const signature = await crypto.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    pair.privateKey,
    new TextEncoder().encode(input),
  );
  const token = `${input}.${base64url(new Uint8Array(signature))}`;

  const verified = await verifyToken(token, cacheOf(server, () => NOW), {
    ...options,
    algorithms: ['RS256'],
  });
  assert.equal(verified.header.alg, 'RS256');
  assert.equal(verified.claims.iss, ISSUER);

  // And a tampered RS256 payload still fails, so the success above is the signature
  // verifying rather than the check being skipped for this algorithm.
  const [header, , sig] = token.split('.');
  const forged = `${header}.${encode(goodClaims({ sub: 'attacker' }))}.${sig}`;
  await assert.rejects(
    () => verifyToken(forged, cacheOf(server, () => NOW), { ...options, algorithms: ['RS256'] }),
    (error: VerifyError) => error.reason === 'bad_signature',
  );
});

test('a tampered payload fails the signature', async () => {
  const key = await signingKey('k1');
  const server = jwksServer([key.jwk]);
  const token = await mint(key, { alg: 'EdDSA', kid: 'k1' }, goodClaims());
  const [header, , signature] = token.split('.');
  const forged = `${header}.${encode(goodClaims({ sub: 'attacker' }))}.${signature}`;
  await assert.rejects(
    () => verifyToken(forged, cacheOf(server, () => NOW), options),
    (error: VerifyError) => error.reason === 'bad_signature',
  );
});

/**
 * `alg: none` is refused, and refused BEFORE any key lookup.
 *
 * The count assertion is the point: a verifier that resolved the key first would let an
 * unauthenticated caller drive JWKS traffic with a token that can never verify.
 */
test('alg none is refused without touching the key set', async () => {
  const key = await signingKey('k1');
  const server = jwksServer([key.jwk]);
  const cache = cacheOf(server, () => NOW);
  const token = `${encode({ alg: 'none', kid: 'k1' })}.${encode(goodClaims())}.`;
  await assert.rejects(
    () => verifyToken(token, cache, options),
    (error: VerifyError) => error.reason === 'algorithm_not_allowed',
  );
  assert.equal(cache.fetchCount, 0, 'a refused algorithm must not cause a fetch');
});

test('an algorithm the issuer does not publish is refused even when supported', async () => {
  const key = await signingKey('k1');
  const server = jwksServer([key.jwk]);
  const token = await mint(key, { alg: 'EdDSA', kid: 'k1' }, goodClaims());
  await assert.rejects(
    // The issuer publishes only RS256 here, so an EdDSA token is refused despite the
    // signature being perfectly good. The allow-list is the issuer's statement.
    () => verifyToken(token, cacheOf(server, () => NOW), { ...options, algorithms: ['RS256'] }),
    (error: VerifyError) => error.reason === 'algorithm_not_allowed',
  );
});

test('an unknown kid refetches once the cooldown allows, and is refused meanwhile', async () => {
  const key = await signingKey('k1');
  const server = jwksServer([key.jwk]);
  let clock = NOW;
  const cache = cacheOf(server, () => clock);
  const token = await mint(key, { alg: 'EdDSA', kid: 'rotated' }, goodClaims());

  await assert.rejects(
    () => verifyToken(token, cache, options),
    (error: VerifyError) => error.reason === 'unknown_key',
  );
  // ONE fetch, not two. The initial load IS the recent fetch, so refetching immediately
  // would ask the same endpoint the same question and get the same answer. My first
  // version of this test expected two and was wrong about the code, not the other way
  // round.
  assert.equal(cache.fetchCount, 1, 'the initial load already has the current keys');

  clock += 31;
  await assert.rejects(() => verifyToken(token, cache, { ...options, now: () => NOW }));
  assert.equal(cache.fetchCount, 2, 'past the cooldown, an unknown kid does refetch');
});

/**
 * A flood of garbage kids costs ONE refetch per cooldown window, not one per token.
 *
 * Minting a token with a nonsense `kid` is free for an attacker; without the cooldown each
 * one is an upstream request, and the JWKS endpoint becomes a reflected amplifier.
 */
test('a flood of unknown kids is rate limited to one refetch per window', async () => {
  const key = await signingKey('k1');
  const server = jwksServer([key.jwk]);
  const cache = cacheOf(server, () => NOW);
  for (let attempt = 0; attempt < 10; attempt += 1) {
    const token = await mint(key, { alg: 'EdDSA', kid: `junk-${attempt}` }, goodClaims());
    await assert.rejects(() => verifyToken(token, cache, options));
  }
  assert.equal(
    cache.fetchCount,
    1,
    'ten garbage tokens cost NOTHING beyond the initial load; without the cooldown each \
     one would be an upstream request and the JWKS endpoint becomes a reflected amplifier',
  );
});

test('a rotation is picked up once the cooldown has passed', async () => {
  const first = await signingKey('k1');
  const second = await signingKey('k2');
  let published: unknown[] = [first.jwk];
  let clock = NOW;
  const state = { calls: 0 };
  const send = (async (): Promise<Response> => {
    state.calls += 1;
    if (state.calls > 20) {
      throw new Error('refetch loop');
    }
    return new Response(JSON.stringify({ keys: published }), {
      status: 200,
      headers: { 'Cache-Control': 'max-age=300' },
    });
  }) as unknown as typeof fetch;
  const cache = new JwksCache({
    uri: 'https://issuer.example/jwks',
    fetch: send,
    now: () => clock,
    refetchCooldownSeconds: 30,
  });

  const rotated = await mint(second, { alg: 'EdDSA', kid: 'k2' }, goodClaims());
  await assert.rejects(() => verifyToken(rotated, cache, options));

  published = [first.jwk, second.jwk];
  clock += 31;
  const verified = await verifyToken(rotated, cache, { ...options, now: () => NOW });
  assert.equal(verified.header.kid, 'k2');
});

test('a stale cache refetches when max-age has passed', async () => {
  const key = await signingKey('k1');
  const server = jwksServer([key.jwk], 'max-age=60');
  let clock = NOW;
  const cache = cacheOf(server, () => clock);
  const token = await mint(key, { alg: 'EdDSA', kid: 'k1' }, goodClaims());
  await verifyToken(token, cache, options);
  assert.equal(cache.fetchCount, 1);
  clock += 61;
  await verifyToken(token, cache, { ...options, now: () => NOW });
  assert.equal(cache.fetchCount, 2, 'the entry expired, so it is fetched again');
});

test('a JWKS blip keeps serving the keys already held', async () => {
  const key = await signingKey('k1');
  let fail = false;
  let clock = NOW;
  const send = (async (): Promise<Response> =>
    fail
      ? new Response('', { status: 503 })
      : new Response(JSON.stringify({ keys: [key.jwk] }), {
          status: 200,
          headers: { 'Cache-Control': 'max-age=10' },
        })) as unknown as typeof fetch;
  const cache = new JwksCache({ uri: 'https://i/jwks', fetch: send, now: () => clock });
  const token = await mint(key, { alg: 'EdDSA', kid: 'k1' }, goodClaims());
  await verifyToken(token, cache, options);

  fail = true;
  clock += 11;
  const verified = await verifyToken(token, cache, { ...options, now: () => NOW });
  assert.equal(
    verified.header.kid,
    'k1',
    'an endpoint blip must not invalidate every token in flight',
  );
});

test('the issuer is matched exactly, not by prefix', async () => {
  const key = await signingKey('k1');
  const server = jwksServer([key.jwk]);
  for (const iss of [
    `${ISSUER}.attacker.example`,
    `${ISSUER}/`,
    'https://issuer.example.evil',
  ]) {
    const token = await mint(key, { alg: 'EdDSA', kid: 'k1' }, goodClaims({ iss }));
    await assert.rejects(
      () => verifyToken(token, cacheOf(server, () => NOW), options),
      (error: VerifyError) => error.reason === 'wrong_issuer',
      `${iss} must not pass as ${ISSUER}`,
    );
  }
});

test('an audience array is accepted only when it contains the expected audience', async () => {
  const key = await signingKey('k1');
  const server = jwksServer([key.jwk]);
  const included = await mint(
    key,
    { alg: 'EdDSA', kid: 'k1' },
    goodClaims({ aud: ['other', AUDIENCE] }),
  );
  assert.ok(await verifyToken(included, cacheOf(server, () => NOW), options));

  const excluded = await mint(
    key,
    { alg: 'EdDSA', kid: 'k1' },
    goodClaims({ aud: ['other'] }),
  );
  await assert.rejects(
    () => verifyToken(excluded, cacheOf(server, () => NOW), options),
    (error: VerifyError) => error.reason === 'wrong_audience',
  );
});

test('expiry and not-before are enforced, with skew applied in both directions', async () => {
  const key = await signingKey('k1');
  const server = jwksServer([key.jwk]);
  const expired = await mint(
    key,
    { alg: 'EdDSA', kid: 'k1' },
    goodClaims({ exp: NOW - 31 }),
  );
  await assert.rejects(
    () => verifyToken(expired, cacheOf(server, () => NOW), options),
    (error: VerifyError) => error.reason === 'expired',
  );
  // Inside the skew, so it still verifies. Without this the skew could be zero and the
  // test above would pass anyway.
  const justExpired = await mint(
    key,
    { alg: 'EdDSA', kid: 'k1' },
    goodClaims({ exp: NOW - 5 }),
  );
  assert.ok(await verifyToken(justExpired, cacheOf(server, () => NOW), options));

  const future = await mint(key, { alg: 'EdDSA', kid: 'k1' }, goodClaims({ nbf: NOW + 31 }));
  await assert.rejects(
    () => verifyToken(future, cacheOf(server, () => NOW), options),
    (error: VerifyError) => error.reason === 'not_yet_valid',
  );
});

/**
 * A forged signature reports `bad_signature`, never a claim failure.
 *
 * Answering "expired" for a token whose signature did not verify would tell an attacker
 * their forgery was accepted and only the clock stopped them.
 */
test('a forged token reports the signature, not the claims', async () => {
  const key = await signingKey('k1');
  const other = await signingKey('k1');
  const server = jwksServer([key.jwk]);
  const forged = await mint(
    other,
    { alg: 'EdDSA', kid: 'k1' },
    goodClaims({ iss: 'https://elsewhere.example', exp: NOW - 9999 }),
  );
  await assert.rejects(
    () => verifyToken(forged, cacheOf(server, () => NOW), options),
    (error: VerifyError) => error.reason === 'bad_signature',
  );
});

test('a token with no kid is refused when the set is ambiguous', async () => {
  const first = await signingKey('k1');
  const second = await signingKey('k2');
  const server = jwksServer([first.jwk, second.jwk]);
  const token = await mint(first, { alg: 'EdDSA' }, goodClaims());
  await assert.rejects(
    () => verifyToken(token, cacheOf(server, () => NOW), options),
    (error: VerifyError) => error.reason === 'unknown_key',
    'picking the first of several would make verification depend on serving order',
  );
});

test('a malformed token is refused before anything else', async () => {
  const server = jwksServer([]);
  for (const token of ['', 'a.b', 'not-base64.$$$.x', 'a.b.c.d']) {
    await assert.rejects(
      () => verifyToken(token, cacheOf(server, () => NOW), options),
      (error: VerifyError) => error.reason === 'malformed',
      `${token} must be malformed`,
    );
  }
});

test('maxAgeOf reads the directive and treats no-store as zero', () => {
  assert.equal(maxAgeOf(new Headers()), 300);
  assert.equal(maxAgeOf(new Headers({ 'Cache-Control': 'max-age=42' })), 42);
  assert.equal(maxAgeOf(new Headers({ 'Cache-Control': 'public, max-age=90' })), 90);
  assert.equal(maxAgeOf(new Headers({ 'Cache-Control': 'no-store' })), 0);
  assert.equal(maxAgeOf(new Headers({ 'Cache-Control': 'no-cache' })), 0);
  assert.equal(maxAgeOf(new Headers({ 'Cache-Control': 'private' })), 300);
});
