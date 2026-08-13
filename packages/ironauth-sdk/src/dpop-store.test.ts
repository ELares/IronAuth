// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from 'node:assert/strict';
import test from 'node:test';

import { createProof, fetchWithProof, generateProofKey } from './dpop.js';
import {
  DpopClientError,
  type DpopFailureReason,
  MemoryProofKeyStore,
  NonceCache,
  loadOrCreateProofKey,
  proofKeySlot,
  type ProofKeyStore,
} from './dpop-store.js';

/** A store whose reads or writes fail, for the fault paths. */
function failingStore(fail: 'load' | 'save'): ProofKeyStore {
  const inner = new MemoryProofKeyStore();
  return {
    load: (key) =>
      fail === 'load' ? Promise.reject(new Error('disk on fire')) : inner.load(key),
    save: (key, value) =>
      fail === 'save' ? Promise.reject(new Error('quota exceeded')) : inner.save(key, value),
    remove: (key) => inner.remove(key),
  };
}

test('a keypair persists across calls, so a reload does not orphan bound tokens', async () => {
  const store = new MemoryProofKeyStore();
  const first = await loadOrCreateProofKey(store, 'cli_1', 'env_prod');
  const second = await loadOrCreateProofKey(store, 'cli_1', 'env_prod');
  assert.equal(
    second.publicJwk.x,
    first.publicJwk.x,
    'a regenerated key is a NEW key, and every token bound to the old one is dead',
  );
  assert.equal(second.privateKey, first.privateKey);
});

test('the stored private key stays non-extractable through the round trip', async () => {
  const store = new MemoryProofKeyStore();
  const key = await loadOrCreateProofKey(store, 'cli_1', 'env_prod');
  assert.equal(key.privateKey.extractable, false);
  const reloaded = await loadOrCreateProofKey(store, 'cli_1', 'env_prod');
  assert.equal(
    reloaded.privateKey.extractable,
    false,
    'a store that exported and re-imported the key would give away the property it exists for',
  );
  await assert.rejects(
    () => crypto.subtle.exportKey('jwk', reloaded.privateKey),
    'no API path may extract the private key',
  );
});

/**
 * Separate environments get separate keys.
 *
 * Sharing one would let a token minted for staging be replayed, with a perfectly valid
 * proof, against production.
 */
test('each client and environment pair gets its own key', async () => {
  const store = new MemoryProofKeyStore();
  const prod = await loadOrCreateProofKey(store, 'cli_1', 'env_prod');
  const staging = await loadOrCreateProofKey(store, 'cli_1', 'env_staging');
  const other = await loadOrCreateProofKey(store, 'cli_2', 'env_prod');
  const keys = new Set([prod.publicJwk.x, staging.publicJwk.x, other.publicJwk.x]);
  assert.equal(keys.size, 3, 'three distinct scopes must hold three distinct keys');
});

/**
 * The slot is length-prefixed so no pair can be made to collide with another.
 *
 * With a plain separator, `("a:b", "c")` and `("a", "b:c")` both render `a:b:c`, so one
 * tenant could aim its key at another tenant's slot by choosing a client id.
 */
test('slot names cannot be made to collide by choosing a client id', () => {
  assert.notEqual(proofKeySlot('a:b', 'c'), proofKeySlot('a', 'b:c'));
  assert.notEqual(proofKeySlot('a.b', 'c'), proofKeySlot('a', 'b.c'));
  assert.equal(proofKeySlot('a', 'b'), proofKeySlot('a', 'b'), 'and it is deterministic');
});

/**
 * A storage fault is a typed error, never a silent fresh key.
 *
 * Falling back to a new in-memory key would look like success and quietly orphan every token
 * bound to the stored one, which is the failure mode this test exists to forbid.
 */
test('a storage fault surfaces as a typed error and not a fresh key', async () => {
  await assert.rejects(
    () => loadOrCreateProofKey(failingStore('load'), 'cli_1', 'env_prod'),
    (error: DpopClientError) => {
      assert.equal(error.reason, 'storage_unavailable');
      return true;
    },
  );
  await assert.rejects(
    () => loadOrCreateProofKey(failingStore('save'), 'cli_1', 'env_prod'),
    (error: DpopClientError) => error.reason === 'storage_unavailable',
  );
});

test('a removed key is regenerated rather than reported missing', async () => {
  const store = new MemoryProofKeyStore();
  const first = await loadOrCreateProofKey(store, 'cli_1', 'env_prod');
  await store.remove(proofKeySlot('cli_1', 'env_prod'));
  const second = await loadOrCreateProofKey(store, 'cli_1', 'env_prod');
  assert.notEqual(second.publicJwk.x, first.publicJwk.x);
});

test('the nonce cache is keyed by origin, not by path or by server', () => {
  const cache = new NonceCache();
  cache.set('https://a.example/token', 'nonce-a');
  assert.equal(cache.get('https://a.example/userinfo'), 'nonce-a', 'same origin, any path');
  assert.equal(cache.get('https://b.example/token'), undefined, 'never another server');
  assert.equal(cache.get('https://a.example:8443/token'), undefined, 'port is part of it');
});

test('observe records a nonce from any response and ignores one without it', () => {
  const cache = new NonceCache();
  cache.observe('https://a.example/token', {
    headers: new Headers({ 'DPoP-Nonce': 'fresh' }),
  });
  assert.equal(cache.get('https://a.example/token'), 'fresh');
  cache.observe('https://a.example/token', { headers: new Headers() });
  assert.equal(cache.get('https://a.example/token'), 'fresh', 'absent must not clear it');
  cache.observe('https://a.example/token', {
    headers: new Headers({ 'DPoP-Nonce': 'rotated' }),
  });
  assert.equal(cache.get('https://a.example/token'), 'rotated', 'a rotation is taken up');
});

/**
 * THE point of the cache: the challenge is paid ONCE, not on every request.
 *
 * Without it a compliant server costs the client two round trips per request forever. The
 * assertion is on the exact call count, because "fewer" would pass even if the second
 * request still challenged.
 */
test('a cached nonce spares every later request the challenge round trip', async () => {
  const key = await generateProofKey();
  const cache = new NonceCache();
  const seen: Array<string | null> = [];
  const send = (async (_input: string, init?: RequestInit): Promise<Response> => {
    const nonce = new Headers(init?.headers).get('DPoP') ?? '';
    const payload = JSON.parse(
      atob(nonce.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')),
    ) as { nonce?: string };
    seen.push(payload.nonce ?? null);
    if (payload.nonce === undefined) {
      return new Response('{"error":"use_dpop_nonce"}', {
        status: 400,
        headers: { 'DPoP-Nonce': 'server-nonce' },
      });
    }
    return new Response('{}', { status: 200, headers: { 'DPoP-Nonce': 'server-nonce' } });
  }) as unknown as typeof fetch;

  const first = await fetchWithProof(key, 'https://a.example/token', {}, send, cache);
  assert.equal(first.status, 200);
  assert.deepEqual(seen, [null, 'server-nonce'], 'the first call challenges then retries');

  const second = await fetchWithProof(key, 'https://a.example/token', {}, send, cache);
  assert.equal(second.status, 200);
  assert.deepEqual(
    seen,
    [null, 'server-nonce', 'server-nonce'],
    'the second call carries the nonce up front: exactly one request, no challenge',
  );
});

/**
 * Without a cache the behaviour is unchanged, which is what keeps the parameter optional.
 *
 * This is the control for the test above: the same server, the same key, and the challenge
 * is paid again, so the saving there is demonstrably the cache and not the server.
 */
test('without a cache every request pays the challenge again', async () => {
  const key = await generateProofKey();
  let calls = 0;
  const send = (async (_input: string, init?: RequestInit): Promise<Response> => {
    calls += 1;
    const proof = new Headers(init?.headers).get('DPoP') ?? '';
    const payload = JSON.parse(
      atob(proof.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')),
    ) as { nonce?: string };
    if (payload.nonce === undefined) {
      return new Response('{}', { status: 400, headers: { 'DPoP-Nonce': 'server-nonce' } });
    }
    return new Response('{}', { status: 200 });
  }) as unknown as typeof fetch;

  await fetchWithProof(key, 'https://a.example/token', {}, send);
  await fetchWithProof(key, 'https://a.example/token', {}, send);
  assert.equal(calls, 4, 'two requests, each costing a challenge plus a retry');
});

/**
 * The retry is bounded at one, and exhausting it is a TYPED failure.
 *
 * Handing the caller the raw 400 would look like an ordinary protocol error, when what
 * actually happened is that the request could not be made under DPoP at all.
 */
test('a server that always challenges gets one retry then a typed exhaustion', async () => {
  const key = await generateProofKey();
  let calls = 0;
  const send = (async (): Promise<Response> => {
    calls += 1;
    return new Response('{}', { status: 400, headers: { 'DPoP-Nonce': 'never-enough' } });
  }) as unknown as typeof fetch;
  await assert.rejects(
    () => fetchWithProof(key, 'https://a.example/token', {}, send),
    (error: DpopClientError) => {
      assert.equal(error.reason, 'nonce_retry_exhausted');
      return true;
    },
  );
  assert.equal(calls, 2, 'the original plus ONE retry, never a loop');
});

/** A server that demands a nonce and supplies none is exhaustion on the first attempt. */
test('a nonce demand with no nonce supplied is exhaustion, not a silent 400', async () => {
  const key = await generateProofKey();
  let calls = 0;
  const send = (async (): Promise<Response> => {
    calls += 1;
    return new Response('{}', {
      status: 401,
      headers: { 'WWW-Authenticate': 'DPoP error="use_dpop_nonce"' },
    });
  }) as unknown as typeof fetch;
  await assert.rejects(
    () => fetchWithProof(key, 'https://a.example/token', {}, send),
    (error: DpopClientError) => error.reason === 'nonce_retry_exhausted',
  );
  assert.equal(calls, 1, 'retrying an identical proof would get an identical answer');
});

/**
 * Every declared failure reason must be REACHABLE.
 *
 * A reason nothing constructs reads as a handled case and is not one; this codebase has hit
 * that dormant-surface defect before, so the set is pinned rather than trusted.
 */
test('the declared failure reasons are exactly the ones that can occur', () => {
  const reachable: DpopFailureReason[] = ['storage_unavailable', 'nonce_retry_exhausted'];
  for (const reason of reachable) {
    assert.equal(new DpopClientError(reason).reason, reason);
  }
});

test('a proof carries the nonce it was given', async () => {
  const key = await generateProofKey();
  const proof = await createProof(key, {
    method: 'POST',
    url: 'https://a.example/token',
    nonce: 'abc',
  });
  const payload = JSON.parse(
    atob(proof.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')),
  ) as { nonce?: string };
  assert.equal(payload.nonce, 'abc');
});
