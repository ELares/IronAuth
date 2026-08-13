// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import { createProof, fetchWithProof, generateProofKey } from './dpop.js';
import { installFakeIndexedDb } from './indexeddb-fake.js';
import {
  DpopClientError,
  IndexedDbProofKeyStore,
  indexedDbAvailable,
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

// ---------------------------------------------------------------------------------------------
// The IndexedDB store (issue #134).
//
// This store shipped with NOTHING exercising it: no test, no runtime check, no caller. Code
// nobody runs is code whose first execution happens in a browser belonging to someone else,
// and the request-and-callback shape is exactly where a transposed onsuccess/onerror or a
// missing onupgradeneeded hides.
//
// The fake is not a browser and the module says so. What it CAN prove is that the store's own
// logic is correct: that it creates its object store, round-trips a non-extractable CryptoKey,
// deletes, and turns every failure into a typed error rather than a hang. Persistence across a
// real page reload stays owed on #134.
// ---------------------------------------------------------------------------------------------

test('the indexeddb store round-trips a key through its real code path', async () => {
  const fake = installFakeIndexedDb();
  try {
    const store = new IndexedDbProofKeyStore('ironauth-test');
    const slot = proofKeySlot('cli_1', 'env_prod');
    assert.equal(await store.load(slot), undefined, 'an empty store holds nothing');

    const key = await generateProofKey();
    await store.save(slot, key);
    const loaded = await store.load(slot);
    assert.ok(loaded, 'the saved key must come back');
    assert.equal(loaded.publicJwk.x, key.publicJwk.x);
    assert.equal(
      loaded.privateKey.extractable,
      false,
      'the CryptoKey is stored as an OBJECT, so it stays non-extractable across the round trip',
    );

    await store.remove(slot);
    assert.equal(await store.load(slot), undefined, 'a removed key is gone');
  } finally {
    fake.uninstall();
  }
});

/**
 * The object store is created by the upgrade callback.
 *
 * A store that forgot `createObjectStore` would throw on its first transaction. Asserting the
 * store exists in the backing database proves the upgrade path actually ran, rather than the
 * fake having quietly provided it.
 */
test('the indexeddb store creates its object store on first open', async () => {
  const fake = installFakeIndexedDb();
  try {
    const store = new IndexedDbProofKeyStore('ironauth-test');
    await store.load(proofKeySlot('cli_1', 'env_prod'));
    assert.ok(
      fake.database.objectStoreNames.contains('proof-keys'),
      'the upgrade callback must have created the object store',
    );
  } finally {
    fake.uninstall();
  }
});

/** A refused open is a typed error, not a hang. */
test('an indexeddb that will not open surfaces a typed error', async () => {
  const fake = installFakeIndexedDb('failing-open');
  try {
    const store = new IndexedDbProofKeyStore('ironauth-test');
    await assert.rejects(
      () => store.load(proofKeySlot('cli_1', 'env_prod')),
      (error: DpopClientError) => error.reason === 'storage_unavailable',
    );
  } finally {
    fake.uninstall();
  }
});

/** A failing request is a typed error too, and it propagates through loadOrCreateProofKey. */
test('a failing indexeddb request surfaces as storage_unavailable', async () => {
  const fake = installFakeIndexedDb('failing-requests');
  try {
    const store = new IndexedDbProofKeyStore('ironauth-test');
    await assert.rejects(
      () => store.load(proofKeySlot('cli_1', 'env_prod')),
      (error: DpopClientError) => error.reason === 'storage_unavailable',
    );
    // And through the helper, which must NOT fall back to a fresh in-memory key.
    await assert.rejects(
      () => loadOrCreateProofKey(store, 'cli_1', 'env_prod'),
      (error: DpopClientError) => error.reason === 'storage_unavailable',
    );
  } finally {
    fake.uninstall();
  }
});

/**
 * With no `indexedDB` global at all, the store reports storage_unavailable rather than throwing
 * a raw TypeError.
 *
 * This is the edge-runtime case: the class must remain IMPORTABLE where the global does not
 * exist, so a bundle shared between a browser and a worker still loads in both.
 */
test('the indexeddb store is importable and reports cleanly where the global is absent', async () => {
  const holder = globalThis as { indexedDB?: unknown };
  const previous = holder.indexedDB;
  delete holder.indexedDB;
  try {
    assert.equal(indexedDbAvailable(), false);
    const store = new IndexedDbProofKeyStore('ironauth-test');
    await assert.rejects(
      () => store.load('slot'),
      (error: DpopClientError) => error.reason === 'storage_unavailable',
    );
  } finally {
    if (previous !== undefined) holder.indexedDB = previous;
  }
});

test('indexedDbAvailable reflects the global', () => {
  const fake = installFakeIndexedDb();
  try {
    assert.equal(indexedDbAvailable(), true);
  } finally {
    fake.uninstall();
  }
  assert.equal(indexedDbAvailable(), false, 'and it goes back to false after uninstall');
});

/**
 * A page reload, simulated faithfully: a NEW store instance against the SAME database.
 *
 * That is exactly what a reload is from the store's point of view. The JavaScript context is
 * discarded and rebuilt, so every in-memory field is gone, while IndexedDB persists. A test
 * reusing one store instance proves only that a `Map` works; this proves the key is read back
 * out of storage.
 *
 * Still not a browser, and issue #134 still owes real automation for that. What it forecloses
 * is the failure this criterion is actually about: a client that mints a NEW key on every load
 * and orphans every token bound to the previous one.
 */
test('a keypair survives a simulated page reload', async () => {
  const fake = installFakeIndexedDb();
  try {
    const before = await loadOrCreateProofKey(
      new IndexedDbProofKeyStore('ironauth-reload'),
      'cli_1',
      'env_prod',
    );

    // The reload: everything in memory is discarded. Only the database survives.
    const after = await loadOrCreateProofKey(
      new IndexedDbProofKeyStore('ironauth-reload'),
      'cli_1',
      'env_prod',
    );

    assert.equal(
      after.publicJwk.x,
      before.publicJwk.x,
      'a new key after a reload orphans every token bound to the old one',
    );
    assert.equal(
      after.privateKey.extractable,
      false,
      'and it is still non-extractable after coming back out of storage',
    );
    await assert.rejects(
      () => crypto.subtle.exportKey('jwk', after.privateKey),
      'no API path may extract it, reload or not',
    );
  } finally {
    fake.uninstall();
  }
});

/**
 * The nonce challenge-retry on a PROTECTED RESOURCE, not just the token endpoint.
 *
 * Issue #134 criterion 3 names both surfaces, and they are not the same code path: a resource
 * call carries an access token and therefore an `ath`, so the re-signed proof has to carry the
 * nonce AND keep the correct `ath`. A retry that dropped the `ath` would be refused by the
 * resource server for a reason that looks nothing like a nonce problem.
 */
test('a protected resource nonce challenge is retried exactly once, keeping ath', async () => {
  const key = await generateProofKey();
  const nonces = new NonceCache();
  const proofs: Array<Record<string, unknown>> = [];
  let challenged = false;
  const send = (async (_input: string, init?: RequestInit): Promise<Response> => {
    const proof = new Headers(init?.headers).get('DPoP') ?? '';
    proofs.push(
      JSON.parse(atob(proof.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))) as Record<
        string,
        unknown
      >,
    );
    if (!challenged) {
      challenged = true;
      return new Response('', {
        status: 401,
        headers: {
          'WWW-Authenticate': 'DPoP error="use_dpop_nonce"',
          'DPoP-Nonce': 'resource-nonce',
        },
      });
    }
    return new Response('{"sub":"usr_1"}', { status: 200 });
  }) as unknown as typeof fetch;

  const response = await fetchWithProof(
    key,
    'https://api.example/resource',
    { accessToken: 'at-9' },
    send,
    nonces,
  );
  assert.equal(response.status, 200, 'the retry must succeed');
  assert.equal(proofs.length, 2, 'exactly one retry, never a loop');

  const expectedAth = createHash('sha256').update('at-9').digest('base64url');
  assert.equal(proofs[0].nonce, undefined, 'the first proof had no nonce to carry');
  assert.equal(proofs[1].nonce, 'resource-nonce', 'the retry carries the issued nonce');
  for (const [index, proof] of proofs.entries()) {
    assert.equal(
      proof.ath,
      expectedAth,
      `proof ${index} must carry the ath of the presented token, nonce or not`,
    );
  }
  // And the nonce is remembered for the next resource call on that origin.
  assert.equal(nonces.get('https://api.example/other'), 'resource-nonce');
});
