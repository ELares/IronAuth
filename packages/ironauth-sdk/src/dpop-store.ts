// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * DPoP proof-key persistence and nonce caching (issue #134).
 *
 * {@link ./dpop.ts} mints proofs. It holds nothing between calls, which is correct for a
 * signing primitive and useless for a client: a keypair regenerated on every page load is a
 * NEW key, so every token bound to the old one is dead, and a nonce learned from a challenge
 * and then forgotten means the next request earns the same challenge again.
 *
 * This module owns both pieces of state, and nothing else.
 *
 * ## Storage is an interface, with a memory default
 *
 * `IndexedDB` exists in browsers and in nothing else this package targets. Workers, Deno,
 * Bun and Node all need somewhere else to put the key, and only the embedding application
 * knows where that is. So {@link ProofKeyStore} is the seam, {@link MemoryProofKeyStore} is
 * the default that works everywhere, and {@link IndexedDbProofKeyStore} is offered where the
 * global exists.
 *
 * The key never leaves as bytes. A non-extractable `CryptoKey` is structured-cloneable, so
 * IndexedDB stores the OBJECT and the private key stays unreadable to page JavaScript across
 * the whole round trip. A store that serialized to JSON would have to make the key
 * extractable first, which would give away the property the key exists for.
 *
 * ## One keypair per (client, environment)
 *
 * Sharing one key across environments would let a token minted for staging be replayed, with
 * a valid proof, against production. The scoping is in the storage key, so it cannot be
 * forgotten at a call site.
 */

import type { ProofKey } from './dpop.js';
import { DpopClientError, generateProofKey } from './dpop.js';

// The error type lives in `./dpop.js` so `fetchWithProof` can throw it without importing this
// module back. Re-exported here because storage faults are raised from this file, so a caller
// handling them should not have to know which module declares the class.
export { DpopClientError } from './dpop.js';
export type { DpopFailureReason } from './dpop.js';

/**
 * Where a proof keypair lives between calls.
 *
 * Implementations MUST round-trip the `CryptoKey` objects themselves. Returning a key that
 * was exported and re-imported as extractable would silently defeat the non-extractability
 * the whole module depends on.
 */
export interface ProofKeyStore {
  /** The stored keypair for `key`, or `undefined` when there is none. */
  load(key: string): Promise<ProofKey | undefined>;
  /** Persist `value` under `key`. */
  save(key: string, value: ProofKey): Promise<void>;
  /** Forget `key`. Used when a key is rotated or a session ends. */
  remove(key: string): Promise<void>;
}

/**
 * The storage key for a (client, environment) pair.
 *
 * The parts are length-prefixed rather than joined with a separator. With a plain separator,
 * a client id containing it could be made to collide with another pair: `("a:b", "c")` and
 * `("a", "b:c")` both render as `a:b:c`, so one tenant could aim its key at another's slot.
 */
export function proofKeySlot(clientId: string, environment: string): string {
  return `ironauth.dpop.${clientId.length}:${clientId}.${environment.length}:${environment}`;
}

/** An in-memory store. The default, and the only one that works in every target runtime. */
export class MemoryProofKeyStore implements ProofKeyStore {
  readonly #entries = new Map<string, ProofKey>();

  load(key: string): Promise<ProofKey | undefined> {
    return Promise.resolve(this.#entries.get(key));
  }

  save(key: string, value: ProofKey): Promise<void> {
    this.#entries.set(key, value);
    return Promise.resolve();
  }

  remove(key: string): Promise<void> {
    this.#entries.delete(key);
    return Promise.resolve();
  }
}

/** The object store name inside the database. */
const IDB_STORE = 'proof-keys';

/**
 * An `IndexedDB`-backed store, for browsers.
 *
 * Survives a page reload, which is the point: without it every reload mints a new key and
 * orphans every token bound to the previous one.
 *
 * Construction does NOT touch `indexedDB`; the first operation does. That keeps the class
 * importable in runtimes without the global, so a bundle shared between a browser and an
 * edge worker still loads in both. Use {@link indexedDbAvailable} to choose.
 */
export class IndexedDbProofKeyStore implements ProofKeyStore {
  readonly #database: string;

  constructor(database = 'ironauth') {
    this.#database = database;
  }

  async #open(): Promise<IDBDatabase> {
    const factory = (globalThis as { indexedDB?: IDBFactory }).indexedDB;
    if (factory === undefined) {
      throw new DpopClientError('storage_unavailable', 'indexedDB is not available here');
    }
    return new Promise((resolve, reject) => {
      const request = factory.open(this.#database, 1);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(IDB_STORE)) {
          request.result.createObjectStore(IDB_STORE);
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () =>
        reject(new DpopClientError('storage_unavailable', 'indexedDB refused to open'));
    });
  }

  async #transact<T>(
    mode: IDBTransactionMode,
    run: (store: IDBObjectStore) => IDBRequest,
  ): Promise<T> {
    const database = await this.#open();
    return new Promise<T>((resolve, reject) => {
      const request = run(database.transaction(IDB_STORE, mode).objectStore(IDB_STORE));
      request.onsuccess = () => resolve(request.result as T);
      request.onerror = () =>
        reject(new DpopClientError('storage_unavailable', 'the indexedDB request failed'));
    });
  }

  async load(key: string): Promise<ProofKey | undefined> {
    return this.#transact<ProofKey | undefined>('readonly', (store) => store.get(key));
  }

  async save(key: string, value: ProofKey): Promise<void> {
    // The CryptoKey objects are structured-cloned as they are. Nothing is exported, so the
    // private key stays non-extractable on the way in and on the way back out.
    await this.#transact('readwrite', (store) => store.put(value, key));
  }

  async remove(key: string): Promise<void> {
    await this.#transact('readwrite', (store) => store.delete(key));
  }
}

/** Whether `IndexedDB` exists in this runtime. */
export function indexedDbAvailable(): boolean {
  return (globalThis as { indexedDB?: IDBFactory }).indexedDB !== undefined;
}

/**
 * The keypair for `(clientId, environment)`, creating and persisting one if there is none.
 *
 * A store read that THROWS is a storage fault and propagates as
 * {@link DpopClientError} `storage_unavailable`: falling back to a fresh in-memory key would
 * look like it worked and would quietly orphan every token bound to the stored key.
 */
export async function loadOrCreateProofKey(
  store: ProofKeyStore,
  clientId: string,
  environment: string,
): Promise<ProofKey> {
  const slot = proofKeySlot(clientId, environment);
  let existing: ProofKey | undefined;
  try {
    existing = await store.load(slot);
  } catch (cause) {
    if (cause instanceof DpopClientError) {
      throw cause;
    }
    throw new DpopClientError('storage_unavailable', 'the proof key store could not be read');
  }
  if (existing !== undefined) {
    return existing;
  }
  const created = await generateProofKey();
  try {
    await store.save(slot, created);
  } catch (cause) {
    if (cause instanceof DpopClientError) {
      throw cause;
    }
    throw new DpopClientError('storage_unavailable', 'the proof key could not be stored');
  }
  return created;
}

/**
 * The most recent `DPoP-Nonce` per server origin.
 *
 * RFC 9449 section 8 has the server hand back a nonce and expect it on subsequent proofs.
 * Without a cache the client learns a nonce, spends it on the one retry, and forgets it, so
 * EVERY request costs a challenge plus a retry: two round trips each, forever, against a
 * server that is behaving exactly as specified.
 *
 * Keyed by ORIGIN, not by full URL. A nonce is issued by a server, not by an endpoint, so
 * keying more narrowly would relearn it per path; keying more broadly would send one
 * server's nonce to another.
 */
export class NonceCache {
  readonly #byOrigin = new Map<string, string>();

  /** The cached nonce for `url`'s origin, or `undefined`. */
  get(url: string): string | undefined {
    return this.#byOrigin.get(originOf(url));
  }

  /** Record `nonce` for `url`'s origin. */
  set(url: string, nonce: string): void {
    this.#byOrigin.set(originOf(url), nonce);
  }

  /**
   * Absorb a response: record its `DPoP-Nonce` when it carries one.
   *
   * Called on EVERY response, not only on challenges. A server may rotate the nonce on a
   * successful response, and a client that only read the header off failures would use the
   * stale one next time and earn a challenge it was told how to avoid.
   */
  observe(url: string, response: { headers: Headers }): void {
    const nonce = response.headers.get('DPoP-Nonce');
    if (nonce !== null && nonce.length > 0) {
      this.set(url, nonce);
    }
  }
}

/** The origin of `url`, used as the nonce cache key. */
function originOf(url: string): string {
  return new URL(url).origin;
}
