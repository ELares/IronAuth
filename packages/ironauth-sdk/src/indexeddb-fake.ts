// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * A minimal in-memory `IndexedDB` for testing the proof-key store (issue #134).
 *
 * `IndexedDbProofKeyStore` shipped with NOTHING exercising it: no test, no runtime check, no
 * caller. Shipped code that nothing runs is code whose first execution happens in a browser
 * belonging to someone else, and its request-and-callback shape is exactly where a transposed
 * `onsuccess`/`onerror` or a missing `onupgradeneeded` hides.
 *
 * ## What this fake is, and what it is not
 *
 * It implements only the surface the store touches: `open` with an upgrade callback,
 * `objectStoreNames.contains`, `createObjectStore`, and `get`/`put`/`delete` on a `readonly` or
 * `readwrite` transaction. Requests resolve asynchronously through the same `onsuccess` and
 * `onerror` callbacks a real implementation uses, because resolving synchronously would let
 * code pass here that deadlocks against a real database.
 *
 * It is NOT a browser. It does not implement versioning beyond the first upgrade, key ranges,
 * cursors, indexes, or transaction abort semantics, and it does not persist across a reload,
 * which is the one property a real browser test would add. Browser automation stays owed on
 * issue #134; this closes the gap between "shipped and never executed" and "shipped and
 * exercised", which is the larger of the two.
 *
 * Kept in `src/` rather than beside the test so the portability scan sees it: it must not
 * introduce a Node-only import either.
 */

/** A request whose callbacks fire on a later microtask, as a real one does. */
class FakeRequest<T> {
  onsuccess: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onupgradeneeded: (() => void) | null = null;
  result!: T;

  /**
   * Resolve with `value`, firing `onupgradeneeded` first when `upgrade` is set.
   *
   * `result` is assigned BEFORE the upgrade callback runs, because that callback reads
   * `request.result` to create its object store, exactly as a real implementation requires.
   */
  settle(value: T, upgrade = false): void {
    queueMicrotask(() => {
      this.result = value;
      if (upgrade) {
        this.onupgradeneeded?.();
      }
      this.onsuccess?.();
    });
  }

  /** Fail, so the store's error path is reachable. */
  fail(): void {
    queueMicrotask(() => {
      this.onerror?.();
    });
  }
}

/** One object store: a name-keyed map. */
class FakeObjectStore {
  constructor(
    private readonly entries: Map<string, unknown>,
    private readonly failing: boolean,
  ) {}

  get(key: string): FakeRequest<unknown> {
    const request = new FakeRequest<unknown>();
    if (this.failing) {
      request.fail();
    } else {
      request.settle(this.entries.get(key));
    }
    return request;
  }

  put(value: unknown, key: string): FakeRequest<void> {
    const request = new FakeRequest<void>();
    if (this.failing) {
      request.fail();
    } else {
      this.entries.set(key, value);
      request.settle(undefined);
    }
    return request;
  }

  delete(key: string): FakeRequest<void> {
    const request = new FakeRequest<void>();
    this.entries.delete(key);
    request.settle(undefined);
    return request;
  }
}

/** A database holding named object stores. */
class FakeDatabase {
  readonly stores = new Map<string, Map<string, unknown>>();

  constructor(private readonly failing: boolean) {}

  get objectStoreNames(): { contains: (name: string) => boolean } {
    return { contains: (name: string) => this.stores.has(name) };
  }

  createObjectStore(name: string): void {
    this.stores.set(name, new Map());
  }

  transaction(name: string, _mode: string): { objectStore: (n: string) => FakeObjectStore } {
    return {
      objectStore: (storeName: string) => {
        // A real implementation throws for an unknown store; creating it lazily would let a
        // store that never ran its upgrade appear to work here and fail in a browser.
        const entries = this.stores.get(storeName ?? name);
        if (entries === undefined) {
          throw new Error(`no object store named ${storeName}`);
        }
        return new FakeObjectStore(entries, this.failing);
      },
    };
  }
}

/** What {@link installFakeIndexedDb} hands back so a test can clean up. */
export interface FakeIndexedDb {
  /** Remove the global again, so one test cannot leak into the next. */
  uninstall: () => void;
  /** How many times `open` was called. */
  opens: () => number;
  /** The backing data, for asserting what was actually persisted. */
  database: FakeDatabase;
}

/**
 * Install a fake `indexedDB` global.
 *
 * `mode` selects the behaviour under test: `"ok"` works, `"failing-requests"` makes every
 * get and put fail so the store's error path runs, and `"failing-open"` refuses to open at all.
 */
export function installFakeIndexedDb(
  mode: 'ok' | 'failing-requests' | 'failing-open' = 'ok',
): FakeIndexedDb {
  const database = new FakeDatabase(mode === 'failing-requests');
  let opens = 0;
  const factory = {
    open(_name: string, _version: number) {
      opens += 1;
      const request = new FakeRequest<FakeDatabase>();
      if (mode === 'failing-open') {
        request.fail();
        return request;
      }
      // The upgrade fires on the FIRST open only, exactly as a version bump does. A store that
      // forgot to create its object store therefore fails HERE, on the first transaction,
      // rather than in a browser belonging to someone else.
      request.settle(database, database.stores.size === 0);
      return request;
    },
  };
  const holder = globalThis as { indexedDB?: unknown };
  const previous = holder.indexedDB;
  holder.indexedDB = factory;
  return {
    uninstall: () => {
      if (previous === undefined) {
        delete holder.indexedDB;
      } else {
        holder.indexedDB = previous;
      }
    },
    opens: () => opens,
    database,
  };
}
