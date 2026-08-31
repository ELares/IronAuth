// SPDX-License-Identifier: MIT OR Apache-2.0
import type { DpopKey } from './dpop.js';

/**
 * Where the tokens live (issue #117).
 *
 * The BCP's first-choice architecture is defined by this file's existence: the access token, the
 * refresh token, and the PKCE verifier are held HERE, on the server, and the browser is given an
 * opaque id that means nothing on its own.
 *
 * The store is an interface so a deployment can put sessions in Redis, Postgres, or a signed
 * server-side cache, and the in-memory implementation below is for tests and single-process
 * development. It is NOT a default anyone should ship: a restart signs everybody out and a second
 * replica sees none of the first's sessions, which the type's own doc says out loud rather than
 * leaving to be discovered in production.
 */

/** What the server holds for one signed-in browser. */
export interface SessionRecord {
  /** The access token. NEVER leaves the server: the proxy attaches it, nothing returns it. */
  accessToken: string;
  /** The refresh token, if the grant issued one. Never leaves the server either. */
  refreshToken?: string;
  /** Epoch seconds at which the access token expires. */
  expiresAt: number;
  /** The identity claims the frontend is allowed to see. */
  claims: Record<string, unknown>;
  /**
   * The authentication context the ID token recorded, for step-up decisions (issue #116).
   *
   * SERVER-SIDE ONLY, and deliberately not in `claims`: `acr` is something a resource server
   * makes decisions on, so it belongs in the set the frontend never sees. It is held here
   * because in a BFF there is no token for a caller to present, so a step-up requirement has
   * nothing else to be measured against.
   *
   * `undefined` means the ID token carried none, which `satisfies` treats as NOT satisfying an
   * acr requirement rather than as acceptable.
   */
  acr?: string;
  /** When the user authenticated, epoch seconds, for `max_age`. Server-side only, as above. */
  authTime?: number;
  /**
   * The DPoP key these tokens are bound to (RFC 9449), when the client uses DPoP.
   *
   * SERVER-SIDE ONLY, like the tokens, and for the same reason: it is the other half of the
   * credential. A DPoP-bound access token is worthless without this key, which is the entire
   * point, and it stops being true the moment the key reaches the browser.
   *
   * Held per SESSION rather than per process so a token stolen from one session cannot be
   * replayed by another on the same replica.
   */
  dpopKey?: DpopKey;
}

/** What the server holds between the login redirect and the callback. */
export interface PendingLogin {
  /** The PKCE code verifier. Server-side only: this is the whole point of PKCE in a BFF. */
  verifier: string;
  /** The `state` value, compared on the callback. */
  state: string;
  /** Where to send the browser once the callback succeeds. */
  returnTo: string;
  /** Epoch seconds after which this pending login is refused. */
  expiresAt: number;
  /**
   * The DPoP key generated at login, carried to the callback that redeems the code.
   *
   * Generated at LOGIN rather than at the callback because the token the exchange returns is
   * bound to whichever key proved possession, and that key then has to be the session's.
   */
  dpopKey?: DpopKey;
}

/**
 * The server-side store. Every method is async so a real backing store fits.
 *
 * `id` values are opaque and unguessable; see `newId`.
 */
export interface SessionStore {
  putPending(id: string, pending: PendingLogin): Promise<void>;
  /** Read AND REMOVE a pending login. Single-use: see the implementation note. */
  takePending(id: string): Promise<PendingLogin | undefined>;
  putSession(id: string, record: SessionRecord): Promise<void>;
  getSession(id: string): Promise<SessionRecord | undefined>;
  deleteSession(id: string): Promise<void>;
}

/**
 * A `Map`-backed store.
 *
 * FOR TESTS AND SINGLE-PROCESS DEVELOPMENT ONLY, and the two consequences are stated rather than
 * implied: a restart signs every user out, and a second replica shares none of the first's
 * sessions, so a load-balanced deployment on this store logs people out at random. Point the
 * interface at Redis or a database before shipping.
 */
export class MemorySessionStore implements SessionStore {
  readonly #pending = new Map<string, PendingLogin>();
  readonly #sessions = new Map<string, SessionRecord>();

  putPending(id: string, pending: PendingLogin): Promise<void> {
    this.#pending.set(id, pending);
    return Promise.resolve();
  }

  takePending(id: string): Promise<PendingLogin | undefined> {
    const found = this.#pending.get(id);
    // DELETED ON READ, always, including when it is about to be rejected as expired. A pending
    // login that survived a failed callback could be replayed, and a `state` that can be
    // presented twice is not a CSRF defence.
    this.#pending.delete(id);
    return Promise.resolve(found);
  }

  putSession(id: string, record: SessionRecord): Promise<void> {
    this.#sessions.set(id, record);
    return Promise.resolve();
  }

  getSession(id: string): Promise<SessionRecord | undefined> {
    return Promise.resolve(this.#sessions.get(id));
  }

  deleteSession(id: string): Promise<void> {
    this.#sessions.delete(id);
    return Promise.resolve();
  }

  /** How many sessions are held. For tests: a fixation check counts them. */
  get sessionCount(): number {
    return this.#sessions.size;
  }
}

/**
 * A fresh unguessable identifier, base64url, from the platform CSPRNG.
 *
 * 32 bytes rather than 16: this value IS the session, so its entropy is the whole of what stands
 * between an attacker and someone's account. `crypto.getRandomValues` is available in every
 * runtime this package targets (Node 20+, Deno, Bun, workerd), so there is no fallback and
 * deliberately no seam to inject a weaker one.
 */
export function newId(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
