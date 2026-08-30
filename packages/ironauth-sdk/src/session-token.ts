// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * The short-lived session JWT client (issue #119, criteria 4 and 6).
 *
 * When an environment runs the opt-in JWT session mode, an SDK exchanges the user's opaque
 * session for a short-lived JWT and re-mints it in the background. That buys networkless
 * verification on hot paths. It also introduces a failure mode that has bitten this pattern in
 * the field, and the whole design of this module is about that failure mode.
 *
 * ## A failed re-mint is NOT a signed-out user
 *
 * This is the rule, and it is the criterion:
 *
 * > Re-mint failure degrades to a stateful session check, never a silent signed-out state.
 *
 * The prior art is `clerk/javascript#9114`, where a handshake fetch that failed resolved as
 * "signed out" -- so a user with a perfectly valid session was logged out by a flaky network. The
 * cost of that bug is not a retry; it is a user losing their work.
 *
 * So this client treats "I could not get a token" and "you are not signed in" as different
 * answers, and only ONE thing in this module ever produces the second: an explicit `401` from the
 * STATEFUL session endpoint. Everything else -- a thrown fetch, a 500, a timeout, a body that
 * does not parse, even a `401` from the mint -- goes to {@link SessionState} `degraded`, which
 * means "no token right now, ask the server the slow way".
 *
 * A `401` from the MINT is deliberately not enough on its own. The mint and the stateful check
 * read the same cookie through the same guard, so they should agree, and when they do the extra
 * request costs one round trip on a path that is already terminal. When they do NOT agree, the
 * disagreement is a bug somewhere, and this resolves it toward "still signed in", which is the
 * direction that does not throw away a user's session.
 *
 * ## What `degraded` obliges the caller to do
 *
 * Fall back to the stateful check for authorization -- which this client has just confirmed
 * succeeds -- and keep the user signed in. `degraded` is not an error state to render; it is the
 * ordinary state of an application whose token minting is briefly unavailable, and it is exactly
 * how the application behaved before anyone turned this mode on.
 */

/** A live token and when it expires (epoch seconds). */
export interface ActiveSession {
  readonly status: 'active';
  /** The compact session JWT. */
  readonly token: string;
  /** Epoch seconds at which it expires. */
  readonly expiresAt: number;
}

/** Why the client has no token, having confirmed the user is still signed in. */
export type DegradeReason =
  /** The mint could not be reached, or answered a non-2xx. */
  | 'mint_unreachable'
  /** The mint answered 2xx with a body this version cannot use. */
  | 'mint_malformed'
  /**
   * The mint failed AND the stateful check could not be reached either.
   *
   * Still not signed out, and this is the case worth being explicit about: two failed requests
   * are evidence of a network problem, not of a session ending. Reporting signed-out here is
   * precisely the #9114 shape.
   */
  | 'stateful_check_unreachable';

/** No token, but the user IS still signed in. */
export interface DegradedSession {
  readonly status: 'degraded';
  readonly reason: DegradeReason;
}

/** The user is not signed in. Only an explicit 401 from the stateful check produces this. */
export interface SignedOutSession {
  readonly status: 'signed-out';
}

export type SessionState = ActiveSession | DegradedSession | SignedOutSession;

/** What the tokenize endpoint returns. */
interface TokenizeBody {
  token?: unknown;
  expires_in?: unknown;
}

/**
 * Mints and re-mints a session JWT, degrading to a stateful check rather than signing anyone out.
 *
 * One instance per (environment, user agent). It holds at most one token and never more: a token
 * is a bearer credential, and a client that kept a history of them would keep credentials alive
 * past the expiry that bounds them.
 */
export class SessionTokenClient {
  readonly #tokenizeUrl: string;
  readonly #sessionCheckUrl: string;
  readonly #fetch: typeof fetch;
  readonly #now: () => number;
  readonly #refreshSkewSeconds: number;
  #cached: ActiveSession | undefined;

  constructor(options: {
    /** The tokenize endpoint, including `?tokenize_as=<template>`. */
    tokenizeUrl: string;
    /**
     * A stateful, session-cookie-authenticated endpoint that answers 2xx when signed in and 401
     * when not. This is the fallback the whole module exists to reach, so it is REQUIRED rather
     * than optional: a client constructed without one could only answer "signed out" on a failed
     * mint, which is the behaviour this file refuses.
     */
    sessionCheckUrl: string;
    fetch?: typeof fetch;
    /** Epoch SECONDS. Injectable so a test can pin the whole lifetime. */
    now?: () => number;
    /**
     * How long before expiry to re-mint. Defaults to 10 seconds.
     *
     * A token used at the moment it expires is a token some verifier rejects for clock skew, so
     * the client stops serving one slightly before the instant it becomes invalid rather than
     * exactly at it.
     */
    refreshSkewSeconds?: number;
  }) {
    this.#tokenizeUrl = options.tokenizeUrl;
    this.#sessionCheckUrl = options.sessionCheckUrl;
    this.#fetch = options.fetch ?? fetch;
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1000));
    this.#refreshSkewSeconds = options.refreshSkewSeconds ?? 10;
  }

  /** How many mint requests this client has made. For tests and for metrics. */
  mintCount = 0;

  /** How many stateful checks this client has made. For tests and for metrics. */
  checkCount = 0;

  /**
   * Drop the cached token, so the next {@link current} re-mints.
   *
   * Call this when a resource server REJECTS the token: a key rotated, the template changed, or
   * the audience moved. The client cannot see that rejection itself -- verification happens at
   * the resource server -- so the caller is what tells it.
   *
   * The re-mint that follows obeys the same rule as every other: if it fails, the answer is
   * `degraded`, never signed-out. A rotation mid-flight must not log anybody out.
   */
  invalidate(): void {
    this.#cached = undefined;
  }

  /** The token to present, or what to do instead. */
  async current(): Promise<SessionState> {
    const cached = this.#cached;
    if (cached !== undefined && this.#now() < cached.expiresAt - this.#refreshSkewSeconds) {
      return cached;
    }
    // The cached token is gone or too close to expiry. It is dropped BEFORE the mint rather than
    // after: if the mint fails we must not keep serving a token that is about to be rejected for
    // being expired, which would turn a recoverable degrade into an authorization error the
    // caller cannot explain.
    this.#cached = undefined;
    const minted = await this.#mint();
    if (minted.ok) {
      this.#cached = minted.session;
      return minted.session;
    }
    return this.#fallBackToStatefulCheck(minted.reason);
  }

  async #mint(): Promise<{ ok: true; session: ActiveSession } | { ok: false; reason: DegradeReason }> {
    this.mintCount += 1;
    let response: Response;
    try {
      response = await this.#fetch(this.#tokenizeUrl, {
        method: 'POST',
        credentials: 'include',
      });
    } catch {
      // A THROWN fetch is the #9114 case exactly: offline, DNS, CORS, an aborted request. It says
      // nothing whatsoever about the session.
      return { ok: false, reason: 'mint_unreachable' };
    }
    if (!response.ok) {
      // INCLUDING 401. See the module header: the mint's own 401 is not enough to sign anyone
      // out, because the stateful check is the authority and it is one request away.
      return { ok: false, reason: 'mint_unreachable' };
    }
    let body: TokenizeBody;
    try {
      body = (await response.json()) as TokenizeBody;
    } catch {
      return { ok: false, reason: 'mint_malformed' };
    }
    const token = body.token;
    const expiresIn = body.expires_in;
    if (typeof token !== 'string' || token === '' || typeof expiresIn !== 'number') {
      return { ok: false, reason: 'mint_malformed' };
    }
    return {
      ok: true,
      session: {
        status: 'active',
        token,
        // From the CLIENT's clock plus the server's stated lifetime, rather than from the token's
        // own `exp`. The client does not parse the token here -- parsing it to decide when to
        // re-mint would be reading an unverified payload to make a decision, which is the habit
        // that ends in trusting one.
        expiresAt: this.#now() + expiresIn,
      },
    };
  }

  async #fallBackToStatefulCheck(reason: DegradeReason): Promise<SessionState> {
    this.checkCount += 1;
    let response: Response;
    try {
      response = await this.#fetch(this.#sessionCheckUrl, {
        method: 'GET',
        credentials: 'include',
      });
    } catch {
      return { status: 'degraded', reason: 'stateful_check_unreachable' };
    }
    if (response.status === 401 || response.status === 403) {
      // THE ONLY PATH TO SIGNED-OUT in this module. An explicit refusal from the endpoint whose
      // job is to answer this question.
      return { status: 'signed-out' };
    }
    if (!response.ok) {
      // A 500 from the check is not an answer. Two failures are a network story.
      return { status: 'degraded', reason: 'stateful_check_unreachable' };
    }
    return { status: 'degraded', reason };
  }
}

/** What the token-mode endpoint reports. */
export interface SessionTokenMode {
  readonly enabled: boolean;
  readonly template?: string;
  readonly ttlSeconds?: number;
  readonly jwksUri?: string;
  readonly audience?: string;
}

/**
 * Read whether an environment runs the JWT session mode.
 *
 * FAILS TO DISABLED, always. Every error -- unreachable, non-2xx, unparseable -- reports
 * `{enabled: false}`, which sends the caller to the stateful session check. That is the same
 * direction the rest of this module fails in and for the same reason: the stateful check is
 * always correct, merely slower, so an SDK that cannot read its configuration should do the
 * correct slow thing rather than guess at the fast one.
 *
 * @param url the `.../session/token-mode` endpoint
 */
export async function readSessionTokenMode(
  url: string,
  options: { fetch?: typeof fetch } = {},
): Promise<SessionTokenMode> {
  const send = options.fetch ?? fetch;
  const disabled: SessionTokenMode = { enabled: false };
  let response: Response;
  try {
    response = await send(url, { method: 'GET' });
  } catch {
    return disabled;
  }
  if (!response.ok) {
    return disabled;
  }
  let body: Record<string, unknown>;
  try {
    body = (await response.json()) as Record<string, unknown>;
  } catch {
    return disabled;
  }
  if (body.enabled !== true) {
    return disabled;
  }
  const template = typeof body.template === 'string' ? body.template : undefined;
  const ttlSeconds = typeof body.ttl_seconds === 'number' ? body.ttl_seconds : undefined;
  const jwksUri = typeof body.jwks_uri === 'string' ? body.jwks_uri : undefined;
  const audience = typeof body.audience === 'string' ? body.audience : undefined;
  // ENABLED REQUIRES ALL THREE. A mode that says it is on but cannot say which template, for how
  // long, or against which keys is not usable configuration, and treating it as on would leave a
  // client minting against `undefined`.
  if (template === undefined || ttlSeconds === undefined || jwksUri === undefined) {
    return disabled;
  }
  return { enabled: true, template, ttlSeconds, jwksUri, audience };
}
