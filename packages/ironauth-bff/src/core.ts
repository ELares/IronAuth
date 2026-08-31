// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * The five BFF handler groups, framework-agnostic (issue #117).
 *
 * Every handler takes a plain {@link BffRequest} and returns a typed {@link BffResult}. Neither
 * type mentions a framework, which is what lets one implementation serve both adapters -- and
 * what makes the adapters thin enough to read in one sitting.
 *
 * ## The results are TYPED, and that is a criterion rather than a style
 *
 * > Error handling: refresh failure, upstream IdP errors, and session expiry surface as typed
 * > results that framework SDKs can map to redirects or 401s.
 *
 * So nothing here throws for an expected outcome and nothing returns a bare status code. A
 * caller matches on `kind` and decides; a framework SDK maps the same union to its own idioms.
 * The one thing a result never carries is a token, which is checked by test rather than trusted.
 *
 * ## What the browser gets
 *
 * A `__Host-` prefixed, HttpOnly, Secure, SameSite session cookie holding an opaque id, and
 * nothing else. The access token, the refresh token and the PKCE verifier live in the
 * {@link SessionStore}. That is the BCP's first-choice architecture, and every other design this
 * package could have had is ranked below it in `docs/bff.md` with the reasons.
 */

import { SESSION_COOKIE, clearSessionCookie, sessionCookie, sessionFromCookieHeader } from './cookie.js';
import { MemorySessionStore, type SessionRecord, type SessionStore, newId } from './session.js';

export { MemorySessionStore, SESSION_COOKIE };
export type { SessionRecord, SessionStore };

/** A request, reduced to what any adapter can produce. */
export interface BffRequest {
  method: string;
  /** The full URL, so query parameters are read from one place. */
  url: string;
  headers: {
    get(name: string): string | null;
  };
  /** The body, for the proxy. Absent on GET. */
  body?: BodyInit | null;
}

/** What the caller should do next. Adapters map these; they never invent one. */
export type BffResult =
  | { kind: 'redirect'; location: string; setCookie?: string; status: 302 }
  | { kind: 'json'; status: number; body: unknown; setCookie?: string }
  | { kind: 'proxied'; response: Response }
  /**
   * The session is gone or was never there. A 401 for the frontend, or a redirect to login --
   * the adapter decides, because a page and an XHR want different answers to the same fact.
   */
  | { kind: 'unauthenticated'; reason: 'no_session' | 'session_expired' | 'refresh_failed' }
  /** The request was refused before anything was looked up. */
  | { kind: 'refused'; reason: 'csrf' | 'bad_state' | 'missing_code' | 'unknown_login' }
  /** The upstream IdP answered something this cannot use. */
  | { kind: 'upstream_error'; status: number; detail: string };

/** What the BFF needs to know about the deployment. */
export interface BffConfig {
  /** The IronAuth issuer, e.g. `https://iss.example/t/ten_x/e/env_y`. */
  issuer: string;
  clientId: string;
  /** The confidential client's secret. Server-side only, like every other secret here. */
  clientSecret?: string;
  /** Where IronAuth sends the browser back. Must be registered. */
  redirectUri: string;
  /** Requested scopes. */
  scope: string;
  /** The upstream API the proxy forwards to. */
  apiBase: string;
  /** Session lifetime in seconds. */
  sessionMaxAgeSeconds: number;
  store: SessionStore;
  /** Injectable for tests. Defaults to the platform `fetch`. */
  fetch?: typeof fetch;
  /** Injectable epoch-seconds clock. Defaults to the wall clock. */
  now?: () => number;
}

/** The header a state-changing BFF endpoint requires. */
export const CSRF_HEADER = 'x-ironauth-bff';

/**
 * Whether a state-changing request carries the CSRF custom header (criterion 4).
 *
 * The BCP's pattern, and it works because a cross-site form post or image load CANNOT set a
 * custom header: doing so makes the request non-simple, which forces a CORS preflight the
 * attacker's origin will not pass. `SameSite=Lax` is the first line and this is the second,
 * because Lax still admits top-level GET navigations and browsers differ on what counts.
 *
 * The VALUE is not checked, only the presence, and that is not laziness: there is no secret to
 * compare against that the attacker could not also read if they could read anything. The
 * security comes from the browser refusing to send the header at all.
 */
export function hasCsrfHeader(request: BffRequest): boolean {
  return request.headers.get(CSRF_HEADER) !== null;
}

function clock(config: BffConfig): number {
  return config.now?.() ?? Math.floor(Date.now() / 1000);
}

function send(config: BffConfig): typeof fetch {
  return config.fetch ?? fetch;
}

/** base64url of a SHA-256 digest, for the PKCE challenge. */
async function s256(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  let binary = '';
  for (const byte of new Uint8Array(digest)) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * `GET /auth/login`: start the code+PKCE flow SERVER-SIDE.
 *
 * The verifier never reaches the browser. In a browser-held-token architecture PKCE protects a
 * public client from code interception; here the client is confidential and the verifier is one
 * more secret the server keeps, which is strictly stronger and costs nothing.
 *
 * The pending login is keyed by a fresh id carried in the session cookie. Using the SESSION
 * cookie for this is deliberate: it means a login started in one browser cannot be completed in
 * another, which is the session-fixation case.
 */
export async function login(config: BffConfig, request: BffRequest): Promise<BffResult> {
  const url = new URL(request.url);
  // The return target is validated as a SAME-ORIGIN PATH and never taken as a full URL. A
  // `returnTo=https://evil.example` would turn this endpoint into an open redirector, which is
  // the classic way a login endpoint becomes a phishing tool.
  const requested = url.searchParams.get('return_to') ?? '/';
  const returnTo = requested.startsWith('/') && !requested.startsWith('//') ? requested : '/';

  const verifier = newId();
  const state = newId();
  const pendingId = newId();
  await config.store.putPending(pendingId, {
    verifier,
    state,
    returnTo,
    // A SHORT life. A pending login is a few seconds of user time; leaving it valid for an hour
    // widens the window in which a stolen `state` is worth anything.
    expiresAt: clock(config) + 600,
  });

  const authorize = new URL(`${config.issuer}/authorize`);
  authorize.searchParams.set('response_type', 'code');
  authorize.searchParams.set('client_id', config.clientId);
  authorize.searchParams.set('redirect_uri', config.redirectUri);
  authorize.searchParams.set('scope', config.scope);
  authorize.searchParams.set('state', state);
  authorize.searchParams.set('code_challenge', await s256(verifier));
  authorize.searchParams.set('code_challenge_method', 'S256');

  return {
    kind: 'redirect',
    status: 302,
    location: authorize.toString(),
    setCookie: sessionCookie(pendingId, 600),
  };
}

/**
 * `GET /auth/callback`: exchange the code and establish the session.
 *
 * # The session id ROTATES here
 *
 * The cookie set at login carries the PENDING id; the cookie set here carries a NEW one. That is
 * the session-fixation defence: an attacker who fixed a value in the victim's browser before the
 * login holds an id that is discarded the moment the login succeeds.
 */
export async function callback(config: BffConfig, request: BffRequest): Promise<BffResult> {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const pendingId = sessionFromCookieHeader(request.headers.get('cookie'));
  if (!pendingId) {
    return { kind: 'refused', reason: 'unknown_login' };
  }
  const pending = await config.store.takePending(pendingId);
  if (!pending) {
    return { kind: 'refused', reason: 'unknown_login' };
  }
  if (pending.expiresAt <= clock(config)) {
    return { kind: 'refused', reason: 'unknown_login' };
  }
  if (!code) {
    return { kind: 'refused', reason: 'missing_code' };
  }
  // COMPARED, and a mismatch is a refusal rather than a warning. `state` is what binds this
  // callback to the login this browser started.
  if (!state || state !== pending.state) {
    return { kind: 'refused', reason: 'bad_state' };
  }

  const form = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: config.redirectUri,
    client_id: config.clientId,
    code_verifier: pending.verifier,
  });
  if (config.clientSecret !== undefined) {
    form.set('client_secret', config.clientSecret);
  }
  let response: Response;
  try {
    response = await send(config)(`${config.issuer}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
  } catch {
    return { kind: 'upstream_error', status: 502, detail: 'the token endpoint was unreachable' };
  }
  if (!response.ok) {
    // The upstream's status is carried but NOT its body: a token-endpoint error body can name
    // the client id and the grant, and this response goes to a browser.
    return { kind: 'upstream_error', status: response.status, detail: 'the code exchange failed' };
  }
  let token: Record<string, unknown>;
  try {
    token = (await response.json()) as Record<string, unknown>;
  } catch {
    return { kind: 'upstream_error', status: 502, detail: 'the token response was unreadable' };
  }
  const accessToken = token.access_token;
  if (typeof accessToken !== 'string') {
    return { kind: 'upstream_error', status: 502, detail: 'the token response carried no access token' };
  }
  const expiresIn = typeof token.expires_in === 'number' ? token.expires_in : 300;

  const sessionId = newId();
  await config.store.putSession(sessionId, {
    accessToken,
    refreshToken: typeof token.refresh_token === 'string' ? token.refresh_token : undefined,
    expiresAt: clock(config) + expiresIn,
    // MINIMAL CLAIMS, and only from the ID token's payload if one came back. The frontend gets
    // an identity, not an authorization: `sub` and the profile fields, never `scope`, never a
    // token, never anything a resource server makes a decision on.
    claims: minimalClaims(token.id_token),
    // SERVER-SIDE, for step-up (issue #116). Read from the same ID token payload the claims come
    // from, but kept OFF the claims bag: `acr` is something a resource server decides on, and the
    // allow-list exists to keep exactly that out of the frontend's hands.
    ...authenticationContext(token.id_token),
  });

  return {
    kind: 'redirect',
    status: 302,
    location: pending.returnTo,
    setCookie: sessionCookie(sessionId, config.sessionMaxAgeSeconds),
  };
}

/**
 * The identity the frontend may see, from an ID token's payload.
 *
 * An ALLOW-LIST rather than a deny-list. The frontend needs to render a name and an avatar; it
 * does not need `scope`, `permissions`, `roles`, `cnf` or anything else a resource server
 * authorizes on, and a deny-list would admit every claim a future token gains.
 *
 * The payload is read WITHOUT verifying the signature, and that is safe only because of where it
 * came from: this ran on the server, over TLS, against the token endpoint's own response to an
 * exchange this server initiated with its own PKCE verifier. It is not a token anyone presented.
 * A verifier here would be checking IronAuth's signature against IronAuth's key on a value
 * IronAuth just handed us over a channel we authenticated -- and `@ironauth/sdk`'s `verifyToken`
 * is what to use where a token IS presented.
 */
function minimalClaims(idToken: unknown): Record<string, unknown> {
  if (typeof idToken !== 'string') {
    return {};
  }
  const payload = idToken.split('.')[1];
  if (payload === undefined) {
    return {};
  }
  let decoded: Record<string, unknown>;
  try {
    const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    decoded = JSON.parse(json) as Record<string, unknown>;
  } catch {
    return {};
  }
  const allowed = ['sub', 'name', 'preferred_username', 'email', 'email_verified', 'picture'];
  const claims: Record<string, unknown> = {};
  for (const name of allowed) {
    if (decoded[name] !== undefined) {
      claims[name] = decoded[name];
    }
  }
  return claims;
}

/**
 * The `acr` and `auth_time` an ID token recorded, for step-up decisions.
 *
 * Separate from {@link minimalClaims} because the two have opposite destinations: those claims go
 * to the frontend, and these must not. Sharing a function would make it one edit to leak them.
 */
function authenticationContext(idToken: unknown): { acr?: string; authTime?: number } {
  if (typeof idToken !== 'string') {
    return {};
  }
  const payload = idToken.split('.')[1];
  if (payload === undefined) {
    return {};
  }
  try {
    const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    const decoded = JSON.parse(json) as Record<string, unknown>;
    return {
      acr: typeof decoded.acr === 'string' ? decoded.acr : undefined,
      authTime: typeof decoded.auth_time === 'number' ? decoded.auth_time : undefined,
    };
  } catch {
    return {};
  }
}

/**
 * `POST /auth/logout`: end the local session, optionally sending the browser on to RP-initiated
 * logout.
 *
 * State-changing, so it demands the CSRF header. A logout CSRF is a real nuisance attack -- an
 * attacker cannot read anything but can sign a user out repeatedly -- and the BCP asks for the
 * check on state-changing endpoints without carving out the ones whose damage is small.
 */
export async function logout(
  config: BffConfig,
  request: BffRequest,
  options: { rpInitiated?: boolean } = {},
): Promise<BffResult> {
  if (!hasCsrfHeader(request)) {
    return { kind: 'refused', reason: 'csrf' };
  }
  const sessionId = sessionFromCookieHeader(request.headers.get('cookie'));
  if (sessionId) {
    // DELETED SERVER-SIDE FIRST. Clearing the cookie alone would leave a live session behind for
    // anyone who kept a copy of the id, which is exactly the "logout that does not log out"
    // defect.
    await config.store.deleteSession(sessionId);
  }
  if (options.rpInitiated) {
    return {
      kind: 'redirect',
      status: 302,
      location: `${config.issuer}/end_session`,
      setCookie: clearSessionCookie(),
    };
  }
  return { kind: 'json', status: 200, body: { signed_out: true }, setCookie: clearSessionCookie() };
}

/**
 * `GET /auth/userinfo`: the session-derived identity for the frontend.
 *
 * Returns the stored claims and NOTHING ELSE. No access token, no refresh token, no expiry of
 * either -- a frontend that knows when the access token expires learns nothing useful and gains
 * a reason to ask for it.
 */
export async function userinfo(config: BffConfig, request: BffRequest): Promise<BffResult> {
  const sessionId = sessionFromCookieHeader(request.headers.get('cookie'));
  if (!sessionId) {
    return { kind: 'unauthenticated', reason: 'no_session' };
  }
  const session = await config.store.getSession(sessionId);
  if (!session) {
    return { kind: 'unauthenticated', reason: 'no_session' };
  }
  return { kind: 'json', status: 200, body: { claims: session.claims } };
}

/**
 * `ANY /api/*`: forward to the upstream API with the access token attached, refreshing first if
 * it is about to expire.
 *
 * # Refresh failure is `unauthenticated`, never a silent pass-through
 *
 * A proxy that forwarded the request WITHOUT a token on a failed refresh would turn an
 * authentication problem into whatever the upstream says about an anonymous call -- typically a
 * 403 that sends the user to the wrong support article. The typed result says which it was.
 */
export async function proxy(config: BffConfig, request: BffRequest): Promise<BffResult> {
  if (request.method !== 'GET' && request.method !== 'HEAD' && !hasCsrfHeader(request)) {
    return { kind: 'refused', reason: 'csrf' };
  }
  const sessionId = sessionFromCookieHeader(request.headers.get('cookie'));
  if (!sessionId) {
    return { kind: 'unauthenticated', reason: 'no_session' };
  }
  let session = await config.store.getSession(sessionId);
  if (!session) {
    return { kind: 'unauthenticated', reason: 'no_session' };
  }

  // A SKEW, so a token that expires mid-flight is refreshed before it is used rather than after
  // the upstream rejects it.
  if (session.expiresAt - 30 <= clock(config)) {
    const refreshed = await refresh(config, session);
    if (!refreshed) {
      // The session is destroyed rather than left to fail on every later request. A session whose
      // refresh token is dead cannot recover, so keeping it is keeping a cookie that means
      // "signed in" while nothing works.
      await config.store.deleteSession(sessionId);
      return {
        kind: 'unauthenticated',
        reason: session.refreshToken ? 'refresh_failed' : 'session_expired',
      };
    }
    session = refreshed;
    await config.store.putSession(sessionId, session);
  }

  const target = new URL(request.url);
  const upstream = new URL(config.apiBase);
  // The PATH is taken from the incoming request and joined onto the configured base, so the
  // proxy cannot be pointed at another host by the caller.
  upstream.pathname = `${upstream.pathname.replace(/\/$/, '')}${target.pathname}`;
  upstream.search = target.search;

  let response: Response;
  try {
    response = await send(config)(upstream.toString(), {
      method: request.method,
      headers: {
        authorization: `Bearer ${session.accessToken}`,
        // The COOKIE IS NOT FORWARDED, deliberately: the upstream authenticates with the bearer
        // token, and passing the session cookie on would hand a third-party API a credential for
        // this origin.
        'content-type': request.headers.get('content-type') ?? 'application/json',
      },
      body: request.body ?? undefined,
    });
  } catch {
    return { kind: 'upstream_error', status: 502, detail: 'the upstream API was unreachable' };
  }
  return { kind: 'proxied', response };
}

/** Exchange the refresh token, or `undefined` when it cannot be. */
async function refresh(config: BffConfig, session: SessionRecord): Promise<SessionRecord | undefined> {
  if (!session.refreshToken) {
    return undefined;
  }
  const form = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: session.refreshToken,
    client_id: config.clientId,
  });
  if (config.clientSecret !== undefined) {
    form.set('client_secret', config.clientSecret);
  }
  let response: Response;
  try {
    response = await send(config)(`${config.issuer}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
  } catch {
    return undefined;
  }
  if (!response.ok) {
    return undefined;
  }
  let token: Record<string, unknown>;
  try {
    token = (await response.json()) as Record<string, unknown>;
  } catch {
    return undefined;
  }
  const accessToken = token.access_token;
  if (typeof accessToken !== 'string') {
    return undefined;
  }
  return {
    accessToken,
    // ROTATION HONOURED: when the response carries a new refresh token the old one is discarded,
    // because IronAuth's refresh family detects reuse and replaying a rotated token kills the
    // family. Keeping the old one would sign the user out on the next refresh.
    refreshToken: typeof token.refresh_token === 'string' ? token.refresh_token : session.refreshToken,
    expiresAt: (config.now?.() ?? Math.floor(Date.now() / 1000)) +
      (typeof token.expires_in === 'number' ? token.expires_in : 300),
    claims: session.claims,
  };
}
