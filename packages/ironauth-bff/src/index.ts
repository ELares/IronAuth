// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * `@ironauth/bff`: the backend-for-frontend helper (issue #117).
 *
 * The OAuth 2.0 for Browser-Based Apps BCP's first-choice architecture. Every token lives on the
 * server; the browser holds one `__Host-` prefixed, `HttpOnly`, `Secure`, `SameSite` cookie
 * carrying an opaque session id.
 *
 * `docs/bff.md` ranks this against the two alternatives with their tradeoffs, and states the one
 * thing this package will never help you do: put a token in `localStorage`.
 *
 * ```ts
 * import { MemorySessionStore, fetchAdapter, login, callback } from '@ironauth/bff';
 *
 * const config = { issuer, clientId, clientSecret, redirectUri, scope: 'openid profile',
 *                  apiBase, sessionMaxAgeSeconds: 3600, store: new MemorySessionStore() };
 *
 * export const onLogin = fetchAdapter((request) => login(config, request));
 * export const onCallback = fetchAdapter((request) => callback(config, request));
 * ```
 *
 * `MemorySessionStore` is for tests and single-process development: a restart signs everybody
 * out and a second replica shares none of the first's sessions. Point `SessionStore` at Redis or
 * a database before shipping.
 */

export {
  CSRF_HEADER,
  MemorySessionStore,
  SESSION_COOKIE,
  callback,
  hasCsrfHeader,
  login,
  logout,
  proxy,
  userinfo,
} from './core.js';
export type { BffConfig, BffRequest, BffResult, SessionRecord, SessionStore } from './core.js';
export {
  type NodeRequestLike,
  type NodeResponseLike,
  type UnauthenticatedPolicy,
  fetchAdapter,
  nodeAdapter,
  toResponse,
} from './adapters.js';
export {
  COOKIE_BUDGET_BYTES,
  type CookieFault,
  assertHardened,
  clearSessionCookie,
  sessionCookie,
  sessionFromCookieHeader,
} from './cookie.js';
export {
  type StepUpGap,
  type StepUpRequirement,
  challengeHeader,
  satisfies,
  stepUpLoginPath,
} from './step-up.js';
