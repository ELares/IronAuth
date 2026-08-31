// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * The one cookie this package sets, and the rules it is set under (issue #117).
 *
 * The OAuth 2.0 for Browser-Based Apps BCP's first-choice architecture keeps every token on the
 * server. What the browser holds is a session HANDLE and nothing else, so this module is small
 * on purpose: there is exactly one cookie, it carries an opaque id, and its attributes are not
 * configurable.
 *
 * ## Why the attributes are not options
 *
 * `HttpOnly`, `Secure`, `SameSite` and the `__Host-` prefix are the whole security argument for
 * the pattern. A knob that turns one off is a knob that turns the architecture into the one the
 * BCP ranks last, while the package still calls itself a BFF. Where a value genuinely varies --
 * the session lifetime -- it is a parameter; where it does not, it is a constant.
 *
 * `__Host-` in particular is load bearing and is the most easily lost: RFC 6265bis gives that
 * prefix its meaning only when the cookie is `Secure`, has `Path=/`, and carries NO `Domain`
 * attribute. A `Domain` would let a sibling subdomain set the session cookie, which is session
 * fixation with extra steps. So this module never emits one, and `assertHardened` refuses a
 * header that has it.
 */

/** The session cookie name. `__Host-` prefixed, which pins Path=/, Secure, and no Domain. */
export const SESSION_COOKIE = '__Host-ironauth_bff';

/**
 * The most bytes the auth cookies may occupy in one request (criterion 2).
 *
 * Common servers cap a whole request header block around 8 KB, and the auth cookies are only one
 * part of that: a prefetch-heavy app also carries analytics, feature flags, and a CDN's own
 * cookies on the same request. Four kilobytes leaves half the budget for everything else.
 *
 * The number is a CEILING ON A DESIGN, not a tuning knob. This package's cookie holds an opaque
 * id of a few dozen bytes, so the only way to approach this bound is to start putting claims or
 * tokens in cookies -- which is the chunked-encrypted-cookie design the BCP warns about and
 * this budget exists to make impossible to reach by accident.
 */
export const COOKIE_BUDGET_BYTES = 4096;

/** Serialize the session cookie. */
export function sessionCookie(value: string, maxAgeSeconds: number): string {
  // NO `Domain`, deliberately: see the module header. The order is the conventional one and
  // carries no meaning.
  return [
    `${SESSION_COOKIE}=${value}`,
    'Path=/',
    'HttpOnly',
    'Secure',
    // `Lax` rather than `Strict`: the callback arrives as a top-level GET redirect from the
    // authorization server, and `Strict` withholds the cookie on exactly that navigation -- so a
    // Strict session cookie makes the login loop forever. `Lax` still withholds it from
    // cross-site POSTs, which is the case that matters, and the custom-header CSRF check covers
    // the rest.
    'SameSite=Lax',
    `Max-Age=${maxAgeSeconds}`,
  ].join('; ');
}

/** Serialize the cookie that CLEARS the session. */
export function clearSessionCookie(): string {
  return [
    `${SESSION_COOKIE}=`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    'Max-Age=0',
  ].join('; ');
}

/** Read the session id out of a `Cookie` header, or `undefined`. */
export function sessionFromCookieHeader(header: string | null | undefined): string | undefined {
  if (!header) {
    return undefined;
  }
  for (const part of header.split(';')) {
    const trimmed = part.trim();
    // `indexOf` rather than `split('=')`: a cookie VALUE may legally contain `=` (base64url
    // padding is the common case), and splitting would truncate it at the first one.
    const eq = trimmed.indexOf('=');
    if (eq <= 0) {
      continue;
    }
    if (trimmed.slice(0, eq) === SESSION_COOKIE) {
      const value = trimmed.slice(eq + 1);
      return value === '' ? undefined : value;
    }
  }
  return undefined;
}

/** Why a `Set-Cookie` header was refused by {@link assertHardened}. */
export type CookieFault =
  | 'not_host_prefixed'
  | 'missing_httponly'
  | 'missing_secure'
  | 'missing_samesite'
  | 'has_domain'
  | 'over_budget';

/**
 * Check a `Set-Cookie` header against every rule above, returning the faults found.
 *
 * Exported so it can be asserted over the headers the ADAPTERS actually emit rather than over
 * the constants this module exports. Those are different claims: a test that checked
 * `sessionCookie()` would pass while an adapter dropped the header, rewrote it, or added a
 * second cookie of its own.
 */
export function assertHardened(setCookie: string): CookieFault[] {
  const faults: CookieFault[] = [];
  const lower = setCookie.toLowerCase();
  if (!setCookie.startsWith('__Host-')) {
    faults.push('not_host_prefixed');
  }
  if (!lower.includes('httponly')) {
    faults.push('missing_httponly');
  }
  if (!lower.includes('secure')) {
    faults.push('missing_secure');
  }
  if (!lower.includes('samesite=')) {
    faults.push('missing_samesite');
  }
  // A `__Host-` cookie with a Domain is not merely redundant: RFC 6265bis says a conforming
  // browser REJECTS it, so the session would silently never be set.
  if (lower.includes('domain=')) {
    faults.push('has_domain');
  }
  if (setCookie.length > COOKIE_BUDGET_BYTES) {
    faults.push('over_budget');
  }
  return faults;
}
