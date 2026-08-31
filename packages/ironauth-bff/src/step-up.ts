// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * RFC 9470 step-up authentication, for a BFF-shaped app (issue #116).
 *
 * > A protected route emits the `insufficient_user_authentication` challenge with
 * > `acr_values`/`max_age`, and the stepped-up token is accepted.
 *
 * A route can require MORE than "signed in": a stronger factor (`acr`), or a RECENT one
 * (`max_age`). RFC 9470 is how a resource server says so without inventing a protocol: a `401`
 * whose `WWW-Authenticate` carries `error="insufficient_user_authentication"` plus the
 * `acr_values` and `max_age` it needs.
 *
 * ## Two shapes, because two callers
 *
 * An XHR wants the challenge; a page navigation wants to be sent somewhere it can satisfy it.
 * Returning a `401` to a top-level navigation shows the user a blank error, and redirecting an
 * XHR gives the fetch an HTML login page it will try to parse as JSON. So both exist and the
 * caller picks -- the same split the BFF's `unauthenticated` result already makes.
 *
 * ## The requirement is checked against what the SESSION recorded, not what a token claims
 *
 * In a BFF the token never reaches the browser, so there is no token for a caller to present and
 * nothing to re-verify. The `acr` and `auth_time` the ID token carried at callback are held on
 * the session record, server-side, and that is what a requirement is measured against. A step-up
 * is complete when a NEW callback overwrites them, which is why `satisfies` is a pure function
 * of the record.
 */

import type { SessionRecord } from './session.js';

/** What a route demands beyond being signed in. */
export interface StepUpRequirement {
  /**
   * Authentication context values, strongest last, matching RFC 9470's `acr_values`.
   *
   * A session satisfies this by having recorded ANY of them. An ordered list is the protocol's
   * shape, and treating it as a set here is deliberate: this package does not know a deployment's
   * ordering, and inventing one would silently downgrade a route that listed two values.
   */
  readonly acrValues?: readonly string[];
  /** The most seconds ago the user may have authenticated. */
  readonly maxAgeSeconds?: number;
}

/** Why a session did not satisfy a requirement. */
export type StepUpGap = 'acr' | 'stale' | 'unknown';

/**
 * Whether `session` already satisfies `requirement`.
 *
 * Returns the GAP rather than a boolean, because the two failures need different messages and a
 * caller that cannot tell them apart sends a user to re-authenticate when their factor was
 * wrong, or asks for a stronger factor when theirs was merely old.
 */
export function satisfies(
  session: SessionRecord,
  requirement: StepUpRequirement,
  nowUnixSeconds: number,
): { ok: true } | { ok: false; gap: StepUpGap } {
  if (requirement.acrValues && requirement.acrValues.length > 0) {
    // FAIL CLOSED on a session that recorded no `acr` at all. "Unknown" is not "acceptable": a
    // route that demanded a phishing-resistant factor must not pass a session whose factor
    // nobody recorded, and treating absence as satisfaction is how that happens quietly.
    if (session.acr === undefined) {
      return { ok: false, gap: 'unknown' };
    }
    if (!requirement.acrValues.includes(session.acr)) {
      return { ok: false, gap: 'acr' };
    }
  }
  if (requirement.maxAgeSeconds !== undefined) {
    if (session.authTime === undefined) {
      return { ok: false, gap: 'unknown' };
    }
    if (nowUnixSeconds - session.authTime > requirement.maxAgeSeconds) {
      return { ok: false, gap: 'stale' };
    }
  }
  return { ok: true };
}

/**
 * The `WWW-Authenticate` value for an unsatisfied requirement (RFC 9470 section 3).
 *
 * `Bearer` scheme, `error="insufficient_user_authentication"`, and the parameters that say what
 * would satisfy it. A challenge that named the error without `acr_values` or `max_age` tells a
 * client it is not authenticated ENOUGH and not what enough is, which is the whole reason the
 * RFC adds those parameters.
 */
export function challengeHeader(requirement: StepUpRequirement): string {
  const parts = ['Bearer error="insufficient_user_authentication"'];
  parts.push('error_description="a stronger or more recent authentication is required"');
  if (requirement.acrValues && requirement.acrValues.length > 0) {
    // SPACE SEPARATED inside one quoted value, which is how `acr_values` is written everywhere
    // else in OAuth. A comma would read as a second auth-param to a conforming parser.
    parts.push(`acr_values="${requirement.acrValues.join(' ')}"`);
  }
  if (requirement.maxAgeSeconds !== undefined) {
    parts.push(`max_age=${requirement.maxAgeSeconds}`);
  }
  return parts.join(', ');
}

/**
 * The login URL that would satisfy `requirement`, for a page navigation.
 *
 * `prompt=login` is NOT set when only `acr_values` is required: the user may already hold the
 * stronger factor and asking them to re-enter a password proves nothing about it. `max_age` is
 * what forces a fresh authentication, and the authorization server is what decides whether the
 * existing session already meets it -- which is its job and not this package's.
 */
export function stepUpLoginPath(
  loginPath: string,
  requirement: StepUpRequirement,
  returnTo: string,
): string {
  const url = new URL(loginPath, 'https://placeholder.invalid');
  // Same-origin path only, matching `login`'s own rule: a `return_to` that is not one turns the
  // login endpoint into an open redirector.
  const safe = returnTo.startsWith('/') && !returnTo.startsWith('//') ? returnTo : '/';
  url.searchParams.set('return_to', safe);
  if (requirement.acrValues && requirement.acrValues.length > 0) {
    url.searchParams.set('acr_values', requirement.acrValues.join(' '));
  }
  if (requirement.maxAgeSeconds !== undefined) {
    url.searchParams.set('max_age', String(requirement.maxAgeSeconds));
  }
  return `${url.pathname}${url.search}`;
}
