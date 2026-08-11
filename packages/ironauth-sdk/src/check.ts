// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * A uniform authorization `check()` (issue #100, criterion 6).
 *
 * One call shape, three resolvers, chosen by CONFIGURATION and not by the call site:
 *
 * - `claims`   reads the permission out of the access token the caller already holds.
 * - `authzen`  asks IronAuth's AuthZEN policy decision point.
 * - `pdp`      asks the customer's own PDP or FGA over the same AuthZEN wire shape.
 *
 * The point of the uniformity is that application code is written once and a deployment
 * decides later where the answer comes from. A team that starts with claims and outgrows
 * the token budget changes a config value, not every call site.
 *
 * ## Fail CLOSED, always
 *
 * Every failure is a DENY: a network error, a non-2xx, a malformed body, a missing claim,
 * an unparseable token. This is the opposite direction from the claims-enrichment hook, and
 * deliberately so. That hook ADDS claims, so its absence under-grants; this function IS the
 * authorization decision, so its absence must never grant. A caller that wants a fallback
 * writes one and can see that they did.
 */

/** What is being asked: the AuthZEN triple, plus the organization the answer is scoped to. */
export interface CheckRequest {
  /** The subject: `{ type: "user" | "service_account", id }`. */
  subject: { type: string; id: string };
  /** The resource type, the first half of the permission slug. */
  resourceType: string;
  /** The action name, the second half. */
  action: string;
  /** The organization the permission is scoped to. */
  organizationId: string;
}

/** Read the permission out of a token the caller already holds. */
export interface ClaimsResolver {
  mode: 'claims';
  /**
   * The access token's decoded payload. A function rather than a value so a long-lived
   * middleware reads the CURRENT request's token instead of one captured at construction,
   * which is the mistake that authorizes every user as whoever logged in first.
   */
  claims: () => Record<string, unknown> | null | undefined;
  /**
   * The claim carrying the permission slugs. Defaults to `permissions`, which is what
   * IronAuth mints; a deployment whose enrichment hook contributes a different name says so
   * here.
   */
  claimName?: string;
}

/** Ask an AuthZEN-shaped endpoint: either IronAuth's PDP or a customer's own. */
export interface EndpointResolver {
  mode: 'authzen' | 'pdp';
  /** The full evaluation endpoint URL. */
  endpoint: string;
  /** A bearer credential, if the endpoint needs one. */
  token?: string;
  /** Injected for tests; defaults to the global `fetch`. */
  fetchImpl?: typeof fetch;
}

export type CheckConfig = ClaimsResolver | EndpointResolver;

/** The permission slug for a request: a pure join, exactly as the PDP builds it. */
export function permissionSlug(request: CheckRequest): string {
  return `${request.resourceType}.${request.action}`;
}

/**
 * Resolve one authorization question. Never throws and never returns anything but a
 * boolean: an authorization primitive that can throw is one every call site has to wrap,
 * and the wrapping is where somebody writes `catch { return true }`.
 */
export async function check(config: CheckConfig, request: CheckRequest): Promise<boolean> {
  try {
    if (config.mode === 'claims') {
      return checkClaims(config, request);
    }
    return await checkEndpoint(config, request);
  } catch {
    // Fail closed. See the module note.
    return false;
  }
}

function checkClaims(config: ClaimsResolver, request: CheckRequest): boolean {
  const claims = config.claims();
  if (!claims) {
    return false;
  }
  const held = claims[config.claimName ?? 'permissions'];
  if (!Array.isArray(held)) {
    // Absent, or present and not a list. Both are "this token does not say", and the
    // overflow case (`permission_claim_overflow = pdp_required`) is exactly the second:
    // an over-budget subject's token carries no usable permission list, and the correct
    // answer here is DENY so the deployment notices it must ask the PDP instead.
    return false;
  }
  return held.includes(permissionSlug(request));
}

async function checkEndpoint(config: EndpointResolver, request: CheckRequest): Promise<boolean> {
  const doFetch = config.fetchImpl ?? fetch;
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (config.token) {
    headers['authorization'] = `Bearer ${config.token}`;
  }
  const response = await doFetch(config.endpoint, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      subject: { type: request.subject.type, id: request.subject.id },
      resource: { type: request.resourceType },
      action: { name: request.action },
      context: { organization_id: request.organizationId },
    }),
  });
  if (!response.ok) {
    return false;
  }
  const body: unknown = await response.json();
  // Exactly `true` and nothing else. A truthy check would read `"false"`, `1` or `{}` as an
  // allow, and a PDP that answered with a string is a PDP this code does not understand.
  return typeof body === 'object' && body !== null && (body as { decision?: unknown }).decision === true;
}
