// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The ONE module in the admin console that performs a network call. Every
// request goes through here: the typed openapi-fetch management client, plus the
// two OIDC public endpoints the login needs (discovery and the token exchange).
// The route audit (scripts/admin-spa-route-audit.sh) is the structural
// guarantee: it fails if any other module performs a network call or names a
// server path, and it checks that every path this app can reach maps to a
// documented management operation or the small OIDC public allowlist.
//
// The management client is typed by the generated management contract
// (management.gen.ts), so a call can only target a path and method the public
// management API documents. A per request middleware attaches the in memory
// bearer (src/auth/session.ts); nothing here ever holds an operator token or a
// management key, so the only credential the browser sends is the short lived
// at+jwt from the OIDC login.

import createClient from "openapi-fetch";
import type { components, paths } from "./management.gen";
import { loadConfig } from "../config";
import { getAccessToken } from "../auth/session";

// The verbatim structured error body every management endpoint returns. Kept as
// a re-export of the generated schema so the UI never hand maintains the shape.
export type ErrorBody = components["schemas"]["ErrorBody"];

// The two list views the shell reads (issue #90, PR 3): the tenant/environment
// context switcher populates itself from these, and every scoped resource view
// downstream reads the active selection. Re-exported from the generated schema so
// the shell never hand maintains a shape the management contract already owns.
export type TenantView = components["schemas"]["TenantView"];
export type EnvironmentView = components["schemas"]["EnvironmentView"];

// The request and result shapes the tenant + environment CRUD surfaces read
// (issue #90, PR 4). Re-exported from the generated schema so the resource views
// never hand maintain a shape the management contract already owns:
// CreateTenantRequest / TenantCreated for the tenant create, TenantStatusView for
// the suspend / resume / restore lifecycle post-condition, and
// CreateEnvironmentRequest for the environment create.
export type CreateTenantRequest = components["schemas"]["CreateTenantRequest"];
export type TenantCreated = components["schemas"]["TenantCreated"];
export type TenantStatusView = components["schemas"]["TenantStatusView"];
export type CreateEnvironmentRequest =
  components["schemas"]["CreateEnvironmentRequest"];

// The request and result shapes the users CRUD surface reads (issue #90, PR 5).
// Users are ENVIRONMENT scoped, so every wrapper below injects the active
// {tenant, environment} into the documented path. Re-exported from the generated
// schema so the users view never hand maintains a shape the management contract
// already owns: UserView / UserList for the reads, CreateUserRequest for the
// create, UpdateUserRequest for the RFC 7396 merge-patch update (claims only),
// SetUserStateRequest / UserStateChangeView for the lifecycle transitions,
// RevokeSessionsRequest / UserRevocationView for the session revoke, and
// LinkExternalIdRequest / UserExternalIdView for the external id mapping.
export type UserView = components["schemas"]["UserView"];
export type UserStateView = components["schemas"]["UserStateView"];
export type CreateUserRequest = components["schemas"]["CreateUserRequest"];
export type UpdateUserRequest = components["schemas"]["UpdateUserRequest"];
export type SetUserStateRequest =
  components["schemas"]["SetUserStateRequest"];
export type UserStateChangeView =
  components["schemas"]["UserStateChangeView"];
export type RevokeSessionsRequest =
  components["schemas"]["RevokeSessionsRequest"];
export type UserRevocationView =
  components["schemas"]["UserRevocationView"];
export type LinkExternalIdRequest =
  components["schemas"]["LinkExternalIdRequest"];
export type UserExternalIdView =
  components["schemas"]["UserExternalIdView"];

// The request and result shapes the organizations, memberships, and invitations
// CRUD surfaces read (issue #94). Organizations and their memberships, and the
// invitations, are all ENVIRONMENT scoped, so every wrapper below injects the
// active {tenant, environment} into the documented path. Re-exported from the
// generated schema so the views never hand maintain a shape the management
// contract already owns.
//
// OrganizationView / CreateOrganizationRequest for the org reads and create;
// MembershipView / CreateMembershipRequest for the members of an org (a
// membership lives UNDER an organization, keyed by user id); InvitationView /
// CreateInvitationRequest for the invitation reads and create;
// InvitationCreatedView is the copy-once surface (its `token` is the raw
// `ira_inv_` token the server returns ONCE at create or resend, never stored, so
// the UI surfaces it a single time and never persists or logs it);
// InvitationStateChangeView is the deterministic post-condition of a revoke; and
// InvitationStateView / InvitationCredentialTypeView are the closed wire enums
// the invitation filter and create form read.
export type OrganizationView = components["schemas"]["OrganizationView"];
export type CreateOrganizationRequest =
  components["schemas"]["CreateOrganizationRequest"];
export type MembershipView = components["schemas"]["MembershipView"];
export type CreateMembershipRequest =
  components["schemas"]["CreateMembershipRequest"];
export type InvitationView = components["schemas"]["InvitationView"];
export type CreateInvitationRequest =
  components["schemas"]["CreateInvitationRequest"];
export type InvitationCreatedView =
  components["schemas"]["InvitationCreatedView"];
export type InvitationStateChangeView =
  components["schemas"]["InvitationStateChangeView"];
export type InvitationStateView = components["schemas"]["InvitationStateView"];
export type InvitationCredentialTypeView =
  components["schemas"]["InvitationCredentialTypeView"];

// The request and result shapes the organization roles and groups surfaces read
// (issue #97). Roles, groups, group members, and the two assignment surfaces all
// live UNDER one organization, which itself lives under the active
// {tenant, environment}, so every wrapper below injects all three ids into the
// documented path. Re-exported from the generated schema so the views never hand
// maintain a shape the management contract already owns.
//
// OrgRoleView / CreateOrgRoleRequest / UpdateOrgRoleRequest for the roles CRUD
// (the slug is IMMUTABLE, so the update carries only the display name and the
// metadata); OrgGroupView / CreateOrgGroupRequest / UpdateOrgGroupRequest for the
// groups CRUD, plus SetOrgGroupParentRequest for the dedicated MOVE operation
// (reparenting is its own endpoint because it carries the cycle and depth
// refusals a plain rename must never be able to trigger);
// OrgGroupMemberView / AddOrgGroupMemberRequest for binding an organization
// membership into a group; OrgGroupRoleView / AssignOrgGroupRoleRequest and
// OrgMembershipRoleView / AssignOrgMembershipRoleRequest for the two grant
// surfaces; and EffectiveRolesView / EffectiveRoleView for the resolved picture.
//
// EffectiveRoleView is ONE GRANT PATH, not one role: a role held both directly
// and through a group yields TWO entries carrying the same slug. That is the
// point of the view, so nothing in this app may collapse it by slug.
export type OrgRoleView = components["schemas"]["OrgRoleView"];
export type CreateOrgRoleRequest = components["schemas"]["CreateOrgRoleRequest"];
export type UpdateOrgRoleRequest = components["schemas"]["UpdateOrgRoleRequest"];
export type OrgGroupView = components["schemas"]["OrgGroupView"];
export type CreateOrgGroupRequest =
  components["schemas"]["CreateOrgGroupRequest"];
export type UpdateOrgGroupRequest =
  components["schemas"]["UpdateOrgGroupRequest"];
export type SetOrgGroupParentRequest =
  components["schemas"]["SetOrgGroupParentRequest"];
export type OrgGroupMemberView = components["schemas"]["OrgGroupMemberView"];
export type AddOrgGroupMemberRequest =
  components["schemas"]["AddOrgGroupMemberRequest"];
export type OrgGroupRoleView = components["schemas"]["OrgGroupRoleView"];
export type AssignOrgGroupRoleRequest =
  components["schemas"]["AssignOrgGroupRoleRequest"];
export type OrgMembershipRoleView =
  components["schemas"]["OrgMembershipRoleView"];
export type AssignOrgMembershipRoleRequest =
  components["schemas"]["AssignOrgMembershipRoleRequest"];
export type EffectiveRoleView = components["schemas"]["EffectiveRoleView"];
export type EffectiveRolesView = components["schemas"]["EffectiveRolesView"];
// The GENERATED union of grant-path sources, re-exported so a view that puts a
// human label on each one can be keyed on the union itself rather than on `string`.
// That is the difference between a fourth variant being a compile error and a
// fourth variant silently taking whatever a fallback branch says: `default` was
// added to this union by issue #98 PR 6 and the console mislabelled it as a direct
// grant for the rest of the issue, because the label was a `string` ternary.
export type EffectiveRoleSourceView =
  components["schemas"]["EffectiveRoleSourceView"];

// The shapes the PERMISSION surfaces read (issue #98). Re-exported from the
// generated schema so no view hand maintains a shape the management contract
// already owns, and grouped by the scope each one belongs to, because getting that
// wrong is the mistake this issue can most easily ship:
//
//   PermissionView / CreatePermissionRequest / UpdatePermissionRequest are the
//   ENVIRONMENT wide vocabulary. A slug here is what a token claim carries, so it
//   is immutable and UpdatePermissionRequest carries `slug` and `kind` only so
//   that naming either is a typed 400 rather than a 200 that ignored it.
//
//   OrgRolePermissionView / AssignOrgRolePermissionRequest are the ORGANIZATION
//   scoped mapping from one role to one vocabulary entry. The row carries the
//   permission ID, never its slug: the slug belongs to the vocabulary.
//
//   SetOrgDefaultRoleRequest designates the default role of ONE organization, a
//   single valued property answered with the OrgRoleView that now holds it.
//
//   ResourceServerView / UpdateResourceServerRequest are the ENVIRONMENT scoped
//   claim opt-in. Only `permission_claims_enabled` is writable there, and it is
//   REQUIRED, so an empty body cannot be a request that silently did nothing.
//
//   PermissionBudgetView is the ADVISORY verdict the effective-roles read carries.
//   It refuses no write and caps nothing that may be STORED; it reports what the
//   NEXT token issuance would carry, and only the ELEMENT half of the budget.
export type PermissionView = components["schemas"]["PermissionView"];
export type CreatePermissionRequest =
  components["schemas"]["CreatePermissionRequest"];
export type UpdatePermissionRequest =
  components["schemas"]["UpdatePermissionRequest"];
export type OrgRolePermissionView =
  components["schemas"]["OrgRolePermissionView"];
export type AssignOrgRolePermissionRequest =
  components["schemas"]["AssignOrgRolePermissionRequest"];
export type SetOrgDefaultRoleRequest =
  components["schemas"]["SetOrgDefaultRoleRequest"];
export type ResourceServerView = components["schemas"]["ResourceServerView"];
export type UpdateResourceServerRequest =
  components["schemas"]["UpdateResourceServerRequest"];
export type PermissionBudgetView =
  components["schemas"]["PermissionBudgetView"];

// The request and result shapes the connectors and clients (DCR) surfaces read
// (issue #90, PR 6). Both surfaces are ENVIRONMENT scoped, so every wrapper below
// injects the active {tenant, environment} into the documented path, exactly as
// the users wrappers do. Re-exported from the generated schema so the views never
// hand maintain a shape the management contract already owns.
//
// Connectors are a real CRUD resource WITH a full-replace PUT update:
// ConnectorView / ConnectorList for the reads, CreateConnectorRequest for BOTH
// the create and the PUT replace (the contract reuses one request body), and the
// ConnectorCapabilitiesView / ConnectorHealthView diagnostics reads.
export type ConnectorView = components["schemas"]["ConnectorView"];
export type CreateConnectorRequest =
  components["schemas"]["CreateConnectorRequest"];
export type ConnectorCapabilitiesView =
  components["schemas"]["ConnectorCapabilitiesView"];
export type ConnectorHealthView =
  components["schemas"]["ConnectorHealthView"];

// Clients are DCR (dynamic client registration) ONLY, never generic client CRUD:
// ClientVerificationView for the get + verify of a registered client,
// DcrPolicyView / CreateDcrPolicyRequest for the reusable registration policies,
// and CreateInitialAccessTokenRequest / InitialAccessTokenCreated for the
// copy-once initial access token. InitialAccessTokenCreated.token is the
// plaintext bearer returned ONCE on the genuine create (HTTP 201) and never
// stored; the UI surfaces it once and never persists or logs it.
export type ClientVerificationView =
  components["schemas"]["ClientVerificationView"];
export type DcrPolicyView = components["schemas"]["DcrPolicyView"];
export type CreateDcrPolicyRequest =
  components["schemas"]["CreateDcrPolicyRequest"];
export type CreateInitialAccessTokenRequest =
  components["schemas"]["CreateInitialAccessTokenRequest"];
export type InitialAccessTokenCreated =
  components["schemas"]["InitialAccessTokenCreated"];

// The token-signing compatibility wizard shapes (issue #93). The interop table is
// the single source of truth on the SERVER: SigningRecommendationView is one row
// (the verifier, its human label, the recommended JOSE algorithm, the one-line
// reason, and the alternatives / supported sets), and ClientSigningAlgorithmView
// is the post-condition of pinning the ID-token algorithm of a client. Re-exported from
// the generated schema so the wizard never hand maintains a shape the management
// contract already owns, and never hardcodes the matrix in TypeScript.
export type SigningRecommendationView =
  components["schemas"]["SigningRecommendationView"];
export type ClientSigningAlgorithmView =
  components["schemas"]["ClientSigningAlgorithmView"];

// The per-client OAuth SCOPE allowlist shape (issue #98). `allowed_scopes` is
// `null` when no allowlist is configured (every scope passes the machine-grant
// denylist floor), an array to restrict to exactly its members, and `[]` to admit
// nothing. Re-exported from the generated schema so the panel never hand maintains a
// shape the management contract already owns.
export type ClientAllowedScopesView =
  components["schemas"]["ClientAllowedScopesView"];

// The recorded client-authentication failure diagnostic the admin flow inspector
// reads (issue #91). Re-exported from the generated schema so the diagnostics view
// never hand maintains a shape the management contract already owns. It carries ONLY
// the safe, non secret fields the server projects (the specific failure reason, the
// assertion key id and algorithm, the derived clock skew, the expectation hint); the
// token endpoint's wire response for every such failure stays the opaque
// invalid_client.
export type ClientAuthDiagnosticView =
  components["schemas"]["ClientAuthDiagnosticView"];

// The recorded policy decision trace the admin flow inspector reads (issue #91): the
// step up, risk, and claim mapping decisions recorded off the request path. Re-exported
// from the generated schema so the diagnostics view never hand maintains a shape the
// management contract already owns. It carries ONLY the safe, non secret fields the
// server projects (the closed policy and outcome, the blind subject handle, the bounded
// reason, and the redacted safe field projection of the decision inputs as a JSON string).
export type PolicyTraceView = components["schemas"]["PolicyTraceView"];

// One computed operational warning the admin flow inspector reads (issue #91): a bounded
// kind, the non secret subject it is about, and a safe detail. Computed LIVE by the server
// from the connector health registry and the token size event sink.
export type WarningItemView = components["schemas"]["WarningItemView"];

// The flow inspector projections (issue #91, PR4). Re-exported from the generated schema so
// the inspector view never hand maintains a shape the management contract already owns. The
// OBSERVE response is the read only projection of an existing flow (its current state, the
// journey plan, a redacted context, the node render, and the recorded policy traces); the
// DRY RUN request and response carry a supplied context and the per step evaluations of the
// real step up and risk evaluators, computed SIDE EFFECT FREE (the server writes no row).
export type FlowObserveResponse = components["schemas"]["FlowObserveResponse"];
export type FlowDryRunRequest = components["schemas"]["FlowDryRunRequest"];
export type FlowDryRunResponse = components["schemas"]["FlowDryRunResponse"];

export type ManagementClient = ReturnType<typeof createClient<paths>>;

// A management call that failed carries the verbatim ErrorBody the server
// worded, plus the HTTP status. The console renders the body VERBATIM (issue
// #90, PR 3): API and SPA users see identical errors, so this never rewords or
// swallows a field. A caller catches this to drive the error boundary, and the
// RFC 9470 sudo re-authentication path reads `body.max_age`.
export class ManagementError extends Error {
  readonly body: ErrorBody;
  readonly status: number;
  constructor(body: ErrorBody, status: number) {
    super(body.message);
    this.name = "ManagementError";
    this.body = body;
    this.status = status;
  }
}

// Narrow an unknown thrown value to a ManagementError, so the error boundary can
// render the verbatim body and detect a sudo challenge.
export function asManagementError(value: unknown): ManagementError | null {
  return value instanceof ManagementError ? value : null;
}

// Map an unknown thrown value to the verbatim ErrorBody a resource view renders
// through the ErrorView boundary (issue #90, PR 4). A ManagementError carries the
// body the server worded, surfaced UNCHANGED; anything else (a network drop, a
// bug) falls back to a generic shape rather than inventing a server error string.
// The resource hooks call this so every failure reaches the boundary as an
// ErrorBody, and a max_age-bearing body still drives the RFC 9470 sudo path.
export function errorBodyFrom(value: unknown): ErrorBody {
  const managed = asManagementError(value);
  if (managed !== null) {
    return managed.body;
  }
  return {
    error: "request_failed",
    message: "The request could not be completed.",
  };
}

// Build the single typed management client. Every request carries the in memory
// bearer (when signed in), attached through the middleware below; the base URL is
// the same origin management proxy (or a standalone management origin) from
// config. The generated types confine the reachable paths to the documented API.
export function createManagementClient(): ManagementClient {
  const config = loadConfig();
  const client = createClient<paths>({ baseUrl: config.managementBase || "/" });
  client.use({
    onRequest({ request }) {
      const token = getAccessToken();
      if (token !== null) {
        request.headers.set("authorization", `Bearer ${token}`);
      }
      return request;
    },
  });
  return client;
}

// The subset of the OIDC discovery document the login uses. Both endpoints are
// absolute URLs the server publishes; the app never hardcodes them.
export interface OidcDiscovery {
  authorization_endpoint: string;
  token_endpoint: string;
}

// Fetch the admin issuer's discovery document. `issuer` is runtime config (a same
// origin path in the embedded deploy, an absolute issuer URL in a standalone
// deploy), so the only path literal here is the allowlisted well known suffix.
export async function discoverOidc(issuer: string): Promise<OidcDiscovery> {
  const response = await fetch(`${issuer}/.well-known/openid-configuration`, {
    headers: { accept: "application/json" },
  });
  if (!response.ok) {
    throw new Error(`OIDC discovery failed: ${response.status}`);
  }
  return (await response.json()) as OidcDiscovery;
}

// A minimal token endpoint response for the Authorization Code + PKCE exchange.
export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  scope?: string;
}

// Exchange an authorization code (with the PKCE verifier) for an access token at
// the discovered token endpoint. `tokenEndpoint` is the absolute URL from
// discovery, never a literal. No client secret is sent: the console is a public
// client, so the PKCE verifier is the proof.
export async function exchangeCode(
  tokenEndpoint: string,
  params: URLSearchParams,
): Promise<TokenResponse> {
  const response = await fetch(tokenEndpoint, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body: params.toString(),
  });
  if (!response.ok) {
    throw new Error(`token exchange failed: ${response.status}`);
  }
  return (await response.json()) as TokenResponse;
}

// Map an unknown non 2xx body to the verbatim ErrorBody the management API
// documents, falling back to a generic shape when the body is absent or does
// not parse. The UI renders every present field as the server worded it
// (verbatim), never a client invented string: `error` and `message` always, and
// `actual_scope`, `expected_scope`, `failed_guardrails`, and `max_age` when the
// server included them (the wrong-scope, guardrail, and RFC 9470 sudo shapes).
export function toErrorBody(body: unknown): ErrorBody {
  const obj = (body ?? {}) as Record<string, unknown>;
  const out: ErrorBody = {
    error: typeof obj.error === "string" ? obj.error : "unknown_error",
    message:
      typeof obj.message === "string"
        ? obj.message
        : "The request could not be processed.",
  };
  if (typeof obj.actual_scope === "string") {
    out.actual_scope = obj.actual_scope;
  }
  if (typeof obj.expected_scope === "string") {
    out.expected_scope = obj.expected_scope;
  }
  if (Array.isArray(obj.failed_guardrails)) {
    out.failed_guardrails = obj.failed_guardrails.filter(
      (item): item is string => typeof item === "string",
    );
  }
  if (typeof obj.max_age === "number") {
    out.max_age = obj.max_age;
  }
  return out;
}

// A URL safe random idempotency key for a mutation, so a retried write is
// recorded once. WebCrypto only, no network.
function idempotencyKey(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let hex = "";
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

// ---- The typed management operations the shell (PR 3) calls -----------------
//
// These thin wrappers keep every management path literal inside this one audited
// module: the shell's store, switcher, and error boundary import a FUNCTION, not
// a path, so the route audit's single funnel holds and every path here maps to a
// documented operation in docs/openapi/management.json. Each throws a
// ManagementError carrying the verbatim ErrorBody on a non 2xx, which the error
// boundary renders unchanged.

// List the tenants the acting credential can reach. The switcher reads this to
// decide cross-tenant reach (more than one tenant) and to offer tenant scope.
export async function fetchTenants(): Promise<TenantView[]> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET("/v1/tenants", {});
  // A non 2xx is a failure even when openapi-fetch yields no error body (it
  // returns `error: undefined` for a bodyless response, for example a 401 or 502
  // with Content-Length 0 from a proxy or gateway). Checking `response.ok` too
  // means such a response is never silently read as success (an empty list, or a
  // failed sudo elevation treated as elevated).
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data?.items ?? [];
}

// List the environments of one tenant. Scope injection in action: the tenant id
// is substituted into the path parameter of the documented operation, targeting
// `/v1/tenants/<tenant>/environments`.
export async function fetchEnvironments(
  tenantId: string,
): Promise<EnvironmentView[]> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments",
    { params: { path: { tenant_id: tenantId } } },
  );
  // A non 2xx is a failure even when openapi-fetch yields no error body (it
  // returns `error: undefined` for a bodyless response, for example a 401 or 502
  // with Content-Length 0 from a proxy or gateway). Checking `response.ok` too
  // means such a response is never silently read as success (an empty list, or a
  // failed sudo elevation treated as elevated).
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data?.items ?? [];
}

// Elevate the acting credential to sudo mode within a scope (RFC 9470 / issue
// #73). Called after a fresh re-authentication when a mutation returned a
// `max_age` challenge, before the mutation is retried. Env-scoped: the tenant and
// environment ids substitute into `/v1/tenants/<t>/environments/<e>/admin/sudo/elevate`.
export async function elevateAdminSudo(
  tenantId: string,
  environmentId: string,
): Promise<void> {
  const client = createManagementClient();
  const { error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/admin/sudo/elevate",
    {
      params: {
        path: { tenant_id: tenantId, environment_id: environmentId },
        header: { "Idempotency-Key": idempotencyKey() },
      },
    },
  );
  // A non 2xx is a failure even when openapi-fetch yields no error body (it
  // returns `error: undefined` for a bodyless response, for example a 401 or 502
  // with Content-Length 0 from a proxy or gateway). Checking `response.ok` too
  // means such a response is never silently read as success (an empty list, or a
  // failed sudo elevation treated as elevated).
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
}

// ---- The tenant + environment CRUD operations (issue #90, PR 4) -------------
//
// The resource views (src/ui/TenantsView.tsx, src/ui/EnvironmentsView.tsx) call
// these named wrappers, never a path, so the single funnel holds: every literal
// below is a path the committed docs/openapi/management.json documents, and each
// throws a ManagementError carrying the verbatim ErrorBody on a non 2xx (the same
// bodyless-non-2xx guard as the reads above), which the ErrorView boundary
// renders unchanged. There is NO tenant or environment UPDATE operation in the
// management contract, so none is invented here: tenants and environments are
// create, read, list, and delete, plus the tenant suspend / resume / restore
// lifecycle.

// Read one tenant (operationId getTenant). The detail view reads this.
export async function getTenant(tenantId: string): Promise<TenantView> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET("/v1/tenants/{tenant_id}", {
    params: { path: { tenant_id: tenantId } },
  });
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Create a tenant (operationId createTenant). The first environment is created
// with it. The Idempotency-Key header (same pattern the sudo elevate uses) makes
// a retried submit record the tenant once.
export async function createTenant(
  request: CreateTenantRequest,
): Promise<TenantCreated> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST("/v1/tenants", {
    params: { header: { "Idempotency-Key": idempotencyKey() } },
    body: request,
  });
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Delete a tenant (operationId deleteTenant). A 204 carries no body: the guard
// treats the bodyless 2xx as success and any non 2xx as the verbatim failure.
export async function deleteTenant(tenantId: string): Promise<void> {
  const client = createManagementClient();
  const { error, response } = await client.DELETE("/v1/tenants/{tenant_id}", {
    params: { path: { tenant_id: tenantId } },
  });
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
}

// Suspend a tenant (operationId suspendTenant): fence it off the data plane. The
// TenantStatusView states the post-condition status. Idempotency-Key guarded.
export async function suspendTenant(
  tenantId: string,
): Promise<TenantStatusView> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/suspend",
    {
      params: {
        path: { tenant_id: tenantId },
        header: { "Idempotency-Key": idempotencyKey() },
      },
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Resume a suspended tenant (operationId resumeTenant). Idempotency-Key guarded.
export async function resumeTenant(tenantId: string): Promise<TenantStatusView> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/resume",
    {
      params: {
        path: { tenant_id: tenantId },
        header: { "Idempotency-Key": idempotencyKey() },
      },
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Restore a tenant (operationId restoreTenant). Idempotency-Key guarded.
export async function restoreTenant(
  tenantId: string,
): Promise<TenantStatusView> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/restore",
    {
      params: {
        path: { tenant_id: tenantId },
        header: { "Idempotency-Key": idempotencyKey() },
      },
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Read one environment of a tenant (operationId getEnvironment). Scope injection:
// the tenant and environment ids substitute into the documented path parameters.
export async function getEnvironment(
  tenantId: string,
  environmentId: string,
): Promise<EnvironmentView> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}",
    { params: { path: { tenant_id: tenantId, environment_id: environmentId } } },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Create an environment under a tenant (operationId createEnvironment).
// Idempotency-Key guarded; the tenant id substitutes into the path.
export async function createEnvironment(
  tenantId: string,
  request: CreateEnvironmentRequest,
): Promise<EnvironmentView> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/environments",
    {
      params: {
        path: { tenant_id: tenantId },
        header: { "Idempotency-Key": idempotencyKey() },
      },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Delete an environment of a tenant (operationId deleteEnvironment). A 204 body
// is absent, so the guard reads the bodyless 2xx as success.
export async function deleteEnvironment(
  tenantId: string,
  environmentId: string,
): Promise<void> {
  const client = createManagementClient();
  const { error, response } = await client.DELETE(
    "/v1/tenants/{tenant_id}/environments/{environment_id}",
    { params: { path: { tenant_id: tenantId, environment_id: environmentId } } },
  );
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
}

// ---- The connectors CRUD operations (issue #90, PR 6) -----------------------
//
// The connectors resource view (src/ui/ConnectorsView.tsx) calls these named
// wrappers, never a path, so the single funnel holds: every literal below is a
// path the committed docs/openapi/management.json documents, connectors live
// UNDER the active {tenant, environment} scope, and the ids substitute into the
// documented path parameters exactly as the users wrappers inject them. Each
// throws a ManagementError carrying the verbatim ErrorBody on a non 2xx (the same
// bodyless-non-2xx guard as the reads above), which the ErrorView boundary
// renders unchanged. Unlike tenants and environments, a connector HAS a real
// update: updateConnector is a full-replace PUT whose body is the same
// CreateConnectorRequest the create takes (the contract reuses it), plus the
// capabilities and health reads for diagnostics.

// List the connectors of one environment (operationId listConnectors). Scope
// injection: the active tenant and environment ids substitute into the documented
// path, targeting `/v1/tenants/<t>/environments/<e>/connectors`.
export async function fetchConnectors(
  tenantId: string,
  environmentId: string,
): Promise<ConnectorView[]> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/connectors",
    { params: { path: { tenant_id: tenantId, environment_id: environmentId } } },
  );
  // A non 2xx is a failure even when openapi-fetch yields no error body (it
  // returns `error: undefined` for a bodyless response, for example a 401 or 502
  // with Content-Length 0 from a proxy or gateway). Checking `response.ok` too
  // means such a response is never silently read as success (an empty list).
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data?.items ?? [];
}

// Read one connector (operationId getConnector). The detail view reads this.
export async function getConnector(
  tenantId: string,
  environmentId: string,
  connectorId: string,
): Promise<ConnectorView> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/connectors/{connector_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          connector_id: connectorId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Create a connector under an environment (operationId createConnector).
// Idempotency-Key guarded (same pattern the user create uses) so a retried submit
// records the connector once. The request body is the declarative connector
// definition; the returned ConnectorView is SECRET-FREE (no client_secret).
export async function createConnector(
  tenantId: string,
  environmentId: string,
  request: CreateConnectorRequest,
): Promise<ConnectorView> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/connectors",
    {
      params: {
        path: { tenant_id: tenantId, environment_id: environmentId },
        header: { "Idempotency-Key": idempotencyKey() },
      },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Update a connector (operationId updateConnector): a full-replace PUT. The
// contract reuses CreateConnectorRequest as the update body, so this REPLACES the
// whole definition (not a merge), and an omitted field takes its documented
// default (for example `enabled` defaults to true). A PUT replace is idempotent
// by construction (the same body twice yields the same state), so no
// Idempotency-Key is sent, mirroring the idempotent external-id PUT.
export async function updateConnector(
  tenantId: string,
  environmentId: string,
  connectorId: string,
  request: CreateConnectorRequest,
): Promise<ConnectorView> {
  const client = createManagementClient();
  const { data, error, response } = await client.PUT(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/connectors/{connector_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          connector_id: connectorId,
        },
      },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Delete a connector (operationId deleteConnector). A 204 carries no body, so the
// guard reads the bodyless 2xx as success and any non 2xx as the verbatim failure.
export async function deleteConnector(
  tenantId: string,
  environmentId: string,
  connectorId: string,
): Promise<void> {
  const client = createManagementClient();
  const { error, response } = await client.DELETE(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/connectors/{connector_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          connector_id: connectorId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
}

// Read a connector's capability matrix (operationId getConnectorCapabilities):
// the derived refresh / groups / logout_propagation / email_verified_trust view
// the detail surface shows alongside the connector.
export async function getConnectorCapabilities(
  tenantId: string,
  environmentId: string,
  connectorId: string,
): Promise<ConnectorCapabilitiesView> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/connectors/{connector_id}/capabilities",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          connector_id: connectorId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Read a connector's live health (operationId getConnectorHealth): THIS node's
// in-memory federation health for admin diagnostics. A connector never exercised
// on this node reports `state = "unknown"` with no timestamps.
export async function getConnectorHealth(
  tenantId: string,
  environmentId: string,
  connectorId: string,
): Promise<ConnectorHealthView> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/connectors/{connector_id}/health",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          connector_id: connectorId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// ---- The clients (DCR) operations (issue #90, PR 6) -------------------------
//
// The clients surface (src/ui/ClientsView.tsx) is DYNAMIC CLIENT REGISTRATION
// (RFC 7591, issue #31), NOT generic client CRUD: the management contract has NO
// listClients / createClient / updateClient / deleteClient, so none is invented.
// The documented surface is: get + verify a registered client, list + create the
// reusable DCR policies, and mint a copy-once initial access token. Every wrapper
// calls a named function, never a path, so the single funnel holds; each literal
// is a documented path and each throws a ManagementError carrying the verbatim
// ErrorBody on a non 2xx (the same bodyless-non-2xx guard as above).

// Read a registered DCR client's verification state (operationId getDcrClient):
// its quarantine and verified flags. SECRET-FREE: no client secret is projected.
export async function getDcrClient(
  tenantId: string,
  environmentId: string,
  clientId: string,
): Promise<ClientVerificationView> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          client_id: clientId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Verify a registered DCR client (operationId verifyDcrClient): lift the
// unverified-client quarantine the authorization / consent path honors. The
// returned ClientVerificationView states the post-condition. Idempotency-Key
// guarded (re-verifying an already-verified client stays a single recorded act).
export async function verifyDcrClient(
  tenantId: string,
  environmentId: string,
  clientId: string,
): Promise<ClientVerificationView> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/verify",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          client_id: clientId,
        },
        header: { "Idempotency-Key": idempotencyKey() },
      },
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// List an environment's DCR policies (operationId listDcrPolicies): the named,
// reusable registration policies a minted token's chain references.
export async function fetchDcrPolicies(
  tenantId: string,
  environmentId: string,
): Promise<DcrPolicyView[]> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/dcr/policies",
    { params: { path: { tenant_id: tenantId, environment_id: environmentId } } },
  );
  // The same bodyless-non-2xx guard the other list reads use: a 401 with no body
  // is a failure, never an empty policy list read as success.
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data?.items ?? [];
}

// Create a named DCR policy (operationId createDcrPolicy). Idempotency-Key
// guarded. The `primitives` are the ordered force / restrict / reject / default
// objects the OIDC policy engine validates at create time.
export async function createDcrPolicy(
  tenantId: string,
  environmentId: string,
  request: CreateDcrPolicyRequest,
): Promise<DcrPolicyView> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/dcr/policies",
    {
      params: {
        path: { tenant_id: tenantId, environment_id: environmentId },
        header: { "Idempotency-Key": idempotencyKey() },
      },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Mint a DCR initial access token (operationId createDcrInitialAccessToken, RFC
// 7591). Idempotency-Key guarded. On the genuine first create the returned
// InitialAccessTokenCreated.token carries the plaintext bearer ONCE (HTTP 201);
// an idempotent replay omits it and sets token_already_issued (HTTP 200). This
// wrapper RETURNS the body to the caller so the UI can surface the token value a
// single time; it NEVER logs it and the UI NEVER persists it (memory-only,
// copy-once), consistent with the token-safety posture.
export async function createDcrInitialAccessToken(
  tenantId: string,
  environmentId: string,
  request: CreateInitialAccessTokenRequest,
): Promise<InitialAccessTokenCreated> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/dcr/initial-access-tokens",
    {
      params: {
        path: { tenant_id: tenantId, environment_id: environmentId },
        header: { "Idempotency-Key": idempotencyKey() },
      },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// ---- The token-signing compatibility wizard operations (issue #93) ----------
//
// The compatibility wizard (src/ui/ClientsView.tsx) calls these named wrappers,
// never a path, so the single funnel holds: each literal below is a path the
// committed docs/openapi/management.json documents, and each throws a
// ManagementError carrying the verbatim ErrorBody on a non 2xx (the same
// bodyless-non-2xx guard as above), which the ErrorView boundary renders
// unchanged. The interop table itself lives on the SERVER (unit tested in Rust);
// the SPA renders exactly what the read returns and never hardcodes the matrix.

// Read the token-signing compatibility interop table (operationId
// getSigningRecommendations): one row per verifier, each carrying its human
// label, the recommended JOSE algorithm, a one-line reason, and the alternatives
// and supported sets. Unscoped and read only: the wizard renders these rows so
// the recommendation the operator sees comes from the server, not a client invented one.
export async function fetchSigningRecommendations(): Promise<
  SigningRecommendationView[]
> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/interop/signing-recommendations",
    {},
  );
  // A non 2xx is a failure even when openapi-fetch yields no error body (it
  // returns `error: undefined` for a bodyless response, for example a 401 or 502
  // with Content-Length 0 from a proxy or gateway). Checking `response.ok` too
  // means such a response is never silently read as success (an empty table).
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  // The 2xx body is the interop array. Guard the shape (a proxy could yield a
  // bodyless 2xx or a non-array) so the wizard always renders over an array.
  return Array.isArray(data) ? data : [];
}

// Pin the ID-token signing algorithm of an EXISTING client (operationId
// setClientSigningAlgorithm): a PUT the wizard issues on confirm. The tenant,
// environment, and client ids substitute into the documented path; the body is
// the single `{ algorithm }` field (one of EdDSA, ES256, RS256). Idempotency-Key
// guarded (mirroring verifyDcrClient) so a retried confirm records the write once.
// The returned ClientSigningAlgorithmView states the post-condition.
export async function setClientSigningAlgorithm(
  tenantId: string,
  environmentId: string,
  clientId: string,
  algorithm: string,
): Promise<ClientSigningAlgorithmView> {
  const client = createManagementClient();
  const { data, error, response } = await client.PUT(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/signing-algorithm",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          client_id: clientId,
        },
        header: { "Idempotency-Key": idempotencyKey() },
      },
      body: { algorithm },
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// ---- The per-client scope allowlist operations (issue #98) ------------------
//
// The allowlist panel (src/ui/ClientsView.tsx) calls these named wrappers, never a
// path, so the single funnel holds: each literal below is a path the committed
// docs/openapi/management.json documents, and each throws a ManagementError carrying
// the verbatim ErrorBody on a non 2xx (the same bodyless-non-2xx guard as above),
// which the ErrorView boundary renders unchanged, including the RFC 9470 sudo
// challenge the WRITE is gated behind.
//
// The three states are carried end to end and never collapsed in TypeScript: `null`
// means NO allowlist is configured, an array RESTRICTS to exactly its members, and
// `[]` admits nothing. A read of a value the server could not parse answers `[]`,
// which is what the token endpoint will enforce, so the panel shows the operator
// what is in force rather than a repaired value.

// Read one client's scope allowlist (operationId getClientAllowedScopes).
export async function getClientAllowedScopes(
  tenantId: string,
  environmentId: string,
  clientId: string,
): Promise<ClientAllowedScopesView> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/allowed-scopes",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          client_id: clientId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Set or CLEAR one client's scope allowlist (operationId setClientAllowedScopes).
// `allowedScopes` is the array to store, or `null` to clear the allowlist; the key is
// always sent, because the server refuses a body that OMITS it with a 400 (an empty
// object would otherwise be a legal request that did nothing). No Idempotency-Key:
// this is an absolute-value PUT addressed by an existing client, so applying the same
// body twice reaches the same state, matching the server, which documents none.
export async function setClientAllowedScopes(
  tenantId: string,
  environmentId: string,
  clientId: string,
  allowedScopes: string[] | null,
): Promise<ClientAllowedScopesView> {
  const client = createManagementClient();
  const { data, error, response } = await client.PUT(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/allowed-scopes",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          client_id: clientId,
        },
      },
      body: { allowed_scopes: allowedScopes },
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// ---- The diagnostics read operations (issue #91, M9 flow inspector) ---------
//
// The diagnostics view (src/ui/DiagnosticsView.tsx) calls this named wrapper, never
// a path, so the single funnel holds: the literal below is the path the committed
// docs/openapi/management.json documents, the diagnostics live UNDER the active
// {tenant, environment} scope, and the ids substitute into the documented path
// parameters exactly as the connectors and users wrappers inject them. It throws a
// ManagementError carrying the verbatim ErrorBody on a non 2xx (the same
// bodyless-non-2xx guard as the reads above), which the ErrorView boundary renders
// unchanged. The read is bounded server side (at most 500 rows, oldest first); the
// optional filters narrow it by client id and time window.

// The optional filters the diagnostics read narrows by. The two instants are unix
// microseconds, matching the documented `since`/`until` query parameters.
export interface ClientAuthDiagnosticsFilter {
  clientId?: string;
  sinceUnixMicros?: number;
  untilUnixMicros?: number;
  limit?: number;
}

// Read the environment's recorded client-authentication failure diagnostics
// (operationId getClientAuthDiagnostics). Scope injection: the active tenant and
// environment ids substitute into the documented path, targeting
// `/v1/tenants/<t>/environments/<e>/diagnostics/client-auth`. Only the filters the
// caller set are sent, so an empty filter reads the whole (bounded) scope window.
// A page of client auth diagnostics: the newest first rows plus whether the result
// hit the limit (older matching failures left out), so the view can tell the operator
// to narrow the window rather than silently dropping the tail.
export interface ClientAuthDiagnosticsPage {
  readonly items: ClientAuthDiagnosticView[];
  readonly truncated: boolean;
}

export async function fetchClientAuthDiagnostics(
  tenantId: string,
  environmentId: string,
  filter: ClientAuthDiagnosticsFilter = {},
): Promise<ClientAuthDiagnosticsPage> {
  const client = createManagementClient();
  const query: {
    client_id?: string;
    since?: number;
    until?: number;
    limit?: number;
  } = {};
  if (filter.clientId !== undefined && filter.clientId !== "") {
    query.client_id = filter.clientId;
  }
  if (filter.sinceUnixMicros !== undefined) {
    query.since = filter.sinceUnixMicros;
  }
  if (filter.untilUnixMicros !== undefined) {
    query.until = filter.untilUnixMicros;
  }
  if (filter.limit !== undefined) {
    query.limit = filter.limit;
  }
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/client-auth",
    {
      params: {
        path: { tenant_id: tenantId, environment_id: environmentId },
        query,
      },
    },
  );
  // A non 2xx is a failure even when openapi-fetch yields no error body (it
  // returns `error: undefined` for a bodyless response, for example a 401 or 502
  // with Content-Length 0 from a proxy or gateway). Checking `response.ok` too
  // means such a response is never silently read as success (an empty list).
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return { items: data?.items ?? [], truncated: data?.truncated ?? false };
}

// The optional filters the policy traces read narrows by. The two instants are unix
// microseconds, matching the documented `since`/`until` query parameters; `policy` is one
// of `step_up` / `risk` / `claim_mapping`; `subject` is a usr_ handle.
export interface PolicyTracesFilter {
  policy?: string;
  subject?: string;
  sinceUnixMicros?: number;
  untilUnixMicros?: number;
  limit?: number;
}

// A page of policy decision traces: the newest first rows plus whether the result hit the
// limit (older matching traces left out), so the view can tell the operator to narrow the
// window rather than silently dropping the tail.
export interface PolicyTracesPage {
  readonly items: PolicyTraceView[];
  readonly truncated: boolean;
}

// Read the environment's recorded policy decision traces (operationId
// getPolicyDecisionTraces). Scope injection: the active tenant and environment ids
// substitute into the documented path, targeting
// `/v1/tenants/<t>/environments/<e>/diagnostics/policy-traces`. Only the filters the caller
// set are sent, so an empty filter reads the whole (bounded) scope window.
export async function fetchPolicyTraces(
  tenantId: string,
  environmentId: string,
  filter: PolicyTracesFilter = {},
): Promise<PolicyTracesPage> {
  const client = createManagementClient();
  const query: {
    policy?: string;
    subject?: string;
    since?: number;
    until?: number;
    limit?: number;
  } = {};
  if (filter.policy !== undefined && filter.policy !== "") {
    query.policy = filter.policy;
  }
  if (filter.subject !== undefined && filter.subject !== "") {
    query.subject = filter.subject;
  }
  if (filter.sinceUnixMicros !== undefined) {
    query.since = filter.sinceUnixMicros;
  }
  if (filter.untilUnixMicros !== undefined) {
    query.until = filter.untilUnixMicros;
  }
  if (filter.limit !== undefined) {
    query.limit = filter.limit;
  }
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/policy-traces",
    {
      params: {
        path: { tenant_id: tenantId, environment_id: environmentId },
        query,
      },
    },
  );
  // A non 2xx is a failure even when openapi-fetch yields no error body (the same
  // bodyless-non-2xx guard as the reads above), so it is never silently read as success.
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return { items: data?.items ?? [], truncated: data?.truncated ?? false };
}

// Read the environment's operational warnings, computed live (operationId
// getDiagnosticsWarnings). Scope injection: the active tenant and environment ids
// substitute into the documented path, targeting
// `/v1/tenants/<t>/environments/<e>/diagnostics/warnings`. There are no filters: the server
// computes the current warnings from the connector health registry and the token size sink.
export async function fetchDiagnosticsWarnings(
  tenantId: string,
  environmentId: string,
): Promise<WarningItemView[]> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/warnings",
    { params: { path: { tenant_id: tenantId, environment_id: environmentId } } },
  );
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data?.items ?? [];
}

// OBSERVE an existing flow read only (operationId getFlowObservation). Scope injection: the
// active tenant and environment ids plus the flow id substitute into the documented path,
// targeting `/v1/tenants/<t>/environments/<e>/diagnostics/flow/<flow>`. The server never
// mutates the flow: this returns its current state, the journey plan, a redacted context,
// the current node render, and the recorded policy traces. A foreign or malformed flow id is
// a uniform 404 (ManagementError).
export async function fetchFlowObservation(
  tenantId: string,
  environmentId: string,
  flowId: string,
): Promise<FlowObserveResponse> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/flow/{flow_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          flow_id: flowId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// DRY REPLAY a supplied context through a journey's plan (operationId postFlowDryRun). Scope
// injection: the active tenant and environment ids substitute into the documented path,
// targeting `/v1/tenants/<t>/environments/<e>/diagnostics/flow/dry-run`. Despite the POST
// verb this is READ ONLY / SIDE EFFECT FREE: the server writes no row. It returns the journey
// plan, the per step evaluations of the real step up and risk evaluators, and the terminal
// state the scenario reaches.
export async function fetchFlowDryRun(
  tenantId: string,
  environmentId: string,
  request: FlowDryRunRequest,
): Promise<FlowDryRunResponse> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/diagnostics/flow/dry-run",
    {
      params: { path: { tenant_id: tenantId, environment_id: environmentId } },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// ---- The users CRUD operations (issue #90, PR 5) ----------------------------
//
// The users resource view (src/ui/UsersView.tsx) calls these named wrappers,
// never a path, so the single funnel holds: every literal below is a path the
// committed docs/openapi/management.json documents, users live UNDER the active
// {tenant, environment} scope, and the ids substitute into the documented path
// parameters exactly as the environments wrappers inject the tenant. Each throws
// a ManagementError carrying the verbatim ErrorBody on a non 2xx (the same
// bodyless-non-2xx guard as the reads above), which the ErrorView boundary
// renders unchanged. Unlike tenants and environments, a user HAS a real update:
// updateUser is the PATCH (an RFC 7396 merge patch of the standard claims), and
// the lifecycle state, external id, and sessions each have their own explicit
// operation the contract documents.

// List the users of one environment (operationId listUsers). Scope injection:
// the active tenant and environment ids substitute into the documented path,
// targeting `/v1/tenants/<t>/environments/<e>/users`.
export async function fetchUsers(
  tenantId: string,
  environmentId: string,
): Promise<UserView[]> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/users",
    { params: { path: { tenant_id: tenantId, environment_id: environmentId } } },
  );
  // A non 2xx is a failure even when openapi-fetch yields no error body (it
  // returns `error: undefined` for a bodyless response, for example a 401 or 502
  // with Content-Length 0 from a proxy or gateway). Checking `response.ok` too
  // means such a response is never silently read as success (an empty list).
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data?.items ?? [];
}

// Read one user (operationId getUser). The detail view reads this.
export async function getUser(
  tenantId: string,
  environmentId: string,
  userId: string,
): Promise<UserView> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          user_id: userId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Create a user under an environment (operationId createUser). Idempotency-Key
// guarded (same pattern the sudo elevate and the tenant / environment creates
// use) so a retried submit records the user once.
export async function createUser(
  tenantId: string,
  environmentId: string,
  request: CreateUserRequest,
): Promise<UserView> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/users",
    {
      params: {
        path: { tenant_id: tenantId, environment_id: environmentId },
        header: { "Idempotency-Key": idempotencyKey() },
      },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Update a user (operationId updateUser): the PATCH, an RFC 7396 merge patch of
// the mutable profile. The contract's UpdateUserRequest accepts ONLY `claims`
// (the lifecycle state and external id have their own operations), so the caller
// sends only that field, never a state or an external id smuggled in here.
export async function updateUser(
  tenantId: string,
  environmentId: string,
  userId: string,
  request: UpdateUserRequest,
): Promise<UserView> {
  const client = createManagementClient();
  const { data, error, response } = await client.PATCH(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          user_id: userId,
        },
      },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Delete a user (operationId deleteUser): a soft-delete offboarding that
// cascades the user's sessions. A 204 carries no body, so the guard reads the
// bodyless 2xx as success and any non 2xx as the verbatim failure.
export async function deleteUser(
  tenantId: string,
  environmentId: string,
  userId: string,
): Promise<void> {
  const client = createManagementClient();
  const { error, response } = await client.DELETE(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          user_id: userId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
}

// Transition a user's lifecycle state (operationId setUserState). The target
// state (and, only for scheduled_offboarding, its instant) plus an optional
// hard_kill ride in the body; the UserStateChangeView states the post-condition.
// Idempotency-Key guarded.
export async function setUserState(
  tenantId: string,
  environmentId: string,
  userId: string,
  request: SetUserStateRequest,
): Promise<UserStateChangeView> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/state",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          user_id: userId,
        },
        header: { "Idempotency-Key": idempotencyKey() },
      },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Revoke EVERY session of one user (operationId revokeUserSessions). An empty
// body is a plain revoke that PRESERVES the offline_access families; hard_kill
// cuts a compromised principal off entirely. The UserRevocationView states the
// post-condition. Idempotency-Key guarded.
export async function revokeUserSessions(
  tenantId: string,
  environmentId: string,
  userId: string,
  request: RevokeSessionsRequest,
): Promise<UserRevocationView> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/sessions/revoke",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          user_id: userId,
        },
        header: { "Idempotency-Key": idempotencyKey() },
      },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Link an external correlation id to a user (operationId linkUserExternalId): a
// PUT that is idempotent by construction (a re-link of the same id is a no-op),
// so no Idempotency-Key is needed. The UserExternalIdView states the mapping.
export async function linkUserExternalId(
  tenantId: string,
  environmentId: string,
  userId: string,
  request: LinkExternalIdRequest,
): Promise<UserExternalIdView> {
  const client = createManagementClient();
  const { data, error, response } = await client.PUT(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/external-id",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          user_id: userId,
        },
      },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// ---- The organizations, memberships, and invitations operations (issue #94) --
//
// The organizations surface (src/ui/OrganizationsView.tsx, with its nested
// memberships panel) and the invitations surface (src/ui/InvitationsView.tsx)
// call these named wrappers, never a path, so the single funnel holds: every
// literal below is a path the committed docs/openapi/management.json documents,
// all three resources live UNDER the active {tenant, environment} scope, and the
// ids substitute into the documented path parameters exactly as the users and
// connectors wrappers inject them. Each throws a ManagementError carrying the
// verbatim ErrorBody on a non 2xx (the same bodyless-non-2xx guard as the reads
// above), which the ErrorView boundary renders unchanged.
//
// The list reads are KEYSET paginated (an items array plus an OPTIONAL
// next_cursor): this wrapper returns the first page as { items, nextCursor } so
// the view can surface a "more exist" indicator rather than SILENTLY DROPPING the
// tail (the no-silent-caps rule, mirroring the diagnostics `truncated` page). The
// nextCursor is normalised to null when the contract omits it (the last page).

// A keyset page: the items on the first page plus the opaque cursor for the next
// page, or null when this is the last page. The view reads nextCursor to decide
// whether to tell the operator more rows exist beyond what is shown.
export interface KeysetPage<T> {
  readonly items: T[];
  readonly nextCursor: string | null;
}

// List the organizations of one environment (operationId listOrganizations).
// Scope injection: the active tenant and environment ids substitute into the
// documented path, targeting `/v1/tenants/<t>/environments/<e>/organizations`.
export async function fetchOrganizations(
  tenantId: string,
  environmentId: string,
): Promise<KeysetPage<OrganizationView>> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations",
    { params: { path: { tenant_id: tenantId, environment_id: environmentId } } },
  );
  // A non 2xx is a failure even when openapi-fetch yields no error body (it
  // returns `error: undefined` for a bodyless response, for example a 401 or 502
  // with Content-Length 0 from a proxy or gateway). Checking `response.ok` too
  // means such a response is never silently read as success (an empty list).
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return { items: data?.items ?? [], nextCursor: data?.next_cursor ?? null };
}

// Read one organization (operationId getOrganization). The detail view reads this.
export async function getOrganization(
  tenantId: string,
  environmentId: string,
  organizationId: string,
): Promise<OrganizationView> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Create an organization under an environment (operationId createOrganization).
// Idempotency-Key guarded (same pattern the user create uses) so a retried submit
// records the organization once.
export async function createOrganization(
  tenantId: string,
  environmentId: string,
  request: CreateOrganizationRequest,
): Promise<OrganizationView> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations",
    {
      params: {
        path: { tenant_id: tenantId, environment_id: environmentId },
        header: { "Idempotency-Key": idempotencyKey() },
      },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Deactivate an organization (operationId deleteOrganization): a soft delete. A
// 204 carries no body, so the guard reads the bodyless 2xx as success and any
// non 2xx as the verbatim failure.
export async function deleteOrganization(
  tenantId: string,
  environmentId: string,
  organizationId: string,
): Promise<void> {
  const client = createManagementClient();
  const { error, response } = await client.DELETE(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
}

// Disable an organization (operationId disableOrganization): the org stays
// readable (this is NOT a soft delete) but is marked disabled. The returned
// OrganizationView states the post-condition (`active: false`). The contract marks
// this idempotent IN EFFECT (re-disabling is a no-op) and takes no Idempotency-Key
// header, mirroring the tenant suspend lifecycle shape.
export async function disableOrganization(
  tenantId: string,
  environmentId: string,
  organizationId: string,
): Promise<OrganizationView> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/disable",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Re-enable a disabled organization (operationId enableOrganization). The
// returned OrganizationView states the post-condition (`active: true`). Idempotent
// in effect (re-enabling is a no-op) and takes no Idempotency-Key header,
// mirroring the tenant resume lifecycle shape.
export async function enableOrganization(
  tenantId: string,
  environmentId: string,
  organizationId: string,
): Promise<OrganizationView> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/enable",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// List the members of one organization (operationId listMemberships). Scope
// injection plus the organization id: the path targets
// `/v1/tenants/<t>/environments/<e>/organizations/<org>/memberships`. Keyset
// paginated, so the first page and its next_cursor are returned; the view surfaces
// a "more exist" indicator rather than dropping the tail.
export async function fetchMemberships(
  tenantId: string,
  environmentId: string,
  organizationId: string,
): Promise<KeysetPage<MembershipView>> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return { items: data?.items ?? [], nextCursor: data?.next_cursor ?? null };
}

// Add a user to an organization (operationId createMembership). The body carries
// the member user id (and optional metadata); Idempotency-Key guarded so a
// retried submit records the membership once.
export async function addMembership(
  tenantId: string,
  environmentId: string,
  organizationId: string,
  request: CreateMembershipRequest,
): Promise<MembershipView> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
        },
        header: { "Idempotency-Key": idempotencyKey() },
      },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Remove a user from an organization (operationId deleteMembership): a soft
// delete keyed by the membership id. A 204 carries no body, so the guard reads
// the bodyless 2xx as success and any non 2xx as the verbatim failure.
export async function removeMembership(
  tenantId: string,
  environmentId: string,
  organizationId: string,
  membershipId: string,
): Promise<void> {
  const client = createManagementClient();
  const { error, response } = await client.DELETE(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships/{membership_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
          membership_id: membershipId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
}

// List the invitations of one environment (operationId listInvitations),
// optionally filtered by lifecycle state. Scope injection: the active tenant and
// environment ids substitute into the documented path, targeting
// `/v1/tenants/<t>/environments/<e>/invitations`. Keyset paginated, so the first
// page and its next_cursor are returned; the view surfaces a "more exist"
// indicator rather than dropping the tail. Only a set state filter is sent, so an
// absent filter reads every invitation in scope.
export async function fetchInvitations(
  tenantId: string,
  environmentId: string,
  state?: InvitationStateView,
): Promise<KeysetPage<InvitationView>> {
  const client = createManagementClient();
  const query: { state?: InvitationStateView } = {};
  if (state !== undefined) {
    query.state = state;
  }
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/invitations",
    {
      params: {
        path: { tenant_id: tenantId, environment_id: environmentId },
        query,
      },
    },
  );
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return { items: data?.items ?? [], nextCursor: data?.next_cursor ?? null };
}

// Read one invitation (operationId getInvitation). Available for a per-row detail
// read; the durable view NEVER carries the token (only its digest is stored).
export async function getInvitation(
  tenantId: string,
  environmentId: string,
  invitationId: string,
): Promise<InvitationView> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/invitations/{invitation_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          invitation_id: invitationId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Create an invitation for a new identity (operationId createInvitation).
// Idempotency-Key guarded. RETURNS the InvitationCreatedView so the UI can
// surface the copy-once token: the returned `token` is the raw `ira_inv_` single
// use token the server returns ONCE (on the genuine 201 create) and never stores;
// an idempotent replay omits it. This wrapper returns the body so the UI can show
// the value a single time; it NEVER logs it and the UI NEVER persists it
// (memory-only, copy-once), consistent with the DCR initial-access-token posture.
export async function createInvitation(
  tenantId: string,
  environmentId: string,
  request: CreateInvitationRequest,
): Promise<InvitationCreatedView> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/invitations",
    {
      params: {
        path: { tenant_id: tenantId, environment_id: environmentId },
        header: { "Idempotency-Key": idempotencyKey() },
      },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Resend a pending invitation (operationId resendInvitation): invalidate the
// prior token and issue a fresh one. RETURNS the InvitationCreatedView with the
// new copy-once `token`, surfaced ONCE exactly as the create does; never logged,
// never persisted. Idempotency-Key guarded.
export async function resendInvitation(
  tenantId: string,
  environmentId: string,
  invitationId: string,
): Promise<InvitationCreatedView> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/invitations/{invitation_id}/resend",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          invitation_id: invitationId,
        },
        header: { "Idempotency-Key": idempotencyKey() },
      },
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Revoke a pending invitation (operationId revokeInvitation): its token becomes
// unredeemable. The returned InvitationStateChangeView states the post-condition
// (`state: revoked`). Idempotency-Key guarded.
export async function revokeInvitation(
  tenantId: string,
  environmentId: string,
  invitationId: string,
): Promise<InvitationStateChangeView> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/invitations/{invitation_id}/revoke",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          invitation_id: invitationId,
        },
        header: { "Idempotency-Key": idempotencyKey() },
      },
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Unlink a user's external id (operationId unlinkUserExternalId). Returns a 200
// with the (now null) mapping, not a 204, so the guard checks the body too.
export async function unlinkUserExternalId(
  tenantId: string,
  environmentId: string,
  userId: string,
): Promise<UserExternalIdView> {
  const client = createManagementClient();
  const { data, error, response } = await client.DELETE(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/users/{user_id}/external-id",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          user_id: userId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// ---- The organization roles and groups operations (issue #97) ---------------
//
// The organization detail surface (src/ui/OrgRolesView.tsx, mounted by
// src/ui/OrganizationsView.tsx) calls these named wrappers, never a path, so the
// single funnel holds: every literal below is a path the committed
// docs/openapi/management.json documents, and the tenant, environment, and
// organization ids substitute into the documented path parameters exactly as the
// memberships wrappers inject them. Each throws a ManagementError carrying the
// verbatim ErrorBody on a non 2xx (the same bodyless-non-2xx guard as the reads
// above), which the ErrorView boundary renders unchanged. That matters more here
// than anywhere else in the console: the reparent refusals (a cycle, or a depth
// past the configured maximum) are 422 bodies the server words precisely, and
// rewording them would cost the operator the reason the move was refused.
//
// The list reads are KEYSET paginated and return { items, nextCursor } so the
// view can surface a "more exist" indicator rather than SILENTLY DROPPING the
// tail. The effective-roles read is deliberately NOT paginated: it is one
// bounded set, and it is returned whole.

// List the roles of one organization (operationId listOrgRoles).
export async function fetchOrgRoles(
  tenantId: string,
  environmentId: string,
  organizationId: string,
): Promise<KeysetPage<OrgRoleView>> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return { items: data?.items ?? [], nextCursor: data?.next_cursor ?? null };
}

// Read one role (operationId getOrgRole). The role detail panel reads this fresh
// rather than reusing the list row, so a rename made elsewhere is visible.
export async function getOrgRole(
  tenantId: string,
  environmentId: string,
  organizationId: string,
  roleId: string,
): Promise<OrgRoleView> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles/{role_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
          role_id: roleId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Define a role in an organization (operationId createOrgRole). Idempotency-Key
// guarded so a retried submit defines the role once.
export async function createOrgRole(
  tenantId: string,
  environmentId: string,
  organizationId: string,
  request: CreateOrgRoleRequest,
): Promise<OrgRoleView> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
        },
        header: { "Idempotency-Key": idempotencyKey() },
      },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Rename a role (operationId updateOrgRole): an RFC 7396 style partial edit over
// the display name only. The slug is IMMUTABLE and is not on this body, so a name
// an authorization decision keys on cannot move under it.
export async function updateOrgRole(
  tenantId: string,
  environmentId: string,
  organizationId: string,
  roleId: string,
  request: UpdateOrgRoleRequest,
): Promise<OrgRoleView> {
  const client = createManagementClient();
  const { data, error, response } = await client.PATCH(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles/{role_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
          role_id: roleId,
        },
      },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Delete a role (operationId deleteOrgRole): a soft delete that also withdraws
// every grant of it. A 204 carries no body, so the guard reads the bodyless 2xx
// as success and any non 2xx as the verbatim failure.
export async function deleteOrgRole(
  tenantId: string,
  environmentId: string,
  organizationId: string,
  roleId: string,
): Promise<void> {
  const client = createManagementClient();
  const { error, response } = await client.DELETE(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles/{role_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
          role_id: roleId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
}

// List the groups of one organization (operationId listOrgGroups). The page is
// FLAT: every group with its parent_id, so the console renders the hierarchy from
// one page sequence rather than one request per level.
export async function fetchOrgGroups(
  tenantId: string,
  environmentId: string,
  organizationId: string,
): Promise<KeysetPage<OrgGroupView>> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return { items: data?.items ?? [], nextCursor: data?.next_cursor ?? null };
}

// Read one group (operationId getOrgGroup). The group detail panel reads this
// fresh, so a move or a rename made elsewhere is visible.
export async function getOrgGroup(
  tenantId: string,
  environmentId: string,
  organizationId: string,
  groupId: string,
): Promise<OrgGroupView> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
          group_id: groupId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Define a group in an organization (operationId createOrgGroup). An omitted or
// null parent_id creates a ROOT. Idempotency-Key guarded.
export async function createOrgGroup(
  tenantId: string,
  environmentId: string,
  organizationId: string,
  request: CreateOrgGroupRequest,
): Promise<OrgGroupView> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
        },
        header: { "Idempotency-Key": idempotencyKey() },
      },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Rename a group (operationId updateOrgGroup). The parent is deliberately NOT on
// this body: moving a group is setOrgGroupParent below, which carries the cycle
// and depth refusals, so a plain rename can never reshape the hierarchy.
export async function updateOrgGroup(
  tenantId: string,
  environmentId: string,
  organizationId: string,
  groupId: string,
  request: UpdateOrgGroupRequest,
): Promise<OrgGroupView> {
  const client = createManagementClient();
  const { data, error, response } = await client.PATCH(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
          group_id: groupId,
        },
      },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Delete a group (operationId deleteOrgGroup). A delete DETACHES the subtree
// rather than cascading: the children survive and are treated as roots.
export async function deleteOrgGroup(
  tenantId: string,
  environmentId: string,
  organizationId: string,
  groupId: string,
): Promise<void> {
  const client = createManagementClient();
  const { error, response } = await client.DELETE(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
          group_id: groupId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
}

// MOVE a group within its organization hierarchy (operationId
// setOrgGroupParent). A PUT replaces the whole parent relationship, so a null
// parent_id promotes the group to a root. The server is the authority on whether
// a move is admissible: it refuses a cycle and a nesting past the configured
// maximum depth with a 422 whose body this wrapper surfaces verbatim.
export async function setOrgGroupParent(
  tenantId: string,
  environmentId: string,
  organizationId: string,
  groupId: string,
  request: SetOrgGroupParentRequest,
): Promise<OrgGroupView> {
  const client = createManagementClient();
  const { data, error, response } = await client.PUT(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/parent",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
          group_id: groupId,
        },
      },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// List the memberships bound into one group (operationId listOrgGroupMembers).
export async function fetchOrgGroupMembers(
  tenantId: string,
  environmentId: string,
  organizationId: string,
  groupId: string,
): Promise<KeysetPage<OrgGroupMemberView>> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/members",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
          group_id: groupId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return { items: data?.items ?? [], nextCursor: data?.next_cursor ?? null };
}

// Bind an organization membership into a group (operationId addOrgGroupMember).
// The body carries a MEMBERSHIP id, never a bare user id. Idempotency-Key
// guarded.
export async function addOrgGroupMember(
  tenantId: string,
  environmentId: string,
  organizationId: string,
  groupId: string,
  request: AddOrgGroupMemberRequest,
): Promise<OrgGroupMemberView> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/members",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
          group_id: groupId,
        },
        header: { "Idempotency-Key": idempotencyKey() },
      },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Unbind a membership from a group (operationId removeOrgGroupMember). The
// binding is addressed by the (group, membership) PAIR, not by its own id.
export async function removeOrgGroupMember(
  tenantId: string,
  environmentId: string,
  organizationId: string,
  groupId: string,
  membershipId: string,
): Promise<void> {
  const client = createManagementClient();
  const { error, response } = await client.DELETE(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/members/{membership_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
          group_id: groupId,
          membership_id: membershipId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
}

// List the roles one group grants (operationId listOrgGroupRoles). Every live
// member of the group and of every DESCENDANT of it resolves these.
export async function fetchOrgGroupRoles(
  tenantId: string,
  environmentId: string,
  organizationId: string,
  groupId: string,
): Promise<KeysetPage<OrgGroupRoleView>> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/roles",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
          group_id: groupId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return { items: data?.items ?? [], nextCursor: data?.next_cursor ?? null };
}

// Grant a role to a group (operationId assignOrgGroupRole). Idempotency-Key
// guarded.
export async function assignOrgGroupRole(
  tenantId: string,
  environmentId: string,
  organizationId: string,
  groupId: string,
  request: AssignOrgGroupRoleRequest,
): Promise<OrgGroupRoleView> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/roles",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
          group_id: groupId,
        },
        header: { "Idempotency-Key": idempotencyKey() },
      },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Withdraw a role from a group (operationId unassignOrgGroupRole). The
// assignment is addressed by the (group, role) PAIR, not by its own id.
export async function unassignOrgGroupRole(
  tenantId: string,
  environmentId: string,
  organizationId: string,
  groupId: string,
  roleId: string,
): Promise<void> {
  const client = createManagementClient();
  const { error, response } = await client.DELETE(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/groups/{group_id}/roles/{role_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
          group_id: groupId,
          role_id: roleId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
}

// List the roles one membership holds DIRECTLY (operationId
// listOrgMembershipRoles). Direct grants ONLY: a role resolved through a group is
// not here, because this list is exactly the set of rows an unassign on this
// surface can remove. The whole resolved picture, with provenance, is
// getOrgMembershipEffectiveRoles below.
export async function fetchOrgMembershipRoles(
  tenantId: string,
  environmentId: string,
  organizationId: string,
  membershipId: string,
): Promise<KeysetPage<OrgMembershipRoleView>> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships/{membership_id}/roles",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
          membership_id: membershipId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return { items: data?.items ?? [], nextCursor: data?.next_cursor ?? null };
}

// Grant a role directly to a membership (operationId assignOrgMembershipRole).
// Exactly this membership resolves the role; no group is involved and no
// descendant inherits it. Idempotency-Key guarded.
export async function assignOrgMembershipRole(
  tenantId: string,
  environmentId: string,
  organizationId: string,
  membershipId: string,
  request: AssignOrgMembershipRoleRequest,
): Promise<OrgMembershipRoleView> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships/{membership_id}/roles",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
          membership_id: membershipId,
        },
        header: { "Idempotency-Key": idempotencyKey() },
      },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Withdraw a role granted directly to a membership (operationId
// unassignOrgMembershipRole). The membership may STILL resolve the role through a
// group, which is why the effective-roles view lists one entry per grant path.
export async function unassignOrgMembershipRole(
  tenantId: string,
  environmentId: string,
  organizationId: string,
  membershipId: string,
  roleId: string,
): Promise<void> {
  const client = createManagementClient();
  const { error, response } = await client.DELETE(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships/{membership_id}/roles/{role_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
          membership_id: membershipId,
          role_id: roleId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
}

// Whether a value is a readable PermissionBudgetView (issue #98).
//
// Every counted field is REQUIRED by the contract, and `overflow` is present ONLY
// when the set is past the maximum, so an absent or null `overflow` is the legal
// within-budget answer while a non string one is a body this app cannot read.
// Anything failing this check is a budget the console must NOT interpret: see the
// refusal in getOrgMembershipEffectiveRoles for why a benign default is unsafe.
//
// An EMPTY `overflow` string is refused with the rest, which is the one part of
// this check no server answer reaches: the field is either absent or one of two
// non empty `permissions_status` values. It is refused rather than ignored because
// the two ways of absorbing it are both worse. Treating it as "no overflow" would
// report a withholding as within budget, the exact downgrade this whole guard
// exists to prevent; letting it through renders a sentence naming a status that
// has no name. Unreadable is the honest reading, and unreadable is reported.
function isReadablePermissionBudget(value: unknown): boolean {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const budget = value as Record<string, unknown>;
  const overflow = budget.overflow;
  return (
    typeof budget.approaching === "boolean" &&
    typeof budget.permission_count === "number" &&
    typeof budget.max_permission_count === "number" &&
    typeof budget.warn_permission_count === "number" &&
    typeof budget.max_token_bytes === "number" &&
    typeof budget.warn_token_bytes === "number" &&
    (overflow === undefined ||
      overflow === null ||
      (typeof overflow === "string" && overflow !== ""))
  );
}

// Resolve every role one membership effectively holds, WITH PROVENANCE, together
// with the permission UNION those roles carry and the advisory budget verdict for
// it (operationId getOrgMembershipEffectiveRoles).
//
// `roles` is one entry per grant path, NOT deduplicated by slug: a role held both
// directly and through a group appears twice, and that is exactly what tells an
// operator that withdrawing one grant will not take the role away. `permissions`
// is the opposite, a deduplicated SET, because that is what a token claim is.
// This wrapper returns the whole object unchanged, and no caller may collapse
// either list.
//
// Not paginated: the contract returns both sets whole, so there is no tail to
// drop and no cursor to surface.
export async function getOrgMembershipEffectiveRoles(
  tenantId: string,
  environmentId: string,
  organizationId: string,
  membershipId: string,
): Promise<EffectiveRolesView> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/memberships/{membership_id}/effective-roles",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
          membership_id: membershipId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  // A MALFORMED 2xx fails just as loud. Coercing a bodyless or wrongly shaped
  // success into an empty array would render "this member resolves no roles",
  // which is indistinguishable from a member who legitimately holds nothing: a
  // silent authorization DOWNGRADE, the very reading the non 2xx path above
  // already refuses to produce. There is no safe empty answer here, so the
  // console says it could not read the resolved set.
  if (data === undefined || !Array.isArray(data.roles)) {
    throw new ManagementError(
      {
        error: "malformed_response",
        message:
          "The effective roles response did not carry a role list, so the resolved set could not be read. It is not being reported as empty.",
      },
      response.status,
    );
  }
  // The SAME property, extended to the two fields issue #98 added, because each
  // has its own indistinguishable-from-benign reading and the contract makes both
  // REQUIRED.
  //
  // A permission list that cannot be read must not become `[]`: that renders
  // "this member holds no permissions", which is the identical silent
  // authorization downgrade one field over. Every element must be a string
  // because the list IS the claim, and a non string entry means the body is not
  // the resolved set this app can show.
  if (
    !Array.isArray(data.permissions) ||
    !data.permissions.every((entry) => typeof entry === "string")
  ) {
    throw new ManagementError(
      {
        error: "malformed_response",
        message:
          "The effective roles response did not carry a readable permission list, so the resolved permission set could not be read. It is not being reported as empty.",
      },
      response.status,
    );
  }
  // And a budget that cannot be read must not become a benign verdict. Defaulting
  // it to no overflow would tell an operator the next token WILL carry these
  // permissions when the mint may be about to withhold them, which is a downgrade
  // in the one direction that matters: they would stop looking. Absent is not
  // within budget, it is unknown, and unknown is reported.
  if (!isReadablePermissionBudget(data.permission_budget)) {
    throw new ManagementError(
      {
        error: "malformed_response",
        message:
          "The effective roles response did not carry a readable permission budget, so whether the next token would withhold the permission claim could not be read. It is not being reported as within budget.",
      },
      response.status,
    );
  }
  return data;
}

// ---- The permission operations (issue #98) ----------------------------------
//
// Four surfaces at THREE different scopes, and the scope of each is the thing to
// keep straight, because a panel placed at the wrong one is the mistake that would
// read plausibly and be wrong:
//
//   The VOCABULARY (src/ui/PermissionsView.tsx) is ENVIRONMENT scoped. A
//   permission slug is defined once per environment and every organization in it
//   maps its roles onto the same vocabulary, so this belongs to the environment
//   section and not to any organization panel.
//
//   The role MAPPING (src/ui/OrgRolePermissionsView.tsx) is ORGANIZATION scoped,
//   nested in one role, because a role is meaningless without an organization.
//
//   The DEFAULT ROLE designation (src/ui/OrgDefaultRoleView.tsx) is a single
//   valued property of ONE organization.
//
//   The claim OPT-IN (src/ui/PermissionsView.tsx) belongs to a registered resource
//   server, which is ENVIRONMENT scoped like the vocabulary.
//
// Each wrapper below is a named function calling a path the committed
// docs/openapi/management.json documents, never a path assembled by a caller, so
// the single funnel holds. Each throws a ManagementError carrying the verbatim
// ErrorBody on a non 2xx (the same bodyless-non-2xx guard as the reads above),
// which the ErrorView boundary renders unchanged. That matters particularly here
// because two refusals are worded precisely by the server and rewording them would
// cost the operator the reason: the 422 on attaching a permission that is not a
// live entry of THIS environment, and the 422 on enabling the claim for a resource
// server whose token format cannot carry one.
//
// The list reads are KEYSET paginated and return { items, nextCursor } so a view
// can surface a "more exist" indicator rather than SILENTLY DROPPING the tail.

// List the permissions one role grants (operationId listOrgRolePermissions).
//
// A row here is a MAPPING and not by itself a live grant: deleting the vocabulary
// entry leaves the mapping row but stops the resolution, which the effective-roles
// read is the authority on.
export async function fetchOrgRolePermissions(
  tenantId: string,
  environmentId: string,
  organizationId: string,
  roleId: string,
): Promise<KeysetPage<OrgRolePermissionView>> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles/{role_id}/permissions",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
          role_id: roleId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return { items: data?.items ?? [], nextCursor: data?.next_cursor ?? null };
}

// Attach a vocabulary entry to a role (operationId assignOrgRolePermission).
// Idempotency-Key guarded so a retried submit attaches it once.
export async function assignOrgRolePermission(
  tenantId: string,
  environmentId: string,
  organizationId: string,
  roleId: string,
  request: AssignOrgRolePermissionRequest,
): Promise<OrgRolePermissionView> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles/{role_id}/permissions",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
          role_id: roleId,
        },
        header: { "Idempotency-Key": idempotencyKey() },
      },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Detach a vocabulary entry from a role (operationId unassignOrgRolePermission).
// Addressed by the (role, permission) PAIR, never by the mapping row id, which the
// contract carries for audit correlation and no endpoint accepts.
export async function unassignOrgRolePermission(
  tenantId: string,
  environmentId: string,
  organizationId: string,
  roleId: string,
  permissionId: string,
): Promise<void> {
  const client = createManagementClient();
  const { error, response } = await client.DELETE(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/roles/{role_id}/permissions/{permission_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
          role_id: roleId,
          permission_id: permissionId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
}

// Designate the default role of one organization (operationId setOrgDefaultRole).
// An idempotent replacement of a single valued property: a second designation MOVES
// it rather than being refused, so no Idempotency-Key, matching the contract, which
// documents none. Answered with the role that now holds the designation.
export async function setOrgDefaultRole(
  tenantId: string,
  environmentId: string,
  organizationId: string,
  request: SetOrgDefaultRoleRequest,
): Promise<OrgRoleView> {
  const client = createManagementClient();
  const { data, error, response } = await client.PUT(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/default-role",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
        },
      },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Clear the default role designation (operationId clearOrgDefaultRole). NOTHING is
// deleted: the role stays a live role of the organization and every direct and
// group grant of it stands. What stops is the resolution that gave it to every
// member without a row. A 204 carries no body, so the guard reads the bodyless 2xx
// as success and any non 2xx as the verbatim failure.
export async function clearOrgDefaultRole(
  tenantId: string,
  environmentId: string,
  organizationId: string,
): Promise<void> {
  const client = createManagementClient();
  const { error, response } = await client.DELETE(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/organizations/{organization_id}/default-role",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          organization_id: organizationId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
}

// List the permission vocabulary of one environment (operationId listPermissions).
export async function fetchPermissions(
  tenantId: string,
  environmentId: string,
): Promise<KeysetPage<PermissionView>> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/permissions",
    { params: { path: { tenant_id: tenantId, environment_id: environmentId } } },
  );
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return { items: data?.items ?? [], nextCursor: data?.next_cursor ?? null };
}

// Read one vocabulary entry (operationId getPermission). The detail panel reads
// this fresh rather than reusing the list row, so a relabel made in another console
// session is visible.
export async function getPermission(
  tenantId: string,
  environmentId: string,
  permissionId: string,
): Promise<PermissionView> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/permissions/{permission_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          permission_id: permissionId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Define a permission in an environment (operationId createPermission).
// Idempotency-Key guarded so a retried submit defines it once. The slug is never
// case folded and its inner punctuation is never rewritten, here or in the form
// that calls this: a non canonical value is refused by the server with the rule
// stated, and repairing it in the browser would store a slug the operator did not
// write while a token claim carries it. The form does trim SURROUNDING whitespace,
// which no canonical slug can contain, so that one repair cannot turn a refusal
// into a different stored value.
export async function createPermission(
  tenantId: string,
  environmentId: string,
  request: CreatePermissionRequest,
): Promise<PermissionView> {
  const client = createManagementClient();
  const { data, error, response } = await client.POST(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/permissions",
    {
      params: {
        path: { tenant_id: tenantId, environment_id: environmentId },
        header: { "Idempotency-Key": idempotencyKey() },
      },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Relabel a permission (operationId updatePermission): an RFC 7396 style partial
// edit over the display name only. `slug` and `kind` are IMMUTABLE and the server
// refuses either KEY being present at all, null included, so this app must never
// put one on the body: the slug is a direct authorization input and a rename under
// live mappings would silently repoint every grant that names it.
export async function updatePermission(
  tenantId: string,
  environmentId: string,
  permissionId: string,
  request: UpdatePermissionRequest,
): Promise<PermissionView> {
  const client = createManagementClient();
  const { data, error, response } = await client.PATCH(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/permissions/{permission_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          permission_id: permissionId,
        },
      },
      body: request,
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}

// Delete a permission (operationId deletePermission): a soft delete. Every role
// mapping that names it stops resolving. A 204 carries no body, so the guard reads
// the bodyless 2xx as success and any non 2xx as the verbatim failure.
export async function deletePermission(
  tenantId: string,
  environmentId: string,
  permissionId: string,
): Promise<void> {
  const client = createManagementClient();
  const { error, response } = await client.DELETE(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/permissions/{permission_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          permission_id: permissionId,
        },
      },
    },
  );
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
}

// List the registered resource servers of one environment (operationId
// listResourceServers). The console needs this to find a resource server by its ID:
// an audience is an absolute URI containing a colon and a slash and cannot be a
// path segment, so the opt-in below is addressed by the `rsv_` id.
export async function fetchResourceServers(
  tenantId: string,
  environmentId: string,
): Promise<KeysetPage<ResourceServerView>> {
  const client = createManagementClient();
  const { data, error, response } = await client.GET(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/resource-servers",
    { params: { path: { tenant_id: tenantId, environment_id: environmentId } } },
  );
  if (error !== undefined || !response.ok) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return { items: data?.items ?? [], nextCursor: data?.next_cursor ?? null };
}

// Set one resource server's permission-claim opt-in (operationId
// updateResourceServerPermissionClaims).
//
// The body carries EXACTLY the one editable field, by two separate rules that
// happen to agree. It is REQUIRED, so an omitted value is a 400 rather than a
// request that quietly did nothing; and `token_format`, `audience` and
// `access_token_ttl_secs` are refused if PRESENT AT ALL, null included, because
// this surface cannot write them. The interaction between the token format and this
// opt-in is the whole subject of the endpoint, so a caller who believes they also
// changed the format must be refused rather than told 200. This wrapper therefore
// takes a boolean and builds the one key body itself; there is no partial edit to
// pass through. The answer to a JWT-only claim on an opaque token is the server's
// 422, rendered verbatim, never a guess made here.
export async function setResourceServerPermissionClaims(
  tenantId: string,
  environmentId: string,
  resourceServerId: string,
  permissionClaimsEnabled: boolean,
): Promise<ResourceServerView> {
  const client = createManagementClient();
  const { data, error, response } = await client.PATCH(
    "/v1/tenants/{tenant_id}/environments/{environment_id}/resource-servers/{resource_server_id}",
    {
      params: {
        path: {
          tenant_id: tenantId,
          environment_id: environmentId,
          resource_server_id: resourceServerId,
        },
      },
      body: { permission_claims_enabled: permissionClaimsEnabled },
    },
  );
  if (error !== undefined || !response.ok || data === undefined) {
    throw new ManagementError(toErrorBody(error), response.status);
  }
  return data;
}
