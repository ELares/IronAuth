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
