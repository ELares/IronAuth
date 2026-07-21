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
