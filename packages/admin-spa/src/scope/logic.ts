// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The PURE scope logic (issue #90, PR 3). The tenant/environment context
// switcher is the single source of the active scope every resource view reads;
// this module holds the parts of that decision that are pure functions, with NO
// Preact, NO signals, and NO network, so they are trivially unit tested. The
// store (src/scope/store.ts) wires these to signals and the one typed client.

// The active scope: the tenant and environment every scoped management call
// substitutes into its path parameters. A view reads this and passes it to a
// typed client wrapper, which is the ONLY place a path is formed.
export interface Scope {
  tenantId: string;
  environmentId: string;
}

// The scope as path parameters for a scoped management operation. The typed
// client substitutes these into `/v1/tenants/{tenant_id}/environments/{environment_id}/...`,
// so this is the shape every scoped call injects. Kept pure and named so the
// injection is one obvious, tested step rather than scattered literals.
export interface ScopePathParams {
  tenant_id: string;
  environment_id: string;
}

// Inject a scope into the path parameters of a scoped management call.
export function scopePathParams(scope: Scope): ScopePathParams {
  return { tenant_id: scope.tenantId, environment_id: scope.environmentId };
}

// The inputs the collapse decision reads: the reachable tenants and the
// environments of the resolved tenant, plus whether the principal reaches more
// than one tenant.
export interface CollapseInput {
  tenants: ReadonlyArray<{ id: string }>;
  environments: ReadonlyArray<{ id: string }>;
  crossTenantReach: boolean;
}

// The single-environment collapse (a hard acceptance criterion). When the
// resolved tenant has exactly ONE environment and the principal has no
// cross-tenant reach, the scope is implicit: there is nothing to choose, so the
// switcher renders NO chrome at all (zero ceremony for the homelab operator).
// Any other shape (more than one environment to pick between, or reach across
// more than one tenant) keeps the switcher visible. Zero environments does not
// collapse: there is no scope to imply, and the shell shows that state instead.
export function shouldCollapseSwitcher(input: CollapseInput): boolean {
  if (input.crossTenantReach) {
    return false;
  }
  return input.tenants.length <= 1 && input.environments.length === 1;
}

// Whether the principal reaches more than one tenant. Derived from the tenant
// list the switcher already loaded, so cross-tenant reach needs no extra call.
export function hasCrossTenantReach(
  tenants: ReadonlyArray<{ id: string }>,
): boolean {
  return tenants.length > 1;
}
