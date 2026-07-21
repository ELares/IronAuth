// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The scope store (issue #90, PR 3): the SINGLE source of the active
// {tenant, environment} that every resource view reads. It is signal backed (the
// locked state primitive) and populated from `listTenants` + `listEnvironments`
// through the one typed client. The selection persists in sessionStorage for
// reload continuity; the BEARER TOKEN never does (that stays in memory only, per
// src/auth/session.ts). This module holds NO path literal and performs NO
// network call itself: it calls the typed client wrappers in src/api/client.ts.

import { computed, signal } from "@preact/signals";
import {
  type EnvironmentView,
  type ErrorBody,
  type TenantView,
  asManagementError,
  fetchEnvironments,
  fetchTenants,
} from "../api/client";
import {
  type Scope,
  hasCrossTenantReach,
  shouldCollapseSwitcher,
} from "./logic";

// The sessionStorage key for the selected scope. Only ids, never a credential.
const SCOPE_KEY = "ironauth.scope.selection";

// The reachable tenants and the resolved tenant's environments, plus the active
// selection. Every switcher and scoped view reads these.
export const tenants = signal<ReadonlyArray<TenantView>>([]);
export const environments = signal<ReadonlyArray<EnvironmentView>>([]);
export const activeScope = signal<Scope | null>(loadPersistedScope());
// A verbatim ErrorBody when loading the scope failed, surfaced by the shell
// through the error boundary (identical to what an API caller would see).
export const scopeError = signal<ErrorBody | null>(null);
// Whether the initial tenant/environment load has completed.
export const scopeLoaded = signal<boolean>(false);

// Whether the switcher chrome should be hidden (single-environment collapse).
export const switcherCollapsed = computed<boolean>(() =>
  shouldCollapseSwitcher({
    tenants: tenants.value,
    environments: environments.value,
    crossTenantReach: hasCrossTenantReach(tenants.value),
  }),
);

// Read the persisted selection (ids only). Guarded so a locked-down or private
// browsing context that throws on sessionStorage does not break the shell.
function loadPersistedScope(): Scope | null {
  try {
    const raw = sessionStorage.getItem(SCOPE_KEY);
    if (raw === null) {
      return null;
    }
    const parsed = JSON.parse(raw) as Partial<Scope>;
    if (
      typeof parsed.tenantId === "string" &&
      typeof parsed.environmentId === "string"
    ) {
      return { tenantId: parsed.tenantId, environmentId: parsed.environmentId };
    }
    return null;
  } catch {
    return null;
  }
}

// Persist (or clear) the selection. Best effort; never throws into the caller.
function persistScope(scope: Scope | null): void {
  try {
    if (scope === null) {
      sessionStorage.removeItem(SCOPE_KEY);
    } else {
      sessionStorage.setItem(SCOPE_KEY, JSON.stringify(scope));
    }
  } catch {
    // A storage failure only costs reload continuity, never correctness.
  }
}

// Record a loading failure as the verbatim server error when the client threw a
// ManagementError, or a generic shape otherwise. Never invents wording.
function recordError(value: unknown): void {
  const managed = asManagementError(value);
  scopeError.value =
    managed !== null
      ? managed.body
      : {
          error: "scope_load_failed",
          message: "The console could not load its tenants and environments.",
        };
}

// Pick the environment to activate for a tenant: the persisted one when it is
// still present, otherwise the first.
function chooseEnvironment(
  list: ReadonlyArray<EnvironmentView>,
  preferredId: string | null,
): EnvironmentView | null {
  if (list.length === 0) {
    return null;
  }
  if (preferredId !== null) {
    const found = list.find((env) => env.id === preferredId);
    if (found !== undefined) {
      return found;
    }
  }
  return list[0] ?? null;
}

// Load the tenants, then the environments of the active (persisted or first)
// tenant, and resolve the active scope. Errors surface verbatim through
// scopeError. Idempotent enough to call once on sign in.
export async function loadScope(): Promise<void> {
  scopeError.value = null;
  try {
    const tenantList = await fetchTenants();
    tenants.value = tenantList;
    if (tenantList.length === 0) {
      environments.value = [];
      activeScope.value = null;
      scopeLoaded.value = true;
      return;
    }
    const persisted = activeScope.value;
    const preferredTenant =
      persisted !== null &&
      tenantList.some((tenant) => tenant.id === persisted.tenantId)
        ? persisted.tenantId
        : (tenantList[0]?.id ?? "");
    await selectTenant(preferredTenant, persisted?.environmentId ?? null);
  } catch (value) {
    recordError(value);
  } finally {
    scopeLoaded.value = true;
  }
}

// Switch the active tenant: load its environments and activate the preferred (or
// first) environment. `preferredEnvironmentId` lets loadScope honour a persisted
// environment; a manual switch passes null to take the first.
export async function selectTenant(
  tenantId: string,
  preferredEnvironmentId: string | null = null,
): Promise<void> {
  scopeError.value = null;
  try {
    const envList = await fetchEnvironments(tenantId);
    environments.value = envList;
    const env = chooseEnvironment(envList, preferredEnvironmentId);
    const next: Scope | null =
      env === null ? null : { tenantId, environmentId: env.id };
    activeScope.value = next;
    persistScope(next);
  } catch (value) {
    recordError(value);
  }
}

// Switch the active environment within the current tenant. A no op when there is
// no active tenant scope yet.
export function selectEnvironment(environmentId: string): void {
  const current = activeScope.value;
  if (current === null) {
    return;
  }
  const next: Scope = { tenantId: current.tenantId, environmentId };
  activeScope.value = next;
  persistScope(next);
}

// Reset the store (used on sign out and by tests).
export function resetScope(): void {
  tenants.value = [];
  environments.value = [];
  activeScope.value = null;
  scopeError.value = null;
  scopeLoaded.value = false;
  persistScope(null);
}
