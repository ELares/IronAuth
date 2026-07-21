// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The tenant/environment context switcher (issue #90, PR 3; the headline of this
// PR). It is the persistent, single source of the active scope every resource
// view reads. It populates from `listTenants` + `listEnvironments` through the
// store (which calls the one typed client) and writes the selection back to the
// store, which every scoped call then injects into its path parameters.
//
// SINGLE-ENVIRONMENT COLLAPSE (a hard acceptance criterion): when the resolved
// tenant has exactly one environment and the principal has no cross-tenant reach,
// the switcher renders NO chrome at all. The scope is implicit and the homelab
// operator sees zero ceremony. The decision is the pure, unit-tested
// shouldCollapseSwitcher (src/scope/logic.ts), read here as a signal.

import {
  activeScope,
  environments,
  selectEnvironment,
  selectTenant,
  switcherCollapsed,
  tenants,
} from "../scope/store";

function onTenantChange(event: Event): void {
  const value = (event.target as HTMLSelectElement).value;
  void selectTenant(value);
}

function onEnvironmentChange(event: Event): void {
  const value = (event.target as HTMLSelectElement).value;
  selectEnvironment(value);
}

export function Switcher() {
  // The collapse: no chrome when the scope is implicit.
  if (switcherCollapsed.value) {
    return null;
  }
  const scope = activeScope.value;
  const tenantList = tenants.value;
  const environmentList = environments.value;
  if (tenantList.length === 0) {
    return null;
  }
  return (
    <div class="switcher" aria-label="Active scope">
      <label class="switcher-field">
        <span class="switcher-label">Tenant</span>
        <select
          class="switcher-select"
          value={scope?.tenantId ?? ""}
          onChange={onTenantChange}
        >
          {tenantList.map((tenant) => (
            <option key={tenant.id} value={tenant.id}>
              {tenant.display_name}
            </option>
          ))}
        </select>
      </label>
      {environmentList.length <= 1 ? null : (
        <label class="switcher-field">
          <span class="switcher-label">Environment</span>
          <select
            class="switcher-select"
            value={scope?.environmentId ?? ""}
            onChange={onEnvironmentChange}
          >
            {environmentList.map((env) => (
              <option key={env.id} value={env.id}>
                {env.display_name}
              </option>
            ))}
          </select>
        </label>
      )}
    </div>
  );
}
