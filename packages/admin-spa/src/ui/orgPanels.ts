// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The small shared plumbing of the organization roles and groups panels (issue
// #97), split out so the three surfaces (src/ui/OrgRolesView.tsx,
// src/ui/OrgGroupsView.tsx, src/ui/MemberRolesView.tsx) agree on the scope they
// take and on how a write offers the RFC 9470 sudo recovery. There is NO network
// call and NO path literal here.

import type { SudoRecovery } from "./ErrorView";
import { activeScope } from "../scope/store";

// The three ids every surface here is scoped by. The organization detail view
// resolves the active {tenant, environment} from the scope store and makes ZERO
// calls without one, so these panels are only ever mounted with all three in
// hand and inherit that guard by construction.
export interface OrgScope {
  tenantId: string;
  environmentId: string;
  organizationId: string;
}

export function inputValue(event: Event): string {
  return (event.target as HTMLInputElement).value;
}

export function selectValue(event: Event): string {
  return (event.target as HTMLSelectElement).value;
}

// The sudo recovery for a write in these panels: the RFC 9470 challenge
// re-authenticates, elevates within the ACTIVE scope, and replays the write.
// Absent when no scope is active, which cannot happen while these panels are
// mounted, but is handled rather than asserted.
export function sudoFor(retry: () => Promise<void>): SudoRecovery | undefined {
  const scope = activeScope.value;
  return scope === null ? undefined : { scope, retry };
}
