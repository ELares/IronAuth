// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Global search (issue #90, PR 7): a cross-resource search built ENTIRELY from
// the public LIST operations the management contract already documents. There is
// NO server search endpoint, and none is invented: search fetches the documented
// lists through the one typed client (src/api/client.ts) and aggregates and
// filters them CLIENT SIDE. The four resources whose list ops exist are tenants
// (global), environments, users, and connectors (each scoped to the active
// {tenant, environment}); a scoped resource is queried ONLY when a scope is
// active, so search never forms a scoped path with no scope.
//
// This module holds NO network sink and NO path literal: it calls the named
// wrappers fetchTenants / fetchEnvironments / fetchUsers / fetchConnectors, so
// the single funnel and the route audit hold. It is the async complement of the
// PR3 command palette (src/ui/CommandPalette.tsx): a result becomes a Command the
// operator runs to navigate, so there is ONE coherent search surface, not two.

import {
  type ConnectorView,
  type EnvironmentView,
  type TenantView,
  type UserView,
  fetchConnectors,
  fetchEnvironments,
  fetchTenants,
  fetchUsers,
} from "../api/client";
import type { Scope } from "../scope/logic";
import type { Command } from "./commands";

// The resource kinds search spans. Each maps to a documented LIST operation and a
// client side route the result navigates to.
export type ResultKind = "tenant" | "environment" | "user" | "connector";

// One typed, navigable search hit. `label` is the primary human text (a display
// name or login handle), `hint` is the resource id, and `href` is the APP ROUTE
// (client side navigation), never a server path.
export interface SearchResult {
  kind: ResultKind;
  id: string;
  label: string;
  hint: string;
  href: string;
}

// The minimum query length before an async search fires. Below it the palette
// still filters the in-memory navigation commands, but it does NOT hit the list
// operations: a one character query would match nearly everything and hammer the
// API on the first keystroke.
export const MIN_QUERY_LENGTH = 2;

// The debounce the palette applies before firing a search, so a fast typist does
// not fan out a list query on every keystroke. Exported so the surface and its
// tests share one value.
export const SEARCH_DEBOUNCE_MS = 200;

// Whether a query is long enough to run an async search. The palette gates the
// list queries on this (and so does searchAll, defensively), so a short or blank
// query never reaches the API.
export function shouldSearch(query: string): boolean {
  return query.trim().length >= MIN_QUERY_LENGTH;
}

// The human noun prefixed onto a result's command label, mirroring the palette's
// existing verb-led labels ("Switch to tenant Acme"). Kept a lookup so a new kind
// is a single addition.
const KIND_NOUN: Record<ResultKind, string> = {
  tenant: "Tenant",
  environment: "Environment",
  user: "User",
  connector: "Connector",
};

// ---- Pure result mappers ----------------------------------------------------
//
// Each maps a documented list view to navigable results. The href is the app
// route the click follows (the same routes app.tsx registers), so a result
// navigates through client side routing, never a server call.

export function resultsFromTenants(
  items: ReadonlyArray<TenantView>,
): SearchResult[] {
  return items.map((tenant) => ({
    kind: "tenant" as const,
    id: tenant.id,
    label: tenant.display_name,
    hint: tenant.id,
    href: `/tenants/${tenant.id}`,
  }));
}

export function resultsFromEnvironments(
  items: ReadonlyArray<EnvironmentView>,
): SearchResult[] {
  return items.map((env) => ({
    kind: "environment" as const,
    id: env.id,
    label: env.display_name,
    hint: env.id,
    href: `/environments/${env.id}`,
  }));
}

export function resultsFromUsers(
  items: ReadonlyArray<UserView>,
): SearchResult[] {
  return items.map((user) => ({
    kind: "user" as const,
    id: user.id,
    label: user.identifier,
    hint: user.id,
    href: `/users/${user.id}`,
  }));
}

export function resultsFromConnectors(
  items: ReadonlyArray<ConnectorView>,
): SearchResult[] {
  return items.map((connector) => ({
    kind: "connector" as const,
    id: connector.id,
    label: connector.connector_slug,
    hint: connector.id,
    href: `/connectors/${connector.id}`,
  }));
}

// Filter aggregated results by a case-insensitive substring over the label and
// the id, mirroring the palette's filterCommands. The list operations return the
// whole (already authz-scoped) set; the query narrows them CLIENT SIDE.
export function filterResults(
  results: ReadonlyArray<SearchResult>,
  query: string,
): SearchResult[] {
  const needle = query.trim().toLowerCase();
  if (needle === "") {
    return results.slice();
  }
  return results.filter((result) => {
    const haystack = `${result.label} ${result.hint}`.toLowerCase();
    return haystack.includes(needle);
  });
}

// Convert a result into a palette Command whose run navigates to the result's
// route. Kept pure (the navigate fn is injected) so it is unit tested without a
// router, and so the result and the navigation command are provably the same
// route. This is the reconciliation seam: a search hit IS a command.
export function toCommand(
  result: SearchResult,
  navigate: (href: string) => void,
): Command {
  return {
    id: `search:${result.kind}:${result.id}`,
    label: `${KIND_NOUN[result.kind]} ${result.label}`,
    hint: result.hint,
    run: () => navigate(result.href),
  };
}

// Run the cross-resource search: fetch the documented lists through the one typed
// client, aggregate, and filter by the query. Tenants are global (always
// queried); environments, users, and connectors are scoped, so they are queried
// ONLY when a scope is active. A short query returns nothing and makes NO call. A
// list failure (including a bodyless non 2xx a wrapper rejects) propagates as the
// thrown ManagementError, so the caller surfaces it through the ErrorView
// boundary rather than silently showing an empty result set.
export async function searchAll(
  query: string,
  scope: Scope | null,
): Promise<SearchResult[]> {
  if (!shouldSearch(query)) {
    return [];
  }
  const groups: Promise<SearchResult[]>[] = [
    fetchTenants().then(resultsFromTenants),
  ];
  if (scope !== null) {
    groups.push(
      fetchEnvironments(scope.tenantId).then(resultsFromEnvironments),
    );
    groups.push(
      fetchUsers(scope.tenantId, scope.environmentId).then(resultsFromUsers),
    );
    groups.push(
      fetchConnectors(scope.tenantId, scope.environmentId).then(
        resultsFromConnectors,
      ),
    );
  }
  const resolved = await Promise.all(groups);
  return filterResults(resolved.flat(), query);
}
