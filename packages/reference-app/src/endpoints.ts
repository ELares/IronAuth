// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The ONE module in the reference app that names a server path. Every entry
// here MUST be a documented public endpoint: scripts/route-audit.sh diffs this
// file against the Rust FLOW_*_PATH constants (crates/ironauth-oidc/src/flow/
// transport.rs) plus the documented public session endpoints, and fails CI on
// any path that is not public. The same audit forbids any server-path literal
// or fetch()/XHR call-site in ANY OTHER source file, so a fork physically
// cannot point the app at a private or management endpoint without tripping the
// gate. This is the structural half of the acceptance criterion "every network
// call targets a documented public endpoint": the server owns all security; the
// app is a pure client that speaks only these public routes.
//
// The values are byte-identical to the Rust path constants (scope-templated
// with {tenant_id}/{environment_id}/{journey}); expandEndpoint fills the scope.

export const PUBLIC_ENDPOINTS = {
  // POST a JSON body to create a flow and receive the flow object plus the first
  // submit token. Mirrors flow::FLOW_CREATE_API_PATH.
  flowCreateApi: "/t/{tenant_id}/e/{environment_id}/flow/api/{journey}",
  // POST the flow id, the submit token, and the node values to advance the flow.
  // Mirrors flow::FLOW_API_SUBMIT_PATH.
  flowSubmitApi: "/t/{tenant_id}/e/{environment_id}/flow/api/{journey}/submit",
} as const;

export type EndpointName = keyof typeof PUBLIC_ENDPOINTS;

export interface Scope {
  tenantId: string;
  environmentId: string;
  journey: string;
}

// Fill the scope template. The tokens are fixed literals from PUBLIC_ENDPOINTS,
// so this introduces no new path text; it only substitutes operator-supplied
// scope values, which are percent-encoded so a scope value can never inject a
// path segment.
export function expandEndpoint(name: EndpointName, scope: Scope): string {
  return PUBLIC_ENDPOINTS[name]
    .replace("{tenant_id}", encodeURIComponent(scope.tenantId))
    .replace("{environment_id}", encodeURIComponent(scope.environmentId))
    .replace("{journey}", encodeURIComponent(scope.journey));
}
