// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The deployment config the operator sets, read from <meta> tags in index.html
// (mirroring packages/reference-app). There are NO secrets here. The admin
// console is a PUBLIC OIDC client: it obtains a bearer token by performing the
// Authorization Code + PKCE login (src/auth/login.ts) against the admin issuer
// and sends it to the management API through the one typed client in
// src/api/client.ts. This module names NO absolute server URL: every base is
// runtime <meta> config, so the route audit can pin the reachable surface to the
// generated client and the small OIDC public allowlist.

export interface AppConfig {
  // The issuer base URL of the IronAuth public plane (for example
  // https://auth.example.com). Empty means the app calls its own origin, which
  // is the embedded, same origin deploy.
  issuerBase: string;
  // The base the management API is reached at. In the embedded deploy this is
  // the same origin management proxy under /admin/api; a standalone deploy points
  // it at the management proxy origin. Empty falls back to the embedded proxy
  // prefix so a default build works same origin out of the box.
  managementBase: string;
  // The ADMIN ISSUER the console signs in against (issue #90, PR 2): the OIDC
  // issuer of the system environment. It may be a same origin path (the embedded
  // deploy, for example /t/<tenant>/e/<env>) or an absolute issuer URL (a
  // standalone deploy). Empty leaves sign in unavailable (nothing to log in to).
  adminIssuer: string;
  // The PUBLIC OAuth client id the console authenticates as. A public client
  // holds no secret, so this is a bounded identifier, never a credential. Empty
  // leaves sign in unavailable.
  consoleClientId: string;
  // The management API audience (RFC 8707) the console's access token is bound
  // to. Sent as the `resource` parameter so the minted token's `aud` is the
  // management API, which the management plane requires exactly. Empty omits the
  // resource parameter (the token then audiences to the client by default).
  managementAudience: string;
}

// The embedded same origin management proxy prefix (mirrors
// ironauth_admin_ui::API_PREFIX). The default build reaches the management API
// here so the browser never needs a cross origin exception.
const EMBEDDED_MANAGEMENT_BASE = "/admin/api";

function meta(name: string): string {
  const el = document.querySelector(`meta[name="${name}"]`);
  return el?.getAttribute("content")?.trim() ?? "";
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

export function loadConfig(): AppConfig {
  const managementBase = trimTrailingSlash(meta("ironauth-management-base"));
  return {
    issuerBase: trimTrailingSlash(meta("ironauth-issuer")),
    managementBase: managementBase === "" ? EMBEDDED_MANAGEMENT_BASE : managementBase,
    adminIssuer: trimTrailingSlash(meta("ironauth-admin-issuer")),
    consoleClientId: meta("ironauth-console-client-id"),
    managementAudience: meta("ironauth-management-audience"),
  };
}
