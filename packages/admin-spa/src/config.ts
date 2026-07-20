// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The deployment config the operator sets, read from <meta> tags in index.html
// (mirroring packages/reference-app). There are NO secrets here. The admin
// console is a public client: it obtains a bearer token by performing the OIDC
// login (that lands in PR2) and sends it to the management API through the one
// typed client in src/api/client.ts. This module names NO server path: the
// route audit forbids a path or URL literal here, so the reachable surface is
// pinned to the generated client.

export interface AppConfig {
  // The issuer base URL of the IronAuth public plane (for example
  // https://auth.example.com). Empty means the app calls its own origin, which
  // is the embedded, same origin deploy.
  issuerBase: string;
  // The base URL the management API is reached at (the same origin management
  // proxy in the embedded deploy, or the management host for a standalone
  // deploy). Empty means same origin.
  managementBase: string;
}

function meta(name: string): string {
  const el = document.querySelector(`meta[name="${name}"]`);
  return el?.getAttribute("content")?.trim() ?? "";
}

export function loadConfig(): AppConfig {
  return {
    issuerBase: meta("ironauth-issuer").replace(/\/+$/, ""),
    managementBase: meta("ironauth-management-base").replace(/\/+$/, ""),
  };
}
