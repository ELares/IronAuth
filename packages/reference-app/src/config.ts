// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The single configuration surface an operator sets when they fork and deploy
// this app: the issuer base URL and the (tenant, environment, journey) scope.
// There are NO secrets here. The flow API is a public client protocol: it
// authenticates a submission with the per-flow submit token the server issued,
// never a client secret, so nothing in this browser app is confidential.
//
// Config is read from <meta> tags in index.html (the operator edits those, or a
// build/deploy step injects them) with a same-origin fallback, and the journey
// can be overridden by a ?journey= query parameter. This module deliberately
// contains NO URL or server-path literal: the route-audit forbids one here, and
// keeping the issuer out of the code is what lets the same built app point at
// any operator's issuer.

import type { Scope } from "./endpoints.js";

export interface AppConfig {
  // The issuer base URL, for example https://auth.example.com. Empty means the
  // app calls its own origin (same-origin deploy behind the IronAuth server).
  issuerBase: string;
  scope: Scope;
}

function meta(name: string): string | null {
  const el = document.querySelector(`meta[name="${name}"]`);
  const value = el?.getAttribute("content")?.trim();
  return value ? value : null;
}

export function loadConfig(): AppConfig {
  const params = new URLSearchParams(window.location.search);
  const issuerBase = (meta("ironauth-issuer") ?? "").replace(/\/+$/, "");
  const journey = params.get("journey") ?? meta("ironauth-journey") ?? "login";
  return {
    issuerBase,
    scope: {
      tenantId: meta("ironauth-tenant") ?? "default",
      environmentId: meta("ironauth-environment") ?? "default",
      journey,
    },
  };
}
