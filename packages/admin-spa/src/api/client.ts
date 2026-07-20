// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The ONE module in the admin console that performs a network call. Every
// request goes through the openapi-fetch client created here, which is typed by
// the generated management contract (management.gen.ts), so a call can only
// target a path and method the public management API actually documents. The
// route audit (scripts/admin-spa-route-audit.sh) is the structural guarantee:
// it fails if any other module imports a network sink or names a server path,
// and it checks that every path this app can reach maps to a documented
// management operation (or the small allowlist of OIDC public endpoints the
// PR2 login module will need).
//
// This is also the single place a non 2xx body is mapped to the verbatim
// management error shape (ErrorBody), so the UI renders the server's own error
// wording rather than inventing its own. PR1 ships the funnel and a stub
// renderer; the login token wiring and real error surfaces land in PR2.

import createClient from "openapi-fetch";
import type { components, paths } from "./management.gen";
import { loadConfig } from "../config";

// The verbatim structured error body every management endpoint returns. Kept as
// a re-export of the generated schema so the UI never hand maintains the shape.
export type ErrorBody = components["schemas"]["ErrorBody"];

export type ManagementClient = ReturnType<typeof createClient<paths>>;

// Build the single typed management client. The bearer token the browser holds
// after login (PR2) is attached per request through a middleware there; PR1
// wires only the base URL from the deployment config.
export function createManagementClient(): ManagementClient {
  const config = loadConfig();
  return createClient<paths>({
    baseUrl: config.managementBase || "/",
  });
}

// Map an unknown non 2xx body to the verbatim ErrorBody the management API
// documents, falling back to a generic shape when the body is absent or does
// not parse. PR1 stub: the UI renders `error` and `message` as the server
// worded them (verbatim), never a client invented string.
export function toErrorBody(body: unknown): ErrorBody {
  const obj = (body ?? {}) as Record<string, unknown>;
  const error = typeof obj.error === "string" ? obj.error : "unknown_error";
  const message =
    typeof obj.message === "string"
      ? obj.message
      : "The request could not be processed.";
  return { error, message };
}
