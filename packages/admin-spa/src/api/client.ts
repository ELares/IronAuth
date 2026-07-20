// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The ONE module in the admin console that performs a network call. Every
// request goes through here: the typed openapi-fetch management client, plus the
// two OIDC public endpoints the login needs (discovery and the token exchange).
// The route audit (scripts/admin-spa-route-audit.sh) is the structural
// guarantee: it fails if any other module performs a network call or names a
// server path, and it checks that every path this app can reach maps to a
// documented management operation or the small OIDC public allowlist.
//
// The management client is typed by the generated management contract
// (management.gen.ts), so a call can only target a path and method the public
// management API documents. A per request middleware attaches the in memory
// bearer (src/auth/session.ts); nothing here ever holds an operator token or a
// management key, so the only credential the browser sends is the short lived
// at+jwt from the OIDC login.

import createClient from "openapi-fetch";
import type { components, paths } from "./management.gen";
import { loadConfig } from "../config";
import { getAccessToken } from "../auth/session";

// The verbatim structured error body every management endpoint returns. Kept as
// a re-export of the generated schema so the UI never hand maintains the shape.
export type ErrorBody = components["schemas"]["ErrorBody"];

export type ManagementClient = ReturnType<typeof createClient<paths>>;

// Build the single typed management client. Every request carries the in memory
// bearer (when signed in), attached through the middleware below; the base URL is
// the same origin management proxy (or a standalone management origin) from
// config. The generated types confine the reachable paths to the documented API.
export function createManagementClient(): ManagementClient {
  const config = loadConfig();
  const client = createClient<paths>({ baseUrl: config.managementBase || "/" });
  client.use({
    onRequest({ request }) {
      const token = getAccessToken();
      if (token !== null) {
        request.headers.set("authorization", `Bearer ${token}`);
      }
      return request;
    },
  });
  return client;
}

// The subset of the OIDC discovery document the login uses. Both endpoints are
// absolute URLs the server publishes; the app never hardcodes them.
export interface OidcDiscovery {
  authorization_endpoint: string;
  token_endpoint: string;
}

// Fetch the admin issuer's discovery document. `issuer` is runtime config (a same
// origin path in the embedded deploy, an absolute issuer URL in a standalone
// deploy), so the only path literal here is the allowlisted well known suffix.
export async function discoverOidc(issuer: string): Promise<OidcDiscovery> {
  const response = await fetch(`${issuer}/.well-known/openid-configuration`, {
    headers: { accept: "application/json" },
  });
  if (!response.ok) {
    throw new Error(`OIDC discovery failed: ${response.status}`);
  }
  return (await response.json()) as OidcDiscovery;
}

// A minimal token endpoint response for the Authorization Code + PKCE exchange.
export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  scope?: string;
}

// Exchange an authorization code (with the PKCE verifier) for an access token at
// the discovered token endpoint. `tokenEndpoint` is the absolute URL from
// discovery, never a literal. No client secret is sent: the console is a public
// client, so the PKCE verifier is the proof.
export async function exchangeCode(
  tokenEndpoint: string,
  params: URLSearchParams,
): Promise<TokenResponse> {
  const response = await fetch(tokenEndpoint, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body: params.toString(),
  });
  if (!response.ok) {
    throw new Error(`token exchange failed: ${response.status}`);
  }
  return (await response.json()) as TokenResponse;
}

// Map an unknown non 2xx body to the verbatim ErrorBody the management API
// documents, falling back to a generic shape when the body is absent or does
// not parse. The UI renders `error` and `message` as the server worded them
// (verbatim), never a client invented string.
export function toErrorBody(body: unknown): ErrorBody {
  const obj = (body ?? {}) as Record<string, unknown>;
  const error = typeof obj.error === "string" ? obj.error : "unknown_error";
  const message =
    typeof obj.message === "string"
      ? obj.message
      : "The request could not be processed.";
  return { error, message };
}
