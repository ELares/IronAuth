<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# IronAuth admin console

The console is a Preact single page application that administers IronAuth through
one generated, typed client of the public management API. It includes Overview,
Tenants, Environments, Clients, Users, Connectors, Organizations, Permissions,
Invitations, and Diagnostics, with detail panels for credentials, memberships,
roles, group hierarchy, and flow inspection.

Read the [admin console guide](../../docs/ADMIN-CONSOLE.md) for deployment,
sign-in prerequisites, page operations, and current limitations. This README
describes the frontend's development and integration contract.

## Toolchain and commands

Use Node **22.22.2 or later on 22.x**, **24.15.0 or later on 24.x**, or **26 and
newer**, with npm. These release lines and minimums match the locked Vitest 5 and
jsdom requirements and the `engines.node` value in `package.json`. Node 20, 23,
and 25 are not supported by the current dependency set. `package-lock.json` is
committed; reproducible installs use `npm ci`.

```sh
cd packages/admin-spa
npm ci
npm run typecheck
npm test
npm run build
```

`npm run codegen` regenerates `src/api/management.gen.ts` from
`docs/openapi/management.json` when the management contract changes. Tests use
Vitest and jsdom; a production build uses Vite and writes `dist/` with hashed
external scripts and stylesheets.

Run frontend contract checks from the repository root:

```sh
scripts/admin-spa-route-audit.sh
scripts/admin-spa-bindings.sh
scripts/admin-spa-embed.sh
```

The embed check installs/builds the SPA, replaces the committed embedded assets,
and fails when the resulting tree differs. After an intentional frontend change,
review and commit those generated assets with the source change. The complete
repository gate remains `scripts/gate.sh`; see [CONTRIBUTING](../../CONTRIBUTING.md).

## Embedded deployment

`crates/ironauth-admin-ui` embeds the **real built console**, committed under
`crates/ironauth-admin-ui/embedded/`. A normal `cargo build` includes it without
requiring Node or a preexisting frontend `dist/`. The embed freshness check
prevents the committed bundle from drifting from the SPA source.

Set `admin_spa.enabled = true` to mount the console on the public plane at
`/admin/`; the default remains `false`, and disabled paths return 404. The server
injects issuer/client/audience metadata at request time, with HTML attribute
escaping. It serves existing embedded assets, falls back to `index.html` for
browser routes, and returns a real 404 for missing static assets.

The default management base is `/admin/api`. That same-origin proxy forwards the
method, headers, query, and body to the in-process management router. It adds no
privileged credential. The proxy needs a configured OIDC bridge and mounted
management plane; enabling only the console shell does not expose the proxy.

## Runtime configuration and standalone hosting

`src/config.ts` reads these public, nonsecret metadata values:

| Meta tag | Purpose | Empty value |
| --- | --- | --- |
| `ironauth-issuer` | Public-plane base available to the client. | Same origin. |
| `ironauth-management-base` | Base of the documented management API/proxy. | `/admin/api`. |
| `ironauth-admin-issuer` | OIDC issuer of the administrator system environment. | Sign-in unavailable. |
| `ironauth-console-client-id` | Public OAuth client identifier for PKCE sign-in. | Sign-in unavailable. |
| `ironauth-management-audience` | Exact resource audience required by the management bridge. | Resource omitted by the browser; a configured management bridge still requires its audience. |

In embedded deployments the server supplies the last three values when OIDC and
the admin issuer/audience bridge are configured; the first two stay empty for
same-origin operation. The configuration reference is generated from
[`AdminSpaConfig`](../../crates/ironauth-config/src/lib.rs).

You can also serve the production `dist/` from your own static host. Keep the
`/admin/` mount and Vite's default `base: "/admin/"`: the current login callback is
always `${window.location.origin}/admin/`. Configure SPA fallback for that mount,
populate the metadata with your admin issuer, client ID, audience, and management
proxy base, and register that exact callback on the issuer. Serving at the site
root requires changing the login callback and routing/build configuration;
changing Vite's base alone is insufficient.

Provide an appropriate CSP on the static host. Prefer a same-origin reverse
proxy for the issuer and management API. Cross-origin targets additionally need
the server's origin policy and the host's `connect-src` to permit discovery,
token exchange, and management calls; the default embedded CSP allows only
`'self'`. The development build does not provision issuer resources or an
administrator automatically.

## Authentication and scope

The console authenticates with Authorization Code + S256 PKCE against the
configured admin issuer, requesting `openid ironauth.manage` and the management
resource audience. PKCE verifier/state are temporary redirect state in
`sessionStorage`; callback processing consumes them and clears code/state from
the address bar. The resulting short-lived bearer is held **in memory only** by
`src/auth/session.ts`. No bootstrap operator token, client secret, or management
key belongs in the frontend metadata.

The server verifies the issuer, audience, token, management scope, and configured
operator-subject allowlist. Browser login currently resolves only to an operator;
the API's delegated management-key personas are not console login roles. The
console sign-out control clears the local token and context without ending the
issuer's SSO session. The RFC 9470 recovery orchestration wires re-authentication,
scope-bound sudo elevation, and mutation retry after a freshness challenge.
However, the real login performs a full-page redirect: the retry closure and
draft are not persisted or resumed by callback processing. Users must return to
the operation and re-enter the action after sign-in; the orchestration's unit
tests alone do not establish automatic browser redirect continuity.

The current SPA's code exchange does **not** send DPoP proofs, while public
clients require DPoP by default. Console setup therefore includes the explicit
per-client exception through the management API, from an authorized operator
client:

```text
PUT /v1/tenants/{tenant_id}/environments/{environment_id}/clients/{client_id}/bearer-tokens
```

```json
{"allowed":true}
```

Use this console client's ID in the admin issuer's scope. The write requires
configuration authority and the applicable sudo freshness. It permits replayable
unbound bearer tokens for this client until their expiry, while other public
clients keep their DPoP requirement. The browser still receives no operator
credential. If issuer sign-in succeeds but token exchange fails, check this
allowance as well as the exact client/callback and resource audience. Provision
the client through DCR and resource servers through the supported
[snapshot/promotion workflow](../../docs/snapshot/README.md); there is no generic
management API create-client or create-resource-server operation.

`src/scope/store.ts` is the single source for active tenant/environment selection.
It loads reachable resources through the typed client and persists only the
selected IDs in `sessionStorage`. Views inject those IDs into the documented
operation's path parameters through the client wrappers. A single loaded tenant
and environment collapse the context selector. Scoped views make no calls when
their required context is absent.

## Resource and navigation behavior

Resource pages prioritize lists. `ResourceCreateAction` opens a native modal only
after an explicit action; creation forms are not mounted while closed. Cancel or
Escape discards the draft and restores trigger focus, except while a submitted
mutation is pending. Successful writes close the dialog and preserve confirmation
or one-time credential output in the surrounding page. `ConfirmButton` provides
an explicit confirmation step for destructive and lifecycle actions.

The command palette opens from the header search control or Cmd/Ctrl+K and uses
only loaded navigation/context data. It supports keyboard selection, Escape
cancellation, and focus restoration. Local list filtering searches loaded rows
only, not the complete server inventory. Cursor-based panels show when more
results exist but do not implement full cursor navigation. The guide describes
the initial-page limitation of other list wrappers as well.

The responsive shell includes grouped navigation, current-page state, a
narrow-screen navigation toggle, a skip link, labeled controls, and route-change
focus management. Accessibility behaviors are covered by component tests; no
certification claim is made.

## Public management API contract

All network calls funnel through `src/api/client.ts`, which uses `openapi-fetch`
with the generated management `paths` type. Every management path/method must
exist in the committed [OpenAPI document](../../docs/openapi/management.json).
The route audit forbids network calls and network-client imports outside the
funnel, hardcoded absolute URLs, and undocumented management paths. OIDC public
endpoints have a small explicit allowlist for login integration.

`scripts/admin-spa-bindings.sh` checks generated type freshness. Add an
administrative capability to the public API and its OpenAPI contract before
exposing it in a view. Do not introduce private browser-only management endpoints
or reach past the management plane.

The `ErrorView` boundary renders API `ErrorBody` fields verbatim as escaped text:
`error`, `message`, and any supplied scope, guardrail, or freshness details. It
never injects those values as HTML. Client wrappers also reject bodyless non-2xx
responses; a failed list request must not appear as an empty successful list.

## Content Security Policy

The embedded console has its own policy, distinct from the authentication pages:

```text
default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'
```

Vite emits external assets without inline scripts/styles, disables the module
preload polyfill, and does not inline build assets. The policy does not require
`unsafe-inline`. A standalone host must set its own policy and adjust allowed
connections to its actual deployment topology.

## Source layout

| Location | Responsibility |
| --- | --- |
| `src/api/client.ts` | Audited network funnel, typed operation wrappers, errors. |
| `src/api/management.gen.ts` | Generated, committed management contract. |
| `src/config.ts` | Runtime metadata parsing. |
| `src/app.tsx`, `src/ui/routing.ts` | Authentication shell and `/admin` browser routes. |
| `src/auth/` | PKCE login, in-memory session, sudo recovery. |
| `src/scope/` | Selected scope, loaded tenant/environment state, collapse rules. |
| `src/ui/useResource.ts` | Explicit read/write state and mutation retry. |
| `src/ui/ResourceView.tsx` | Resource headings, filters, creation dialogs, confirmations. |
| `src/ui/*View.tsx` | Management pages and resource/detail panels. |
| `src/ui/CommandPalette.tsx`, `commands.ts`, `sections.ts` | Shared navigation and palette data. |
| `src/style.css` | External stylesheet for the shell and resource views. |
| `test/`, `vitest.config.ts` | Unit/component tests in jsdom. |
| `vite.config.ts` | Production assets, CSP constraints, `/admin/` build base. |
