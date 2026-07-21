<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# IronAuth admin console (admin SPA)

The admin console is a Preact single page app that manages an IronAuth
deployment by speaking the PUBLIC management API through one generated, typed
client. It is served two ways from the same build: EMBEDDED in the single
IronAuth binary (the default operator experience), and STANDALONE as static
assets pointed at a configured management base.

Progress on issue #90:

- PR1 was the FOUNDATION: a static shell (an app frame with nav placeholders),
  the one typed client, the route audit covenant, and in process serving.
- PR2 wired the real login: the Authorization Code + PKCE flow against the admin
  issuer, the short lived at+jwt held in memory, and the bearer attached to the
  typed client.
- PR3 (this change) is the app SHELL: the real console frame (header, sidebar
  nav of the resource sections, routed placeholder views), the persistent
  tenant/environment CONTEXT SWITCHER that scopes every view, a keyboard COMMAND
  PALETTE, and the verbatim management ErrorBody rendering boundary.

The CRUD content of each resource section lands in PR4 through PR6.

## The context switcher and the single environment collapse

The tenant/environment switcher (`src/ui/Switcher.tsx`) is the SINGLE source of
the active scope every resource view reads. It populates from `listTenants` and
`listEnvironments` through the one typed client (`src/scope/store.ts`), and every
scoped management call injects the selected `{tenant_id, environment_id}` into its
path parameters inside the one typed client wrapper (`src/api/client.ts`), the
only place a path is formed. The selection persists
in `sessionStorage` for reload continuity; the bearer token never does (it stays
in memory only).

The COLLAPSE is a hard rule: when the resolved tenant has exactly one environment
and the principal has no cross-tenant reach, the switcher renders NO chrome at
all. The scope is implicit and the homelab operator sees zero ceremony. The
decision is the pure, unit tested `shouldCollapseSwitcher`.

## The command palette

`src/ui/CommandPalette.tsx` is a hand built (no new runtime dependency) palette
opened with Cmd or Ctrl K. It is an ARIA combobox: focus is trapped on the search
input, the active option is tracked with `aria-activedescendant`, and
ArrowUp/ArrowDown move the selection, Enter runs it, and Escape closes and
restores focus. It is driven ONLY by data the one typed client already loaded
(the nav sections plus the tenants and environments the store holds), so it names
no new endpoint.

## The verbatim ErrorBody boundary

`src/ui/ErrorView.tsx` renders the management `ErrorBody` the one client
surfaced, VERBATIM: `error` and `message` always, plus `actual_scope`,
`expected_scope`, and `failed_guardrails` when present, with no rewording and no
swallowing (API and SPA users see identical errors). Every value is rendered as
TEXT, escaped by Preact by construction, so a hostile looking message is inert;
the component uses no `dangerouslySetInnerHTML`. A `max_age` bearing error is the
RFC 9470 sudo challenge (issue #73): the boundary offers a re-authentication
(the PR2 login re-run with `max_age` and `prompt=login`), then a sudo elevation,
then a retry of the mutation. That sequence is dependency injected and unit
tested; its live end to end continuity across the redirect login is verified
under the runtime embed (issue #323).

## The one rule: public management API only

Every network call funnels through `src/api/client.ts`, the single module that
holds an `openapi-fetch` client typed by the generated management contract. No
other module may perform a network call, import the network library, or name a
server API path. `scripts/admin-spa-route-audit.sh` enforces this structurally:
it fails CI if any other module calls a network sink or imports `openapi-fetch`,
if any absolute URL is hardcoded (the issuer and management bases are runtime
config, never a literal), and if any management API path the app names is not
documented in `docs/openapi/management.json`. A small allowlist of OIDC public
endpoints (`/authorize`, `/token`, `/.well-known/openid-configuration`,
`/end_session`) is declared for the PR2 login module to draw on.

## How it binds the contract

The app does not hand maintain the request and response shapes.
`src/api/management.gen.ts` is GENERATED from `docs/openapi/management.json` by
`openapi-typescript` (`npm run codegen`) and is committed. A CI freshness gate
(`scripts/admin-spa-bindings.sh`) regenerates it and fails if the committed
client drifts, so the console and the served management contract can never
diverge. The generated `paths` type is what makes the one `openapi-fetch` client
reject an undocumented path or method at compile time.

## Embedded and standalone

The build is served two ways:

- EMBEDDED. The Rust crate `crates/ironauth-admin-ui` embeds the built `dist/`
  with `rust-embed` and mounts it on the PUBLIC plane under `/admin`, behind the
  `admin_spa.enabled` config flag (DEFAULT OFF while this is a skeleton; a later
  change flips it on once the console is functional). While off, every `/admin`
  path is a uniform 404. The Vite `base` is `/admin/` so every built asset URL is
  prefixed to match the mount.
- STANDALONE. The same app builds to static assets you host yourself, pointed at
  a management base through the `<meta>` tags in `index.html` (like the
  reference app in `../reference-app`). Rebuild with Vite `base: "/"` if you
  serve it at a site root.

Config is read from `<meta>` tags by `src/config.ts`: `ironauth-issuer` (the
public plane base) and `ironauth-management-base` (where the management API is
reached). Both empty means same origin, which is the embedded deploy.

## Content Security Policy

The embedded console is served with its OWN CSP (see
`crates/ironauth-admin-ui`), separate from the strict auth-page CSP of issue #89:

```
default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; object-src 'none'; frame-ancestors 'none'
```

There is no `unsafe-inline`. The Vite build is configured to emit only content
hashed, EXTERNAL script and stylesheet assets (no inline `<script>` or `<style>`,
the module preload polyfill disabled, assets never inlined), so the policy holds
with `script-src 'self'` and `style-src 'self'`. A standalone deploy MUST serve
an equivalent CSP from its own static host.

## The embedded dist in PR1

`crates/ironauth-admin-ui` embeds a committed placeholder shell
(`crates/ironauth-admin-ui/embedded/index.html`) so `cargo build` is green
WITHOUT a Node toolchain and never needs the (gitignored) `dist/`. The real Vite
`dist/` is produced by the CI `admin-spa` job and by `npm run build` locally; a
later change wires the embed to the real build output. Because the flag defaults
off, nothing is served in production regardless.

## Toolchain

Node 20, npm. `package-lock.json` is committed; CI installs with `npm ci`.

```sh
cd packages/admin-spa
npm ci            # or npm install to refresh the lockfile
npm run codegen   # regenerate src/api/management.gen.ts from the management spec
npm run typecheck # tsc --noEmit, strict
npm test          # vitest run (unit and component tests, jsdom)
npm run build     # vite build -> dist/ (content hashed external assets)
```

Dependencies are kept to a tight budget. Prod (unchanged in PR3): `preact`,
`@preact/signals` (UI state), `preact-iso` (routing), `openapi-fetch` (the one
network client). Everything else is a dev dependency: `typescript`, `vite`,
`@preact/preset-vite`, `openapi-typescript`, and the test runner `vitest` with
`jsdom`.

## Layout

- `src/api/client.ts`: the one module that performs a network call (audited);
  holds the typed list and elevate wrappers and the verbatim `ErrorBody` mapping.
- `src/api/management.gen.ts`: the generated management contract (committed).
- `src/config.ts`: reads the issuer and management base from `<meta>` tags.
- `src/app.tsx`: the app shell (header, nav, routed views, error boundary wiring).
- `src/scope/logic.ts`: the pure scope logic (collapse, scope injection).
- `src/scope/store.ts`: the signal backed active scope (the single source).
- `src/ui/Switcher.tsx`: the tenant/environment context switcher.
- `src/ui/CommandPalette.tsx` and `src/ui/commands.ts`: the command palette.
- `src/ui/ErrorView.tsx`: the verbatim management `ErrorBody` boundary.
- `src/ui/sections.ts`: the resource sections shared by the nav and the palette.
- `src/auth/sudo.ts`: the RFC 9470 sudo re-authentication orchestration.
- `src/main.tsx`: the Preact entry point.
- `src/style.css`: the one external stylesheet.
- `vite.config.ts`: the CSP clean, `/admin/` based build config.
- `vitest.config.ts`: the jsdom test config; tests live under `test/`.
