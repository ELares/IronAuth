<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# IronAuth admin console (admin SPA)

The admin console is a Preact single page app that manages an IronAuth
deployment by speaking the PUBLIC management API through one generated, typed
client. It is served two ways from the same build: EMBEDDED in the single
IronAuth binary (the default operator experience), and STANDALONE as static
assets pointed at a configured management base.

This is PR1 of issue #90: the FOUNDATION only. The app ships as a static shell
(an app frame with nav placeholders and a "not signed in" placeholder). There is
NO real auth yet: performing the OIDC login, holding the bearer token, attaching
it to the typed client, and the same origin management proxy all land in PR2.

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
npm run build     # vite build -> dist/ (content hashed external assets)
```

Dependencies are kept to a tight budget. Prod: `preact`, `@preact/signals`
(UI state), `preact-iso` (routing), `openapi-fetch` (the one network client).
Everything else (`typescript`, `vite`, `@preact/preset-vite`,
`openapi-typescript`) is a dev dependency.

## Layout

- `src/api/client.ts`: the one module that performs a network call (audited).
- `src/api/management.gen.ts`: the generated management contract (committed).
- `src/config.ts`: reads the issuer and management base from `<meta>` tags.
- `src/app.tsx`: the app shell (nav placeholders, the sign in placeholder).
- `src/main.tsx`: the Preact entry point.
- `src/style.css`: the one external stylesheet.
- `vite.config.ts`: the CSP clean, `/admin/` based build config.
