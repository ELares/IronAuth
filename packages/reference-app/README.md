<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# IronAuth hosted pages: the standalone reference app

This is the forkable half of IronAuth's hosted pages (issue #85). IronAuth
serves complete, branded sign in pages in process from the single binary; those
pages are server rendered Rust. This package is the escape hatch for an operator
who wants a fully custom single page app instead: a small, dependency light
TypeScript app that renders the SAME headless flow contract by speaking ONLY the
public flow API.

It runs OUTSIDE the IronAuth binary as a separate deployable, pointed at a
configured issuer URL. Hosted vs custom is a fork, not a rewrite.

## What it is (and is not)

- It is a PURE CLIENT. The IronAuth server is the source of truth for the flow
  contract and for ALL security. This app renders and submits; it enforces
  nothing. A malicious fork of it cannot bypass any server gate, because the
  server validates every submission.
- It carries NO secret. The flow API is a public client protocol: a submission
  is authenticated with the per flow submit token the server issued, never a
  client secret. Nothing in this browser app is confidential.
- It renders GENERICALLY from the contract. The renderer dispatches on each
  node's typed attributes (`node_type`, then `input_type` and `group`), never on
  the journey, so login, registration, MFA challenge and enrollment, recovery,
  and federation all render from the same code. A new auth method that adds a new
  node group renders with no code change (the same forward compatibility the
  server side renderer has).
- It talks to public endpoints ONLY. Every network call goes through `src/api.ts`
  and targets a path declared in `src/endpoints.ts`, which is diffed in CI
  (`scripts/route-audit.sh`) against the server's `FLOW_*_PATH` constants plus
  the documented public session endpoints. A fork cannot point it at a private
  or management endpoint without failing that gate.

## How it binds the contract

The app does not hand maintain the flow object shape. `src/contract/flow.gen.ts`
(TypeScript types plus schema derived validation constants) and
`src/contract/messages.gen.ts` (the numeric message id to copy fallback map) are
GENERATED from the published artifacts `docs/flow-schema.json` and
`docs/flow-messages.json` by `scripts/gen-reference-app-bindings.py`. A CI
freshness gate (`scripts/reference-app-bindings.sh`) fails if the committed
bindings drift from those artifacts, so the app and the server can never diverge
on the object shape or the message copy. Run `npm run codegen` to regenerate them
after the contract changes.

Copy is keyed on the stable numeric message id, never on the default text. That
is the localization seam: a fork localizes by passing a locale overrides map to
`Copy` in `src/messages.ts`, without touching any render logic.

## Fork workflow

1. Fork this package (copy `packages/reference-app` into your own repository, or
   fork the monorepo and keep this directory).

2. Install the toolchain and build:

   ```sh
   cd packages/reference-app
   npm install
   npm run build
   ```

   `npm run build` runs `tsc`, which typechecks and emits plain ES modules to
   `dist/`. There is no bundler and no runtime dependency: `dist/main.js` loads
   directly in the browser.

3. Point it at your issuer. Edit the `<meta>` tags in `index.html` (or have your
   deploy step inject them):

   ```html
   <meta name="ironauth-issuer" content="https://auth.example.com" />
   <meta name="ironauth-tenant" content="your-tenant" />
   <meta name="ironauth-environment" content="your-environment" />
   <meta name="ironauth-journey" content="login" />
   ```

   Leave `ironauth-issuer` empty to call the same origin (a first party deploy
   behind the IronAuth server). The `journey` can also be set per load with a
   `?journey=registration` query parameter.

4. Deploy `index.html` plus the `dist/` directory as static assets on any host.
   The app makes only same document navigations and `fetch` calls to the
   configured issuer; there are no other external hosts.

## Customizing

- Styling: edit the `<style>` block in `index.html` or the class names the
  renderer emits (`flow-node`, `flow-label`, `flow-message-*`, `flow-group-*`).
- Localization: pass a `{ [messageId]: string }` overrides map to `new Copy(...)`
  in `src/messages.ts`.
- Rendering: `src/render.ts` is the one place that turns a flow node into DOM.
  Keep the safe rendering rule if you change it: server supplied strings are
  written with `textContent` or as DOM attribute values, NEVER assigned to
  `innerHTML`, so server data can never become markup.

## Layout

- `src/endpoints.ts`: the only module that names a server path (audited).
- `src/api.ts`: the only module that performs a network call (audited).
- `src/render.ts`: the generic, contract driven renderer.
- `src/messages.ts`: the id keyed copy and localization seam.
- `src/validate.ts`: a lightweight structural guard, driven by the generated
  schema constants.
- `src/config.ts`: reads the issuer and scope from `index.html`.
- `src/main.ts`: the create, render, submit, continue loop.
- `src/contract/*.gen.ts`: generated from the published contract (committed).
