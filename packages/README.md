# packages

TypeScript artifacts live here: the pure-WebCrypto SDK core, framework SDKs,
the admin SPA, and hosted pages. They arrive with milestones M9 (hosted pages,
admin SPA) and M12 (SDKs).

- `reference-app/` (issue #85, M9): the standalone forkable hosted-pages app. It
  renders the published headless flow contract over the public flow API only and
  runs OUTSIDE the IronAuth binary against a configured issuer. See its README
  for the fork workflow.
- `admin-spa/` (issue #90, M9): the admin console, a Preact + TypeScript (Vite)
  single page app that manages a deployment over the PUBLIC management API
  through one generated typed client. It is served two ways from one build:
  EMBEDDED in the binary (crate `ironauth-admin-ui`, mounted under `/admin`
  behind the default-off `admin_spa.enabled` flag) and STANDALONE against a
  configured management base. This is the repo's first npm prod dependency tree
  (`package-lock.json` committed, CI uses `npm ci`). See its README for the
  public-API-only rule, the codegen and route-audit gates, the embed/standalone
  duality, and the console CSP. PR1 is the skeleton (a static shell, no auth yet);
  auth dogfooding lands in PR2.

The first real TypeScript CI lane lands with `reference-app`: `ci.yml` builds and
typechecks it (`tsc`, no bundler), and `scripts/route-audit.sh` plus
`scripts/reference-app-bindings.sh` run as static checks in the `invariants`
lane. The `admin-spa` app adds an `admin-spa` job (`npm ci`, codegen freshness,
`tsc` typecheck, `vite build`), with its route audit
(`scripts/admin-spa-route-audit.sh`) in the `invariants` lane. Earlier a lint lane over zero packages was deferred on purpose (it would
assert nothing while still being able to rot); the per-artifact release and
changelog discipline in docs/RELEASING.md already covers these artifacts by name,
so nothing about the scheme changes as they land. This app is a SEPARATE
deployable and is deliberately NOT part of the Rust release pipeline.
