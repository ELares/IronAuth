# packages

TypeScript artifacts live here: the pure-WebCrypto SDK core, framework SDKs,
the admin SPA, and hosted pages. They arrive with milestones M9 (hosted pages,
admin SPA) and M12 (SDKs).

- `reference-app/` (issue #85, M9): the standalone forkable hosted-pages app. It
  renders the published headless flow contract over the public flow API only and
  runs OUTSIDE the IronAuth binary against a configured issuer. See its README
  for the fork workflow.

The first real TypeScript CI lane lands with `reference-app`: `ci.yml` builds and
typechecks it (`tsc`, no bundler), and `scripts/route-audit.sh` plus
`scripts/reference-app-bindings.sh` run as static checks in the `invariants`
lane. Earlier a lint lane over zero packages was deferred on purpose (it would
assert nothing while still being able to rot); the per-artifact release and
changelog discipline in docs/RELEASING.md already covers these artifacts by name,
so nothing about the scheme changes as they land. This app is a SEPARATE
deployable and is deliberately NOT part of the Rust release pipeline.
