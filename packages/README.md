# packages

TypeScript artifacts live here: the pure-WebCrypto SDK core, framework SDKs,
the admin SPA, and hosted pages. They arrive with milestones M9 (hosted pages,
admin SPA) and M12 (SDKs).

The CI lane for TypeScript (lint, test, per-package release) lands together
with the first real package rather than now: a lint lane over zero packages
would assert nothing while still being able to rot. This is a deliberate,
documented deviation from the M1 scaffold issue's letter; the per-artifact
release and changelog discipline in docs/RELEASING.md already covers these
artifacts by name so nothing about the scheme changes when they land.
