# ironauth-env changelog

All notable changes to the `ironauth-env` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- Initial determinism seam: `Clock` and `Entropy` traits, `SystemClock`,
  `OsEntropy`, `ManualClock`, `FixedEntropy`, and the `Env` capability bundle.
