# ironauth-hooks changelog

All notable changes to the `ironauth-hooks` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- **The hook runtime has a caller (issue #114).** `LoadedHook::customize` had zero: the engine,
  the deny-by-default sandbox, the four resource bounds, the WIT interface and a latency
  benchmark all shipped, and no hook had ever customized a token. `ironauth-oidc` now runs a
  deployed component at the same seam the declarative mapping uses.
- **A `testing` feature exporting the guest fixtures as bytes.** The build script hands each
  artifact's path to this crate alone, so only this crate can `include_bytes!` one -- and the
  test that matters drives a real component through a real issuance, which happens in
  `ironauth-oidc`. Feature-gated because these are test data: a claim-shaping guest compiled into
  the server would be several hundred kilobytes of WASM nothing executes.
- **A `claim-forger` guest fixture**, which returns `sub` and `iss`. The fence on what a hook
  RETURNS had no guest that exercised it, so replacing `filter_hook_claims` with an identity
  function left every test green.
