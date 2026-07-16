# ironauth-importers fuzzing

A cargo-fuzz harness with one target per vendor export parser
(`keycloak`, `auth0`, `firebase`, `scim`, `ldap`). Each target drives arbitrary
input at the corresponding `map_*` entry point and proves:

- the parser never panics on any input (malformed vendor JSON included), and
- memory stays bounded: parsing goes through `serde_json`, whose default
  128-level recursion limit rejects a deeply nested document rather than
  overflowing the stack, and no importer allocates beyond the input size.

This crate is intentionally **not** a workspace member (its `Cargo.toml` carries
an empty `[workspace]` table). libFuzzer needs a nightly toolchain and must not
constrain the stable workspace, and keeping it detached also keeps its
`libfuzzer-sys` dependency out of the `cargo-deny` graph. This is the same
pattern `ironauth-jose/fuzz/`, `ironauth-store/fuzz/`, `ironauth-fetch/fuzz/`,
and the sibling Iron projects use.

## Running locally

```
cargo install cargo-fuzz
cd crates/ironauth-importers/fuzz
cargo +nightly fuzz run keycloak     # or auth0 / firebase / scim / ldap
```

## Seed corpus

Each `corpus/<target>/` is seeded from the committed sanitized fixture for that
source, so the fuzzer starts from a structurally valid export and mutates
outward. The same input space also has stable, in-CI coverage in each importer
module's unit tests and the fixture integration suites.
