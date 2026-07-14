# ironauth-store fuzzing

A cargo-fuzz harness over the redirect-URI comparator and registrability rule
(issue #13), `ironauth_store::redirect_uri_matches` and
`ironauth_store::redirect_uri_is_registrable`. These two pure functions are the
whole redirect-matching policy, and a single accepted bypass is an open
redirector, so they are worth fuzzing continuously.

The target (`redirect_match`) splits its input on the first NUL into two
candidate URIs and proves: neither function panics on any input; matching is
reflexive and symmetric; and a match between two DIFFERENT strings is ONLY ever
the RFC 8252 loopback port exception (both sides `http`), never a wildcard,
substring, case-fold, or normalization bypass.

This crate is intentionally **not** a workspace member (its `Cargo.toml` carries
an empty `[workspace]` table). libFuzzer needs a nightly toolchain and must not
constrain the stable workspace, and keeping it detached also keeps its
`libfuzzer-sys` dependency out of the `cargo-deny` graph. This is the same
pattern the repository's root `fuzz/` crate, `ironauth-jose/fuzz/`, and
`ironauth-fetch/fuzz/` use.

## Running locally

```
cargo install cargo-fuzz
cd crates/ironauth-store/fuzz
cargo +nightly fuzz run redirect_match
```

## Seed corpus

`corpus/redirect_match/` is seeded from representative pairs: an identical
https redirect, a loopback IP-literal pair that differs only in the port (the
one accepted deviation), and a userinfo-smuggling pair that must stay rejected.
Continuous fuzzing should persist and grow this corpus.

## Stable, in-CI coverage of the same input space

The same adversarial input space is covered on every build by the unit tests in
`crates/ironauth-store/src/redirect.rs`: the CVE regression corpus
(`cve_corpus_no_accepted_bypasses`, the wildcard / substring / case /
normalization / encoding classes) and the loopback-exception cases. The
scheduled nightly fuzz lane is `.github/workflows/fuzz.yml`.
