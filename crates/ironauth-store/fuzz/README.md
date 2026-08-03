# ironauth-store fuzzing

Two targets live here: `redirect_match` over the redirect-URI comparator, and
`canonicalize_identifier` over the identifier canonicalization seam.

## `redirect_match`

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
one accepted deviation), a userinfo-smuggling pair that must stay rejected, and
`seed_multibyte_prefix_boundary`, the input that crashed the nightly lane (a
candidate whose byte 7 falls inside a multi-byte character, which the http-prefix
strip used to slice through). Continuous fuzzing should persist and grow this
corpus; a reproducer for a fixed crash belongs here, since `artifacts/` is
scratch and is not committed.

## `canonicalize_identifier`

A harness over `ironauth_store::identifier::canonicalize_identifier` (issue #54),
the single seam every login-identifier comparison and uniqueness check routes
through. It proves the function is TOTAL (never panics on any byte string, fed
lossily as text) and IDEMPOTENT for all three identifier kinds.

### Seed corpus

`corpus/canonicalize_identifier/` had NO seeds until the branding sanitizer's
idempotence defect prompted an audit of every target asserting that property.
A target with an empty corpus starts each nightly run from zero, and byte-level
mutation reaches an interesting Unicode sequence rarely, so "the fuzzer has never
complained" said very little about this function. The seeds now cover the classes
that make canonicalization non-trivial: a mixed-case email, invisible padding, a
fullwidth homoglyph, E.164 separators, the full case-fold EXPANSIONS (the sharp s
and the `ﬀ` ligature, whose folds are sequences rather than single characters),
the Greek sigma and iota-subscript cases, compatibility singletons (OHM SIGN,
KELVIN SIGN, the squared and ligature forms), default-ignorable fillers, a
bidirectional override, and a shapeless all-`@` value.

The property itself was verified DIRECTLY rather than left to the fuzzer: an
exhaustive sweep of all 1,112,064 Unicode scalar values plus 1,000,000
pseudorandom sequences, canonicalized twice for each kind, found zero
divergences. The seeds exist so a future change to the folding steps has a
running start at breaking that.

## Stable, in-CI coverage of the same input space

The same adversarial input space is covered on every build by the unit tests in
`crates/ironauth-store/src/redirect.rs`: the CVE regression corpus
(`cve_corpus_no_accepted_bypasses`, the wildcard / substring / case /
normalization / encoding classes) and the loopback-exception cases. The
scheduled nightly fuzz lane is `.github/workflows/fuzz.yml`.
