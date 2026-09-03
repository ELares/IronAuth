# ironauth-saml fuzzing

Three cargo-fuzz targets, one per path issue #138 names: `saml_parse` (the XML
parse), `saml_canonicalize` (exclusive canonicalization), and `saml_verify`
(signature verification). All three read bytes an unauthenticated party posts to
an assertion consumer service.

This crate is intentionally **not** a workspace member (its `Cargo.toml` carries
an empty `[workspace]` table). libFuzzer needs a nightly toolchain and must not
constrain the stable workspace, and keeping it detached also keeps its
`libfuzzer-sys` dependency out of the `cargo-deny` graph. Same pattern as the
root `fuzz/` crate and the sibling per-crate harnesses.

## Running locally

```
cargo install cargo-fuzz
cd crates/ironauth-saml/fuzz
cargo +nightly fuzz run saml_parse
```

## What each target asserts, and what a fuzzer cannot reach

A fuzzer cannot forge a signature, so it cannot explore the ACCEPT path. What it
can do is prove the accept path is unreachable without the key, and that is what
`saml_verify` asserts: the anchors it pins signed nothing, so any `Ok` at all is
a finding. One assertion covers every bypass class -- wrapping, a skipped digest
comparison, an algorithm confusion, a canonicalization collision -- because each
of them ends in an `Ok` the pinned key did not authorise.

The accept path is covered instead by `tests/wrapping.rs`, where every document
starts from a genuinely valid signature. Neither substitutes for the other, and
this paragraph is here so a reader does not mistake the fuzz lane for coverage of
the half it structurally cannot reach.

`saml_canonicalize` asserts determinism and the FIXED POINT: canonicalising a
canonical document must not move it. That is what a signature depends on, because
the signer and the verifier start from different-but-equivalent documents.

`saml_parse` re-measures every accepted document against the limits it was parsed
under, rather than trusting the parser to have checked them. A bound checked in
the wrong place, or against the wrong number, fails here.

## Seed corpus

`corpus/<target>/` is seeded from the committed regression documents: the XXE and
billion-laughs shapes from `tests/hostile.rs`, a genuinely signed response, and
the wrapping documents from `tests/wrapping.rs`. Continuous fuzzing should persist
and grow these.

## What has actually been run

Ninety seconds per target on an M-series laptop, from the seeds above:

| target | executions | new units |
| --- | --- | --- |
| `saml_parse` | 11,727,964 | 19,483 |
| `saml_canonicalize` | 6,541,595 | 15,990 |
| `saml_verify` | 2,256,060 | 9,055 |

No crashes, and `artifacts/` was empty afterwards. That is a floor, not a
result: ninety seconds is a smoke test, and the scheduled lane is what makes it
continuous. The numbers are here so a later reader can tell whether the lane has
ever actually executed, which is the failure `scripts/fuzz-matrix-freshness.sh`
exists for.

## Triage

A crash reproduces with `cargo +nightly fuzz run <target> <artifact>`. The process
for one is:

1. **Minimise first.** `cargo +nightly fuzz tmin <target> <artifact>`. A minimised
   input usually names the defect on sight, and it is what goes into the test.
2. **Classify by what an unauthenticated party gets.** A panic in `parse` or
   `canonicalize` is a denial of service on the assertion consumer endpoint and is
   the highest severity this crate can produce, because it needs no key and no
   valid document. An `Ok` from `saml_verify` is an authentication bypass and is
   higher still.
3. **Write the failing test BEFORE the fix**, in `tests/hostile.rs` for a parse
   crash, `tests/canonical.rs` for a canonicalization one, `tests/wrapping.rs` for
   anything reaching `verify`. The corpus entry alone is not the regression: the
   fuzz lane is scheduled, so a corpus-only fix is not checked on a pull request.
4. **Mutation-verify the fix.** Remove the new guard, run the suite, confirm the
   new test fails. Nine guards in this crate were once deletable with the whole
   suite green, and each had a test that named it.
5. **Add the minimised input to `corpus/<target>/`** so the shape stays explored.

Crashes are not filed as public issues before a fix exists: an artifact for this
crate is a working exploit against every deployment running it.
