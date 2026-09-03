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

`saml_verify` carries a FIXED private key and a document that genuinely verifies
under it, so the accept path exists and the fuzzer's mutations of that document
can reach it. When they do, two things are asserted: the returned subtree carries
no `SignatureValue` (the enveloped transform removed it before the digest, so a
`VerifiedAssertion` still holding one holds content the digest did not cover --
which is exactly the authenticate-as-anyone defect this crate shipped and fixed),
and the returned element's `ID` is the fragment the `Reference` URI named.

AN EARLIER VERSION OF THIS TARGET ASSERTED NOTHING, and the correction is worth
recording. It pinned anchors that had signed nothing and asserted `verify` never
returns `Ok`. `verify`'s only `Ok` exit sits immediately after
`if !anchors.iter().any(|a| verify_xml_signature(..))`, so with an empty slice
the `Err` is taken by construction whatever happened upstream. A reviewer deleted
the digest comparison, the exactly-one-candidate refusal and the
duplicate-identifier guard in turn and the target stayed green on every input.
It asserted that `any()` over an empty iterator is false.

What a fuzzer still cannot do is FORGE. Every `Ok` it reaches comes from a
mutation that left the signature and the digest intact, so it explores the accept
path's edges rather than its perimeter. The perimeter is `tests/wrapping.rs`,
where each document is built deliberately. Neither substitutes for the other.

`saml_canonicalize` asserts determinism and the FIXED POINT: canonicalising a
canonical document must not move it. That is what a signature depends on, because
the signer and the verifier start from different-but-equivalent documents. It
canonicalises a DESCENDANT as well as the root, because the inherited-scope path
-- where this crate's worst canonicalization defect lived -- is not entered at
all when the apex is the document element. It does NOT assert totality: a
document with an unbound prefix parses and is refused here on purpose.

`saml_parse` re-measures every accepted document against the limits it was parsed
under, against the EFFECTIVE depth bound (`max_depth.min(DEPTH_CEILING)`) rather
than the ceiling. Its limits are small -- 2048 bytes, 8 deep, 64 elements --
because libFuzzer generates 4096 bytes by default and the deployed defaults (a
megabyte, ten thousand elements) cannot be crossed by any input the lane
produces. The property under test is that `parse` enforces whatever bounds it is
given.

## Seed corpus

`corpus/<target>/` holds hand-written seeds, tracked by name: `fuzz/.gitignore`
keeps `seed_*` and drops everything libFuzzer generates. They are the XXE and
billion-laughs shapes, the malformed-QName shapes, a plain response, two
canonicalization shapes with declarations and processing instructions in them,
a two-assertion wrapping document, and `seed_genuinely_signed` -- a response
really signed by the key `fuzz_targets/saml_verify.rs` embeds, which is what
makes the accept path reachable from the corpus at all.

`tests/fuzz_seeds.rs` is what holds those claims: it asserts the tracked-seed
floors, that every canonicalization seed PARSES, that the parse corpus carries
both accepted and DOCTYPE-refused documents, and that at least one verify seed
genuinely VERIFIES under the embedded key. An earlier version of that last
assertion accepted "gets past candidate selection", which a document carrying
`<ds:DigestValue>AAAA</ds:DigestValue>` satisfies while never reaching the
signature primitive at all.

Continuous fuzzing should persist and grow these.

## What has actually been run

Ninety seconds per target on an M-series laptop, from the seeds above:

| target | executions | new units |
| --- | --- | --- |
| `saml_parse` | 11,727,964 | 19,483 |
| `saml_canonicalize` | 6,541,595 | 15,990 |
| `saml_verify` | 2,256,060 | 9,055 |

No crashes, and `artifacts/` was empty afterwards.

TWO CAVEATS, because a number in a README is worth exactly what its provenance
is. These were measured by hand on a developer machine before the targets were
rewritten in response to review, so they say the harness RAN, not that the
current targets have. And nothing in this repository verifies them: they are a
note, not a check. `scripts/fuzz-matrix-freshness.sh` is a different thing
entirely -- a static three-way check that the registered `[[bin]]` entries, the
target files and the workflow matrix rows all agree -- and it deliberately never
invokes cargo, so it cannot tell whether the lane has ever executed. Nothing
can, from inside the repository.

Ninety seconds is a smoke test. The scheduled lane is what makes it continuous.

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
