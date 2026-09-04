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
can reach it. When they do, three things are asserted: the element returned is
the one asked for; it carries no `ds:Signature` DIRECT CHILD, because the
enveloped transform removes exactly the one it had; and whatever verified under
the pinned anchor does NOT verify under a different real key.

AN EARLIER PAIR OF ASSERTIONS SAID SOMETHING ELSE, and this section described
them for a commit after they were deleted. They were that the returned subtree
carries no `ds:SignatureValue` anywhere, and that its `ID` equals the fragment of
the first `URI="#` found by scanning the raw input. Both fired on CONFORMING
documents -- the first on the ordinary Okta and ADFS response that signs the
Response and the assertion inside it, the second on any document with an earlier
`URI="#` -- so the target crashed on legal SAML. Direct children, and no ID
comparison at all, is what replaced them.

WHAT THE THREE DO NOT CATCH is in the target's own module doc, at more length
than fits here: the first two are settled before the digest is ever computed, so
deleting the digest comparison, the exactly-one-candidate refusal or the
duplicate-identifier guard leaves this target green. Those are covered by tests
in `tests/wrapping.rs`, which is where a document with a signature over content
the attacker chose can be built. A fuzzer cannot build one.

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

`saml_parse` re-measures every accepted document against the limits IT SETS,
against the EFFECTIVE depth bound (`max_depth.min(DEPTH_CEILING)`) rather than
the ceiling. Not every bound `Limits` has: the public `Element` exposes no
attributes by design, so `max_attributes` and the attribute-name half of
`max_name_bytes` cannot be seen from a target and are covered by
`one_element_cannot_be_unbounded` in `tests/hostile.rs` instead. The target does
not set them, so it does not claim them. Its limits are small -- 2048 bytes, 8 deep, 64 elements --
because libFuzzer generates 4096 bytes by default and the deployed defaults (a
megabyte, ten thousand elements) cannot be crossed by any input the lane
produces. The property under test is that `parse` enforces whatever bounds it is
given.

## Seed corpus

`corpus/<target>/` holds hand-written seeds, tracked by name: `fuzz/.gitignore`
keeps `seed_*` and drops everything libFuzzer generates. All twelve, by target:

* `saml_parse`: `seed_xxe_local_file`, `seed_billion_laughs`,
  `seed_empty_prefix_declaration`, `seed_two_colons`, `seed_response_shape`.
* `saml_canonicalize`: `seed_two_declarations`, `seed_pi_and_comment`,
  `seed_attribute_normalisation`, and `seed_inherited_scope` -- the last is the
  only one that reaches the inherited-scope path described above, so it is the
  one not to prune.
* `saml_verify`: `seed_genuinely_signed` (a response really signed by the key
  `fuzz_targets/saml_verify.rs` embeds, which is what makes the accept path
  reachable from the corpus at all), `seed_response_shape`, `seed_two_assertions`.

Enumerated rather than summarised because the previous summary read as complete
and omitted two, one of them the seed the paragraph above calls load-bearing.

`tests/fuzz_seeds.rs` is what holds those claims: it asserts the tracked-seed
floors, that every canonicalization seed PARSES, that the parse corpus carries
both accepted and DOCTYPE-refused documents, and that at least one verify seed
genuinely VERIFIES under the embedded key. An earlier version of that last
assertion accepted "gets past candidate selection", which a document carrying
`<ds:DigestValue>AAAA</ds:DigestValue>` satisfies while never reaching the
signature primitive at all.

Continuous fuzzing should persist and grow these.

## What has actually been run

Nothing here. An earlier version of this section carried a table of execution
counts, and the table outlived two rewrites of the things it described: the
numbers were measured when `saml_verify` still pinned anchors that had signed
nothing and the corpus held no signed document, so its two million executions
were evidence about the parser and about nothing in `verify` -- while sitting
under a heading that says what has actually been run.

A hand-copied number that no check re-derives is a claim with a decaying
half-life, and this one decayed inside a single pull request. Run the targets
yourself if you want a number; the command is above.

What IS checked, on every build rather than by a note: `tests/fuzz_seeds.rs`
asserts the seeds are tracked, that every canonicalization seed parses, that the
parse corpus carries both accepted and DOCTYPE-refused documents, and that at
least one verify seed genuinely VERIFIES under the embedded key.
`scripts/fuzz-matrix-freshness.sh` asserts that the registered `[[bin]]` entries,
the target files and the workflow matrix rows all agree -- it is deliberately
static and never invokes cargo, so it says nothing about whether the lane has
executed. Nothing in this repository can say that.

## Triage

A crash reproduces with `cargo +nightly fuzz run <target> <artifact>`. The process
for one is:

1. **Minimise first.** `cargo +nightly fuzz tmin <target> <artifact>`. A minimised
   input usually names the defect on sight, and it is what goes into the test.
2. **Classify by what an unauthenticated party gets.** A panic in `parse` or
   `canonicalize` is a denial of service on the assertion consumer endpoint and is
   the highest severity this crate can produce, because it needs no key and no
   valid document.

   AN `Ok` FROM `saml_verify` IS THE NORMAL CASE, not a finding. An earlier
   version of this rule said the opposite, and it was written for an earlier
   version of the target that asserted `verify` never returns `Ok` at all. The
   target now embeds a real key so the accept path is reachable, and every
   iteration reaches it. A triager following the old rule would read a legal SAML
   response as a working exploit.

   What a `saml_verify` artifact means is that one of two invariants broke: the
   element returned was not the one asked for, or a verified assertion still
   carried the `ds:Signature` child the enveloped transform removes. The second is
   the authentication bypass -- it is the historical defect where the verifier
   digested a stripped copy and returned the original -- and it is the highest
   severity here. The first is a wrapping bug of some other shape.

   Read the panic message before assuming which. Both assertions have been wrong
   before: a version of this target aborted on the ordinary Okta document that
   signs the Response and the assertion inside it, and on any document with a
   `URI="#..."` anywhere before the Reference. If an artifact reproduces on a
   document a real identity provider would send, the TARGET is the defect.
3. **Write the failing test BEFORE the fix**, in `tests/hostile.rs` for a parse
   crash, `tests/canonical.rs` for a canonicalization one, `tests/wrapping.rs` for
   anything reaching `verify`. The corpus entry alone is not the regression: the
   fuzz lane is scheduled, so a corpus-only fix is not checked on a pull request.
4. **Mutation-verify the fix.** Remove the new guard, run the suite, confirm the
   new test fails. Nine guards in this crate were once deletable with the whole
   suite green, and each had a test that named it.
5. **Add the minimised input to `corpus/<target>/`** so the shape stays explored.

Crashes are not filed as public issues before a fix exists IF THE VERIFIER IS THE
DEFECT: an artifact of that kind is a working exploit against every deployment
running this crate.

But decide which it is FIRST, using step 2. Twice in this crate's history a
`saml_verify` artifact was the TARGET being wrong about a conforming document,
and an unconditional embargo rule turns that into an unfiled zero-day that nobody
can look at. A target bug is an ordinary bug and belongs in the tracker.
