# ironauth-jose fuzzing

A cargo-fuzz harness over the ONE public verification entry point,
`ironauth_jose::verify`. The target (`verify_jws`) drives arbitrary input
against a fixed, representative policy and clock, proving two things:

- `verify` never panics on any input, and
- no input is ever accepted unless it is a genuine signature over the exact
  header it carries (the adversarial seeds must always stay rejected).

This crate is intentionally **not** a workspace member (its `Cargo.toml` carries
an empty `[workspace]` table). libFuzzer needs a nightly toolchain and must not
constrain the stable workspace, and keeping it detached also keeps its
`libfuzzer-sys` dependency out of the `cargo-deny` graph. This is the same
pattern the repository's root `fuzz/` crate, `ironauth-fetch/fuzz/`, and the
sibling Iron projects use.

## Running locally

```
cargo install cargo-fuzz
cd crates/ironauth-jose/fuzz
cargo +nightly fuzz run verify_jws
```

## Seed corpus

`corpus/verify_jws/` is seeded from the committed regression vectors: a valid
ES256 token (a positive vector), an `alg:none` token, an embedded-`jwk`
injection, an unknown `crit`, and a five-segment JWE shape. Continuous fuzzing
should persist and grow this corpus.

## Stable, in-CI coverage of the same input space

Because there is (until the assembler wires it) no stable CI fuzz lane, the same
adversarial input space is covered on every build by:

- `crates/ironauth-jose/tests/cve_corpus.rs` (the full CVE regression corpus), and
- `crates/ironauth-jose/tests/property.rs` (fixed-seed property tests: arbitrary
  `alg` strings never verify, alg-swaps always break, arbitrary input never
  panics or verifies).

## Scheduled-fuzz CI job for the assembler to add

Issue #8 asks for the fuzz target to "run in CI on a schedule". No scheduled
fuzz workflow exists yet (only `.github/workflows/scorecard.yml` has a
`schedule:` trigger). The assembler should add a new workflow,
`.github/workflows/fuzz.yml`, along these lines (this crate does NOT edit
workflows itself):

```yaml
# SPDX-License-Identifier: MIT OR Apache-2.0
name: fuzz
on:
  schedule:
    - cron: "17 4 * * *"   # nightly
  workflow_dispatch: {}
permissions:
  contents: read
jobs:
  jose:
    name: fuzz ironauth-jose verify_jws
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - run: cargo install cargo-fuzz --locked
      - name: Run verify_jws for a bounded budget
        run: |
          cd crates/ironauth-jose/fuzz
          cargo +nightly fuzz run verify_jws -- -max_total_time=600 -timeout=25
      - name: Upload crashes on failure
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: jose-fuzz-crashes
          path: crates/ironauth-jose/fuzz/artifacts/
```

A crash makes the job (and so the scheduled run) fail, with the reproducer
uploaded as an artifact for triage; the recovered input should then be added to
`cve_corpus.rs` as a permanent regression vector.
