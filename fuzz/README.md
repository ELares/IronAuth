# fuzz

The cargo-fuzz harness lands with the M1 issue "Implement the hardened JOSE
core with fuzzing and algorithm exclusions", as a standalone crate that is
deliberately not a workspace member: its libFuzzer dependency needs a nightly
toolchain and must not constrain the stable workspace (the same pattern the
sibling Iron projects use). The CI fuzz lane is added in that issue together
with the first real fuzz targets and the JOSE CVE regression corpus.

## `ceremony_parse`

Everything byte-facing in a WebAuthn ceremony: the CBOR attestationObject, the
authenticator data (including the variable-length COSE key slice), the COSE
credential public key, and the clientDataJSON through the full registration and
authentication verify paths.

It also covers the DER and X.509 parsers under `x509::parse_certificate` (issue
#419). Those deserve fuzzing because of WHEN they run: a `packed` attestation
statement's `x5c` chain is parsed before its signature, AAGUID, and chain checks,
and an MDS3 BLOB's `x5c` chain is parsed before the JWS signature check, so both
run on bytes nothing has vouched for yet. Neither is reachable by handing the
fuzzer's bytes to a top-level entry point, so the target BUILDS the two carriers
(a CBOR attestation statement and a JWS header) around the input.

```
cargo install cargo-fuzz
cargo +nightly fuzz run ceremony_parse
```

## Seed corpus

`corpus/ceremony_parse/seed_multibyte_der_time` is a certificate whose
`notBefore` has the right byte length but is not all one-byte characters, the
input class that made the DER time parser slice through a character (issue
#419). It is stored doubled, since the target splits its input in half and reads
the first half as the certificate. Continuous fuzzing should persist and grow
this corpus; a reproducer for a fixed crash belongs here, since `artifacts/` is
scratch and is not committed.

## Stable, in-CI coverage of the same input space

The same input space is covered on every build by the stable tests the normal
gate runs: `crates/ironauth-webauthn/tests/parse_fuzz.rs` for the ceremony
parsers, and the `der`, `x509`, and `mds3` unit tests for the certificate path
(including the char-boundary regressions this corpus seeds). The scheduled
nightly fuzz lane is `.github/workflows/fuzz.yml`.

## Adding a target

A new fuzz target needs all three of these, and the gate enforces that they
agree:

1. the `fuzz_targets/<name>.rs` file;
2. a `[[bin]]` entry naming it in that fuzz crate's `Cargo.toml`, which is what
   `cargo fuzz list` and `cargo fuzz run` actually see;
3. a row in the `.github/workflows/fuzz.yml` matrix, whose `dir` is the fuzz
   crate's PARENT (`.` for this root crate).

Miss step 3 and the target never executes, which is indistinguishable from not
having written it. That happened twice (one target, then seven), so
`scripts/fuzz-matrix-freshness.sh` now compares the three sets on every gate run
and fails naming whichever targets are on one side and not the other. It parses
the manifests and the workflow statically, so it runs without a nightly
toolchain and without `cargo-fuzz` installed.
