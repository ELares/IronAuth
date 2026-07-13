# ironauth-fetch fuzzing

A cargo-fuzz harness over the two pure gates the SSRF-hardened connector
consults before it opens a socket: URL parsing (`parse_target`) and
destination validation (`classify`).

This crate is intentionally **not** a workspace member (its `Cargo.toml`
carries an empty `[workspace]` table). libFuzzer needs a nightly toolchain and
must not constrain the stable workspace, and keeping it detached also keeps its
`libfuzzer-sys`/`arbitrary` dependencies out of the `cargo-deny` graph. This is
the same pattern the repository's root `fuzz/` crate and the sibling Iron
projects use.

There is **no CI fuzz lane** for this target: the stable, in-CI coverage of the
same input space lives in `crates/ironauth-fetch/tests/adversarial_table.rs`.
Run the fuzzer locally when changing the parser or the deny policy:

```
cargo install cargo-fuzz
cd crates/ironauth-fetch/fuzz
cargo +nightly fuzz run fetch_validation
```

## Target

- `fetch_validation` drives:
  - `parse_target` over arbitrary strings (the parser must never panic; a parsed
    IP-literal host must always classify; `host_header` must never panic), and
  - `classify` over arbitrary IPv4 and IPv6 addresses (the deny policy must be
    total over the whole address space).
