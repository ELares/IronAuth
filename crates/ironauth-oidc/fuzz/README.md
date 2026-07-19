<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# ironauth-oidc fuzz

Continuous fuzzing of the headless flow **submission parser** (issue #84, PR 4):
the untrusted edge every flow advance ingests.

## Targets

- **`flow_submission_parse`** — fuzzes the two submission decoders the live
  transports route through:
  - `ironauth_oidc::flow::parse_api_submission` — the API JSON submit envelope
    (flow id, submit token, node values, transient payload), and
  - `ironauth_oidc::flow::parse_form_transient_payload` — the browser
    transient-payload field (a JSON string).

  The property: for **every** input, both parsers are **total** — they return
  either a decoded submission or a **typed** `FlowError`
  (`InvalidSubmission` / `MalformedTransientPayload`), never a panic, never a
  500, never a partial value. A malformed node payload, an oversized or non-JSON
  transient payload, a bad submit token shape, and arbitrary/invalid-UTF-8 bytes
  are all exercised.

These are the exact functions the API (`flow_api_submit`) and browser
(`flow_browser_post`) handlers call, so the fuzzer covers the real decode path,
not a copy. The same input space also has stable, per-PR coverage in the crate's
`tests/flow_api.rs` and `tests/flow_matrix.rs` integration suites.

## Running

This crate is **detached** from the workspace (it has its own `[workspace]`
table) so its nightly-only libFuzzer dependency never constrains the stable
workspace or the cargo-deny graph. It needs a nightly toolchain:

```sh
cargo +nightly fuzz run flow_submission_parse
```

The scheduled CI lane that runs this target lives in
`.github/workflows/fuzz.yml`.
