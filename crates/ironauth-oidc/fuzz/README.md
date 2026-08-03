<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# ironauth-oidc fuzz

Continuous fuzzing of two untrusted edges this crate owns: the headless flow
**submission parser** (issue #84, PR 4), which every flow advance ingests, and
the branding **rich-text sanitizer** (issue #86), the one place operator-authored
markup becomes safe markup.

## Targets

- **`flow_submission_parse`** -- fuzzes the two submission decoders the live
  transports route through:
  - `ironauth_oidc::flow::parse_api_submission` -- the API JSON submit envelope
    (flow id, submit token, node values, transient payload), and
  - `ironauth_oidc::flow::parse_form_transient_payload` -- the browser
    transient-payload field (a JSON string).

  The property: for **every** input, both parsers are **total** -- they return
  either a decoded submission or a **typed** `FlowError`
  (`InvalidSubmission` / `MalformedTransientPayload`), never a panic, never a
  500, never a partial value. A malformed node payload, an oversized or non-JSON
  transient payload, a bad submit token shape, and arbitrary/invalid-UTF-8 bytes
  are all exercised.

These are the exact functions the API (`flow_api_submit`) and browser
(`flow_browser_post`) handlers call, so the fuzzer covers the real decode path,
not a copy. The same input space also has stable, per-PR coverage in the crate's
`tests/flow_api.rs` and `tests/flow_matrix.rs` integration suites.

- **`branding_sanitize`** fuzzes `ironauth_oidc::branding::sanitize`, the ONE
  place branding rich text becomes safe markup (issue #86). The properties: it
  never panics, its output is **inert**, and it is a **fixed point** of itself
  (`sanitize(sanitize(x)) == sanitize(x)`), which is what makes re-sanitizing a
  stored slot on read safe and what makes a snapshot IronAuth exported pass the
  config-promotion import wall.

  Its seed corpus, `corpus/branding_sanitize/`, carries the Casdoor-class bypass
  payloads plus a reproducer for every crash this lane has found, because
  `artifacts/` is scratch and is never committed.
  `seed_regression_select_nested_p` is the input that broke idempotence: an
  element outside the allowlist suppressed the implied `</p>`, so stripping that
  element left a `<p>` nested inside a `<p>`, which no parser can produce and the
  next parse unfolded into siblings. `sanitize` now applies the allowlist until a
  pass changes nothing. The same bytes are pinned in the crate's
  `branding::sanitize` unit tests, which `include_bytes!` this very file, so the
  seed and the every-PR regression cannot drift apart.

## Running

This crate is **detached** from the workspace (it has its own `[workspace]`
table) so its nightly-only libFuzzer dependency never constrains the stable
workspace or the cargo-deny graph. It needs a nightly toolchain:

```sh
cargo +nightly fuzz run flow_submission_parse
```

The scheduled CI lane that runs this target lives in
`.github/workflows/fuzz.yml`.
