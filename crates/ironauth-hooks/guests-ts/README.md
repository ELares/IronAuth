# The TypeScript token.customize hook

Issue #114 criterion 1 asks that "a Rust hook and a TypeScript hook each customize token claims
through `token.customize` under sandbox limits in the integration suite". The Rust half is the
fourteen components in `../guests/`. This directory is the TypeScript half, and it is one
component that is both the SAMPLE a tenant would copy and the FIXTURE the suite runs.

Deliberately the same artifact. A sample nothing executes rots into a snippet that no longer
compiles, and a fixture that is not the sample proves nothing about what a tenant would ship.

## Layout

| Path | What it is |
| --- | --- |
| `src/token-customize.ts` | The hook. About four kilobytes of TypeScript. |
| `build.mjs` | Componentizes the compiled JavaScript against `../wit`. |
| `dist/token-customize.wasm` | The built component, **committed**. |
| `package.json` | Pinned `componentize-js` and `typescript`. |

## Building

```sh
npm install
npm run build      # tsc, then node build.mjs
```

`npm run build` type-checks first, so a TypeScript error is a build failure rather than a
silently stale `build/`.

## Why the component is committed

Every Rust fixture is compiled by this crate's `build.rs`, which needs only `cargo` and one
rustup target. This one needs Node, an npm install and a JavaScript engine to embed. Running
`npm install` from a build script would put a network fetch in the path of every build of
`ironauth-hooks`, which breaks offline and vendored builds.

So it is built by hand and committed, and `build.rs` points the tests at the committed file and
FAILS when it is missing, exactly as it fails for a missing Rust fixture. A TypeScript hook test
that quietly did not run would leave half of criterion 1 unverified while the suite reported
green.

The risk that trades for is drift between the source and the artifact.
`scripts/ts-hook-freshness.sh` closes it: where Node is available it rebuilds from source and
runs the same integration tests against the rebuilt component. It compares BEHAVIOUR, not bytes.

That is measured, not assumed: two consecutive builds on one machine from an unchanged source
produced 11127131 and 11127118 bytes with different digests. A checksum gate would fail on a
rebuild that changed nothing, which is the fastest way to teach everyone to regenerate the
artifact without reading the diff.

## Two things a hook author should know before writing one

**Turn every componentize-js feature off.** Each feature left enabled adds `wasi:*` imports,
and the host linker satisfies only the fourteen interfaces `Sandbox::link` adds by hand: no
sockets, no filesystem, no `wasi:http`. Measured, with `fetch-event` left on, the component
imports `wasi:io/poll`, `wasi:io/streams` and `wasi:http/types`, and loading it fails with

```
hook asked for a capability it was not granted: component imports instance
`wasi:http/types@0.2.3`, but a matching implementation was not found in the linker
```

Note which one. `wasi:io/poll` and `wasi:io/streams` are in the linker and resolve fine, because
std's startup needs them. It is `wasi:http/types`, pulled in because the JavaScript engine has a
`fetch` global, that nothing satisfies. That is criterion 2's deny-by-default sandbox working.
`build.mjs` disables all five features.

**A JavaScript hook carries a JavaScript engine.** This one is roughly 10.6 MiB, of which about
four kilobytes is the code in `src/`. That is not a footnote:

- the admin surface's upload cap had to admit it, and 8 MiB did not. See
  `0166_token_hook_component_bound.sql`, and `MAX_COMPONENT_BYTES` in `ironauth-admin`, which is
  now pinned against this artifact's real length rather than against a chosen number.
- compiling it costs seconds in a release build and around two minutes in a debug one, which is
  why `tests/typescript_hook.rs` compiles it once and shares it.
- **the first login after deploying one pays that compile, inline.** Measured under the limits
  the server actually applies (`Limits::claim_shaping` with `EPOCH_TICKS_PER_HOOK`, a
  free-running 10 ms epoch ticker): `HookEngine::load` takes **6.5 s**, and every invocation
  after it takes **0.5-1.4 ms**. `ironauth-oidc`'s hook cache is populated lazily on a miss, so
  that 6.5 s lands on one unlucky request rather than on the deploy. A Rust hook is small enough
  that nobody noticed; a JavaScript hook is not.

  Criterion 4's AOT precompilation at DEPLOY time is what removes this, and it is a different
  criterion. Said here because "microsecond-scale cold starts" is the headline claim for hooks,
  and it is true of the warm path and false of the first request for this artifact.
- it still runs inside the shipped `Limits::claim_shaping`, unmodified.
  `the_typescript_hook_fits_the_shipped_limits_with_margin` searches for the smallest limit it
  survives and PRINTS the ratio: memory at 8 MiB of the shipped 16 (2x), fuel at 12.5M of the
  shipped 50M (4x).

## The test modes

One component serves the whole suite, because four would be forty-four megabytes of JavaScript
engine in the repository. The hook reads an ID-token claim named `ironauth_ts_hook_mode` and
strips it from its output:

| Mode | What the hook does | What it demonstrates |
| --- | --- | --- |
| *(absent)* | Adds `ts_hook_tier`, derived from the grant type, client and subject | Criterion 1 |
| `spin` | Loops forever | Fuel aborts a JavaScript interpreter loop |
| `decline` | Throws a string | The WIT `err` arm is a decline, not a trap |

Every mode in the source is in that table and every one is exercised by
`tests/typescript_hook.rs`. That is a rule, not an observation: a fourth mode was written and
never tested, which made it undocumented behaviour inside an eleven-megabyte artifact tenants
are told to copy, and the freshness check cannot police a branch nothing calls. It was removed.

A hook a tenant actually ships would have none of this. It is here because the alternative was
two more copies of SpiderMonkey.
