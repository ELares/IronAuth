// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Builds `dist/token-customize.wasm` from the TypeScript in `src/`.
//
// # Why the artifact is committed
//
// Every Rust guest fixture in `../guests/` is compiled by this crate's `build.rs`, because
// building them needs only `cargo` and one rustup target. Building THIS one needs Node, an
// npm install, and a JavaScript engine to embed, and running `npm install` from a `build.rs`
// would mean a network fetch on every build of `ironauth-hooks` -- which breaks offline and
// vendored builds and makes the build non-reproducible.
//
// So the component is built here, by hand, and committed. `build.rs` points the tests at the
// committed file and FAILS if it is missing, exactly as it fails for a missing Rust fixture:
// a TypeScript hook test that silently does not run would leave criterion 1's TypeScript half
// unverified while the suite reported green.
//
// The risk this trades for is the committed artifact drifting from the source beside it.
// `scripts/ts-hook-freshness.sh` closes that: where Node is available it rebuilds from source
// and runs the same integration test against the REBUILT component. It compares BEHAVIOUR and
// not bytes, and that is not a preference -- MEASURED, on one machine, from an unchanged
// source: two consecutive builds produced 11127131 and 11127118 bytes with different SHA-256
// digests. A checksum gate would therefore fail on a rebuild that changed nothing, which is
// the fastest way to teach everyone to regenerate the artifact without reading the diff.

import { componentize } from "@bytecodealliance/componentize-js";
import { writeFile } from "node:fs/promises";

const out = process.argv[2] ?? "dist/token-customize.wasm";

const { component } = await componentize({
  sourcePath: "build/token-customize.js",
  witPath: "../wit",
  worldName: "token-customize-hook",
  // EVERY feature off. Each one componentize-js leaves enabled adds a `wasi:*` import to the
  // component, and the host linker offers nothing at all -- criterion 2's deny-by-default
  // sandbox -- so a component that imports `wasi:http/types` because the engine has a `fetch`
  // global fails to LINK. With `fetch-event` still on, this component imported
  // `wasi:io/poll`, `wasi:io/streams` and `wasi:http/types` and could not be loaded.
  //
  // That is the sandbox working, not a build problem: the guest must ask for nothing.
  disableFeatures: ["http", "random", "stdio", "clocks", "fetch-event"],
});

await writeFile(out, component);
console.log(`wrote ${out}, ${component.length} bytes`);
