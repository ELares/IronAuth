// SPDX-License-Identifier: MIT OR Apache-2.0
// Builds an untracked test component from the TypeScript in `src/`.
//
// Node and locked npm dependencies are explicit test prerequisites, prepared by
// `scripts/build-ts-hook-fixture.sh`, rather than part of every Rust build. The binary is
// generated from source and never committed. `scripts/ts-hook-freshness.sh` rebuilds it in a
// temporary directory and runs the behavioral assertions against those exact bytes.
//
// componentize-js output is not byte-reproducible: two consecutive builds from unchanged
// source produced different byte counts and digests. Test behavior and upload bounds instead
// of comparing generated file hashes.

import { componentize } from "@bytecodealliance/componentize-js";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

const out = process.argv[2] ?? "dist/token-customize.wasm";

const { component } = await componentize({
  sourcePath: "build/token-customize.js",
  witPath: "../wit",
  worldName: "token-customize-hook",
  // EVERY feature off. Each one componentize-js leaves enabled adds `wasi:*` imports, and the
  // host linker satisfies only the fourteen interfaces `Sandbox::link` adds by hand -- no
  // sockets, no filesystem, no `wasi:http`. A component importing one of the others cannot be
  // instantiated at all.
  //
  // MEASURED, with `fetch-event` left enabled: the component then imports `wasi:io/poll`,
  // `wasi:io/streams` and `wasi:http/types`, and loading it fails with
  //
  //   hook asked for a capability it was not granted: component imports instance
  //   `wasi:http/types@0.2.3`, but a matching implementation was not found in the linker
  //
  // Note WHICH one. `wasi:io/poll` and `wasi:io/streams` ARE in the linker and resolve fine --
  // std's startup needs them, pointed at streams that lead nowhere. It is `wasi:http/types`,
  // pulled in because the JavaScript engine has a `fetch` global, that nothing satisfies. An
  // earlier version of this comment said the linker "offers nothing at all" and blamed all
  // three imports; both were wrong, and the second would send the next author looking for a
  // problem in the io interfaces.
  //
  // That is criterion 2's deny-by-default sandbox working, not a build problem.
  disableFeatures: ["http", "random", "stdio", "clocks", "fetch-event"],
});

await mkdir(dirname(out), { recursive: true });
await writeFile(out, component);
console.log(`wrote ${out}, ${component.length} bytes`);
