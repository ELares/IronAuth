#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Rebuild the TypeScript hook from source and check the COMMITTED component still behaves.
#
# `crates/ironauth-hooks/guests-ts/dist/token-customize.wasm` is committed rather than built by
# `build.rs`, because building it needs Node and an npm install and a build script has no
# business fetching from the network (guests-ts/build.mjs carries the full reasoning). The cost
# of committing a build output is that it can drift from the source beside it, and this script
# is what closes that.
#
# IT COMPARES BEHAVIOUR, NOT BYTES. componentize-js output is not byte-reproducible even on one
# machine from an unchanged source: two consecutive builds produced 11127131 and 11127118 bytes
# with different SHA-256 digests. A checksum gate would fail on a rebuild that changed nothing,
# which would train everyone to regenerate the artifact without reading the diff.
# Instead: rebuild from `src/`, then run the SAME integration tests against the rebuilt
# component through `IRONAUTH_GUEST_TS_TOKEN_CUSTOMIZE_OVERRIDE`. If the committed artifact and
# the source disagree about what the hook DOES, one of the two runs fails.
#
# WHY IT IS NOT IN THE DEFAULT GATE: it needs Node and a network-reachable npm registry. It runs
# where those exist, and it SKIPS LOUDLY where they do not -- with an exit code of 0, because a
# missing toolchain is not a failing check, and with a message saying exactly what was not
# verified so the skip is never mistaken for a pass.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
guest_dir="$repo_root/crates/ironauth-hooks/guests-ts"
committed="$guest_dir/dist/token-customize.wasm"

if [ ! -f "$committed" ]; then
  echo "FAIL: the committed TypeScript component is missing: $committed" >&2
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "SKIPPED: npm is not on PATH."
  echo "  NOT VERIFIED: that $committed still matches the behaviour of"
  echo "  $guest_dir/src/token-customize.ts. The committed component was used as-is."
  exit 0
fi

echo "== rebuilding the TypeScript hook from source =="
fresh="$(mktemp -d)/token-customize.wasm"
(
  cd "$guest_dir"
  npm install --no-audit --no-fund
  # `tsc` first: it type-checks AND emits the JavaScript componentize-js consumes, so a
  # TypeScript error here is a build failure rather than a silently stale `build/`.
  npx tsc
  node build.mjs "$fresh"
)

echo "== running the integration tests against the REBUILT component =="
# The override is read by `tests/typescript_hook.rs`. Running the same assertions against the
# rebuilt artifact is the actual check: it says the source and the committed bytes agree about
# behaviour, which is the property that matters.
IRONAUTH_GUEST_TS_TOKEN_CUSTOMIZE_OVERRIDE="$fresh" \
  cargo test --release -p ironauth-hooks --test typescript_hook

echo "== and against the COMMITTED component, so both are known good =="
cargo test --release -p ironauth-hooks --test typescript_hook

# The size is what the admin surface's upload cap is pinned to, so report it: a rebuild that
# grows the engine is the thing most likely to push a TypeScript hook past the bound.
committed_bytes=$(wc -c < "$committed" | tr -d ' ')
fresh_bytes=$(wc -c < "$fresh" | tr -d ' ')
echo "committed: $committed_bytes bytes; rebuilt: $fresh_bytes bytes"
echo "OK: the committed TypeScript component behaves as its source says it does."
