#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Prepare the source-built TypeScript component before hook and upload-bound tests.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
guest_dir="$repo_root/crates/ironauth-hooks/guests-ts"
out="${1:-$guest_dir/dist/token-customize.wasm}"
if [[ "$out" != /* ]]; then
  out="$PWD/$out"
fi

for tool in node npm; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "FAIL: $tool is required to build the TypeScript hook test fixture." >&2
    echo "  Install Node and npm, then run ./scripts/build-ts-hook-fixture.sh." >&2
    exit 1
  fi
done

cd "$guest_dir"
npm ci --no-audit --no-fund
# Use the locked local compiler; do not let npx fetch an unlisted package.
./node_modules/.bin/tsc
node build.mjs "$out"
if [ ! -s "$out" ]; then
  echo "FAIL: building the TypeScript hook did not produce a component at $out." >&2
  exit 1
fi
