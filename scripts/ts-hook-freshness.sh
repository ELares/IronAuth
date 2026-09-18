#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Rebuild the TypeScript hook from locked source dependencies and test those exact bytes.
# Generated components are temporary or ignored, never committed. Missing build tools and
# failed builds are failures, since a skipped TypeScript suite would leave its guarantees
# unverified. componentize-js output is not byte-reproducible, so retain behavior assertions
# and check the upload cap instead of comparing generated hashes.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temp_dir="$(mktemp -d)"
trap 'rm -rf "$temp_dir"' EXIT
fresh="$temp_dir/token-customize.wasm"
probe_log="$temp_dir/probe.log"

cd "$repo_root"
echo "== rebuilding the TypeScript hook from locked source dependencies =="
./scripts/build-ts-hook-fixture.sh "$fresh"

# Read the upload cap from its source of truth; a missing match must fail the check.
cap_mib=$(sed -n 's/^pub(crate) const MAX_COMPONENT_BYTES: usize = \([0-9]*\) \* 1024 \* 1024;$/\1/p' \
            "$repo_root/crates/ironauth-admin/src/token_hooks.rs")
if [ -z "$cap_mib" ]; then
  echo "FAIL: could not read MAX_COMPONENT_BYTES from ironauth-admin/src/token_hooks.rs." >&2
  exit 1
fi
fresh_bytes=$(wc -c < "$fresh" | tr -d ' ')
cap_bytes=$(( cap_mib * 1024 * 1024 ))
echo "rebuilt: $fresh_bytes bytes; cap: $cap_bytes bytes"
if [ "$fresh_bytes" -gt "$cap_bytes" ]; then
  echo "FAIL: the source-built TypeScript hook is $fresh_bytes bytes, over the" >&2
  echo "  ${cap_bytes}-byte MAX_COMPONENT_BYTES. It cannot be deployed through the admin API." >&2
  exit 1
fi

echo "== proving the integration tests load the rebuilt component =="
export IRONAUTH_GUEST_TS_TOKEN_CUSTOMIZE_OVERRIDE="$fresh"
# Capture the probe first; piping cargo to grep -q can trigger SIGPIPE with pipefail.
if ! cargo test --release -p ironauth-hooks --test typescript_hook \
    the_override_is_the_component_under_test -- --nocapture >"$probe_log" 2>&1; then
  cat "$probe_log" >&2
  exit 1
fi
if ! grep -F -q "$fresh" "$probe_log"; then
  echo "FAIL: the tests did not load the rebuilt component from $fresh." >&2
  cat "$probe_log" >&2
  exit 1
fi

echo "== running the behavioral integration assertions against the rebuilt component =="
cargo test --release -p ironauth-hooks --test typescript_hook

echo "OK: the source-built TypeScript hook passes its behavior assertions and fits the upload cap."
