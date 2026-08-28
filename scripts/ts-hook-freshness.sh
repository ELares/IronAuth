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
# WHY IT IS NOT IN THE DEFAULT GATE: it rebuilds an eleven-megabyte component and then runs the
# hook tests twice, which is minutes for a check that only ever confirms what the committed
# artifact already does. Not because Node is exotic here -- `scripts/gate.sh` already has node
# lanes -- but because of what this particular check costs.
#
# It SKIPS LOUDLY when npm is absent -- exit 0, because a missing toolchain is not a failing
# check, and a message saying exactly what was not verified so the skip is never mistaken for a
# pass. An UNREACHABLE REGISTRY IS A FAILURE, not a skip, and that is deliberate: the header
# used to promise a skip for it and the code never implemented one. A skip is right for "this
# machine does not do JavaScript"; a registry that cannot be reached on a machine that does is a
# broken environment, and answering it with a green check is how this check stops meaning
# anything on the one runner that is supposed to run it.

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
#
# BUT THE TEST FALLS BACK to the committed component when the variable is unset, which is right
# for an ordinary run and wrong here: a typo in the name below would make this job re-test the
# committed artifact twice and report success, which is exactly the outcome it exists to rule
# out. So the override is proven to have taken effect before it is trusted.
export IRONAUTH_GUEST_TS_TOKEN_CUSTOMIZE_OVERRIDE="$fresh"
# CAPTURED TO A FILE, then searched. Not `cargo test ... | grep -q`, which looks equivalent and
# is not: `grep -q` exits at the first match and closes the pipe, `cargo test` then dies on
# SIGPIPE, and `set -o pipefail` reports the pipeline as failed. Measured -- that spelling made
# this guard fire on a run where the override HAD taken effect, which is a check that fails
# correct work and would have been switched off within a week.
probe_log="$(mktemp)"
cargo test --release -p ironauth-hooks --test typescript_hook \
    the_override_is_the_component_under_test -- --nocapture >"$probe_log" 2>&1
if ! grep -F -q "$fresh" "$probe_log"; then
  echo "FAIL: the tests did not load the rebuilt component from $fresh." >&2
  echo "  The override variable is not reaching tests/typescript_hook.rs, so a rebuild would" >&2
  echo "  have been compared against nothing. The probe printed:" >&2
  sed -n 's/^typescript hook under test/  typescript hook under test/p' "$probe_log" >&2
  exit 1
fi
cargo test --release -p ironauth-hooks --test typescript_hook

echo "== and against the COMMITTED component, so both are known good =="
unset IRONAUTH_GUEST_TS_TOKEN_CUSTOMIZE_OVERRIDE
cargo test --release -p ironauth-hooks --test typescript_hook

# THE REBUILT SIZE IS CHECKED, not just printed.
#
# `the_shipped_typescript_sample_fits_this_bound` measures the COMMITTED blob, which a pin bump
# does not change -- so the promise that "a componentize-js upgrade past the bound is a failing
# test" was true only when dist/ happened to be regenerated in the same commit. This script is
# the only thing that builds from the current package.json pin, so it is the only place that
# number can be held against the cap before it reaches a deploy.
committed_bytes=$(wc -c < "$committed" | tr -d ' ')
fresh_bytes=$(wc -c < "$fresh" | tr -d ' ')
# The bound, read from the source of truth rather than repeated here.
cap_mib=$(sed -n 's/^pub(crate) const MAX_COMPONENT_BYTES: usize = \([0-9]*\) \* 1024 \* 1024;$/\1/p' \
            "$repo_root/crates/ironauth-admin/src/token_hooks.rs")
if [ -z "$cap_mib" ]; then
  echo "FAIL: could not read MAX_COMPONENT_BYTES from ironauth-admin/src/token_hooks.rs." >&2
  echo "  Its shape changed, so this check would silently compare against nothing." >&2
  exit 1
fi
cap_bytes=$(( cap_mib * 1024 * 1024 ))
echo "committed: $committed_bytes bytes; rebuilt: $fresh_bytes bytes; cap: $cap_bytes bytes"
if [ "$fresh_bytes" -gt "$cap_bytes" ]; then
  echo "FAIL: a component built from the CURRENT pin is $fresh_bytes bytes, over the" >&2
  echo "  ${cap_bytes}-byte MAX_COMPONENT_BYTES. Committing this artifact would ship a sample" >&2
  echo "  the admin surface refuses. Raise the bound in a migration, or hold the pin." >&2
  exit 1
fi
echo "OK: the committed TypeScript component behaves as its source says it does, and a" \
     "component built from the current pin still fits the upload cap."
