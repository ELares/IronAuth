#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The local merge gate: run everything CI runs that can run locally, in the
# same order. Green here should mean green in CI for the fmt, clippy, test,
# invariant, dash, and compatibility lanes; cargo-deny and the MSRV and musl
# lanes run in CI (install cargo-deny locally to close that gap too).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

echo "==> fmt"
cargo fmt --all --check

echo "==> clippy (pedantic, -D warnings)"
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "==> test"
cargo test --workspace --all-features

echo "==> invariant lints"
scripts/invariant-lints.sh

echo "==> dash scan"
scripts/dash-scan.sh

echo "==> compatibility matrix freshness"
scripts/compat-matrix.sh
git diff --exit-code docs/COMPATIBILITY.md

if command -v cargo-deny >/dev/null 2>&1; then
  echo "==> cargo deny"
  cargo deny check
else
  echo "==> cargo deny skipped (not installed; CI enforces it)"
fi

echo "gate: all local checks green"
