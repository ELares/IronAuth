#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Freshness gate for the admin console's COMMITTED embed (issue #323), mirroring
# scripts/admin-spa-bindings.sh and the other committed generated artifact gates
# (config-schema, flow-golden, openapi-check). The in process serving crate
# ironauth-admin-ui bakes the built console into the binary with rust-embed from
# crates/ironauth-admin-ui/embedded/, and that directory is COMMITTED so a plain
# cargo build (no Node toolchain) ships the real working console. This gate
# rebuilds the Vite dist and fails if the committed embed drifts from a fresh
# build, so the binary can never ship a stale console.
#
# The Vite build is byte reproducible (content hashed assets, no build time
# nondeterminism), so a fresh build reproduces the committed hashes exactly and
# this diff is stable rather than flaky.
#
# Like the bindings gate this drives the Node toolchain (npm ci + vite build), so
# it runs in the CI admin-spa job where Node is set up, not the python only
# invariants job.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

EMBED_DIR="crates/ironauth-admin-ui/embedded"
DIST_DIR="packages/admin-spa/dist"

# Build the console from a clean, locked install so the embed is exactly what the
# published contract produces (npm ci from the committed lockfile, then vite build).
npm --prefix packages/admin-spa ci --no-audit --no-fund
npm --prefix packages/admin-spa run build

# Replace the committed embed with the freshly built dist, byte for byte. The
# rm first so a removed or renamed hashed asset is reflected (a stale file left
# behind would otherwise hide drift).
rm -rf "$EMBED_DIR"
mkdir -p "$EMBED_DIR"
cp -R "$DIST_DIR"/. "$EMBED_DIR"/

# Fail if the working tree now differs from the commit. git status --porcelain
# reports modifications, deletions AND untracked additions (a new hashed asset
# filename), which a plain git diff would miss, so this catches every kind of
# drift in the embedded directory.
status="$(git status --porcelain -- "$EMBED_DIR")"
if [ -n "$status" ]; then
  echo "admin-spa-embed: STALE. The committed embed does not match a fresh Vite build." >&2
  echo "Rebuild and commit crates/ironauth-admin-ui/embedded/ (run this script, then git add)." >&2
  echo "$status" >&2
  exit 1
fi

echo "admin-spa-embed: clean (committed embed matches a fresh Vite build)"
