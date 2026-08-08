#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Prove the independently publishable crates actually package (issue #55, criterion 6).
#
# `cargo publish --dry-run` needs NO registry token: it resolves the manifest, packages the
# crate, and builds it from the packaged form. That last step is the one worth having, because
# it catches the failures a workspace build cannot see: a file the package excludes but the
# build needs, a path dependency with no version, or a dependency on a crate that is not itself
# published. All of those compile perfectly inside the workspace and fail at release time.
#
# The unit tests in the crate assert the STATIC half (no ironauth-* dependency, publish metadata
# present). This asserts the half only cargo can answer.
set -euo pipefail

PUBLISHABLE=(ironauth-hash-scheme)

for crate in "${PUBLISHABLE[@]}"; do
    # --allow-dirty because the gate runs against a working tree that legitimately carries the
    # change under review; the packaging question is about the manifest, not about git state.
    cargo publish --dry-run --quiet --allow-dirty -p "$crate"
    echo "publishable-crates: ${crate} packages and builds from its package"
done
