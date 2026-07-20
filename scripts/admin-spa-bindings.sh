#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Freshness gate for the admin console's generated management client bindings
# (issue #90), mirroring scripts/reference-app-bindings.sh and the openapi-check
# gate. The admin console binds the SAME published management contract the server
# serves: its TypeScript types (packages/admin-spa/src/api/management.gen.ts) are
# GENERATED from docs/openapi/management.json by openapi-typescript. This gate
# regenerates them and fails if the committed output drifts, so the console and
# the management API can never diverge on the request and response shapes.
#
# Unlike the reference-app bindings gate (a pure python regen), this one drives
# the Node toolchain (openapi-typescript), so it runs in the CI admin-spa job
# where Node is set up, not the python-only invariants job.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# Regenerate through the package script so the exact codegen invocation is the
# one source of truth (package.json "codegen"). npm ci must have been run first.
npm --prefix packages/admin-spa run codegen

git diff --exit-code packages/admin-spa/src/api/management.gen.ts
echo "admin-spa-bindings: clean (generated client matches docs/openapi/management.json)"
