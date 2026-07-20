#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Freshness gate for the reference app's generated contract bindings (issue #85),
# mirroring the flow-schema and flow-golden freshness gates. The app binds the
# SAME published contract as the server: its TypeScript types, its schema derived
# validation constants, and its numeric id to copy map are GENERATED from
# docs/flow-schema.json and docs/flow-messages.json. This gate regenerates them
# and fails if the committed output drifts, so the reference app and the server
# can never diverge on the flow object shape or the message copy.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

python3 scripts/gen-reference-app-bindings.py
git diff --exit-code \
  packages/reference-app/src/contract/flow.gen.ts \
  packages/reference-app/src/contract/messages.gen.ts
echo "reference-app-bindings: clean (generated bindings match docs/flow-*.json)"
