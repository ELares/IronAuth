#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Regenerates the management API OpenAPI 3.1 document from the annotated handlers
# (crates/ironauth-admin) into docs/openapi/management.json and fails if the
# committed file is stale. The spec is the source of truth: it is derived from
# the `#[utoipa::path]` annotations on the handlers, which are wired to the same
# paths in the router (a contract test pins the documented method+path set). This
# check fails the build if the COMMITTED artifact drifts from the code, so a
# handler change that is not reflected in the spec never merges. Mirrors
# scripts/config-schema.sh.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# Generate deterministically (database-free; the spec comes from the handler
# annotations, not a running server). The example prints the exact byte content
# committed to the artifact, including the trailing newline.
cargo run --quiet -p ironauth-admin --example openapi > docs/openapi/management.json

echo "openapi-check: docs/openapi/management.json regenerated"

# Fail on drift from the committed artifact.
if ! git diff --exit-code docs/openapi/management.json; then
  echo
  echo "openapi-check: the served management API spec drifted from the committed"
  echo "docs/openapi/management.json. Review the diff above and commit the update."
  exit 1
fi

echo "openapi-check: clean (served spec matches the committed artifact)"
