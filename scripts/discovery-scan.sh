#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Discovery scan (issue #18 acceptance criterion 1): the OIDC discovery document
# is GENERATED from live config at serve time, never a hand-maintained artifact.
# This lint proves there is no static discovery JSON anywhere in the tree and that
# the document is assembled in exactly one place, the generator. A second copy in
# code, or a committed openid-configuration JSON, would be free to drift from the
# server's real behavior, which is the failure this scan exists to prevent.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# The ONE place the discovery document is built.
generator="crates/ironauth-oidc/src/discovery.rs"

fail=0

# 1. No committed JSON artifact that is a discovery document. A discovery document
#    is unmistakable by its required OIDC metadata keys.
json_hits=$(
  git ls-files -z '*.json' \
    | xargs -0 grep -l -e '"authorization_endpoint"' -e '"response_types_supported"' 2>/dev/null \
    || true
)
if [ -n "$json_hits" ]; then
  echo "discovery-scan: static discovery JSON found (must be generated, not stored):"
  echo "$json_hits"
  fail=1
fi

# 2. The discovery document is assembled ONLY by the generator. No other LIBRARY
#    source (src/**) may hand-build it; a second copy would drift. Reads and
#    assertions in tests/** are fine and are not scanned. The pathspec wildcard
#    crosses directory separators (git fnmatch without FNM_PATHNAME), so this also
#    catches nested modules like crates/*/src/foo/bar.rs, not just top-level files.
src_hits=$(
  {
    git ls-files -z 'crates/*/src/*.rs' \
      | xargs -0 grep -ln -e 'authorization_endpoint' -e 'openid-configuration' 2>/dev/null \
      | grep -v -x "$generator"
  } || true
)
if [ -n "$src_hits" ]; then
  echo "discovery-scan: discovery metadata assembled outside the generator ($generator):"
  echo "$src_hits"
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "discovery-scan: clean (discovery is generated from live config; no static artifact)"
