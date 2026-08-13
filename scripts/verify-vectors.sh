#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Regenerate the cross-language JWT verification conformance corpus (issue #118) from
# `packages/ironauth-sdk/scripts/generate-vectors.mjs`.
#
#   packages/ironauth-sdk/vectors/verify-vectors.json
#
# Issue #118 ships six independent verifiers (Cloudflare Workers, Fastly Compute in Rust,
# Lambda@Edge, plain WebCrypto, and official Java and .NET artifacts). All six are judged
# against THIS one corpus, which is the only way "they all agree" is measured rather than
# hoped. The corpus is therefore a contract, not a fixture.
#
# The generator is deterministic (fixed keys, a fixed evaluation instant, fixed claims), so
# regenerating produces byte-identical output and a drift here is always a real change.
#
# WHY THIS GATE EXISTS. A conformance corpus is exactly the artifact someone weakens under
# deadline: delete the `alg_none` vector and every verifier goes green. Committing the corpus
# WITHOUT this check would make that edit invisible, because the file would simply be whatever
# was last committed. With it, the corpus can only change by changing the generator, in a diff
# a reviewer reads.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# shellcheck source=scripts/lib/generated-artifact.sh
. scripts/lib/generated-artifact.sh

CORPUS="packages/ironauth-sdk/vectors/verify-vectors.json"

node packages/ironauth-sdk/scripts/generate-vectors.mjs >/dev/null

echo "verify-vectors: ${CORPUS} regenerated"
require_tracked "verify-vectors" "${CORPUS}" || exit 1
if ! git diff --exit-code "${CORPUS}" >/dev/null 2>&1; then
    echo "verify-vectors: the committed corpus is STALE."
    echo "  Review the diff carefully. A REMOVED or WEAKENED vector is the change this gate"
    echo "  exists to surface: dropping a refusal case makes every verifier in issue #118 go"
    echo "  green on a token it should refuse."
    git --no-pager diff -- "${CORPUS}" || true
    exit 1
fi
echo "verify-vectors: clean"
