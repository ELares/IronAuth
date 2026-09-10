#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Emitted SETs validate with an EXTERNAL, INDEPENDENT library (issue #143 criterion 3).
#
# > Emitted SETs are signed with the environment's keys and validate with an external,
# > independent JWT/SET library against the environment JWKS.
#
# Two steps, and the split is the point. `ssf_set_corpus` mints one SET per algorithm a
# provisioned environment holds and writes it beside the JWKS that environment publishes;
# `validate-set-external.py` then judges what it wrote using PyJWT, which shares no line of code
# with this repository. Verifying an ironauth-jose signature with ironauth-jose is one
# implementation agreeing with itself.
#
# THE VALIDATOR NEEDS A THIRD PARTY PACKAGE, unlike every other gate here, and that is deliberate
# rather than an oversight: a stdlib-only second implementation would be a JOSE implementation
# this repository wrote, which is the thing the criterion rules out. It is provisioned from
# deploy/conformance/requirements-set.txt.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

if ! python3 -c "import jwt" >/dev/null 2>&1; then
    echo "ssf-set-external-validation: PyJWT is not installed." >&2
    echo "  python3 -m pip install -r deploy/conformance/requirements-set.txt" >&2
    echo "  (CI installs the same file with --require-hashes; see .github/workflows/ci.yml)" >&2
    exit 1
fi

# A FRESH DIRECTORY EVERY RUN. The corpus test clears what it is given, but pointing the
# validator at a path that survived a previous run is how a dropped algorithm goes on being
# validated from leftovers.
corpus="$(mktemp -d "${TMPDIR:-/tmp}/ssf-set-corpus.XXXXXX")"
trap 'rm -rf "$corpus"' EXIT

SSF_SET_CORPUS_DIR="$corpus" cargo test -p ironauth-oidc --test ssf_set_corpus -- --nocapture

python3 scripts/validate-set-external.py "$corpus"
