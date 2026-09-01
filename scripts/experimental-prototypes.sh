#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The version-tagged draft prototypes (issue #133), in one place.
#
# WHY A SCRIPT AND NOT A LIST OF `cargo test` LINES IN THE WORKFLOW. Two reasons, and the
# second is the one that matters. A workflow-inline list is not runnable locally, so the lane
# that is hardest to reason about is the one nobody can drive by hand. And the pinned draft
# revisions have to be REPORTED, not just implied: a green run of this lane should tell a
# reader WHICH revision was satisfied, because "the prototype passes" is meaningless without
# it -- the whole risk these surfaces carry is that the draft moves underneath them.
#
# `--revisions` prints the revision table and exits. The CI lane runs it as its own step so the
# table appears in the log above the test output rather than buried in it.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# One row per prototype: the flag, the pinned revision, and the note that records its upgrade
# risk. Read from the SOURCE constants rather than restated, so a bump cannot make this table
# stale -- a hand-written revision beside a code constant is the defect this repository keeps
# finding in its own documentation.
revisions() {
    echo "Issue #133 prototypes, and the exact revision each pins:"
    echo
    printf '  %-28s %-52s %s\n' FLAG REVISION 'UPGRADE-RISK NOTE'
    local pinned
    pinned=$(grep -A1 'pub const ATTESTATION_CLIENT_AUTH_VERSION' \
        crates/ironauth-config/src/features.rs | grep -oE '"[^"]+"' | tr -d '"')
    printf '  %-28s %-52s %s\n' \
        'attestation-client-auth' "$pinned" 'docs/experimental/attestation-client-auth.md'
    echo
    echo "Each is EXPERIMENTAL and off by default; enabling one requires an acknowledgment"
    echo "equal to the revision above, so a draft bump invalidates it deliberately."
}

if [ "${1:-}" = "--revisions" ]; then
    revisions
    exit 0
fi

revisions
echo
echo "== attestation-based client authentication =="
# The verification seam: every refusal the draft names, driven by minting the attack. Needs no
# database, so it runs even where the service container is unavailable.
cargo test -p ironauth-oidc --test attestation_client_auth
# The TOKEN ENDPOINT: that the seam is reachable, that the default posture reaches nobody, and
# that the method is not advertised. Needs a database.
cargo test -p ironauth-oidc --features testing --test attestation_token_endpoint
# The default-posture proof: the flag is off and the section is empty in `Config::default()`.
cargo test -p ironauth-config attestation

echo
echo "experimental-prototypes: all pinned prototypes passed at the revisions above"
