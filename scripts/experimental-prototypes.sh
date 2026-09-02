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
    # 92, not 52: identity-chaining's pinned value is two draft names joined by a `+` and is
    # 89 characters, so the narrower column pushed its note off the row and the table stopped
    # lining up. A revision column too narrow for the longest revision is a table that reports
    # correctly and reads wrong.
    printf '  %-28s %-92s %s\n' FLAG REVISION 'UPGRADE-RISK NOTE'
    # ONE row per prototype and ONE extraction, rather than the copy per prototype this started
    # as. Four near-identical blocks was already three chances for a bump to be applied to some
    # of them; a fifth would have made that the shape of the file. The table below is the only
    # thing a new prototype adds.
    local flag const note pinned
    while read -r flag const note; do
        [ -n "$flag" ] || continue
        # `|| true` is load-bearing, and it took a mutation to see why. `set -e` with
        # `pipefail` aborts the whole script the moment the first grep matches nothing -- so
        # the check below, written to explain exactly that failure, could never run. The lane
        # exited 1 with no message at all, which is a worse answer than the one it was built to
        # give: red, and silent about which prototype's extraction broke.
        pinned=$(grep -A1 "pub const ${const}" \
            crates/ironauth-config/src/features.rs | grep -oE '"[^"]+"' | tr -d '"' || true)
        # REFUSE an empty table rather than print one. This whole function exists so a green run
        # says WHICH revision was satisfied; a grep that silently stopped matching -- a rename, a
        # reformat that moved the literal off the following line -- would leave a blank column
        # that reads as "no pinned revision" and passes. The lane would then be green about
        # nothing.
        if [ -z "$pinned" ]; then
            echo "experimental-prototypes: could not read the pinned revision for ${flag}" \
                 "(${const}) out of crates/ironauth-config/src/features.rs." >&2
            echo "The table is derived from the SOURCE on purpose; fix the extraction rather" \
                 "than hard-coding the revision here." >&2
            exit 1
        fi
        printf '  %-28s %-92s %s\n' "$flag" "$pinned" "$note"
    done <<'ROWS'
attestation-client-auth ATTESTATION_CLIENT_AUTH_VERSION docs/experimental/attestation-client-auth.md
authzen-agent-profile AUTHZEN_AGENT_PROFILE_VERSION docs/experimental/authzen-agent-profile.md
transaction-tokens TRANSACTION_TOKENS_VERSION docs/experimental/transaction-tokens.md
identity-chaining IDENTITY_CHAINING_VERSION docs/experimental/identity-chaining.md
ROWS
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
# And the BOOT path: both conditions required, neither sufficient, a duplicate issuer dropped.
# The filter is `attester`, not `attestation`: the test is
# `tests::the_attester_registry_needs_the_ack_and_an_attester` in a different package, and the
# lane ran `-p ironauth-config attestation` believing it covered this. It matched nothing.
cargo test -p ironauth --bin ironauth attester

echo
echo "== AuthZEN agent tool profile =="
# The intersection, the confinement, the suspended-agent denial, and the OFF posture. Needs a
# database.
cargo test -p ironauth-admin --features testing --test authzen_agent_profile
# And the flag: off by default, and an ack for the wrong version refuses the BOOT rather than
# quietly leaving it off. Needs no database.
cargo test -p ironauth-config authzen
# And the BOOT wiring: armed by ITS OWN acknowledgment and not by another prototype's. The lane
# made this exact omission for attestation four lines above; the filter is `agent_tool_profile`,
# and it lives in a different package from the registry test.
cargo test -p ironauth --bin ironauth agent_tool_profile

echo
echo "== transaction tokens =="
# What the token carries, the refusal without a trust domain, the lifetime clamp, and that it
# does not verify as an access token. Needs no database.
cargo test -p ironauth-oidc --test transaction_tokens
# And the EXCHANGE: that the branch sits after every policy check, that an unarmed deployment
# answers as it does for any unknown URI, and that the audit row is written. Needs a database.
cargo test -p ironauth-oidc --features testing --test token_exchange transaction
# And the BOOT wiring: the ack AND a domain, and another prototype's ack arming nothing.
cargo test -p ironauth --bin ironauth transaction_token

echo
echo "== identity chaining / ID-JAG (receiving side) =="
# The four admission rules, each driven by minting the honest assertion and changing exactly
# one thing. Needs no database.
cargo test -p ironauth-oidc --test identity_chaining
# And the GRANT: that it reaches those rules, that every ordinary jwt-bearer refusal still
# fires, and that the assertion's scope is not a way past the machine-grant floor or the
# presenting client's allowlist. Needs a database.
#
# The filter is `id_jag`, and every grant test in that section is NAMED for it. That is not a
# convention, it is the lane's coverage: the first version of this line matched exactly ONE of
# them -- the unarmed-posture test, the only one that still passes with the whole prototype
# deleted -- so the lane was green having exercised none of the checks it names above. A test
# in `structural.rs` now fails if an ID-JAG test is added without the substring, because a
# filter and a naming convention with nothing holding them together drift the moment someone
# writes the obvious name. `identity_chaining` was the alternative and matches ZERO tests.
cargo test -p ironauth-oidc --features testing --test jwt_bearer id_jag
# And the BOOT wiring: armed by ITS OWN acknowledgment, refusing the boot on a missing or stale
# one, and not armed by another prototype's.
cargo test -p ironauth --bin ironauth identity_chaining
echo
echo "experimental-prototypes: all pinned prototypes passed at the revisions above"
