// SPDX-License-Identifier: MIT OR Apache-2.0

//! The PURE trust decision for guarded account linking (issue #78).
//!
//! This module is I/O-free by construction: it holds a single EXHAUSTIVE `match` over
//! the four trust inputs and returns a [`LinkDecision`]. It touches no store, no clock,
//! no network. That is what makes the decision table machine-checkable: a unit matrix
//! (below) asserts EVERY combination of the inputs, so the anti-takeover invariant is
//! encoded in code, not merely in prose.
//!
//! # Inputs
//!
//! - **P** = the environment's auto-link posture ([`AutoLinkPosture`]). Under the default
//!   `Off`, NO arm returns [`LinkDecision::AutoLink`].
//! - **local exists** = a pre-existing local account matches the upstream email.
//! - **L** = that local account's email is SERVER-verified (a `user_identifiers` row with
//!   `verified = true`, the server-owned column, never a client-writable trait).
//! - **U** = the upstream asserts `email_verified == true` in the JOSE-VERIFIED id-token
//!   claim map (never an unverified token).
//! - **T** = the connector's `email_verified` trust is `Trusted` (default `Untrusted`).
//!
//! # The structural anti-takeover guarantee
//!
//! [`LinkDecision::AutoLink`] is returned from EXACTLY ONE arm: the tuple
//! `(VerifiedToVerified, local_exists = true, L = true, U = true, Trusted)`. Because it is
//! a single exhaustive `match` (no `if` short-circuit, no OR-path), no future edit can add
//! an auto-link path without touching that one arm. "Unverified local", "missing upstream
//! `email_verified`", and "untrusted connector" are therefore non-AutoLink BY
//! CONSTRUCTION, and the `Off` posture is a second structural floor above them all.
//!
//! # Inertness (PR 1)
//!
//! This decision is NOT yet consulted by the live federated-login callback
//! (`finalize_federated_login`); a federated login still provisions a separate account
//! exactly as today. PR 2 wires the callback to dispatch on this result. The function is
//! unit-tested in isolation here so the table is proven correct before it goes live.

use ironauth_config::AutoLinkPosture;
use ironauth_connector::EmailVerifiedTrust;

/// What to do when a federated login's identity could be bound to a local account
/// (issue #78). The safe fallback is ALWAYS "do not merge": only the single `AutoLink` arm
/// auto-links; every weaker cell either provisions a separate account or surfaces the
/// manual-link interstitial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkDecision {
    /// Auto-link the federated identity into the pre-existing local account. Returned
    /// from EXACTLY ONE arm (posture `VerifiedToVerified`, verified local, upstream
    /// `email_verified`, trusted connector). Every other input yields a non-AutoLink
    /// decision by construction.
    AutoLink,
    /// Provision a SEPARATE federated account (today's issue #77 default): either the
    /// posture is `Off`, or there is no local collision to link into (a first-ever login
    /// for this identity).
    SeparateFederatedAccount,
    /// Do NOT auto-link: surface the Keycloak-safe "an account already exists, sign in to
    /// link" interstitial. A would-be login collided with an existing local account under
    /// the `VerifiedToVerified` posture, but the full trust conditions for an auto-link
    /// are not all met (unverified local, missing upstream `email_verified`, or an
    /// untrusted connector). The interstitial creates no session and links nothing; it
    /// instructs the user to authenticate locally and use the manual-link flow.
    ManualLinkInterstitial,
    /// A reserved hard-refuse decision (issue #78). No arm of the current table returns
    /// it: there is no hard-fail cell, because the safe fallback is always "don't merge"
    /// ([`SeparateFederatedAccount`](Self::SeparateFederatedAccount) or
    /// [`ManualLinkInterstitial`](Self::ManualLinkInterstitial)). It is part of the closed
    /// decision vocabulary so a future policy that must hard-refuse a merge has a typed
    /// outcome to return without widening the enum under pressure.
    Refuse,
}

/// The pure trust decision (issue #78): a single EXHAUSTIVE `match` over the four inputs.
///
/// `local_exists` is whether a pre-existing local account matches the upstream email;
/// `local_verified` is L; `upstream_email_verified` is U; `connector_trust` is T.
///
/// [`LinkDecision::AutoLink`] is returned from EXACTLY ONE arm; see the module docs.
#[must_use]
pub fn link_decision(
    posture: AutoLinkPosture,
    local_exists: bool,
    local_verified: bool,
    upstream_email_verified: bool,
    connector_trust: EmailVerifiedTrust,
) -> LinkDecision {
    use AutoLinkPosture::{Off, VerifiedToVerified};
    use EmailVerifiedTrust::Trusted;
    // The two SeparateFederatedAccount arms (posture Off, and opted-in with no local
    // collision) are DELIBERATELY kept distinct: they encode two structurally different
    // rows of the decision table, and merging them with `|` would obscure the table this
    // exhaustive match is the machine-checked encoding of.
    #[allow(clippy::match_same_arms)]
    match (
        posture,
        local_exists,
        local_verified,
        upstream_email_verified,
        connector_trust,
    ) {
        // The ONE arm that yields AutoLink: opted-in posture, a verified local account
        // (L), an upstream that asserts email_verified (U), and a trusted connector (T).
        (VerifiedToVerified, true, true, true, Trusted) => LinkDecision::AutoLink,

        // Posture Off (the conservative default): never auto-link and never interstitial.
        // A federated login provisions its own separate account exactly as issue #77 does
        // today, whether or not a local account with the same email exists.
        (Off, _, _, _, _) => LinkDecision::SeparateFederatedAccount,

        // Opted in, but no local collision: this is the first-ever login for this
        // identity, so it provisions its own account (nothing to link into).
        (VerifiedToVerified, false, _, _, _) => LinkDecision::SeparateFederatedAccount,

        // Opted in, a local collision exists, but the AutoLink tuple above was not
        // matched: an unverified local account, a missing upstream email_verified, or an
        // untrusted connector each falls here. Never auto-link; surface the interstitial.
        (VerifiedToVerified, true, _, _, _) => LinkDecision::ManualLinkInterstitial,
    }
}

#[cfg(test)]
mod tests {
    use super::{LinkDecision, link_decision};
    use ironauth_config::AutoLinkPosture;
    use ironauth_connector::EmailVerifiedTrust;

    /// The independently-computed expectation for one input tuple, kept SEPARATE from the
    /// production `match` so the test is not a tautology: it reasons from the decision
    /// table, not from the code under test.
    fn expected(
        posture: AutoLinkPosture,
        local_exists: bool,
        local_verified: bool,
        upstream: bool,
        trust: EmailVerifiedTrust,
    ) -> LinkDecision {
        // Off: never auto-link, never interstitial (today's separate-account default).
        if posture == AutoLinkPosture::Off {
            return LinkDecision::SeparateFederatedAccount;
        }
        // VerifiedToVerified with no local collision: first-ever login, separate account.
        if !local_exists {
            return LinkDecision::SeparateFederatedAccount;
        }
        // VerifiedToVerified with a local collision: auto-link ONLY when all three trust
        // conditions hold, else the manual interstitial.
        if local_verified && upstream && trust == EmailVerifiedTrust::Trusted {
            LinkDecision::AutoLink
        } else {
            LinkDecision::ManualLinkInterstitial
        }
    }

    /// The EXHAUSTIVE matrix: every combination of the five boolean/enum inputs (2^4 * 2
    /// = 32 tuples). Asserts the production decision equals the independently-computed
    /// expectation for every one, and that `AutoLink` is returned by EXACTLY the single
    /// `(VerifiedToVerified, exists, verified, upstream, Trusted)` tuple.
    #[test]
    fn decision_matrix_is_exhaustive_and_autolink_has_exactly_one_arm() {
        let postures = [AutoLinkPosture::Off, AutoLinkPosture::VerifiedToVerified];
        let trusts = [EmailVerifiedTrust::Untrusted, EmailVerifiedTrust::Trusted];
        let mut autolink_count = 0;
        let mut total = 0;
        for posture in postures {
            for local_exists in [false, true] {
                for local_verified in [false, true] {
                    for upstream in [false, true] {
                        for trust in trusts {
                            total += 1;
                            let got = link_decision(
                                posture,
                                local_exists,
                                local_verified,
                                upstream,
                                trust,
                            );
                            let want =
                                expected(posture, local_exists, local_verified, upstream, trust);
                            assert_eq!(
                                got, want,
                                "posture={posture:?} local_exists={local_exists} \
                                 local_verified={local_verified} upstream={upstream} \
                                 trust={trust:?}"
                            );
                            if got == LinkDecision::AutoLink {
                                autolink_count += 1;
                                // The one AutoLink tuple, asserted structurally.
                                assert_eq!(posture, AutoLinkPosture::VerifiedToVerified);
                                assert!(local_exists, "AutoLink requires a local account");
                                assert!(local_verified, "AutoLink requires a verified local (L)");
                                assert!(upstream, "AutoLink requires upstream email_verified (U)");
                                assert_eq!(
                                    trust,
                                    EmailVerifiedTrust::Trusted,
                                    "AutoLink requires a trusted connector (T)"
                                );
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(total, 32, "the matrix must cover all 32 input tuples");
        assert_eq!(
            autolink_count, 1,
            "AutoLink must be returned by EXACTLY one arm of the decision table"
        );
    }

    /// The default posture is `Off`, and under `Off` NO input can auto-link: a second
    /// structural floor above the trust table. This locks the conservative default.
    #[test]
    fn default_posture_is_off_and_off_never_autolinks() {
        assert_eq!(AutoLinkPosture::default(), AutoLinkPosture::Off);
        for local_exists in [false, true] {
            for local_verified in [false, true] {
                for upstream in [false, true] {
                    for trust in [EmailVerifiedTrust::Untrusted, EmailVerifiedTrust::Trusted] {
                        assert_ne!(
                            link_decision(
                                AutoLinkPosture::Off,
                                local_exists,
                                local_verified,
                                upstream,
                                trust,
                            ),
                            LinkDecision::AutoLink,
                            "posture Off must never auto-link"
                        );
                    }
                }
            }
        }
    }

    /// An UNVERIFIED local account can never be auto-linked, regardless of the upstream or
    /// the connector trust: the pre-account-takeover (nOAuth / Better-Auth CVE) defense,
    /// asserted as a structural impossibility on the L dimension.
    #[test]
    fn unverified_local_is_never_autolink() {
        for upstream in [false, true] {
            for trust in [EmailVerifiedTrust::Untrusted, EmailVerifiedTrust::Trusted] {
                assert_ne!(
                    link_decision(
                        AutoLinkPosture::VerifiedToVerified,
                        true,
                        false,
                        upstream,
                        trust,
                    ),
                    LinkDecision::AutoLink,
                    "an unverified local account must never auto-link"
                );
            }
        }
    }

    /// An UNTRUSTED connector can never be auto-linked, even with a verified local and a
    /// (forgeable) upstream `email_verified`: the T dimension locked structurally.
    #[test]
    fn untrusted_connector_is_never_autolink() {
        for local_verified in [false, true] {
            for upstream in [false, true] {
                assert_ne!(
                    link_decision(
                        AutoLinkPosture::VerifiedToVerified,
                        true,
                        local_verified,
                        upstream,
                        EmailVerifiedTrust::Untrusted,
                    ),
                    LinkDecision::AutoLink,
                    "an untrusted connector must never auto-link"
                );
            }
        }
    }
}
