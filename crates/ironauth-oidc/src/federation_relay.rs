// SPDX-License-Identifier: MIT OR Apache-2.0

//! Apple Hide My Email private-relay classification (issue #74), a DATA-driven quirk
//! handler.
//!
//! Apple's Hide My Email issues a per-app RELAY address at `privaterelay.appleid.com`.
//! Such an address is VERIFIED (Apple asserts it) but UNROUTABLE for operational mail
//! without the documented relay setup: sending to it directly is silently dropped. So it
//! must satisfy verification checks yet NEVER be selected as an operational mail routing
//! target. This module classifies an email against the connector's `relay_email_domain`
//! quirk (a domain string, never a provider switch) and provides the routing-target
//! selection policy the rest of the system uses.
//!
//! The relay decision is recorded as a boolean `email_relay` trait on the federated
//! identity (see the federation callback), so it persists across logins exactly like the
//! rest of the stored profile.

/// The trait key that records that a federated identity's email is an Apple Hide My Email
/// relay address (verified but unroutable).
pub const EMAIL_RELAY_TRAIT: &str = "email_relay";

/// Whether `email` is an Apple private-relay address for the connector's configured
/// `relay_domain` (issue #74): its host part equals the relay domain, case-insensitively.
///
/// A relay address is verified-but-unroutable. `relay_domain` is [`None`] for a connector
/// with no relay quirk, in which case no address is ever a relay.
#[must_use]
pub fn is_relay_email(email: &str, relay_domain: Option<&str>) -> bool {
    let Some(relay_domain) = relay_domain else {
        return false;
    };
    let Some((_local, host)) = email.rsplit_once('@') else {
        return false;
    };
    host.eq_ignore_ascii_case(relay_domain)
}

/// Select the operational mail routing target for a federated identity (issue #74): the
/// `email` when it is routable, or [`None`] when it is a verified-but-unroutable relay
/// address. This is the single policy point that guarantees a Hide My Email relay address
/// is never used as a routing target without the documented relay setup.
///
/// `email_relay` is the persisted relay flag (the `email_relay` trait). A relay address is
/// still a valid VERIFIED identity; it is only barred as a ROUTING target.
#[must_use]
pub fn routable_email(email: &str, email_relay: bool) -> Option<&str> {
    if email_relay { None } else { Some(email) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAY: &str = "privaterelay.appleid.com";

    #[test]
    fn a_relay_address_is_classified_verified_but_unroutable() {
        assert!(is_relay_email(
            "abc123@privaterelay.appleid.com",
            Some(RELAY)
        ));
        // Case-insensitive host match.
        assert!(is_relay_email(
            "abc123@PrivateRelay.AppleID.com",
            Some(RELAY)
        ));
        // It is never selected as a routing target.
        assert_eq!(
            routable_email("abc123@privaterelay.appleid.com", true),
            None
        );
    }

    #[test]
    fn an_ordinary_address_is_routable() {
        assert!(!is_relay_email("ada@example.test", Some(RELAY)));
        assert_eq!(
            routable_email("ada@example.test", false),
            Some("ada@example.test")
        );
    }

    #[test]
    fn a_connector_without_a_relay_quirk_classifies_nothing_as_relay() {
        assert!(!is_relay_email("abc123@privaterelay.appleid.com", None));
    }

    #[test]
    fn a_malformed_address_is_not_a_relay() {
        assert!(!is_relay_email("not-an-email", Some(RELAY)));
    }
}
