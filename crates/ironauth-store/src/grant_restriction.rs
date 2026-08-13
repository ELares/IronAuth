// SPDX-License-Identifier: MIT OR Apache-2.0

//! The shared grant-restriction seam (issue #125).
//!
//! Issue #125 requires that "client restriction enforcement lives in ONE shared grant-handler
//! seam applied uniformly to every grant type, so a new grant cannot recreate the Dex bypass".
//!
//! The bypass it names is a real and recurring shape: a server checks "may this client use this
//! grant" inside each grant handler, someone adds a new grant type, and the new handler simply
//! does not carry the check. Nothing fails. No test covers it, because the test suite grew
//! alongside the handlers that DID have it. The gap is discovered by someone using it.
//!
//! # The defence is exhaustiveness, not diligence
//!
//! One function decides for every grant type, and it matches on an enum with no wildcard arm.
//! Adding a variant therefore fails to COMPILE until someone writes its rule down. That is the
//! only version of this that survives contact with a codebase people are still adding to:
//! a convention that every handler must remember to call something is exactly the convention
//! the bypass is made of.
//!
//! The test suite adds a second layer by enumerating every variant explicitly, so a variant
//! added with a hastily-copied arm still has to appear in a list a reviewer reads.

/// Every grant type this server implements.
///
/// Adding a variant here forces a decision in [`client_may_use`], because that match has no
/// wildcard. Resist adding one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GrantType {
    /// RFC 6749 authorization code.
    AuthorizationCode,
    /// RFC 6749 refresh token.
    RefreshToken,
    /// RFC 6749 client credentials.
    ClientCredentials,
    /// RFC 8628 device authorization.
    DeviceCode,
    /// RFC 7523 JWT bearer assertion.
    JwtBearer,
    /// RFC 8693 token exchange.
    TokenExchange,
}

impl GrantType {
    /// Every variant, for the exhaustiveness guard in the tests.
    ///
    /// Deliberately a hand-written list rather than a derive: it is the thing a reviewer reads
    /// to check nothing was added quietly, and a derive would make it agree with the enum
    /// automatically and therefore prove nothing.
    pub const ALL: [Self; 6] = [
        Self::AuthorizationCode,
        Self::RefreshToken,
        Self::ClientCredentials,
        Self::DeviceCode,
        Self::JwtBearer,
        Self::TokenExchange,
    ];

    /// The RFC wire value for this grant.
    #[must_use]
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::RefreshToken => "refresh_token",
            Self::ClientCredentials => "client_credentials",
            Self::DeviceCode => "urn:ietf:params:oauth:grant-type:device_code",
            Self::JwtBearer => "urn:ietf:params:oauth:grant-type:jwt-bearer",
            Self::TokenExchange => "urn:ietf:params:oauth:grant-type:token-exchange",
        }
    }
}

/// What a client is permitted to do.
#[derive(Debug, Clone)]
pub struct ClientGrantPolicy {
    /// The grants this client is registered for. RFC 7591 `grant_types`.
    pub allowed: Vec<GrantType>,
    /// Whether the client authenticates. A public client is one that cannot keep a secret.
    pub confidential: bool,
}

/// Why a grant was refused for this client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantDenial {
    /// The grant is not in the client's registered set.
    NotRegistered,
    /// The grant requires a confidential client and this one is public.
    RequiresConfidentialClient,
}

impl GrantDenial {
    /// A stable, value-free description.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotRegistered => "the client is not registered for this grant type",
            Self::RequiresConfidentialClient => {
                "this grant requires a confidential client and this one is public"
            }
        }
    }
}

/// Whether `grant` requires a client that can authenticate.
///
/// This match has NO wildcard, on purpose. A new grant type does not compile until someone
/// states which side it falls on, which is the whole anti-bypass mechanism: the decision cannot
/// be skipped, only made.
#[must_use]
pub fn requires_confidential_client(grant: GrantType) -> bool {
    match grant {
        // A public client legitimately uses these: the authorization code flow with PKCE, its
        // refresh, and the device flow are all designed for clients that cannot keep a secret.
        GrantType::AuthorizationCode | GrantType::RefreshToken | GrantType::DeviceCode => false,
        // The user-absent grants. All three act with no human in the loop, so the CLIENT is the
        // only principal being authenticated, and a public client using any of them would be an
        // unauthenticated caller minting tokens.
        //
        // Token exchange belongs here for a slightly different reason worth keeping written
        // down: it trades one credential for another, and its delegation and impersonation
        // modes act on a subject's behalf, so a public client could trade any token it happened
        // to obtain for another one.
        //
        // Merging these into one arm does not weaken the anti-bypass property. That comes from
        // this match having NO WILDCARD, so a new variant fails to compile until its rule is
        // written; arm count is irrelevant to it.
        GrantType::ClientCredentials | GrantType::JwtBearer | GrantType::TokenExchange => true,
    }
}

/// The one check every grant handler runs.
///
/// # Errors
///
/// [`GrantDenial`] naming the first rule that refused.
pub fn client_may_use(policy: &ClientGrantPolicy, grant: GrantType) -> Result<(), GrantDenial> {
    // Registration first: "you never asked for this grant" is a more fundamental answer than
    // "you are the wrong kind of client for it", and reporting the latter to a client that was
    // never registered would tell it which grants exist to ask for.
    if !policy.allowed.contains(&grant) {
        return Err(GrantDenial::NotRegistered);
    }
    if requires_confidential_client(grant) && !policy.confidential {
        return Err(GrantDenial::RequiresConfidentialClient);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ClientGrantPolicy, GrantDenial, GrantType, client_may_use, requires_confidential_client,
    };

    fn policy(allowed: &[GrantType], confidential: bool) -> ClientGrantPolicy {
        ClientGrantPolicy {
            allowed: allowed.to_vec(),
            confidential,
        }
    }

    /// THE anti-bypass guard: every grant type is named here explicitly.
    ///
    /// The enum match in `requires_confidential_client` has no wildcard, so a new variant fails
    /// to compile until its rule is written. This adds a second layer: the variant must also
    /// appear in a list a reviewer reads, so a hastily-copied arm still surfaces in review.
    ///
    /// `ALL` is hand-written rather than derived for exactly that reason. A derive would agree
    /// with the enum automatically and prove nothing.
    #[test]
    fn every_grant_type_is_enumerated_and_decided() {
        let named = [
            GrantType::AuthorizationCode,
            GrantType::RefreshToken,
            GrantType::ClientCredentials,
            GrantType::DeviceCode,
            GrantType::JwtBearer,
            GrantType::TokenExchange,
        ];
        assert_eq!(
            named.len(),
            GrantType::ALL.len(),
            "a grant type was added without being named in this test"
        );
        let mut sorted = GrantType::ALL;
        sorted.sort_unstable();
        let mut expected = named;
        expected.sort_unstable();
        assert_eq!(sorted, expected);

        // And every one has a decision and a distinct wire value.
        let mut wires = std::collections::BTreeSet::new();
        for grant in GrantType::ALL {
            let _ = requires_confidential_client(grant);
            assert!(
                wires.insert(grant.as_wire()),
                "{grant:?} shares a wire value with another grant"
            );
        }
        assert_eq!(wires.len(), GrantType::ALL.len());
    }

    /// A grant the client never registered for is refused, whatever kind of client it is.
    #[test]
    fn an_unregistered_grant_is_refused() {
        let confidential = policy(&[GrantType::AuthorizationCode], true);
        assert_eq!(
            client_may_use(&confidential, GrantType::ClientCredentials).unwrap_err(),
            GrantDenial::NotRegistered
        );
        // Even a confidential client, which would pass the second check, is refused here.
    }

    /// Registration is checked FIRST, so a client that never registered is told that rather
    /// than being told it is the wrong kind of client, which would disclose that the grant
    /// exists and what it needs.
    #[test]
    fn registration_is_checked_before_client_kind() {
        let public_unregistered = policy(&[GrantType::AuthorizationCode], false);
        assert_eq!(
            client_may_use(&public_unregistered, GrantType::ClientCredentials).unwrap_err(),
            GrantDenial::NotRegistered,
            "an unregistered grant must not report the confidential-client requirement"
        );
    }

    /// The grants that mint tokens with no user present require an authenticated client.
    #[test]
    fn user_absent_grants_require_a_confidential_client() {
        for grant in [
            GrantType::ClientCredentials,
            GrantType::JwtBearer,
            GrantType::TokenExchange,
        ] {
            assert!(requires_confidential_client(grant), "{grant:?}");
            let public = policy(&[grant], false);
            assert_eq!(
                client_may_use(&public, grant).unwrap_err(),
                GrantDenial::RequiresConfidentialClient,
                "{grant:?} must refuse a public client"
            );
            // The same registration on a confidential client is permitted, so the refusal is
            // the client kind and nothing else.
            assert!(
                client_may_use(&policy(&[grant], true), grant).is_ok(),
                "{grant:?}"
            );
        }
    }

    /// The grants designed for clients that cannot keep a secret must NOT require one.
    ///
    /// Requiring it would break every SPA and native app, which is the opposite failure and
    /// just as important to pin.
    #[test]
    fn public_client_grants_do_not_require_confidentiality() {
        for grant in [
            GrantType::AuthorizationCode,
            GrantType::RefreshToken,
            GrantType::DeviceCode,
        ] {
            assert!(!requires_confidential_client(grant), "{grant:?}");
            assert!(
                client_may_use(&policy(&[grant], false), grant).is_ok(),
                "{grant:?} must work for a public client"
            );
        }
    }

    /// Token exchange specifically requires a confidential client.
    ///
    /// Called out separately because it is the grant this issue adds, and a public client able
    /// to exchange could trade any token it obtained for another.
    #[test]
    fn token_exchange_requires_a_confidential_client() {
        let public = policy(&[GrantType::TokenExchange], false);
        assert_eq!(
            client_may_use(&public, GrantType::TokenExchange).unwrap_err(),
            GrantDenial::RequiresConfidentialClient
        );
    }

    #[test]
    fn a_registered_grant_on_the_right_client_is_permitted() {
        let client = policy(&GrantType::ALL, true);
        for grant in GrantType::ALL {
            assert!(client_may_use(&client, grant).is_ok(), "{grant:?}");
        }
    }

    #[test]
    fn every_denial_describes_itself_distinctly() {
        let all = [
            GrantDenial::NotRegistered,
            GrantDenial::RequiresConfidentialClient,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for denial in all {
            assert!(denial.as_str().len() > 20);
            assert!(seen.insert(denial.as_str()), "{denial:?} shares its text");
        }
        assert_eq!(seen.len(), all.len());
    }
}
