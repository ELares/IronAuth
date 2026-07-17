// SPDX-License-Identifier: MIT OR Apache-2.0

//! First-party connector PRESETS (issue #74): Google, Apple, Microsoft, GitHub, and a
//! generic OIDC upstream, expressed as pure connector DATA on the #75 declarative
//! framework.
//!
//! The strategy is breadth versus depth: rather than absorb a provider long tail as
//! in-tree code, IronAuth ships four deeply tested first-party connectors and lets the
//! long tail be data. Each preset here is a [`ConnectorDefinition`] BUILDER: it fills in
//! the provider's stable, well-known facts (its issuer or endpoints, the scopes to
//! request, the claim mapping, the capability matrix, and the documented quirks), and
//! takes only the operator-supplied per-environment credentials (the client id and the
//! sealed secret; Apple additionally the team id and key id). There is NO provider
//! branch anywhere in the login path: a preset is data, and the sharp edges (Apple's
//! signed-JWT client secret, its first-authorization-only profile and Hide My Email
//! relay, GitHub's email endpoint) are handled by DATA-driven quirk handlers, not by
//! switching on a provider name.
//!
//! # Capability matrix accuracy
//!
//! Every preset populates its [`CapabilityMatrix`] accurately from the provider's real
//! behavior (refresh support, whether the upstream `email_verified` is trusted, whether
//! it delivers groups, whether it propagates logout). These are the values an operator
//! introspects; they are conservative where a provider's behavior is not authoritative.

use ironauth_config::Secret;

use crate::{
    CapabilityMatrix, ClaimMapping, ClaimRule, ClientAuth, ConnectorDefinition, DiscoveryEndpoints,
    EmailSource, EmailVerifiedTrust, Endpoints, OAuth2Endpoints, PkceMode, Protocol, Quirks,
};

/// Apple's OIDC issuer.
const APPLE_ISSUER: &str = "https://appleid.apple.com";
/// Apple's Hide My Email private-relay domain.
const APPLE_RELAY_DOMAIN: &str = "privaterelay.appleid.com";
/// Google's OIDC issuer.
const GOOGLE_ISSUER: &str = "https://accounts.google.com";

/// A required claim rule over a single `source` path.
fn required(path: &str) -> ClaimRule {
    ClaimRule {
        source: vec![path.to_owned()],
        required: true,
    }
}

/// An optional claim rule over a single `source` path.
fn optional(path: &str) -> ClaimRule {
    ClaimRule {
        source: vec![path.to_owned()],
        required: false,
    }
}

/// Assemble a trait mapping from `(field, rule)` pairs.
fn traits(pairs: impl IntoIterator<Item = (&'static str, ClaimRule)>) -> ClaimMapping {
    ClaimMapping {
        subject: None,
        traits: pairs
            .into_iter()
            .map(|(field, rule)| (field.to_owned(), rule))
            .collect(),
    }
}

/// The generic OIDC upstream preset (issue #74): a ready-to-use discovery-form connector
/// for any standards-compliant OIDC provider. The operator supplies the `issuer`, the
/// requested `scopes`, and the credentials; email is read from the ID token and, by the
/// conservative default, the upstream `email_verified` is NOT trusted.
#[must_use]
pub fn generic_oidc(
    connector_id: impl Into<String>,
    display_name: impl Into<String>,
    issuer: impl Into<String>,
    client_id: impl Into<String>,
    client_secret: Secret,
    scopes: Vec<String>,
) -> ConnectorDefinition {
    ConnectorDefinition {
        connector_id: connector_id.into(),
        display_name: display_name.into(),
        protocol: Protocol::Oidc,
        endpoints: Endpoints::Discovery(DiscoveryEndpoints {
            issuer: issuer.into(),
        }),
        scopes,
        client_id: client_id.into(),
        client_secret,
        client_auth: ClientAuth::Static,
        pkce: PkceMode::AutoWhereSupported,
        claim_mapping: traits([("email", optional("email"))]),
        capabilities: CapabilityMatrix::default(),
        quirks: Quirks::default(),
        passthrough: crate::PassthroughPolicy::default(),
        enabled: true,
    }
}

/// The Google connector preset (issue #74): standard OIDC via discovery. Google supports
/// refresh tokens, publishes a trustworthy `email_verified`, and does not deliver group
/// memberships or propagate logout through the OIDC surface.
#[must_use]
pub fn google(
    connector_id: impl Into<String>,
    client_id: impl Into<String>,
    client_secret: Secret,
) -> ConnectorDefinition {
    ConnectorDefinition {
        connector_id: connector_id.into(),
        display_name: "Google".to_owned(),
        protocol: Protocol::Oidc,
        endpoints: Endpoints::Discovery(DiscoveryEndpoints {
            issuer: GOOGLE_ISSUER.to_owned(),
        }),
        scopes: vec![
            "openid".to_owned(),
            "email".to_owned(),
            "profile".to_owned(),
        ],
        client_id: client_id.into(),
        client_secret,
        client_auth: ClientAuth::Static,
        pkce: PkceMode::AutoWhereSupported,
        claim_mapping: traits([("email", required("email")), ("name", optional("name"))]),
        capabilities: CapabilityMatrix {
            refresh: true,
            groups: false,
            logout_propagation: false,
            email_verified_trust: EmailVerifiedTrust::Trusted,
        },
        quirks: Quirks::default(),
        passthrough: crate::PassthroughPolicy::default(),
        enabled: true,
    }
}

/// The Microsoft connector preset (issue #74): standard OIDC via discovery against a
/// per-tenant v2.0 issuer (`https://login.microsoftonline.com/{tenant}/v2.0`, where
/// `{tenant}` is a directory id, `organizations`, `consumers`, or `common`). Microsoft
/// supports refresh, publishes a trustworthy `email_verified`, and can deliver group
/// memberships; it does not propagate logout through this surface.
#[must_use]
pub fn microsoft(
    connector_id: impl Into<String>,
    tenant: &str,
    client_id: impl Into<String>,
    client_secret: Secret,
) -> ConnectorDefinition {
    let issuer = format!("https://login.microsoftonline.com/{tenant}/v2.0");
    ConnectorDefinition {
        connector_id: connector_id.into(),
        display_name: "Microsoft".to_owned(),
        protocol: Protocol::Oidc,
        endpoints: Endpoints::Discovery(DiscoveryEndpoints { issuer }),
        scopes: vec![
            "openid".to_owned(),
            "email".to_owned(),
            "profile".to_owned(),
        ],
        client_id: client_id.into(),
        client_secret,
        client_auth: ClientAuth::Static,
        pkce: PkceMode::AutoWhereSupported,
        claim_mapping: traits([("email", required("email")), ("name", optional("name"))]),
        capabilities: CapabilityMatrix {
            refresh: true,
            groups: true,
            logout_propagation: false,
            email_verified_trust: EmailVerifiedTrust::Trusted,
        },
        quirks: Quirks::default(),
        passthrough: crate::PassthroughPolicy::default(),
        enabled: true,
    }
}

/// The Apple "Sign in with Apple" connector preset (issue #74), the connector most
/// frequently fumbled elsewhere. Every sharp edge is expressed as DATA and handled by a
/// documented quirk handler:
///
/// - **Signed-JWT client secret.** Apple does not use a static shared secret; it requires
///   a per-request ES256 JWT assertion. [`ClientAuth::SignedJwt`] carries the `team_id`,
///   `key_id`, and audience; the sealed `client_secret` holds the operator's EC private
///   key, and the federation callback regenerates a short-lived assertion each exchange.
/// - **First-authorization-only profile.** Apple delivers name and email ONLY on the
///   first authorization. [`Quirks::profile_delivered_first_auth_only`] makes a returning
///   login reuse the stored profile instead of failing the required-email check.
/// - **Hide My Email relay.** [`Quirks::relay_email_domain`] names `privaterelay.appleid.com`
///   so a relay address is classified verified-but-unroutable.
/// - **Sticky scopes.** [`Quirks::sticky_scopes`] records that a changed scope set does not
///   re-deliver the profile.
///
/// Apple publishes a trustworthy `email_verified` but supports neither groups nor logout
/// propagation, and issues no long-lived refresh usable for silent renewal here.
#[must_use]
pub fn apple(
    connector_id: impl Into<String>,
    client_id: impl Into<String>,
    team_id: impl Into<String>,
    key_id: impl Into<String>,
    private_key: Secret,
) -> ConnectorDefinition {
    let client_id = client_id.into();
    ConnectorDefinition {
        connector_id: connector_id.into(),
        display_name: "Apple".to_owned(),
        protocol: Protocol::Oidc,
        endpoints: Endpoints::Discovery(DiscoveryEndpoints {
            issuer: APPLE_ISSUER.to_owned(),
        }),
        scopes: vec!["openid".to_owned(), "email".to_owned(), "name".to_owned()],
        client_id: client_id.clone(),
        client_secret: private_key,
        client_auth: ClientAuth::SignedJwt {
            team_id: team_id.into(),
            key_id: key_id.into(),
            audience: APPLE_ISSUER.to_owned(),
        },
        pkce: PkceMode::AutoWhereSupported,
        claim_mapping: traits([
            ("email", required("email")),
            ("name", optional("name")),
            ("email_relay", optional("email_relay")),
        ]),
        capabilities: CapabilityMatrix {
            refresh: false,
            groups: false,
            logout_propagation: false,
            email_verified_trust: EmailVerifiedTrust::Trusted,
        },
        quirks: Quirks {
            profile_delivered_first_auth_only: true,
            email_source: EmailSource::IdToken,
            userinfo_required: false,
            relay_email_domain: Some(APPLE_RELAY_DOMAIN.to_owned()),
            sticky_scopes: true,
        },
        passthrough: crate::PassthroughPolicy::default(),
        enabled: true,
    }
}

/// The GitHub connector preset (issue #74): a NON-OIDC OAuth 2.0 upstream (there is no ID
/// token). The identity is read from the `/user` profile endpoint, and because the profile
/// may omit a usable email, the primary VERIFIED email is resolved from `/user/emails`.
/// The identity is keyed on the stable numeric GitHub `id` (namespaced by
/// `https://api.github.com`), never the mutable `login` or email.
///
/// GitHub issues no OIDC-style `email_verified` claim, so it is `Untrusted` here; the
/// verified flag is resolved from the email endpoint at login instead. GitHub supports
/// neither refresh (for this app flow), OIDC groups, nor logout propagation.
#[must_use]
pub fn github(
    connector_id: impl Into<String>,
    client_id: impl Into<String>,
    client_secret: Secret,
) -> ConnectorDefinition {
    ConnectorDefinition {
        connector_id: connector_id.into(),
        display_name: "GitHub".to_owned(),
        protocol: Protocol::Oauth2,
        endpoints: Endpoints::OAuth2(OAuth2Endpoints::new(
            "https://github.com/login/oauth/authorize",
            "https://github.com/login/oauth/access_token",
            "https://api.github.com/user",
            Some("https://api.github.com/user/emails".to_owned()),
            "https://api.github.com",
        )),
        scopes: vec!["read:user".to_owned(), "user:email".to_owned()],
        client_id: client_id.into(),
        client_secret,
        client_auth: ClientAuth::Static,
        pkce: PkceMode::AutoWhereSupported,
        claim_mapping: traits([
            ("email", required("email")),
            ("name", optional("name")),
            ("login", optional("login")),
        ]),
        capabilities: CapabilityMatrix {
            refresh: false,
            groups: false,
            logout_propagation: false,
            email_verified_trust: EmailVerifiedTrust::Untrusted,
        },
        quirks: Quirks::default(),
        passthrough: crate::PassthroughPolicy::default(),
        enabled: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> Secret {
        Secret::Env("PRESET_SECRET".to_owned())
    }

    #[test]
    fn every_preset_validates_and_carries_accurate_capabilities() {
        let google = google("google", "gid", secret());
        google.validate().expect("google validates");
        assert!(google.capabilities().refresh);
        assert_eq!(
            google.capabilities().email_verified_trust,
            EmailVerifiedTrust::Trusted
        );

        let microsoft = microsoft("microsoft", "common", "mid", secret());
        microsoft.validate().expect("microsoft validates");
        assert!(microsoft.capabilities().groups);

        let apple = apple("apple", "com.example.app", "TEAMID", "KEYID", secret());
        apple.validate().expect("apple validates");
        assert!(matches!(apple.client_auth, ClientAuth::SignedJwt { .. }));
        assert!(apple.quirks.profile_delivered_first_auth_only);
        assert_eq!(
            apple.quirks.relay_email_domain.as_deref(),
            Some(APPLE_RELAY_DOMAIN)
        );
        assert!(apple.quirks.sticky_scopes);

        let github = github("github", "ghid", secret());
        github.validate().expect("github validates");
        assert_eq!(github.protocol, Protocol::Oauth2);
        assert!(matches!(github.endpoints, Endpoints::OAuth2(_)));

        let generic = generic_oidc(
            "generic",
            "Example",
            "https://issuer.example.com",
            "cid",
            secret(),
            vec!["openid".to_owned(), "email".to_owned()],
        );
        generic.validate().expect("generic validates");
    }

    #[test]
    fn every_preset_round_trips_through_its_secret_free_projection() {
        // A preset's secret-free projection must re-parse as a runtime config, proving the
        // stored form the federation login path reads is well-formed for every provider.
        for def in [
            google("google", "gid", secret()),
            microsoft("microsoft", "common", "mid", secret()),
            apple("apple", "com.example.app", "TEAMID", "KEYID", secret()),
            github("github", "ghid", secret()),
        ] {
            let projection = def.secret_free_json().expect("projection serializes");
            let runtime: crate::ConnectorRuntimeConfig =
                serde_json::from_value(projection).expect("runtime projection parses");
            assert_eq!(runtime.client_id, def.client_id);
        }
    }
}
