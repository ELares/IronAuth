// SPDX-License-Identifier: MIT OR Apache-2.0

//! The signed security-advisory feed (issue #163).
//!
//! Operators of disconnected deployments are exactly the ones who miss security
//! advisories. This module is the signed feed every deployment can consume:
//!
//! - **The online path**: the server polls the feed (opt-out config, never
//!   load-bearing) and verifies the signature before ANY advisory is accepted.
//! - **The offline path**: an air-gapped deployment imports the SAME signed feed
//!   as a bundle through the admin API; the signature verification is identical,
//!   so a bundle that failed verification online cannot succeed offline.
//!
//! # The signature
//!
//! The feed is signed with the platform's default asymmetric primitive (Ed25519,
//! `ironauth_jose::sign_detached`/`verify_detached`): the feed's canonical form
//! (the JSON bytes of the `feed` member) is signed, and the signature rides the
//! `signature` member (base64url). A feed whose signature does not verify against
//! the deployment's configured verification key is REJECTED entirely and logged
//! as a security event - never partially applied, so a tampered feed cannot
//! inject one advisory while the rest fails.
//!
//! # The severity tiers
//!
//! The banner tiering (critical/high/medium/low) drives the admin SPA's rendering
//! and the dismiss-per-admin audit; the tiers are part of the advisory model.

use ironauth_jose::TrustedKey;
use serde::Deserialize;
use serde_json::Value;
use base64::Engine as _;

/// The advisory severity tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdvisorySeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// One security advisory.
#[derive(Debug, Clone, Deserialize)]
pub struct Advisory {
    /// The stable advisory identifier (the M1 security program's format).
    pub id: String,
    /// The human-facing title.
    pub title: String,
    /// The severity tier.
    pub severity: AdvisorySeverity,
    /// The affected versions (a semver range list).
    pub affected_versions: Vec<String>,
    /// The summary an operator reads in the banner.
    pub summary: String,
    /// The advisory's published date (unix seconds).
    pub published_at: i64,
}

/// A parsed + verified feed.
#[derive(Debug, Clone)]
pub struct VerifiedFeed {
    /// The accepted advisories.
    pub advisories: Vec<Advisory>,
}

/// Parse + verify a signed feed (online or offline, the SAME path).
///
/// # Errors
///
/// [`FeedError::BadSignature`] when the signature does not verify (a tampered
/// feed is rejected entirely); [`FeedError::Malformed`] when the feed does not
/// parse.
pub fn verify_feed(
    feed_json: &str,
    verification_key: &TrustedKey,
) -> Result<VerifiedFeed, FeedError> {
    let value: Value =
        serde_json::from_str(feed_json).map_err(|_| FeedError::Malformed)?;
    let signature = value
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or(FeedError::Malformed)?;
    let feed_member = value.get("feed").ok_or(FeedError::Malformed)?;
    let canonical = serde_json::to_vec(feed_member).map_err(|_| FeedError::Malformed)?;
    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| FeedError::BadSignature)?;
    if ironauth_jose::verify_detached(
        verification_key,
        ironauth_jose::JwsAlgorithm::EdDsa,
        &canonical,
        &sig_bytes,
    )
    .is_err()
    {
        return Err(FeedError::BadSignature);
    }
    let advisories: Vec<Advisory> =
        serde_json::from_value(feed_member.clone()).map_err(|_| FeedError::Malformed)?;
    Ok(VerifiedFeed { advisories })
}

/// Sign a feed (the authoring side: tests and the release tooling).
pub fn sign_feed(feed_member: &Value, signing_key: &ironauth_jose::SigningKey) -> String {
    let canonical = serde_json::to_vec(feed_member).expect("the feed serializes");
    let signature = ironauth_jose::sign_detached(signing_key, &canonical).expect("the feed signs");
    let value = serde_json::json!({
        "feed": feed_member,
        "signature": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature),
    });
    value.to_string()
}

/// A feed-processing failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedError {
    /// The feed does not parse.
    Malformed,
    /// The signature does not verify: the feed is REJECTED entirely, and the
    /// caller records the security event.
    BadSignature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironauth_env::Env;
    use ironauth_jose::SigningKey;
    use std::time::SystemTime;

    fn signing_key(env: &Env) -> SigningKey {
        SigningKey::ed25519_from_seed(Some("advisory-key".to_owned()), &[3_u8; 32])
            .expect("the key loads")
    }

    #[test]
    fn a_signed_feed_verifies_and_parses() {
        let (env, _) = Env::deterministic(SystemTime::UNIX_EPOCH, 1);
        let key = signing_key(&env);
        let feed = serde_json::json!([{
            "id": "ADV-2026-001",
            "title": "a seeded advisory",
            "severity": "high",
            "affected_versions": ["<1.2.0"],
            "summary": "a summary",
            "published_at": 1_700_000_000
        }]);
        let signed = sign_feed(&feed, &key);
        let trusted = key.verifying_key().expect("the trusted key");
        let verified = verify_feed(&signed, &trusted).expect("verifies");
        assert_eq!(verified.advisories.len(), 1);
        assert_eq!(verified.advisories[0].severity, AdvisorySeverity::High);
    }

    #[test]
    fn a_tampered_feed_is_rejected_entirely() {
        let (env, _) = Env::deterministic(SystemTime::UNIX_EPOCH, 2);
        let key = signing_key(&env);
        let feed = serde_json::json!([{ "id": "ADV-2026-002", "title": "t", "severity": "low", "affected_versions": [], "summary": "s", "published_at": 1 }]);
        let signed = sign_feed(&feed, &key);
        // Tamper: change one advisory byte after signing.
        let tampered = signed.replace("\"ADV-2026-002\"", "\"ADV-2026-003\"");
        let trusted = key.verifying_key().expect("the trusted key");
        assert_eq!(
            verify_feed(&tampered, &trusted),
            Err(FeedError::BadSignature),
            "a tampered feed is rejected, never partially applied"
        );
    }

    #[test]
    fn a_wrong_key_rejects_the_feed() {
        let (env, _) = Env::deterministic(SystemTime::UNIX_EPOCH, 3);
        let key = signing_key(&env);
        let feed = serde_json::json!([{ "id": "ADV-2026-004", "title": "t", "severity": "low", "affected_versions": [], "summary": "s", "published_at": 1 }]);
        let signed = sign_feed(&feed, &key);
        let (other_env, _) = Env::deterministic(SystemTime::UNIX_EPOCH, 4);
        let other = signing_key(&other_env);
        let trusted = other.verifying_key().expect("the trusted key");
        assert!(verify_feed(&signed, &trusted).is_err());
    }
}