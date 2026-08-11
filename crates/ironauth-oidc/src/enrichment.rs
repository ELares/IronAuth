// SPDX-License-Identifier: MIT OR Apache-2.0

//! The claims-enrichment hook (issue #100): an outbound call at TOKEN ISSUANCE that asks an
//! external policy decision point or fine-grained-authorization service for extra claims,
//! and merges the ones it was told to accept into the token.
//!
//! This is the seam the `AuthZEN` work is built around. `IronAuth` answers what it already
//! indexes and deliberately does not ship a `Zanzibar` engine; a deployment whose model
//! needs relationships runs `OpenFGA`, `SpiceDB` or `Cerbos` and points this hook at it. The
//! blessed architecture is coarse claims plus a fine `PDP`, and this is the coarse half
//! learning what the fine half knows.
//!
//! # Three rules, and each of them is load-bearing
//!
//! **It only ever ADDS.** A returned claim whose name is not in the configured allowlist is
//! dropped, and so is one that collides with a claim `IronAuth` already minted. A hook that
//! could overwrite `sub`, `aud`, `exp` or `permissions` would not be an enrichment hook, it
//! would be a token-forgery endpoint, and a deployment that trusts an FGA to answer a
//! relationship question has not thereby decided to let it choose subjects. The allowlist is
//! additionally refused AT CONFIG LOAD if it names a reserved claim, so the collision check
//! here is the second of two fences rather than the only one.
//!
//! **It fails OPEN.** An error, a timeout, a non-2xx, or a malformed body contributes
//! nothing and the token is issued without the extra claims. Failing closed would take every
//! login in the deployment down with the FGA, and these claims are ADDITIVE: their absence is
//! fewer permissions, never more. A relying party that needs an enriched claim to authorize
//! still refuses without it, which is correct and which it already implements.
//!
//! **It is bounded.** One call, one configured timeout, and at most the allowlist's worth of
//! claims. The token-size budget (issue #98) is the backstop that refuses an over-large
//! token; the bound here is what stops a misbehaving service filling that budget.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::{HeaderValue, Method, header};
use ironauth_config::ClaimsEnrichmentConfig;
use ironauth_fetch::{FetchPurpose, FetchRequest, Fetcher};
use ironauth_store::Scope;
use serde::Deserialize;

/// What an enrichment service answers: a flat object of claims under `claims`.
///
/// Deliberately NOT the bare object. A wrapper leaves room for the service to say something
/// else later (a cache hint, a decision id) without every existing field becoming a claim,
/// and it means a service that mistakenly returns its own error envelope contributes nothing
/// rather than contributing `{"error": "..."}` as a claim named `error`.
#[derive(Debug, Deserialize)]
struct EnrichmentResponse {
    #[serde(default)]
    claims: BTreeMap<String, serde_json::Value>,
}

/// The configured hook, resolved once at boot.
pub struct ClaimsEnrichmentHook {
    fetcher: Arc<Fetcher>,
    endpoint: String,
    secret: Option<String>,
    allowed: Vec<String>,
    /// Whether a plaintext `http` endpoint is permitted. Always false in a production
    /// build: only the `testing`-gated constructor sets it, so an integration test can
    /// serve claims from an in-process loopback server through the injected dialer.
    allow_http: bool,
}

impl std::fmt::Debug for ClaimsEnrichmentHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The endpoint and the allowlist are operator configuration and safe to show; the
        // shared secret is not, and is omitted rather than redacted so it cannot be
        // reintroduced by someone "improving" the redaction.
        f.debug_struct("ClaimsEnrichmentHook")
            .field("endpoint", &self.endpoint)
            .field("allowed", &self.allowed)
            .finish_non_exhaustive()
    }
}

impl ClaimsEnrichmentHook {
    /// Build the hook from configuration, or [`None`] when it is disabled or has nothing it
    /// is permitted to contribute.
    ///
    /// An enabled hook with an EMPTY allowlist resolves to `None` rather than to a hook that
    /// calls out and drops everything. The outbound call would be pure cost on the issuance
    /// path with no reachable effect, and a boot that silently performs it is one an operator
    /// cannot tell from a working configuration.
    #[must_use]
    pub fn from_config(config: &ClaimsEnrichmentConfig, fetcher: Arc<Fetcher>) -> Option<Self> {
        if !config.enabled || config.allowed_claims.is_empty() {
            return None;
        }
        let endpoint = config.endpoint.clone()?;
        Some(Self {
            fetcher,
            endpoint,
            secret: config
                .secret
                .as_ref()
                .and_then(|secret| secret.resolve().ok())
                .map(|resolved| resolved.expose().to_owned()),
            allowed: config.allowed_claims.clone(),
            allow_http: false,
        })
    }

    /// Like [`ClaimsEnrichmentHook::from_config`] but permitting a plaintext `http`
    /// endpoint, so an integration test can serve claims from an in-process loopback
    /// server. Behind the `testing` feature so it never exists in a production build.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn new_allow_http(
        fetcher: Arc<Fetcher>,
        endpoint: impl Into<String>,
        secret: Option<String>,
        allowed: Vec<String>,
    ) -> Self {
        Self {
            fetcher,
            endpoint: endpoint.into(),
            secret,
            allowed,
            allow_http: true,
        }
    }

    /// The claim names this hook may contribute, for the tests and for diagnostics.
    #[must_use]
    pub fn allowed(&self) -> &[String] {
        &self.allowed
    }

    /// Ask the service for extra claims for `subject` in `scope`, and return the ones that
    /// survive the allowlist.
    ///
    /// Never fails: every error path yields an empty map. See the module note on why this
    /// direction is the safe one.
    pub async fn enrich(
        &self,
        scope: Scope,
        subject: &str,
        client_id: &str,
    ) -> BTreeMap<String, serde_json::Value> {
        let empty = BTreeMap::new();
        // The request names WHICH claims are wanted. A service that honours it does less
        // work and sends less back, and one that ignores it is filtered here anyway, so the
        // field is a courtesy rather than a control.
        let body = serde_json::json!({
            "subject": subject,
            "tenant_id": scope.tenant().to_string(),
            "environment_id": scope.environment().to_string(),
            "client_id": client_id,
            "requested_claims": self.allowed,
        })
        .to_string();

        let mut request =
            FetchRequest::new(FetchPurpose::ClaimsEnrichment, Method::POST, &self.endpoint)
                .header(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                )
                .body(body);
        if self.allow_http {
            request = request.allow_plaintext_http();
        }
        if let Some(secret) = &self.secret {
            let bearer = format!("Bearer {secret}");
            let Ok(value) = HeaderValue::from_str(&bearer) else {
                // A secret carrying control characters cannot become a header. Sending the
                // request UNAUTHENTICATED instead would hand a third party a subject
                // identifier it was never meant to see, so the call is abandoned.
                return empty;
            };
            request = request.header(header::AUTHORIZATION, value);
        }

        let Ok(response) = self.fetcher.fetch(request).await else {
            return empty;
        };
        if !response.status().is_success() {
            return empty;
        }
        let Ok(parsed) = serde_json::from_slice::<EnrichmentResponse>(response.body()) else {
            return empty;
        };
        self.filter(parsed.claims)
    }

    /// Keep only the allowlisted names.
    ///
    /// Separated from the call so it is testable without a network, and so the ONE place
    /// that decides what may enter a token is a pure function over a map.
    fn filter(
        &self,
        claims: BTreeMap<String, serde_json::Value>,
    ) -> BTreeMap<String, serde_json::Value> {
        claims
            .into_iter()
            .filter(|(name, _)| self.allowed.iter().any(|allowed| allowed == name))
            // Belt and braces with the config-load refusal: a reserved name can never be
            // allowlisted, so this can only fire if that check regressed. It is cheap, and
            // the failure it guards against is an external service choosing the subject.
            .filter(|(name, _)| {
                !ironauth_config::RESERVED_ENRICHMENT_CLAIMS.contains(&name.as_str())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hook(allowed: &[&str]) -> ClaimsEnrichmentHook {
        ClaimsEnrichmentHook {
            fetcher: Arc::new(Fetcher::for_tests(ironauth_fetch::FetchLimits::default())),
            endpoint: "https://pdp.example.test/enrich".to_owned(),
            secret: None,
            allowed: allowed.iter().map(|name| (*name).to_owned()).collect(),
            allow_http: false,
        }
    }

    fn claims(pairs: &[(&str, &str)]) -> BTreeMap<String, serde_json::Value> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), serde_json::json!(v)))
            .collect()
    }

    /// Only allowlisted names survive, and an unlisted one is dropped rather than renamed,
    /// nested, or reported.
    #[test]
    fn the_filter_keeps_only_allowlisted_names() {
        let kept = hook(&["fga_roles", "tier"]).filter(claims(&[
            ("fga_roles", "a"),
            ("tier", "gold"),
            ("surprise", "b"),
        ]));
        assert_eq!(
            kept.keys().collect::<Vec<_>>(),
            vec!["fga_roles", "tier"],
            "a name the operator did not allowlist reached the token"
        );
    }

    /// A RESERVED name is dropped even if it somehow reached the allowlist.
    ///
    /// Config load refuses to store one, so this can only fire if that check regressed. It
    /// is asserted because the thing it prevents is an external service choosing the
    /// subject, the audience, or the permission set of a token IronAuth signs.
    #[test]
    fn a_reserved_name_is_dropped_even_when_allowlisted() {
        // Constructed directly, bypassing `from_config`, which is exactly the regression
        // being guarded against.
        let hook = hook(&["sub", "permissions", "exp", "fga_roles"]);
        let kept = hook.filter(claims(&[
            ("sub", "attacker"),
            ("permissions", "everything"),
            ("exp", "9999999999"),
            ("fga_roles", "reader"),
        ]));
        assert_eq!(
            kept.keys().collect::<Vec<_>>(),
            vec!["fga_roles"],
            "a reserved claim survived the filter, so an external service can overwrite \
             what IronAuth minted: {kept:?}"
        );
    }

    /// An enabled hook that is permitted to contribute NOTHING resolves to `None`.
    ///
    /// It would otherwise spend an outbound call on the issuance path with no reachable
    /// effect, which an operator cannot tell from a working configuration.
    #[test]
    fn an_enabled_hook_with_an_empty_allowlist_is_not_built() {
        let config = ClaimsEnrichmentConfig {
            enabled: true,
            endpoint: Some("https://pdp.example.test/enrich".to_owned()),
            secret: None,
            timeout_secs: 2,
            allowed_claims: Vec::new(),
        };
        let fetcher = Arc::new(Fetcher::for_tests(ironauth_fetch::FetchLimits::default()));
        assert!(
            ClaimsEnrichmentHook::from_config(&config, fetcher).is_none(),
            "an enabled hook with nothing it may contribute must not be built"
        );
    }

    /// A DISABLED hook is not built even with a full allowlist.
    #[test]
    fn a_disabled_hook_is_not_built() {
        let config = ClaimsEnrichmentConfig {
            enabled: false,
            endpoint: Some("https://pdp.example.test/enrich".to_owned()),
            secret: None,
            timeout_secs: 2,
            allowed_claims: vec!["fga_roles".to_owned()],
        };
        let fetcher = Arc::new(Fetcher::for_tests(ironauth_fetch::FetchLimits::default()));
        assert!(ClaimsEnrichmentHook::from_config(&config, fetcher).is_none());
    }

    /// An empty response, and a response whose `claims` key is absent, both contribute
    /// nothing rather than erroring.
    #[test]
    fn a_response_with_no_claims_contributes_nothing() {
        for body in ["{}", r#"{"claims":{}}"#, r#"{"decision_id":"abc"}"#] {
            let parsed: EnrichmentResponse =
                serde_json::from_str(body).expect("the wrapper tolerates a missing claims key");
            assert!(
                hook(&["fga_roles"]).filter(parsed.claims).is_empty(),
                "{body} contributed a claim"
            );
        }
    }
}
