// SPDX-License-Identifier: MIT OR Apache-2.0

//! Environments as first-class, typed objects: the closed set of environment
//! KINDS, the two GUARDRAIL CLASSES they map to, and the typed guardrail set each
//! class enforces (issue #42).
//!
//! An environment is the load-bearing object under snapshot export and config
//! promotion (issues #43 and #44). It carries three things that make it
//! first-class:
//!
//! - a KIND ([`EnvironmentType`]): a CLOSED enum of `dev`, `staging`, or `prod`.
//!   An unknown kind is rejected, not coerced, so a typo can never silently
//!   create an untyped environment.
//! - typed GUARDRAILS ([`GuardrailSet`]): platform-enforced constraints, not
//!   convention. The three kinds map onto exactly two guardrail CLASSES
//!   ([`GuardrailClass`]): `dev` and `staging` inherit the NON-PRODUCTION set,
//!   `prod` gets the PRODUCTION set. The asymmetry (Clerk and `WorkOS` pioneered
//!   the relaxed-dev / hard-prod split) is validated on every config write, so a
//!   `prod` environment can never silently carry `dev` laxity.
//! - SCOPED KEYS: a per-environment signing key set (issue #19), classified
//!   ENVIRONMENT-IDENTITY (issue #41) so a promotion never copies one
//!   environment's issuer identity onto another. This module owns the guardrail
//!   TYPING; the signing keys live in the `signing_keys` repository.
//!
//! Everything here is PURE and deterministic (no clock, no entropy, no
//! database), so the guardrail policy is exhaustively unit-testable and has one
//! definition the control plane (environment creation) and the data plane
//! (redirect registration through the issuer machinery) both consult.
//!
//! # The two guardrail classes
//!
//! - NON-PRODUCTION relaxes, for fast iteration: `http` loopback redirect URIs
//!   are registrable (RFC 8252 section 7.3), hosted pages are marked
//!   non-indexable, and a visible environment banner is shown.
//! - PRODUCTION hard-requires: a configured custom domain, HTTPS-only redirect
//!   URIs (RFC 9700 section 4.1), and one-time-view secrets (a secret value is
//!   shown once at creation and never readable again).

use crate::redirect::redirect_uri_is_registrable;

/// The closed set of environment kinds. Unlimited in COUNT (never gated by
/// billing) but a FIXED, typed set: an environment is exactly one of these three.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnvironmentType {
    /// A development environment: the most relaxed non-production guardrails.
    Dev,
    /// A staging environment: non-production guardrails, for pre-production
    /// verification.
    Staging,
    /// A production environment: the hard production guardrails.
    Prod,
}

impl EnvironmentType {
    /// Every kind, in a stable order. Iterated by the guardrail matrix tests and
    /// any surface that must enumerate the closed set.
    pub const ALL: [EnvironmentType; 3] = [
        EnvironmentType::Dev,
        EnvironmentType::Staging,
        EnvironmentType::Prod,
    ];

    /// The stable wire string (`dev`, `staging`, `prod`). This is the exact token
    /// persisted in the `environments.kind` column (its CHECK constraint pins the
    /// same three values) and served on the management API.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            EnvironmentType::Dev => "dev",
            EnvironmentType::Staging => "staging",
            EnvironmentType::Prod => "prod",
        }
    }

    /// Parse an untrusted kind token. An unknown value is REJECTED with
    /// [`UnknownEnvironmentType`] rather than coerced to a default, so a typo
    /// (`prd`, `production`, `PROD`) can never silently create a mis-typed
    /// environment. The accepted tokens are exactly [`EnvironmentType::as_str`].
    ///
    /// # Errors
    ///
    /// [`UnknownEnvironmentType`] if `raw` is not one of `dev`, `staging`, `prod`.
    pub fn parse(raw: &str) -> Result<Self, UnknownEnvironmentType> {
        match raw {
            "dev" => Ok(EnvironmentType::Dev),
            "staging" => Ok(EnvironmentType::Staging),
            "prod" => Ok(EnvironmentType::Prod),
            _ => Err(UnknownEnvironmentType {
                value: raw.to_owned(),
            }),
        }
    }

    /// The guardrail CLASS this kind maps onto. `dev` and `staging` both inherit
    /// the non-production set; `prod` gets the production set. This mapping is the
    /// whole two-class asymmetry in one place.
    #[must_use]
    pub fn guardrail_class(self) -> GuardrailClass {
        match self {
            EnvironmentType::Dev | EnvironmentType::Staging => GuardrailClass::NonProduction,
            EnvironmentType::Prod => GuardrailClass::Production,
        }
    }

    /// The typed guardrail set this kind enforces (its class's set).
    #[must_use]
    pub fn guardrails(self) -> GuardrailSet {
        GuardrailSet::for_class(self.guardrail_class())
    }
}

/// An unknown environment kind token, rejected at parse time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownEnvironmentType {
    /// The rejected value (safe to echo: it is the caller's own input).
    pub value: String,
}

impl std::fmt::Display for UnknownEnvironmentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown environment kind {:?}; expected one of dev, staging, prod",
            self.value
        )
    }
}

impl std::error::Error for UnknownEnvironmentType {}

/// The two guardrail classes the three environment kinds map onto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GuardrailClass {
    /// The relaxed set for `dev` and `staging`.
    NonProduction,
    /// The hard set for `prod`.
    Production,
}

impl GuardrailClass {
    /// The stable wire string (`non-production`, `production`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            GuardrailClass::NonProduction => "non-production",
            GuardrailClass::Production => "production",
        }
    }
}

/// The typed, platform-enforced guardrails for an environment. Derived purely
/// from the environment's [`GuardrailClass`], so two environments of the same
/// class always enforce the identical set and the production asymmetry can never
/// drift by accident.
// The guardrail flags ARE a flat set of independent booleans by design: each is a
// distinct platform-enforced constraint, and collapsing them into an enum would
// hide exactly the "which guardrails does this class enforce" table the type
// documents.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardrailSet {
    /// The class these guardrails belong to.
    pub class: GuardrailClass,
    /// Whether an `http` loopback (or private-use scheme) redirect URI is
    /// registrable. True for non-production (RFC 8252 section 7.3 native-app
    /// loopback), false for production.
    pub allow_insecure_redirect_uris: bool,
    /// Whether every redirect URI must be `https` (RFC 9700 section 4.1). True for
    /// production only.
    pub require_https_redirect_uris: bool,
    /// Whether the environment must have a configured custom domain. True for
    /// production only (verification and ACME are out of scope; this only enforces
    /// that a domain is configured).
    pub require_custom_domain: bool,
    /// Whether secret values are one-time-view (shown once at creation, never
    /// readable again). True for production only; management-key secrets are
    /// one-time in every environment, and production additionally forbids any
    /// re-readable secret surface.
    pub one_time_view_secrets: bool,
    /// Whether hosted pages carry a `noindex` marker (kept out of search indexes).
    /// True for non-production only.
    pub hosted_pages_noindex: bool,
    /// Whether a visible environment banner is shown on hosted pages and admin
    /// surfaces. True for non-production only.
    pub show_environment_banner: bool,
}

impl GuardrailSet {
    /// The guardrail set for a class. This is the single definition of what each
    /// class enforces; [`EnvironmentType::guardrails`] routes through it.
    #[must_use]
    pub fn for_class(class: GuardrailClass) -> Self {
        match class {
            GuardrailClass::NonProduction => GuardrailSet {
                class,
                allow_insecure_redirect_uris: true,
                require_https_redirect_uris: false,
                require_custom_domain: false,
                one_time_view_secrets: false,
                hosted_pages_noindex: true,
                show_environment_banner: true,
            },
            GuardrailClass::Production => GuardrailSet {
                class,
                allow_insecure_redirect_uris: false,
                require_https_redirect_uris: true,
                require_custom_domain: true,
                one_time_view_secrets: true,
                hosted_pages_noindex: false,
                show_environment_banner: false,
            },
        }
    }

    /// The guardrail set for an environment kind.
    #[must_use]
    pub fn for_kind(kind: EnvironmentType) -> Self {
        Self::for_class(kind.guardrail_class())
    }

    /// Validate a redirect URI against these guardrails, the SAME check at
    /// registration time and on promotion. Every environment requires an RFC 8252
    /// registrable target (rejecting dangerous schemes, fragments, and non-ASCII
    /// authorities); a PRODUCTION environment additionally requires the `https`
    /// scheme, so an `http` loopback that a `dev` environment accepts is rejected
    /// in `prod`.
    ///
    /// # Errors
    ///
    /// [`GuardrailViolation`] naming the failed guardrail: `registrable_redirect_uri`
    /// for a non-registrable target, or `https_only_redirect_uris` for a non-`https`
    /// target in a production environment.
    pub fn check_redirect_uri(&self, uri: &str) -> Result<(), GuardrailViolation> {
        if !redirect_uri_is_registrable(uri) {
            return Err(GuardrailViolation::new(
                Guardrail::RegistrableRedirectUri,
                self.class,
                format!("redirect URI {uri:?} is not a registrable RFC 8252 target"),
            ));
        }
        if self.require_https_redirect_uris && !uri_is_https(uri) {
            return Err(GuardrailViolation::new(
                Guardrail::HttpsOnlyRedirectUris,
                self.class,
                format!(
                    "redirect URI {uri:?} must use the https scheme in a production environment \
                     (RFC 9700 section 4.1)"
                ),
            ));
        }
        Ok(())
    }

    /// Validate a configured custom domain against these guardrails. A production
    /// environment requires a non-empty custom domain; a non-production
    /// environment accepts either a configured domain or none.
    ///
    /// # Errors
    ///
    /// [`GuardrailViolation`] `custom_domain_required` if the environment requires
    /// a custom domain and none is configured.
    pub fn check_custom_domain(&self, domain: Option<&str>) -> Result<(), GuardrailViolation> {
        let configured = domain.is_some_and(|value| !value.trim().is_empty());
        if self.require_custom_domain && !configured {
            return Err(GuardrailViolation::new(
                Guardrail::CustomDomainRequired,
                self.class,
                "a production environment requires a configured custom domain".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Whether `uri`'s scheme is `https` (ASCII case-insensitive).
fn uri_is_https(uri: &str) -> bool {
    uri.split_once(':')
        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("https"))
}

/// The closed set of named guardrails a config write can violate. Each carries a
/// stable wire code so a structured error names exactly which guardrail failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Guardrail {
    /// A redirect URI is not a registrable RFC 8252 target.
    RegistrableRedirectUri,
    /// A redirect URI is not `https` in a production environment.
    HttpsOnlyRedirectUris,
    /// A production environment has no configured custom domain.
    CustomDomainRequired,
}

impl Guardrail {
    /// The stable wire code for this guardrail.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Guardrail::RegistrableRedirectUri => "registrable_redirect_uri",
            Guardrail::HttpsOnlyRedirectUris => "https_only_redirect_uris",
            Guardrail::CustomDomainRequired => "custom_domain_required",
        }
    }
}

/// A single failed guardrail: which guardrail, in which class, and an
/// operator-safe message. A config write that fails several guardrails collects
/// these into a [`GuardrailReport`] so the caller learns EVERY failure at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardrailViolation {
    /// The failed guardrail.
    pub guardrail: Guardrail,
    /// The guardrail class that was being enforced.
    pub class: GuardrailClass,
    /// An operator-safe explanation (never attacker-controlled free text beyond
    /// the caller's own echoed input).
    pub message: String,
}

impl GuardrailViolation {
    /// Build a violation.
    #[must_use]
    pub fn new(guardrail: Guardrail, class: GuardrailClass, message: String) -> Self {
        Self {
            guardrail,
            class,
            message,
        }
    }

    /// The failed guardrail's stable wire code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        self.guardrail.code()
    }
}

impl std::fmt::Display for GuardrailViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.guardrail.code(), self.message)
    }
}

impl std::error::Error for GuardrailViolation {}

/// An accumulated set of guardrail violations from validating one config write.
/// Empty means the write satisfies every guardrail; a non-empty report lists each
/// failed guardrail so the caller can surface them all in one structured error.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuardrailReport {
    violations: Vec<GuardrailViolation>,
}

impl GuardrailReport {
    /// An empty report (no violations yet).
    #[must_use]
    pub fn new() -> Self {
        Self {
            violations: Vec::new(),
        }
    }

    /// Record the outcome of one guardrail check, keeping any violation.
    pub fn check(&mut self, outcome: Result<(), GuardrailViolation>) {
        if let Err(violation) = outcome {
            self.violations.push(violation);
        }
    }

    /// Whether every recorded check passed.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }

    /// The recorded violations, in the order they were checked.
    #[must_use]
    pub fn violations(&self) -> &[GuardrailViolation] {
        &self.violations
    }

    /// Consume the report into its violations.
    #[must_use]
    pub fn into_violations(self) -> Vec<GuardrailViolation> {
        self.violations
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EnvironmentType, Guardrail, GuardrailClass, GuardrailReport, GuardrailSet,
        GuardrailViolation,
    };

    #[test]
    fn kinds_round_trip_through_their_wire_strings() {
        for kind in EnvironmentType::ALL {
            assert_eq!(
                EnvironmentType::parse(kind.as_str()),
                Ok(kind),
                "{} must round-trip",
                kind.as_str()
            );
        }
    }

    #[test]
    fn unknown_kind_is_rejected_not_coerced() {
        // A typo, a synonym, and a wrong case are all rejected: an unknown
        // guardrail kind never silently becomes a default.
        for bad in ["prd", "production", "PROD", "test", "", "Dev"] {
            assert!(
                EnvironmentType::parse(bad).is_err(),
                "{bad:?} must be rejected as an unknown environment kind"
            );
        }
    }

    #[test]
    fn dev_and_staging_are_non_production_prod_is_production() {
        assert_eq!(
            EnvironmentType::Dev.guardrail_class(),
            GuardrailClass::NonProduction
        );
        assert_eq!(
            EnvironmentType::Staging.guardrail_class(),
            GuardrailClass::NonProduction
        );
        assert_eq!(
            EnvironmentType::Prod.guardrail_class(),
            GuardrailClass::Production
        );
    }

    #[test]
    fn non_production_relaxes_and_production_hardens() {
        let dev = GuardrailSet::for_kind(EnvironmentType::Dev);
        assert!(dev.allow_insecure_redirect_uris);
        assert!(!dev.require_https_redirect_uris);
        assert!(!dev.require_custom_domain);
        assert!(!dev.one_time_view_secrets);
        assert!(dev.hosted_pages_noindex);
        assert!(dev.show_environment_banner);

        let prod = GuardrailSet::for_kind(EnvironmentType::Prod);
        assert!(!prod.allow_insecure_redirect_uris);
        assert!(prod.require_https_redirect_uris);
        assert!(prod.require_custom_domain);
        assert!(prod.one_time_view_secrets);
        assert!(!prod.hosted_pages_noindex);
        assert!(!prod.show_environment_banner);
    }

    #[test]
    fn dev_and_staging_enforce_the_identical_set() {
        assert_eq!(
            GuardrailSet::for_kind(EnvironmentType::Dev),
            GuardrailSet::for_kind(EnvironmentType::Staging),
            "the two non-production kinds must enforce the same guardrails"
        );
    }

    #[test]
    fn localhost_http_redirect_registers_in_dev_and_is_rejected_in_prod() {
        // Acceptance criterion 1: the RFC 8252 loopback IP literal (the "localhost
        // http redirect") is registrable in a dev environment and rejected with a
        // guardrail error in a prod environment.
        let loopback = "http://127.0.0.1:8080/callback";

        assert!(
            GuardrailSet::for_kind(EnvironmentType::Dev)
                .check_redirect_uri(loopback)
                .is_ok(),
            "a dev environment accepts an http loopback redirect"
        );
        assert!(
            GuardrailSet::for_kind(EnvironmentType::Staging)
                .check_redirect_uri(loopback)
                .is_ok(),
            "a staging environment accepts an http loopback redirect"
        );

        let violation = GuardrailSet::for_kind(EnvironmentType::Prod)
            .check_redirect_uri(loopback)
            .expect_err("a prod environment rejects an http loopback redirect");
        assert_eq!(violation.guardrail, Guardrail::HttpsOnlyRedirectUris);
        assert_eq!(violation.code(), "https_only_redirect_uris");
        assert_eq!(violation.class, GuardrailClass::Production);
    }

    #[test]
    fn https_redirect_is_accepted_in_every_environment() {
        for kind in EnvironmentType::ALL {
            assert!(
                GuardrailSet::for_kind(kind)
                    .check_redirect_uri("https://app.example.com/cb")
                    .is_ok(),
                "an https redirect is accepted in {}",
                kind.as_str()
            );
        }
    }

    #[test]
    fn a_non_registrable_redirect_is_rejected_everywhere_with_the_shape_guardrail() {
        for kind in EnvironmentType::ALL {
            let violation = GuardrailSet::for_kind(kind)
                .check_redirect_uri("javascript:alert(1)")
                .expect_err("a dangerous scheme is never registrable");
            assert_eq!(violation.guardrail, Guardrail::RegistrableRedirectUri);
        }
    }

    #[test]
    fn prod_requires_a_custom_domain_and_non_prod_does_not() {
        let prod = GuardrailSet::for_kind(EnvironmentType::Prod);
        assert!(prod.check_custom_domain(None).is_err());
        assert!(prod.check_custom_domain(Some("  ")).is_err());
        assert!(prod.check_custom_domain(Some("auth.acme.example")).is_ok());

        let dev = GuardrailSet::for_kind(EnvironmentType::Dev);
        assert!(dev.check_custom_domain(None).is_ok());
        assert!(dev.check_custom_domain(Some("dev.acme.example")).is_ok());
    }

    #[test]
    fn a_report_accumulates_every_failed_guardrail() {
        // A prod environment with no domain and an http redirect fails TWO
        // guardrails; the report lists both so the caller sees every failure.
        let prod = GuardrailSet::for_kind(EnvironmentType::Prod);
        let mut report = GuardrailReport::new();
        report.check(prod.check_custom_domain(None));
        report.check(prod.check_redirect_uri("http://127.0.0.1/cb"));
        assert!(!report.is_clean());
        let codes: Vec<&str> = report
            .violations()
            .iter()
            .map(GuardrailViolation::code)
            .collect();
        assert_eq!(
            codes,
            vec!["custom_domain_required", "https_only_redirect_uris"]
        );
    }

    #[test]
    fn a_clean_report_has_no_violations() {
        let prod = GuardrailSet::for_kind(EnvironmentType::Prod);
        let mut report = GuardrailReport::new();
        report.check(prod.check_custom_domain(Some("auth.acme.example")));
        report.check(prod.check_redirect_uri("https://app.example/cb"));
        assert!(report.is_clean());
        assert!(report.into_violations().is_empty());
    }
}
