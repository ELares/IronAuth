// SPDX-License-Identifier: MIT OR Apache-2.0

//! The feature maturity ladder and the experimental acknowledgment gate.
//!
//! Every feature flag registers here with a maturity: Experimental features
//! carry an exact version string and a changelog pointer, Preview features
//! are stable enough to toggle freely, Supported features are first-class.
//! The gate (after node-oidc-provider practice): enabling an Experimental
//! feature requires the config to acknowledge the feature's EXACT current
//! version. When a breaking change bumps that version, every deployment that
//! enabled the feature fails at boot with the changelog pointer, instead of
//! silently changing behavior. This machinery must exist before the first
//! experimental feature ships; it cannot be retrofitted once acks are in the
//! wild.

use std::collections::BTreeMap;
use std::fmt;

use crate::{Config, FeatureToggle};

/// The exact revision of `draft-parecki-oauth-global-token-revocation` this build
/// implements (issue #36). It doubles as the experimental `ack` version for the
/// `global-token-revocation` feature: an operator enabling the feature acknowledges
/// this exact draft revision, and a future draft that changes the wire shape bumps
/// this string and invalidates the old ack. Surfaced in `docs/CONFIG.md` (the feature
/// ladder table) so an interop mismatch with another implementer is diagnosable.
pub const GLOBAL_TOKEN_REVOCATION_DRAFT: &str = "draft-parecki-oauth-global-token-revocation-01";

/// The registry name of the Global Token Revocation experimental feature (issue #36).
pub const GLOBAL_TOKEN_REVOCATION_FEATURE: &str = "global-token-revocation";

/// The registry name of the per-environment custom-domains-with-built-in-ACME
/// experimental feature (issue #47).
pub const CUSTOM_DOMAINS_ACME_FEATURE: &str = "custom-domains-acme";

/// The experimental `ack` version for the custom-domains-with-ACME feature (issue
/// #47). It is EXPLORATORY: the cert-management operational model (renewal
/// scheduling, CA rate-limit budgeting, multi-replica challenge serving) is
/// unproven in this codebase, and a live ACME handshake needs a provisioned CA
/// account and a reachable domain (infra/owner-gated). Enabling the feature
/// acknowledges this exact revision; a graduation that changes the shape bumps it.
pub const CUSTOM_DOMAINS_ACME_VERSION: &str = "0.1.0-exp.1";

/// How mature a feature is, and therefore what enabling it requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Maturity {
    /// Draft-spec or unstable machinery. Enabling requires `ack` equal to
    /// `version`; a breaking change bumps `version` and invalidates old acks.
    Experimental {
        /// The exact version string an `ack` must match.
        version: &'static str,
        /// Where the operator reads what changed before re-acking.
        changelog: &'static str,
    },
    /// Stable surface, off by default. Enabling requires only `enabled`.
    Preview,
    /// First-class. `ack` is ignored so a feature promoted out of
    /// Experimental never breaks boots that still carry the old ack.
    Supported,
}

/// A registered feature flag.
///
/// Construct through [`Feature::experimental`], [`Feature::preview`], or
/// [`Feature::supported`] rather than a struct literal. The constructors bind
/// the default-enabled policy to the maturity (only a Supported feature may be
/// on by default), and keeping the fields private means a later field addition
/// changes only the constructors, not every registration site.
#[derive(Debug, Clone, Copy)]
pub struct Feature {
    name: &'static str,
    maturity: Maturity,
    doc: &'static str,
    default_enabled: bool,
}

impl Feature {
    /// An Experimental feature: off by default, and enabling it requires an
    /// `ack` equal to `version` (see [`Maturity::Experimental`]). It is never
    /// on by default, because an ungated default-on experiment would silently
    /// change behavior across a breaking version bump, which is exactly what
    /// the ack gate exists to prevent.
    #[must_use]
    pub const fn experimental(
        name: &'static str,
        doc: &'static str,
        version: &'static str,
        changelog: &'static str,
    ) -> Self {
        Self {
            name,
            maturity: Maturity::Experimental { version, changelog },
            doc,
            default_enabled: false,
        }
    }

    /// A Preview feature: stable enough to toggle freely, off by default.
    #[must_use]
    pub const fn preview(name: &'static str, doc: &'static str) -> Self {
        Self {
            name,
            maturity: Maturity::Preview,
            doc,
            default_enabled: false,
        }
    }

    /// A Supported (first-class) feature. `on_by_default` decides whether it is
    /// enabled when the config does not mention it; either way an operator can
    /// still set it explicitly, including `enabled = false` to turn a
    /// default-on feature off.
    #[must_use]
    pub const fn supported(name: &'static str, doc: &'static str, on_by_default: bool) -> Self {
        Self {
            name,
            maturity: Maturity::Supported,
            doc,
            default_enabled: on_by_default,
        }
    }

    /// The name config files use in the `[features]` table.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Where the feature sits on the maturity ladder.
    #[must_use]
    pub const fn maturity(&self) -> Maturity {
        self.maturity
    }

    /// One-line operator-facing description.
    #[must_use]
    pub const fn doc(&self) -> &'static str {
        self.doc
    }

    /// Whether the feature is enabled when the config does not mention it.
    /// True only for a Supported feature declared on by default.
    #[must_use]
    pub const fn default_enabled(&self) -> bool {
        self.default_enabled
    }
}

/// The set of feature flags this build knows about.
///
/// Later issues register their flags in [`FeatureRegistry::builtin`]; the
/// boot path calls [`FeatureRegistry::validate`] with the loaded [`Config`]
/// before starting any component.
#[derive(Debug, Default)]
pub struct FeatureRegistry {
    features: BTreeMap<&'static str, Feature>,
}

impl FeatureRegistry {
    /// An empty registry, for tests and embedders.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The registry of every feature this build ships.
    #[must_use]
    pub fn builtin() -> Self {
        let mut registry = Self::new();
        registry.register_sample_experimental();
        registry.register_global_token_revocation();
        registry.register_custom_domains_acme();
        registry
    }

    /// Register a feature.
    ///
    /// # Panics
    ///
    /// Panics on a duplicate name: two registrations for one name is a
    /// programming error that must fail the build's tests, not be resolved
    /// silently at runtime.
    pub fn register(&mut self, feature: Feature) {
        // The single choke point every feature passes through, so it enforces
        // the maturity coupling regardless of how the Feature was built: only a
        // Supported feature may be on by default. A default-on ack-gated or
        // preview feature would be enabled without appearing in [features] and
        // so bypass the validate() gate entirely. The constructors already
        // guarantee this; this backstops any struct literal added inside the
        // module (where the private fields are reachable).
        debug_assert!(
            !feature.default_enabled || matches!(feature.maturity, Maturity::Supported),
            "feature '{}' is on by default but not Supported; only Supported features may default on",
            feature.name
        );
        let previous = self.features.insert(feature.name, feature);
        assert!(
            previous.is_none(),
            "feature '{}' registered twice",
            feature.name
        );
    }

    /// Registers the sample flag that exercises the acknowledgment gate end
    /// to end. It gates no behavior; it exists so the ladder machinery is
    /// tested against a real registered feature from day one.
    #[doc(hidden)]
    pub fn register_sample_experimental(&mut self) {
        self.register(Feature::experimental(
            "sample-experimental",
            "Sample experimental flag exercising the acknowledgment gate; \
             gates no behavior.",
            "0.1.0-exp.1",
            "crates/ironauth-config/CHANGELOG.md",
        ));
    }

    /// Registers the Global Token Revocation receiver feature (issue #36), the Okta
    /// Universal Logout shape of `draft-parecki-oauth-global-token-revocation`. It is
    /// EXPERIMENTAL: the draft is an individual Internet-Draft (not yet WG-adopted),
    /// so the wire shape may break between releases and enabling it must acknowledge
    /// the exact implemented draft revision. Off by default; when enabled AND acked,
    /// the OIDC provider mounts `POST /global-token-revocation`.
    pub fn register_global_token_revocation(&mut self) {
        self.register(Feature::experimental(
            GLOBAL_TOKEN_REVOCATION_FEATURE,
            "Global Token Revocation receiver (Okta Universal Logout shape, \
             draft-parecki-oauth-global-token-revocation): a strongly-authenticated, \
             subject-scoped revoke-everything endpoint. EXPERIMENTAL: the draft is not \
             yet WG-adopted and the wire shape may break between releases.",
            GLOBAL_TOKEN_REVOCATION_DRAFT,
            "crates/ironauth-oidc/CHANGELOG.md",
        ));
    }

    /// Registers the per-environment custom-domains-with-built-in-ACME feature
    /// (issue #47). It is EXPERIMENTAL and EXPLORATORY: it ships the persistence,
    /// domain validation, encrypted certificate storage, and the SSRF-hardened
    /// ACME/CA fetch path, but the live cert-management operational model (renewal
    /// scheduling, CA rate-limit budgeting, multi-replica HTTP-01 answering, SNI
    /// serving) is unproven, and a live issuance needs a provisioned CA account
    /// and a reachable domain (infra/owner-gated). Off by default; enabling it
    /// requires acknowledging the exact implemented revision.
    pub fn register_custom_domains_acme(&mut self) {
        self.register(Feature::experimental(
            CUSTOM_DOMAINS_ACME_FEATURE,
            "Per-environment custom domains with built-in ACME (RFC 8555): CNAME \
             verification, HTTP-01/DNS-01 challenges, and encrypted-at-rest \
             certificate storage. EXPLORATORY: the cert-management operational \
             model is unproven and a live issuance is infra/owner-gated on a \
             provisioned CA account and a reachable domain.",
            CUSTOM_DOMAINS_ACME_VERSION,
            "crates/ironauth-store/CHANGELOG.md",
        ));
    }

    /// Look up a registered feature.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Feature> {
        self.features.get(name)
    }

    /// Iterate over registered features in name order.
    pub fn iter(&self) -> impl Iterator<Item = &Feature> {
        self.features.values()
    }

    /// Whether `name` is registered and enabled, with its gate satisfied. An
    /// explicit `enabled = true`/`false` wins; a feature the config does not
    /// mention, or mentions without an explicit `enabled`, falls back to its
    /// [`Feature::default_enabled`] (true only for a Supported feature declared
    /// on by default). This can therefore return `true` for a feature entirely
    /// absent from `[features]`. Call only after [`FeatureRegistry::validate`]
    /// passed; it does not itself check the ack gate.
    #[must_use]
    pub fn is_enabled(&self, config: &Config, name: &str) -> bool {
        self.features.get(name).is_some_and(|feature| {
            config
                .features
                .get(name)
                .and_then(|toggle| toggle.enabled)
                .unwrap_or(feature.default_enabled)
        })
    }

    /// The boot-time gate. Checks every entry in `config.features` against
    /// the registry and collects every violation, so an operator fixes one
    /// boot's worth of problems per attempt, not one problem per attempt.
    ///
    /// # Errors
    ///
    /// Returns [`FeatureValidationError`] listing each violation: an unknown
    /// feature name, or an enabled Experimental feature whose `ack` is
    /// missing or does not equal the feature's exact current version.
    pub fn validate(&self, config: &Config) -> Result<(), FeatureValidationError> {
        let mut violations = Vec::new();
        for (name, toggle) in &config.features {
            match self.features.get(name.as_str()) {
                None => violations.push(FeatureViolation::UnknownFeature {
                    name: name.clone(),
                    known: self.features.keys().copied().collect(),
                }),
                Some(feature) => {
                    if let Some(violation) = check_gate(feature, toggle) {
                        violations.push(violation);
                    }
                }
            }
        }
        if violations.is_empty() {
            Ok(())
        } else {
            Err(FeatureValidationError { violations })
        }
    }
}

impl<'a> IntoIterator for &'a FeatureRegistry {
    type Item = &'a Feature;
    type IntoIter = std::collections::btree_map::Values<'a, &'static str, Feature>;

    fn into_iter(self) -> Self::IntoIter {
        self.features.values()
    }
}

/// The per-feature gate rule. Disabled features are never gated: an ack for
/// a disabled feature is inert, and Preview/Supported ignore ack entirely. A
/// toggle that omits `enabled` resolves to the feature's default (so a bare or
/// ack-only entry does not accidentally gate, nor accidentally disable).
fn check_gate(feature: &Feature, toggle: &FeatureToggle) -> Option<FeatureViolation> {
    if !toggle.enabled.unwrap_or(feature.default_enabled) {
        return None;
    }
    match feature.maturity {
        Maturity::Preview | Maturity::Supported => None,
        Maturity::Experimental { version, changelog } => {
            if toggle.ack.as_deref() == Some(version) {
                None
            } else {
                Some(FeatureViolation::AckRequired {
                    feature: feature.name,
                    required: version,
                    changelog,
                    provided: toggle.ack.clone(),
                })
            }
        }
    }
}

/// One reason [`FeatureRegistry::validate`] refused to boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeatureViolation {
    /// The config names a feature this build does not know.
    UnknownFeature {
        /// The unrecognized name as written in config.
        name: String,
        /// Every name this build accepts.
        known: Vec<&'static str>,
    },
    /// An Experimental feature is enabled without an exact-version ack.
    AckRequired {
        /// The feature being enabled.
        feature: &'static str,
        /// The exact version string the ack must equal.
        required: &'static str,
        /// Where to read what changed before acking.
        changelog: &'static str,
        /// The ack the config supplied, if any (stale after a version bump).
        provided: Option<String>,
    },
}

impl fmt::Display for FeatureViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FeatureViolation::UnknownFeature { name, known } => {
                write!(
                    f,
                    "unknown feature '{name}' (this build knows: {})",
                    known.join(", ")
                )
            }
            FeatureViolation::AckRequired {
                feature,
                required,
                changelog,
                provided,
            } => {
                match provided {
                    Some(stale) => write!(
                        f,
                        "feature '{feature}' is experimental and changed since it was \
                         acknowledged: ack '{stale}' does not match the current version \
                         '{required}'"
                    )?,
                    None => write!(
                        f,
                        "feature '{feature}' is experimental at version '{required}' \
                         and requires an explicit acknowledgment"
                    )?,
                }
                write!(
                    f,
                    "; review {changelog}, then set [features.\"{feature}\"] \
                     ack = \"{required}\""
                )
            }
        }
    }
}

/// The boot-refusal error: every feature-gate violation found in one pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureValidationError {
    violations: Vec<FeatureViolation>,
}

impl FeatureValidationError {
    /// The individual violations, in config (name) order.
    #[must_use]
    pub fn violations(&self) -> &[FeatureViolation] {
        &self.violations
    }
}

impl fmt::Display for FeatureValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "refusing to boot: {} feature violation(s):",
            self.violations.len()
        )?;
        for violation in &self.violations {
            writeln!(f, "  - {violation}")?;
        }
        Ok(())
    }
}

impl std::error::Error for FeatureValidationError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_features(toml_features: &str) -> Config {
        let input = format!("[features]\n{toml_features}");
        crate::Config::from_toml_str(&input, "test.toml")
            .expect("test config parses")
            .config
    }

    #[test]
    fn unknown_feature_name_refuses_to_boot() {
        let registry = FeatureRegistry::builtin();
        let config = config_with_features("\"no-such-feature\" = { enabled = true }");
        let err = registry.validate(&config).expect_err("unknown feature");
        let msg = err.to_string();
        assert!(msg.contains("no-such-feature"), "{msg}");
        assert!(
            msg.contains("sample-experimental"),
            "should list known: {msg}"
        );
    }

    #[test]
    fn disabled_features_are_never_gated() {
        let registry = FeatureRegistry::builtin();
        let config = config_with_features("\"sample-experimental\" = { enabled = false }");
        registry.validate(&config).expect("disabled is fine");
        assert!(!registry.is_enabled(&config, "sample-experimental"));
    }

    #[test]
    fn preview_requires_enabled_only_and_supported_ignores_ack() {
        let mut registry = FeatureRegistry::new();
        registry.register(Feature::preview("preview-thing", "test"));
        registry.register(Feature::supported("supported-thing", "test", false));
        // The stale ack on the supported feature simulates a feature promoted
        // out of Experimental: old acks must not break the boot.
        let config = config_with_features(
            "\"preview-thing\" = { enabled = true }\n\
             \"supported-thing\" = { enabled = true, ack = \"0.0.1-exp.1\" }",
        );
        registry.validate(&config).expect("no gate applies");
        assert!(registry.is_enabled(&config, "preview-thing"));
        assert!(registry.is_enabled(&config, "supported-thing"));
    }

    #[test]
    fn a_supported_feature_defaults_on_when_absent_and_can_be_disabled() {
        let mut registry = FeatureRegistry::new();
        registry.register(Feature::supported("on-by-default", "test", true));

        // Absent from [features]: resolves enabled by default.
        let absent = config_with_features("");
        registry
            .validate(&absent)
            .expect("no gate applies to a default-on supported feature");
        assert!(
            registry.is_enabled(&absent, "on-by-default"),
            "a Supported feature not mentioned in [features] resolves as enabled"
        );

        // Explicit enabled = false turns it off.
        let disabled = config_with_features("\"on-by-default\" = { enabled = false }");
        registry
            .validate(&disabled)
            .expect("explicit disable is fine");
        assert!(
            !registry.is_enabled(&disabled, "on-by-default"),
            "an explicit enabled = false disables a default-on feature"
        );

        // Present but with `enabled` omitted (a bare table, or one attaching
        // only an inert ack) must NOT silently disable a default-on feature: an
        // omitted `enabled` falls back to the default.
        for present in [
            "\"on-by-default\" = {}",
            "\"on-by-default\" = { ack = \"x\" }",
        ] {
            let cfg = config_with_features(present);
            registry.validate(&cfg).expect("no gate applies");
            assert!(
                registry.is_enabled(&cfg, "on-by-default"),
                "a present entry without an explicit enabled must keep the default ({present})"
            );
        }
    }

    #[test]
    fn an_ack_only_entry_does_not_enable_a_default_off_experimental_feature() {
        // Naming an experimental feature to attach an ack, without enabling it,
        // must leave it off and must not trip the ack gate (nothing is enabled
        // to gate). Only an explicit enabled = true arms the gate.
        let registry = FeatureRegistry::builtin();
        let ack_only = config_with_features("\"sample-experimental\" = { ack = \"0.1.0-exp.1\" }");
        registry
            .validate(&ack_only)
            .expect("an ack without enable is inert, not a gate violation");
        assert!(!registry.is_enabled(&ack_only, "sample-experimental"));
    }

    #[test]
    fn a_supported_feature_off_by_default_stays_off_when_absent() {
        let mut registry = FeatureRegistry::new();
        registry.register(Feature::supported("off-by-default", "test", false));
        let absent = config_with_features("");
        registry.validate(&absent).expect("no gate");
        assert!(
            !registry.is_enabled(&absent, "off-by-default"),
            "an off-by-default Supported feature stays off when absent"
        );
    }

    #[test]
    fn the_maturity_constructors_set_the_expected_default_enabled() {
        // Only a Supported feature can be on by default; the ack-gated and
        // preview constructors force off-by-default so an ungated feature can
        // never be enabled without appearing in [features].
        assert!(!Feature::experimental("e", "d", "1", "c").default_enabled());
        assert!(!Feature::preview("p", "d").default_enabled());
        assert!(Feature::supported("s", "d", true).default_enabled());
        assert!(!Feature::supported("s", "d", false).default_enabled());
    }

    #[test]
    #[should_panic(expected = "registered twice")]
    fn duplicate_registration_panics() {
        let mut registry = FeatureRegistry::builtin();
        registry.register_sample_experimental();
    }

    #[test]
    fn custom_domains_acme_is_experimental_and_off_by_default() {
        // Issue #47 ships behind a default-off experimental flag: absent from
        // [features] it resolves disabled, and enabling it without the exact ack
        // refuses to boot.
        let registry = FeatureRegistry::builtin();
        let feature = registry
            .get(CUSTOM_DOMAINS_ACME_FEATURE)
            .expect("custom-domains-acme is registered");
        assert!(matches!(feature.maturity(), Maturity::Experimental { .. }));
        assert!(!feature.default_enabled());

        let absent = config_with_features("");
        registry.validate(&absent).expect("absent is fine");
        assert!(
            !registry.is_enabled(&absent, CUSTOM_DOMAINS_ACME_FEATURE),
            "custom-domains-acme is off when absent from [features]"
        );

        // Enabled without an ack refuses to boot.
        let no_ack = config_with_features("\"custom-domains-acme\" = { enabled = true }");
        registry
            .validate(&no_ack)
            .expect_err("an experimental feature enabled without an ack must refuse to boot");

        // Enabled WITH the exact ack boots and reports enabled.
        let acked = config_with_features(&format!(
            "\"custom-domains-acme\" = {{ enabled = true, ack = \"{CUSTOM_DOMAINS_ACME_VERSION}\" }}"
        ));
        registry.validate(&acked).expect("the exact ack boots");
        assert!(registry.is_enabled(&acked, CUSTOM_DOMAINS_ACME_FEATURE));
    }
}
