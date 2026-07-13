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
#[derive(Debug, Clone, Copy)]
pub struct Feature {
    /// The name config files use in the `[features]` table.
    pub name: &'static str,
    /// Where the feature sits on the maturity ladder.
    pub maturity: Maturity,
    /// One-line operator-facing description.
    pub doc: &'static str,
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
        self.register(Feature {
            name: "sample-experimental",
            maturity: Maturity::Experimental {
                version: "0.1.0-exp.1",
                changelog: "crates/ironauth-config/CHANGELOG.md",
            },
            doc: "Sample experimental flag exercising the acknowledgment gate; \
                  gates no behavior.",
        });
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

    /// Whether `name` is registered and enabled in `config`, with its gate
    /// satisfied. Call only after [`FeatureRegistry::validate`] passed.
    #[must_use]
    pub fn is_enabled(&self, config: &Config, name: &str) -> bool {
        self.features.contains_key(name)
            && config
                .features
                .get(name)
                .is_some_and(|toggle| toggle.enabled)
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
/// a disabled feature is inert, and Preview/Supported ignore ack entirely.
fn check_gate(feature: &Feature, toggle: &FeatureToggle) -> Option<FeatureViolation> {
    if !toggle.enabled {
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
        registry.register(Feature {
            name: "preview-thing",
            maturity: Maturity::Preview,
            doc: "test",
        });
        registry.register(Feature {
            name: "supported-thing",
            maturity: Maturity::Supported,
            doc: "test",
        });
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
    #[should_panic(expected = "registered twice")]
    fn duplicate_registration_panics() {
        let mut registry = FeatureRegistry::builtin();
        registry.register_sample_experimental();
    }
}
