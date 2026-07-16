// SPDX-License-Identifier: MIT OR Apache-2.0

//! The NIST SP 800-63B-4 memorized-secret verifier policy.
//!
//! SP 800-63B-4 (finalized July 2025) reshapes password policy around length and
//! screening and explicitly RETIRES composition rules and periodic forced rotation.
//! The shipped defaults here are exactly that modern posture:
//!
//! - Minimum length 15 code points when the password is the SOLE authentication
//!   factor (SP 800-63B-4 section 3.1.1.2 SHALL), and a minimum of 8 permitted only
//!   when the password is ONE factor of a multi-factor authentication.
//! - Maximum length at least 64 code points (SHOULD); a long passphrase with no
//!   digits or symbols is accepted.
//! - No composition rules and no periodic forced rotation by default.
//! - Unicode accepted: the password is NFKC-normalized ONCE ([`normalize_nfkc`])
//!   before length counting, screening, and hashing, and length is counted in CODE
//!   POINTS, not bytes or UTF-16 units.
//!
//! Legacy compliance regimes are expressed as SETTINGS on the policy object (enable
//! composition, set a rotation interval, change the lengths), never a fork. Every
//! such setting is reported by [`PasswordPolicy::nist_deviations`] so an admin
//! surface can render it as a documented deviation from 63B-4.

use unicode_normalization::UnicodeNormalization;

/// The 800-63B-4 minimum length when the password is the SOLE factor (SHALL).
pub const NIST_MIN_LENGTH_SOLE_FACTOR: usize = 15;
/// The 800-63B-4 minimum length permitted when the password is ONE factor of MFA.
pub const NIST_MIN_LENGTH_MFA_FACTOR: usize = 8;
/// The 800-63B-4 minimum for the maximum acceptable length (SHOULD be at least this).
pub const NIST_MIN_MAX_LENGTH: usize = 64;

/// Normalize a password with Unicode NFKC, applied ONCE at the password boundary so
/// screening, length counting, and hashing all see the same form. NFKC folds the
/// compatibility-confusable class (fullwidth ASCII, ligatures, circled forms) onto
/// ordinary forms, so two visually or semantically equivalent Unicode spellings of the
/// same password normalize to one value and verify against one another.
#[must_use]
pub fn normalize_nfkc(password: &str) -> String {
    password.nfkc().collect()
}

/// Whether the password being evaluated is the sole authentication factor or one
/// factor of a multi-factor authentication. This selects which minimum-length floor
/// applies (63B-4 permits the shorter 8-character floor only for an MFA factor).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactorContext {
    /// The password is the only authentication factor: the 15-character SHALL applies.
    SoleFactor,
    /// The password is one factor of an MFA: the 8-character floor is permitted.
    ///
    /// NOTE (issue #63 residual): this context is currently INERT on the shipped set/change
    /// paths. Every credential-set surface today (register, account change-password,
    /// invitation-accept) evaluates as [`FactorContext::SoleFactor`], whose 15 floor is
    /// always 63B-4-compliant, so the 8-code-point MFA floor never relaxes anything yet. The
    /// floor is wired here as a policy INPUT and activates only when the MFA-enrollment
    /// context (#69/#65) drives an evaluation with `MfaFactor`.
    MfaFactor,
}

/// Why a password failed policy evaluation. Each variant carries the bound it missed
/// so a caller can render a clear (non-enumerating) message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyRejection {
    /// Shorter than the minimum length (in code points) for the factor context.
    TooShort {
        /// The minimum acceptable length in code points.
        min: usize,
    },
    /// Longer than the maximum acceptable length (in code points).
    TooLong {
        /// The maximum acceptable length in code points.
        max: usize,
    },
    /// A composition rule (a legacy 63B-4 deviation) required a character class the
    /// password lacked.
    MissingCharacterClass {
        /// The missing class label (`lowercase`, `uppercase`, `digit`, `symbol`).
        class: &'static str,
    },
    /// The password scored below the configured zxcvbn strength minimum (issue #66):
    /// its estimated guessability was too low. The message is deliberately
    /// NON-enumerating (it never reports the achieved score or WHY the estimator was
    /// unhappy, which would be a hint to an attacker refining a guess), only that a
    /// stronger password is required.
    TooWeak {
        /// The minimum acceptable zxcvbn score (0-4) the policy requires.
        min_score: u8,
    },
}

impl PolicyRejection {
    /// A clear, non-enumerating message describing the requirement that was not met.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            PolicyRejection::TooShort { min } => {
                format!("The password must be at least {min} characters.")
            }
            PolicyRejection::TooLong { max } => {
                format!("The password must be at most {max} characters.")
            }
            PolicyRejection::MissingCharacterClass { class } => {
                format!("The password must contain at least one {class} character.")
            }
            // Non-enumerating on purpose: never echo the achieved score or the
            // estimator's reasoning, only that a stronger password is needed.
            PolicyRejection::TooWeak { .. } => {
                "This password is too easy to guess. Choose a longer or less predictable one."
                    .to_owned()
            }
        }
    }
}

/// One documented deviation from the NIST SP 800-63B-4 defaults, for an admin surface
/// to render (the label a legacy per-tenant override is annotated with).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deviation {
    /// A stable machine code for the deviating setting.
    pub code: &'static str,
    /// A human-readable description of how the setting deviates from 63B-4.
    pub description: String,
}

/// A resolved memorized-secret verifier policy. Built from per-tenant/environment
/// configuration (see `ironauth_config::PasswordPolicyConfig`); the shipped defaults
/// are the 800-63B-4 posture and any deviation is reported by [`Self::nist_deviations`].
// The four composition flags plus the screening flag each map to an independent,
// individually documented policy setting; folding them into an enum would obscure that
// one-to-one mapping to configuration for no gain, so the excessive-bools lint is allowed.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordPolicy {
    min_length_sole_factor: usize,
    min_length_mfa_factor: usize,
    max_length: usize,
    require_lowercase: bool,
    require_uppercase: bool,
    require_digit: bool,
    require_symbol: bool,
    rotation_max_age_days: u64,
    screening_enabled: bool,
    min_zxcvbn_score: u8,
}

impl Default for PasswordPolicy {
    /// The shipped NIST SP 800-63B-4 defaults: 15 sole-factor / 8 MFA-factor minimum,
    /// 64 maximum, NO composition, NO rotation, screening MANDATORY, zxcvbn scoring OFF
    /// (`min_zxcvbn_score = 0`, so no surprise regression on an existing deployment).
    fn default() -> Self {
        Self {
            min_length_sole_factor: NIST_MIN_LENGTH_SOLE_FACTOR,
            min_length_mfa_factor: NIST_MIN_LENGTH_MFA_FACTOR,
            max_length: NIST_MIN_MAX_LENGTH,
            require_lowercase: false,
            require_uppercase: false,
            require_digit: false,
            require_symbol: false,
            rotation_max_age_days: 0,
            screening_enabled: true,
            min_zxcvbn_score: 0,
        }
    }
}

impl PasswordPolicy {
    /// Build a policy from explicit settings. Callers derive these from validated
    /// configuration; nothing here re-validates the numeric bounds (config load does).
    #[must_use]
    #[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
    pub fn new(
        min_length_sole_factor: usize,
        min_length_mfa_factor: usize,
        max_length: usize,
        require_lowercase: bool,
        require_uppercase: bool,
        require_digit: bool,
        require_symbol: bool,
        rotation_max_age_days: u64,
        screening_enabled: bool,
        min_zxcvbn_score: u8,
    ) -> Self {
        Self {
            min_length_sole_factor,
            min_length_mfa_factor,
            max_length,
            require_lowercase,
            require_uppercase,
            require_digit,
            require_symbol,
            rotation_max_age_days,
            screening_enabled,
            min_zxcvbn_score,
        }
    }

    /// The configured strength-score minimum (0-4), or `0` when scoring is OFF (the
    /// default). A caller can render this on an admin surface next to the deviations. The
    /// field is named for the `min_zxcvbn_score` config key and the 0-4 zxcvbn scale it
    /// mirrors; the backing estimator is the in-tree fallback (see [`crate::strength`]),
    /// swappable for zxcvbn behind the same seam the day its dependency tree passes the
    /// supply-chain gate.
    #[must_use]
    pub fn min_zxcvbn_score(&self) -> u8 {
        self.min_zxcvbn_score
    }

    /// Score `normalized` (an already NFKC-normalized password) against the configured
    /// strength minimum (issue #66). This is a SEPARATE step from [`Self::evaluate`], run
    /// AFTER the length/composition policy passes but BEFORE the (network/hash-spending)
    /// breach screen, so a password that fails the strength floor costs neither an
    /// outbound screening call nor an Argon2id hash.
    ///
    /// The estimator is a PURE, deterministic function (no clock read, no RNG), so it
    /// needs no environment seam. When `min_zxcvbn_score` is `0` (the shipped default)
    /// this is an unconditional no-op, so an existing deployment sees no change. The
    /// backing implementation is the in-tree reduced-strength estimator
    /// ([`crate::strength::score`]); the zxcvbn crate was proposed but FAILED the
    /// supply-chain gate under the MSRV floor (see that module), so the fallback ships
    /// behind this same 0-4 contract.
    ///
    /// # Errors
    ///
    /// [`PolicyRejection::TooWeak`] when the estimated score is below the configured
    /// minimum. The rejection's message is non-enumerating (it never reports the
    /// achieved score).
    pub fn evaluate_strength(&self, normalized: &str) -> Result<(), PolicyRejection> {
        if self.min_zxcvbn_score == 0 {
            return Ok(());
        }
        // The estimate reflects the password alone (the set/change surfaces do not thread
        // the identifier/email through), the safe never-over-strict direction.
        if crate::strength::score(normalized) < self.min_zxcvbn_score {
            return Err(PolicyRejection::TooWeak {
                min_score: self.min_zxcvbn_score,
            });
        }
        Ok(())
    }

    /// The minimum length (code points) required for `factor`.
    #[must_use]
    pub fn min_length_for(&self, factor: FactorContext) -> usize {
        match factor {
            FactorContext::SoleFactor => self.min_length_sole_factor,
            FactorContext::MfaFactor => self.min_length_mfa_factor,
        }
    }

    /// Whether compromised-list screening is enabled (the mandatory default).
    #[must_use]
    pub fn screening_enabled(&self) -> bool {
        self.screening_enabled
    }

    /// The configured forced-rotation interval in days, or [`None`] when rotation is
    /// off (the 63B-4 default). A non-`None` value is a documented deviation.
    #[must_use]
    pub fn rotation_max_age_days(&self) -> Option<u64> {
        (self.rotation_max_age_days > 0).then_some(self.rotation_max_age_days)
    }

    /// Evaluate `normalized` (an already NFKC-normalized password) against the policy
    /// for the given factor context. Length is counted in CODE POINTS. Returns the
    /// first requirement that was not met, or `Ok(())` when every check passes. This is
    /// pure policy: it does NOT perform breach screening (that is a separate step so a
    /// hash is never computed for a password that already fails policy).
    ///
    /// # Errors
    ///
    /// [`PolicyRejection`] describing the first failed length or composition rule.
    pub fn evaluate(&self, normalized: &str, factor: FactorContext) -> Result<(), PolicyRejection> {
        let length = normalized.chars().count();
        let min = self.min_length_for(factor);
        if length < min {
            return Err(PolicyRejection::TooShort { min });
        }
        if length > self.max_length {
            return Err(PolicyRejection::TooLong {
                max: self.max_length,
            });
        }
        // Composition rules are OFF by default (a 63B-4 deviation when on). When a
        // legacy tenant enables them, they are checked over code points.
        if self.require_lowercase && !normalized.chars().any(char::is_lowercase) {
            return Err(PolicyRejection::MissingCharacterClass { class: "lowercase" });
        }
        if self.require_uppercase && !normalized.chars().any(char::is_uppercase) {
            return Err(PolicyRejection::MissingCharacterClass { class: "uppercase" });
        }
        if self.require_digit && !normalized.chars().any(|c| c.is_ascii_digit()) {
            return Err(PolicyRejection::MissingCharacterClass { class: "digit" });
        }
        if self.require_symbol && !normalized.chars().any(is_symbol) {
            return Err(PolicyRejection::MissingCharacterClass { class: "symbol" });
        }
        Ok(())
    }

    /// The list of settings that DEVIATE from the NIST SP 800-63B-4 defaults, each with
    /// a stable code and a human description, so an admin surface can render the policy
    /// as compliant or as a documented deviation. An empty list means the policy matches
    /// 63B-4.
    #[must_use]
    pub fn nist_deviations(&self) -> Vec<Deviation> {
        let mut out = Vec::new();
        if self.min_length_sole_factor < NIST_MIN_LENGTH_SOLE_FACTOR {
            out.push(Deviation {
                code: "min_length_below_15",
                description: format!(
                    "sole-factor minimum length {} is below the 63B-4 floor of {NIST_MIN_LENGTH_SOLE_FACTOR}",
                    self.min_length_sole_factor
                ),
            });
        }
        if self.min_length_mfa_factor < NIST_MIN_LENGTH_MFA_FACTOR {
            out.push(Deviation {
                code: "mfa_min_length_below_8",
                description: format!(
                    "MFA-factor minimum length {} is below the 63B-4 floor of {NIST_MIN_LENGTH_MFA_FACTOR}",
                    self.min_length_mfa_factor
                ),
            });
        }
        if self.max_length < NIST_MIN_MAX_LENGTH {
            out.push(Deviation {
                code: "max_length_below_64",
                description: format!(
                    "maximum length {} is below the 63B-4 recommended minimum of {NIST_MIN_MAX_LENGTH}",
                    self.max_length
                ),
            });
        }
        if self.require_lowercase
            || self.require_uppercase
            || self.require_digit
            || self.require_symbol
        {
            out.push(Deviation {
                code: "composition_rules",
                description: "composition rules are enabled; 63B-4 forbids imposing \
                              character-class requirements"
                    .to_owned(),
            });
        }
        if self.rotation_max_age_days > 0 {
            out.push(Deviation {
                code: "forced_rotation",
                description: format!(
                    "forced rotation every {} days is enabled; 63B-4 forbids periodic rotation \
                     without evidence of compromise",
                    self.rotation_max_age_days
                ),
            });
        }
        if !self.screening_enabled {
            out.push(Deviation {
                code: "screening_disabled",
                description: "compromised-list screening is disabled; 63B-4 requires it".to_owned(),
            });
        }
        out
    }
}

/// Whether a character counts as a symbol for a legacy composition rule: any character
/// that is neither alphanumeric nor whitespace.
fn is_symbol(c: char) -> bool {
    !c.is_alphanumeric() && !c.is_whitespace()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_the_63b4_posture() {
        let policy = PasswordPolicy::default();
        assert_eq!(policy.min_length_for(FactorContext::SoleFactor), 15);
        assert_eq!(policy.min_length_for(FactorContext::MfaFactor), 8);
        assert!(policy.screening_enabled());
        assert_eq!(policy.rotation_max_age_days(), None);
        assert!(
            policy.nist_deviations().is_empty(),
            "the shipped default deviates from nothing"
        );
    }

    #[test]
    fn sole_factor_requires_fifteen_and_mfa_permits_eight() {
        let policy = PasswordPolicy::default();
        // 14 code points fails as a sole factor.
        assert_eq!(
            policy.evaluate("abcdefghijklmn", FactorContext::SoleFactor),
            Err(PolicyRejection::TooShort { min: 15 })
        );
        // The same 14 passes as one factor of MFA (>= 8).
        assert!(
            policy
                .evaluate("abcdefghijklmn", FactorContext::MfaFactor)
                .is_ok()
        );
        // 7 fails even as an MFA factor.
        assert_eq!(
            policy.evaluate("abcdefg", FactorContext::MfaFactor),
            Err(PolicyRejection::TooShort { min: 8 })
        );
    }

    #[test]
    fn a_long_passphrase_with_no_digits_or_symbols_is_accepted() {
        let policy = PasswordPolicy::default();
        assert!(
            policy
                .evaluate("correct horse battery staple", FactorContext::SoleFactor)
                .is_ok(),
            "no composition rules by default"
        );
    }

    #[test]
    fn length_is_counted_in_code_points_not_bytes() {
        let policy = PasswordPolicy::default();
        // 15 non-ASCII code points: 15 chars but 30+ bytes. Must pass on code points.
        let pw: String = std::iter::repeat_n('e', 15).collect::<String>();
        assert_eq!(pw.chars().count(), 15);
        assert!(policy.evaluate(&pw, FactorContext::SoleFactor).is_ok());
        // A 15-code-point accented string (each 'e' with combining acute after NFKC is
        // a single precomposed code point) counts as 15, not its byte length.
        let accented = normalize_nfkc(&"\u{00e9}".repeat(15));
        assert_eq!(accented.chars().count(), 15);
        assert!(
            policy
                .evaluate(&accented, FactorContext::SoleFactor)
                .is_ok()
        );
    }

    #[test]
    fn max_length_at_least_64_accepts_a_64_char_passphrase() {
        let policy = PasswordPolicy::default();
        let pw = "a".repeat(64);
        assert!(policy.evaluate(&pw, FactorContext::SoleFactor).is_ok());
        let too_long = "a".repeat(65);
        assert_eq!(
            policy.evaluate(&too_long, FactorContext::SoleFactor),
            Err(PolicyRejection::TooLong { max: 64 })
        );
    }

    #[test]
    fn nfkc_folds_equivalent_unicode_representations() {
        // Fullwidth "ABC" (U+FF21..) folds to ASCII "ABC" under NFKC; a precomposed and
        // a decomposed accented form fold to the same value.
        assert_eq!(normalize_nfkc("\u{ff21}\u{ff22}\u{ff23}"), "ABC");
        let precomposed = normalize_nfkc("\u{00e9}"); // é
        let decomposed = normalize_nfkc("e\u{0301}"); // e + combining acute
        assert_eq!(precomposed, decomposed);
    }

    #[test]
    fn a_legacy_override_applies_and_is_annotated_as_a_deviation() {
        // Composition (upper+digit) plus a 90-day rotation: both apply and both annotate.
        let policy = PasswordPolicy::new(15, 8, 64, false, true, true, false, 90, true, 0);
        // A passphrase lacking an uppercase or a digit is now rejected.
        assert_eq!(
            policy.evaluate("all lowercase letters here", FactorContext::SoleFactor),
            Err(PolicyRejection::MissingCharacterClass { class: "uppercase" })
        );
        assert!(
            policy
                .evaluate("Has Uppercase And Digit 1 here", FactorContext::SoleFactor)
                .is_ok()
        );
        // Both deviations are reported for the admin surface.
        let codes: Vec<&str> = policy.nist_deviations().iter().map(|d| d.code).collect();
        assert!(codes.contains(&"composition_rules"));
        assert!(codes.contains(&"forced_rotation"));
        assert_eq!(policy.rotation_max_age_days(), Some(90));
    }

    #[test]
    fn disabling_screening_is_reported_as_a_deviation() {
        let policy = PasswordPolicy::new(15, 8, 64, false, false, false, false, 0, false, 0);
        let codes: Vec<&str> = policy.nist_deviations().iter().map(|d| d.code).collect();
        assert!(codes.contains(&"screening_disabled"));
    }

    #[test]
    fn zxcvbn_scoring_is_off_by_default() {
        // The shipped default is min_zxcvbn_score = 0, so evaluate_strength is an
        // unconditional no-op: even the weakest password passes the strength step (the
        // length policy and breach screen still apply separately). No surprise
        // regression on an existing deployment.
        let policy = PasswordPolicy::default();
        assert_eq!(policy.min_zxcvbn_score(), 0);
        assert!(policy.evaluate_strength("password").is_ok());
        assert!(policy.evaluate_strength("123456").is_ok());
    }

    #[test]
    fn zxcvbn_threshold_rejects_below_and_accepts_at_or_above() {
        // A policy requiring a minimum score of 3. A trivially guessable password
        // scores 0 and is rejected as TooWeak; a high-entropy passphrase scores >= 3 and
        // passes the strength step.
        let policy = PasswordPolicy::new(1, 1, 64, false, false, false, false, 0, true, 3);
        assert_eq!(
            policy.evaluate_strength("password1"),
            Err(PolicyRejection::TooWeak { min_score: 3 }),
            "a common password is below the score floor"
        );
        // A long, unpredictable passphrase clears the floor.
        assert!(
            policy.evaluate_strength("7xQ!v9mLp2#wZr8Kt4").is_ok(),
            "a high-entropy password is at or above the score floor"
        );
        // The rejection message never enumerates the achieved score.
        let message = PolicyRejection::TooWeak { min_score: 3 }.message();
        assert!(
            !message.contains('3'),
            "the message is non-enumerating: {message}"
        );
    }
}
