// SPDX-License-Identifier: MIT OR Apache-2.0

//! Breached-password screening and the NIST SP 800-63B-4 password policy (issue #63).
//!
//! This crate ships two things a modern identity provider needs to default to, and
//! that the IronAuth covenant forbids paywalling:
//!
//! 1. **Compromised-credential screening**, via a pluggable [`BreachRangeProvider`]
//!    and a [`Screener`] that applies a configurable [`FailurePolicy`]. Two first-party
//!    providers ship: [`HibpRangeProvider`] (the online HIBP range API, k-anonymized,
//!    over the SSRF-hardened `ironauth-fetch`) and [`OfflineCorpusProvider`] (an
//!    operator-supplied dataset, fully offline). Neither is paywalled and neither
//!    depends on a first-party IronAuth service.
//! 2. **The 800-63B-4 memorized-secret verifier policy** ([`PasswordPolicy`]): length
//!    primacy (15 sole-factor / 8 MFA-factor minimum, 64 maximum), NO composition, NO
//!    forced rotation, Unicode accepted (NFKC-normalized once, counted in code points),
//!    and screening mandatory by default. Legacy compliance regimes are SETTINGS on the
//!    policy, each reported by [`PasswordPolicy::nist_deviations`] as a documented
//!    deviation.
//!
//! # The k-anonymity guarantee
//!
//! The SHA-1 of the password is computed LOCALLY ([`digest_password`]) and split into a
//! 5-character prefix and a 35-character suffix. A provider is only ever handed the
//! [`Sha1Prefix`]; it structurally cannot receive the password or the full hash. The
//! candidate suffix is compared against the provider's returned set INSIDE this process,
//! in constant time. This holds for BOTH providers, so switching between online and
//! offline never changes what leaves the process (for offline, nothing does).
//!
//! # Determinism seam
//!
//! Nothing here reads wall-clock or monotonic time or draws randomness, so there is
//! nothing to route through the `ironauth-env` seam and the invariant lints hold without
//! it. The only outbound traffic (the HIBP range query) goes through `ironauth-fetch`,
//! the single hardened outbound path (issue #10).

mod digest;
mod hibp;
mod offline;
mod policy;
mod provider;
mod strength;

pub use digest::{Sha1Digest, Sha1Prefix, Sha1Suffix, digest_password};
pub use hibp::{HIBP_BASE_URL, HibpRangeProvider};
pub use offline::OfflineCorpusProvider;
pub use policy::{
    Deviation, FactorContext, NIST_MIN_LENGTH_MFA_FACTOR, NIST_MIN_LENGTH_SOLE_FACTOR,
    NIST_MIN_MAX_LENGTH, PasswordPolicy, PolicyRejection, normalize_nfkc,
};
pub use provider::{
    BreachRange, BreachRangeProvider, FailurePolicy, ProviderError, ScreenOutcome, Screener,
};
