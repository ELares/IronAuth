// SPDX-License-Identifier: MIT OR Apache-2.0

//! The recorded authentication event and the declarative method registry that
//! is the SINGLE source for the ID token's `acr`, `amr`, and `auth_time` (issue
//! #14).
//!
//! The privacy and honesty guarantee of these claims is that they are DERIVED
//! from what actually happened when the subject authenticated, never asserted
//! from a request parameter. A relying party can ask for a level (`acr_values`,
//! `max_age`), but the provider only ever reflects what it ACHIEVED. So there is
//! exactly one place an authentication method turns into `amr`/`acr`: the
//! [`AuthMethod`] table below. Login records the method(s); the ID token derives
//! the claims from the recorded methods; a request parameter never supplies a
//! value.
//!
//! # The declarative registry
//!
//! [`AuthMethod`] is the row set. Each method maps to:
//!
//! - its RFC 8176 `amr` token(s) (the concrete factors used), and
//! - the authentication context class (`acr`) it achieves.
//!
//! The bootstrap password login is the one ACTIVE method today (`pwd`). The
//! passkey rows are present but DORMANT: they carry the OpenID Connect EAP ACR
//! values `phr` (phishing-resistant) and `phrh` (phishing-resistant,
//! hardware-protected), so when M7 ships passkeys the mapping is already in
//! place and nothing outside this table changes. Later factor issues extend the
//! enum; every downstream derivation follows automatically.

use std::fmt;

/// The IronAuth ACR for a single password (knowledge) factor.
///
/// A namespaced URN rather than a bare number or an ISO/IEC 29115 level: it
/// asserts exactly what happened (a password was used) without claiming an
/// assurance level the bootstrap has not earned. The passkey rows use the EAP
/// registered values instead, which are bare tokens by that specification.
const ACR_PWD: &str = "urn:ironauth:acr:pwd";
/// The IronAuth ACR for a multi-factor authentication: a primary knowledge or
/// possession factor combined with a verified second factor (a TOTP code or a
/// one-time recovery code, issue #69). A namespaced URN rather than a bare level:
/// it asserts that a second factor was checked, which is exactly what a relying
/// party asking for step-up wants to know, without claiming an ISO/IEC 29115
/// assurance level. It sits above the single-factor password ACR and below the
/// phishing-resistant passkey ACRs (TOTP is a shared secret, not origin-bound).
const ACR_MFA: &str = "urn:ironauth:acr:mfa";
/// The OpenID Connect EAP ACR value for a phishing-resistant authenticator
/// (a synced passkey). Per OpenID Connect EAP ACR Values 1.0 `phr` means
/// PHISHING-RESISTANT (origin-bound, which every WebAuthn ceremony is); it does
/// NOT by itself assert user verification, so a phishing-resistant passkey login
/// earns `phr` whether or not user verification was performed. Dormant until M7
/// ships passkeys.
const ACR_PHR: &str = "phr";
/// The OpenID Connect EAP ACR value for a phishing-resistant, hardware-protected
/// authenticator (a device-bound passkey). Like `phr` this asserts phishing
/// resistance (and hardware protection), NOT user verification. Dormant until M7
/// ships passkeys.
const ACR_PHRH: &str = "phrh";
/// The IronAuth ACR for an ATTESTED passkey: a phishing-resistant authenticator
/// whose registration-time attestation statement was verified against the FIDO
/// Metadata Service and admitted by tenant AAGUID policy (issue #66, the
/// `attested_passkey` credential class, the ladder's strongest rung). A namespaced
/// URN rather than an EAP bare token: no registered EAP value asserts "the
/// authenticator model was cryptographically attested", which is exactly what this
/// claims beyond `phr`/`phrh`. DORMANT until PR B lands the attestation writer: the
/// attested [`AuthMethod`] rows carrying it return `false` from [`AuthMethod::is_active`],
/// so this ACR is unreachable (never advertised, never derivable, and a policy that
/// requires it fails closed) until attestation is actually verified.
const ACR_ATTESTED: &str = "urn:ironauth:acr:attested_passkey";

/// One authentication method the provider can record at login: one row of the
/// declarative registry mapping it to its RFC 8176 `amr` token(s) and the `acr`
/// it achieves.
///
/// Only [`AuthMethod::Password`] is ACTIVE today; the passkey variants are
/// dormant table entries (see the module docs) that M7 activates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthMethod {
    /// A password (a knowledge factor). The bootstrap login. RFC 8176 `pwd`.
    Password,
    /// An email one-time proof (issue #68): a numeric email-OTP code OR a scanner-safe
    /// magic link, both proving control of the registered email address (a possession
    /// factor). RFC 8176 `otp` (a one-time password). RFC 8176 defines no link-based
    /// method value, so a magic-link login honestly reports `otp` too: both are a
    /// single-use out-of-band proof delivered to the address. Used as a PRIMARY
    /// passwordless factor, so on its own it achieves the single-factor `pwd`-level ACR.
    EmailOtp,
    /// An SMS one-time proof (issue #70): a numeric code delivered to a registered
    /// phone number over PSTN. RFC 8176 `sms` (a confirmation by text message to a
    /// registered number). It is the WEAKEST factor IronAuth ships (NIST SP 800-63B-4
    /// classifies PSTN out-of-band as a RESTRICTED authenticator), so the amr reports
    /// `sms` HONESTLY and DISTINCTLY from `otp`: an SMS login is never conflated with a
    /// stronger app-based one-time password, which is what lets the no-silent-downgrade
    /// invariant be enforced at all. On its own it achieves the single-factor
    /// `pwd`-level ACR.
    Sms,
    /// A TOTP code (a possession factor: an authenticator app holding the shared
    /// seed). RFC 8176 `otp`. Used as a SECOND factor, so combined with a primary it
    /// achieves the multi-factor ACR (issue #69).
    Totp,
    /// A one-time recovery code redeemed IN PLACE OF the second factor (issue #69):
    /// a pre-shared knowledge secret. RFC 8176 `kba` (knowledge-based
    /// authentication), which is honest and DISTINCT from `otp` so a recovery-code
    /// login never masquerades as a live authenticator.
    RecoveryCode,
    /// A synced passkey used WITHOUT user verification (user presence only): a
    /// phishing-resistant possession factor. Achieves the EAP ACR `phr` (phishing
    /// resistance does not require user verification) with amr `swk`+`user`, but
    /// contributes NO verification factor.
    Passkey,
    /// A synced passkey used WITH user verification (a PIN or biometric was
    /// checked). Achieves `phr` with amr `swk`+`user`+`mfa`: the possession of the
    /// key plus the verification the authenticator performed are two factors, so
    /// `mfa` is honest here and absent from the presence-only [`AuthMethod::Passkey`].
    PasskeyVerified,
    /// A device-bound passkey used WITHOUT user verification (phishing-resistant,
    /// hardware-protected, user presence only). Achieves `phrh` with amr
    /// `hwk`+`user` and no verification factor.
    PasskeyHardware,
    /// A device-bound passkey used WITH user verification. Achieves `phrh` with amr
    /// `hwk`+`user`+`mfa`.
    PasskeyHardwareVerified,
    /// An ATTESTED synced passkey used WITHOUT user verification (issue #66): a
    /// backup-eligible passkey whose registration attestation was verified. Achieves
    /// the `attested_passkey` ACR with amr `swk`+`user`. DORMANT until PR B lands the
    /// attestation writer ([`AuthMethod::is_active`] returns `false`).
    AttestedPasskey,
    /// An ATTESTED synced passkey used WITH user verification (issue #66). Achieves the
    /// `attested_passkey` ACR with amr `swk`+`user`+`mfa`. DORMANT until PR B.
    AttestedPasskeyVerified,
    /// An ATTESTED device-bound passkey used WITHOUT user verification (issue #66).
    /// Achieves the `attested_passkey` ACR with amr `hwk`+`user`. DORMANT until PR B.
    AttestedPasskeyHardware,
    /// An ATTESTED device-bound passkey used WITH user verification (issue #66).
    /// Achieves the `attested_passkey` ACR with amr `hwk`+`user`+`mfa`. DORMANT until
    /// PR B.
    AttestedPasskeyHardwareVerified,
}

impl AuthMethod {
    /// Every method in the registry, in ascending order of the ACR it achieves.
    /// The order is load-bearing: [`achieved_acr`] reflects the STRONGEST method
    /// of an event, so a later entry outranks an earlier one. Methods sharing an
    /// ACR (the verified and presence-only variants of one passkey class) sit
    /// adjacent; their relative order does not matter to [`achieved_acr`] because
    /// their ACR is identical.
    const ALL: [AuthMethod; 13] = [
        AuthMethod::Password,
        // Email OTP / magic link is a single-factor PRIMARY passwordless proof at the
        // same `pwd`-level ACR as a password (adjacent, relative order immaterial since
        // the ACR is identical).
        AuthMethod::EmailOtp,
        // SMS OTP (issue #70) is also a single-factor PRIMARY passwordless proof at the
        // `pwd`-level ACR (adjacent, relative order immaterial since the ACR is
        // identical). It is the WEAKEST such factor, but the ACR reflects the number of
        // factors, not their strength; its restricted-authenticator posture is enforced
        // by the off-by-default guard layer and the no-silent-downgrade invariant, not by
        // the ACR ladder.
        AuthMethod::Sms,
        // The second-factor methods sit above the single password ACR and below the
        // phishing-resistant passkey ACRs: pwd+otp is multi-factor but not
        // phishing-resistant, so a passkey login still outranks it.
        AuthMethod::Totp,
        AuthMethod::RecoveryCode,
        AuthMethod::Passkey,
        AuthMethod::PasskeyVerified,
        AuthMethod::PasskeyHardware,
        AuthMethod::PasskeyHardwareVerified,
        // The ATTESTED passkey rows sit at the STRICTEST end (issue #66): their
        // `attested_passkey` ACR outranks every plain passkey ACR, so achieved_acr
        // ranks them highest once PR B activates them. They are DORMANT in PR A
        // (is_active == false), so they are never derived or advertised yet.
        AuthMethod::AttestedPasskey,
        AuthMethod::AttestedPasskeyVerified,
        AuthMethod::AttestedPasskeyHardware,
        AuthMethod::AttestedPasskeyHardwareVerified,
    ];

    /// The stable persistence token for this method (the value recorded in the
    /// session's and code's `auth_methods`, and parsed back by [`parse_methods`]).
    #[must_use]
    pub fn as_token(self) -> &'static str {
        match self {
            AuthMethod::Password => "pwd",
            AuthMethod::EmailOtp => "email_otp",
            AuthMethod::Sms => "sms",
            AuthMethod::Totp => "totp",
            AuthMethod::RecoveryCode => "recovery_code",
            AuthMethod::Passkey => "passkey",
            AuthMethod::PasskeyVerified => "passkey_uv",
            AuthMethod::PasskeyHardware => "passkey_hw",
            AuthMethod::PasskeyHardwareVerified => "passkey_hw_uv",
            AuthMethod::AttestedPasskey => "attested_passkey",
            AuthMethod::AttestedPasskeyVerified => "attested_passkey_uv",
            AuthMethod::AttestedPasskeyHardware => "attested_passkey_hw",
            AuthMethod::AttestedPasskeyHardwareVerified => "attested_passkey_hw_uv",
        }
    }

    /// Parse a persistence token back into a method. Unknown tokens are [`None`]
    /// (an older or foreign token is ignored, not guessed).
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        AuthMethod::ALL
            .into_iter()
            .find(|method| method.as_token() == token)
    }

    /// The RFC 8176 `amr` token(s) this method contributes, in a stable order.
    ///
    /// `user` (RFC 8176) is a user-PRESENCE test, which every WebAuthn ceremony
    /// performs, so it appears for every passkey method. It does NOT assert user
    /// verification. When the authenticator VERIFIED the user (a PIN or biometric),
    /// the verified variant additionally contributes `mfa` (possession of the key
    /// plus the verification are multiple factors); the presence-only variant does
    /// not, so the amr never implies a verification factor that did not happen.
    #[must_use]
    pub fn amr(self) -> &'static [&'static str] {
        match self {
            // `pwd`: password-based authentication.
            AuthMethod::Password => &["pwd"],
            // `otp`: a single-use out-of-band proof to the registered email (a numeric
            // code or a magic link). A single primary factor, so no `mfa` here.
            AuthMethod::EmailOtp => &["otp"],
            // `sms`: a confirmation by text message to a registered number (RFC 8176).
            // Named DISTINCTLY from `otp` so an SMS login never masquerades as a
            // stronger app-based OTP. A single primary factor, so no `mfa` here.
            AuthMethod::Sms => &["sms"],
            // `otp`: a one-time password (RFC 6238); `mfa`: the second factor plus
            // the primary make multiple factors.
            AuthMethod::Totp => &["otp", "mfa"],
            // `kba`: knowledge-based authentication (the pre-shared recovery code);
            // `mfa`: it stands in for the second factor beyond the primary.
            AuthMethod::RecoveryCode => &["kba", "mfa"],
            // `swk`: a software-secured key (a synced passkey); `user`: presence.
            // An attested passkey's amr MIRRORS its underlying passkey: attestation is a
            // registration-time authenticator-model proof, not an RFC 8176 authentication
            // method reference, so it changes the acr (attested_passkey), never the amr.
            // Each attested row therefore shares its passkey counterpart's amr arm.
            AuthMethod::Passkey | AuthMethod::AttestedPasskey => &["swk", "user"],
            // `mfa`: possession of the key + the user verification performed.
            AuthMethod::PasskeyVerified | AuthMethod::AttestedPasskeyVerified => {
                &["swk", "user", "mfa"]
            }
            // `hwk`: a hardware-secured key (a device-bound passkey); `user`: presence.
            AuthMethod::PasskeyHardware | AuthMethod::AttestedPasskeyHardware => &["hwk", "user"],
            AuthMethod::PasskeyHardwareVerified | AuthMethod::AttestedPasskeyHardwareVerified => {
                &["hwk", "user", "mfa"]
            }
        }
    }

    /// The authentication context class (`acr`) this method achieves on its own.
    /// The verified and presence-only variants of one passkey class share an ACR:
    /// `phr`/`phrh` assert phishing resistance (and hardware protection), NOT user
    /// verification, so user verification changes the amr, never the acr.
    #[must_use]
    pub fn acr(self) -> &'static str {
        match self {
            AuthMethod::Password | AuthMethod::EmailOtp | AuthMethod::Sms => ACR_PWD,
            AuthMethod::Totp | AuthMethod::RecoveryCode => ACR_MFA,
            AuthMethod::Passkey | AuthMethod::PasskeyVerified => ACR_PHR,
            AuthMethod::PasskeyHardware | AuthMethod::PasskeyHardwareVerified => ACR_PHRH,
            AuthMethod::AttestedPasskey
            | AuthMethod::AttestedPasskeyVerified
            | AuthMethod::AttestedPasskeyHardware
            | AuthMethod::AttestedPasskeyHardwareVerified => ACR_ATTESTED,
        }
    }

    /// Whether a login path can produce this method today. M7 (issue #65)
    /// activates the passkey methods: a passkey ceremony records one of the four
    /// passkey variants by its STORED backup-eligibility (synced vs device-bound)
    /// and the assertion's user-verification result, so their EAP ACRs
    /// (`phr`/`phrh`) are now achievable and advertised in
    /// [`acr_values_supported`]. A future dormant method added ahead of its login
    /// path returns `false` here until its writer lands, so the achievability
    /// guard in [`parse_methods`] never derives a claim it cannot achieve.
    ///
    /// The four ATTESTED passkey rows (issue #66) are the current dormant set: PR A
    /// ships the `attested_passkey` credential class and its ACR/amr mapping, but the
    /// attestation-verification writer lands in PR B. Until then they return `false`,
    /// so a recorded `attested_passkey*` token is DROPPED by [`parse_methods`], the
    /// `attested_passkey` ACR is never advertised by [`acr_values_supported`], and a
    /// policy requiring the `attested_passkey` class can never be satisfied (its floor
    /// is unranked and fails closed). PR B flips these to `true` when the writer exists.
    #[must_use]
    pub fn is_active(self) -> bool {
        // PR B (issue #66) activates the four ATTESTED passkey rows: the attestation
        // writer now lands a STORED attestation-verified fact at registration and the
        // login path records an attested method only when that fact is set, so their
        // `attested_passkey` ACR is achievable, advertised by [`acr_values_supported`],
        // and ranked at the TOP of the default order. Every method is now active; the
        // `is_active` gate is retained so a FUTURE dormant method added ahead of its
        // writer still fails closed in [`parse_methods`].
        matches!(
            self,
            AuthMethod::Password
                | AuthMethod::EmailOtp
                | AuthMethod::Sms
                | AuthMethod::Totp
                | AuthMethod::RecoveryCode
                | AuthMethod::Passkey
                | AuthMethod::PasskeyVerified
                | AuthMethod::PasskeyHardware
                | AuthMethod::PasskeyHardwareVerified
                | AuthMethod::AttestedPasskey
                | AuthMethod::AttestedPasskeyVerified
                | AuthMethod::AttestedPasskeyHardware
                | AuthMethod::AttestedPasskeyHardwareVerified
        )
    }
}

/// The multi-factor authentication context class (`acr`) a second factor achieves
/// (issue #72). Exposed so the step-up gate can rank a request's requirement against
/// the multi-factor level without re-deriving the URN.
#[must_use]
pub fn acr_for_mfa() -> &'static str {
    ACR_MFA
}

/// The credential-class ladder (issue #66): the minimum authenticator assurance a
/// tenant/group/org policy can require of a login, weakest to strongest.
///
/// The order is the whole point: the variants are declared ascending and `Ord` is
/// DERIVED, so [`Ord::max`] over a set of policy minimums is STRICTEST-WINS
/// composition, and a satisfied class is compared against a required class with a
/// plain `>=`. The ladder is `Any < Mfa < Passkey < AttestedPasskey`:
///
/// - `Any`: a single primary factor (a password, an email OTP): the honest floor.
/// - `Mfa`: a verified second factor was combined with a primary (the multi-factor
///   ACR was achieved).
/// - `Passkey`: a phishing-resistant passkey was used (user-verifying when the
///   tenant requires user verification).
/// - `AttestedPasskey`: a passkey whose registration attestation was verified (the
///   strongest rung). DORMANT in PR A: [`satisfied_class`] can never RETURN it (no
///   stored attestation-verified fact exists yet), and requiring it fails closed
///   (its [`acr_for_class`] URN is unranked until PR B activates the attested
///   [`AuthMethod`] rows). It exists so the mapping and composition are already in
///   place, exactly as the passkey ACRs shipped dormant ahead of M7.
///
/// This ladder is CO-LOCATED with the ACR registry deliberately: a class maps to an
/// ACR through [`acr_for_class`] in this one module, so there is a single honesty
/// choke point where an authenticator fact becomes an assurance claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CredentialClass {
    /// A single primary factor: the honest floor.
    Any,
    /// A verified second factor combined with a primary (the multi-factor ACR).
    Mfa,
    /// A phishing-resistant passkey (user-verifying when the tenant requires it).
    Passkey,
    /// A passkey whose registration attestation was verified (dormant in PR A).
    AttestedPasskey,
}

impl CredentialClass {
    /// The persistence / policy token for this class (the value stored in
    /// `credential_class_policies.min_class` and accepted by the CLI).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            CredentialClass::Any => "any",
            CredentialClass::Mfa => "mfa",
            CredentialClass::Passkey => "passkey",
            CredentialClass::AttestedPasskey => "attested_passkey",
        }
    }

    /// Parse a policy token back into a class. An unknown token is [`None`] (a
    /// foreign or misspelled value is rejected, never silently downgraded).
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "any" => Some(CredentialClass::Any),
            "mfa" => Some(CredentialClass::Mfa),
            "passkey" => Some(CredentialClass::Passkey),
            "attested_passkey" => Some(CredentialClass::AttestedPasskey),
            _ => None,
        }
    }
}

impl fmt::Display for CredentialClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The STORED authenticator facts [`satisfied_class`] folds into a class, distinct
/// from the recorded [`AuthenticationEvent`] methods (issue #66).
///
/// Every field is a fact the SERVER stored or PROVED, never a client-supplied wire
/// value: this is the covenant. The client supplies NONE of these.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CredentialFacts {
    /// Whether the tenant requires user verification for a passkey to count as the
    /// `Passkey` class (the `webauthn_require_user_verification` setting). When set, a
    /// presence-only passkey does NOT reach the passkey rung.
    pub require_user_verification: bool,
    /// The STORED attestation-verified fact for the passkey used (issue #66 PR B): the
    /// `webauthn_credentials.attestation_verified` column, stamped at registration when
    /// the presented AAGUID was admitted by tenant policy AND its attestation statement
    /// chained to the pinned FIDO MDS3 root. It is a reg-time-IMMUTABLE fact (never a
    /// wire value, INSERT-only in the schema). [`satisfied_class`] requires it (together
    /// with a recorded attested method) to reach `AttestedPasskey`, so the strongest rung
    /// is gated on a stored, cryptographically established truth.
    pub attestation_verified: bool,
}

/// The credential class a recorded authentication actually SATISFIES (issue #66),
/// folded PURELY from stored/proven facts: the recorded [`AuthenticationEvent`]
/// methods (which already encode the registration-time backup-eligibility and the
/// asserted user-verification bit, per [`AuthenticationEvent::passkey`]) and the
/// stored [`CredentialFacts`]. The client supplies none of the inputs.
///
/// This is THE covenant function: the token's acr derives from the class this
/// returns, so it must never over-claim. It can only reflect what happened:
///
/// - a passkey method that meets the user-verification requirement reaches
///   `Passkey` (or `AttestedPasskey` when the stored attestation fact is set, which
///   is dormant in PR A);
/// - otherwise a multi-factor ACR reaches `Mfa`;
/// - everything else is `Any`.
#[must_use]
pub fn satisfied_class(event: &AuthenticationEvent, facts: &CredentialFacts) -> CredentialClass {
    let methods = event.methods();
    // Every passkey method reaches the passkey rung, INCLUDING the four attested rows
    // (issue #66 PR B). PR A omitted the attested variants here, which left the
    // representation DISJOINT: [`AuthenticationEvent::attested_passkey`] records an
    // attested method that was invisible to this check, so an attested login folded to
    // `Any` while its [`achieved_acr`] was already `attested_passkey`. Including them
    // here makes the SATISFIED class and the acr-floor enforcement agree, because both
    // now read the SAME recorded methods.
    let has_passkey = methods.iter().any(|method| {
        matches!(
            method,
            AuthMethod::Passkey
                | AuthMethod::PasskeyVerified
                | AuthMethod::PasskeyHardware
                | AuthMethod::PasskeyHardwareVerified
                | AuthMethod::AttestedPasskey
                | AuthMethod::AttestedPasskeyVerified
                | AuthMethod::AttestedPasskeyHardware
                | AuthMethod::AttestedPasskeyHardwareVerified
        )
    });
    // A passkey that PROVED user verification, when the tenant requires it. When the
    // tenant does not require user verification a presence-only passkey still counts
    // (it is phishing-resistant possession); when it does, only a verified passkey
    // reaches the rung, so the class never over-claims the verification posture.
    let user_verified = methods.iter().any(|method| {
        matches!(
            method,
            AuthMethod::PasskeyVerified
                | AuthMethod::PasskeyHardwareVerified
                | AuthMethod::AttestedPasskeyVerified
                | AuthMethod::AttestedPasskeyHardwareVerified
        )
    });
    // Whether the RECORDED event carries an attested method. This is the SAME signal
    // [`achieved_acr`] reads to emit `attested_passkey`, so the two never diverge: the
    // attested rung is method-driven, never fact-driven alone (a plain passkey login
    // can never reach it even if a stale attestation fact were passed). The STORED
    // `attestation_verified` fact is additionally REQUIRED (defence in depth): the login
    // path records an attested method ONLY when that stored column is set, so the method
    // and the fact are two views of one registration-time truth and always agree.
    let has_attested_method = methods.iter().any(|method| {
        matches!(
            method,
            AuthMethod::AttestedPasskey
                | AuthMethod::AttestedPasskeyVerified
                | AuthMethod::AttestedPasskeyHardware
                | AuthMethod::AttestedPasskeyHardwareVerified
        )
    });
    let passkey_class_reached = has_passkey && (!facts.require_user_verification || user_verified);
    if passkey_class_reached {
        // The AttestedPasskey rung requires BOTH an attested recorded method AND the
        // stored attestation-verified fact. Because the login path derives the attested
        // method FROM that stored fact, the two agree; requiring both keeps the class
        // from ever over-claiming (a plain passkey with a spurious fact stays `Passkey`,
        // matching its `phr`/`phrh` acr), and keeps the class from over-claiming an
        // attested method whose stored fact was cleared.
        if has_attested_method && facts.attestation_verified {
            return CredentialClass::AttestedPasskey;
        }
        return CredentialClass::Passkey;
    }
    if achieved_acr(methods) == ACR_MFA {
        return CredentialClass::Mfa;
    }
    CredentialClass::Any
}

/// The credential class a set of applicable policy minimums REQUIRES (issue #66):
/// strictest-wins composition, `policies.max().unwrap_or(Any)`.
///
/// "Applicable" in PR A is the single tenant-level policy row; the group and org
/// rows are the inert seam (end-to-end group attachment is M10-gated). The
/// composition ALGORITHM is nonetheless proven over multiple synthetic rows, so the
/// acceptance example (two groups requiring `mfa` and `attested_passkey` compose to
/// `attested_passkey`) holds the moment the attachment surface lands.
#[must_use]
pub fn required_class(policies: impl IntoIterator<Item = CredentialClass>) -> CredentialClass {
    policies.into_iter().max().unwrap_or(CredentialClass::Any)
}

/// The canonical `acr` a credential class maps to (issue #66), the ONE place a class
/// becomes an assurance URN so the step-up gate and the class enforcer compare
/// against the same mapping:
///
/// - `Any` -> the single-factor password ACR,
/// - `Mfa` -> the multi-factor ACR,
/// - `Passkey` -> the phishing-resistant `phr` floor (a synced passkey satisfies it;
///   a device-bound `phrh` outranks it under the default order),
/// - `AttestedPasskey` -> the `attested_passkey` ACR, RANKED at the TOP of the default
///   order now that PR B activates the attested methods (it appears last in
///   [`acr_values_supported`], so it is the strongest rung and strictest-wins is exact:
///   an attested floor dominates every `phr`/`phrh` floor, and only an attested login
///   satisfies it).
#[must_use]
pub fn acr_for_class(class: CredentialClass) -> &'static str {
    match class {
        CredentialClass::Any => ACR_PWD,
        CredentialClass::Mfa => ACR_MFA,
        CredentialClass::Passkey => ACR_PHR,
        CredentialClass::AttestedPasskey => ACR_ATTESTED,
    }
}

/// Parse a space-separated `auth_methods` token string into the recorded
/// methods, dropping unknown tokens.
///
/// An empty or fully-unrecognized string falls back to
/// [`AuthMethod::Password`]: the only login path that has ever existed is the
/// bootstrap password login, so a recorded event with no parseable method was,
/// by construction, a password authentication. The fallback keeps the derived
/// claims honest for any legacy row rather than emitting an empty `amr`. It can
/// only ever under-claim (drop an unknown method), never over-claim, so it is the
/// safe direction.
///
/// The achievability guard (M7, issue #65): a recorded token whose method is not
/// currently [`AuthMethod::is_active`] is DROPPED, so a stale or dormant elevated
/// method (a passkey `phr` recorded before its login path shipped, or a future
/// dormant factor) can never be derived into a claim the current authentication did
/// not actually achieve. It can only under-claim, never over-claim.
#[must_use]
pub fn parse_methods(auth_methods: &str) -> Vec<AuthMethod> {
    let methods: Vec<AuthMethod> = auth_methods
        .split_whitespace()
        .filter_map(AuthMethod::from_token)
        .filter(|method| method.is_active())
        .collect();
    if methods.is_empty() {
        vec![AuthMethod::Password]
    } else {
        methods
    }
}

/// Serialize recorded methods to the space-separated persistence token string.
#[must_use]
pub fn methods_token(methods: &[AuthMethod]) -> String {
    methods
        .iter()
        .map(|method| method.as_token())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The RFC 8176 `amr` values for a set of recorded methods: the union of each
/// method's tokens, de-duplicated while preserving first-seen order, so `amr`
/// contains only factors actually used and never a duplicate.
#[must_use]
pub fn amr_values(methods: &[AuthMethod]) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for method in methods {
        for &token in method.amr() {
            if !out.contains(&token) {
                out.push(token);
            }
        }
    }
    out
}

/// The achieved `acr` for a set of recorded methods: the ACR of the STRONGEST
/// method present (registry order). Combining distinct factors into an elevated
/// multi-factor ACR is M7; the bootstrap records a single method, so this
/// returns that method's ACR. An empty set falls back to the password ACR (see
/// [`parse_methods`]).
#[must_use]
pub fn achieved_acr(methods: &[AuthMethod]) -> &'static str {
    AuthMethod::ALL
        .into_iter()
        .rev()
        .find(|candidate| methods.contains(candidate))
        .unwrap_or(AuthMethod::Password)
        .acr()
}

/// The `acr_values_supported` the discovery document advertises: the achieved
/// ACR of every ACTIVE method, de-duplicated in registry order.
///
/// This is the consumable data the discovery generator (issue #18) reads; it is
/// deliberately NOT wired into the discovery document here, to keep this issue
/// off the discovery-generation surface. Dormant methods (the passkeys) are
/// excluded until M7 activates them, so the provider never advertises a level it
/// cannot actually achieve.
#[must_use]
pub fn acr_values_supported() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for method in AuthMethod::ALL {
        if method.is_active() && !out.contains(&method.acr()) {
            out.push(method.acr());
        }
    }
    out
}

/// A recorded authentication event: the method(s) the subject authenticated
/// with and when.
///
/// Constructed at login (the SINGLE source), persisted on the session, frozen
/// onto the authorization code at issuance, and read back at ID-token mint time.
/// The claims (`amr`, `acr`, `auth_time`) are always derived from it, never from
/// the authorization request.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthenticationEvent {
    methods: Vec<AuthMethod>,
    auth_time_unix_micros: i64,
}

impl AuthenticationEvent {
    /// The bootstrap password authentication at `auth_time_unix_micros`.
    #[must_use]
    pub fn password(auth_time_unix_micros: i64) -> Self {
        Self {
            methods: vec![AuthMethod::Password],
            auth_time_unix_micros,
        }
    }

    /// An email one-time proof authentication at `auth_time_unix_micros` (issue #68): a
    /// numeric email-OTP code or a scanner-safe magic link, both `amr` `otp`.
    #[must_use]
    pub fn email_otp(auth_time_unix_micros: i64) -> Self {
        Self {
            methods: vec![AuthMethod::EmailOtp],
            auth_time_unix_micros,
        }
    }

    /// An SMS one-time proof authentication at `auth_time_unix_micros` (issue #70): a
    /// numeric code delivered over PSTN, `amr` `sms` (honestly named, distinct from the
    /// email/app `otp`).
    #[must_use]
    pub fn sms(auth_time_unix_micros: i64) -> Self {
        Self {
            methods: vec![AuthMethod::Sms],
            auth_time_unix_micros,
        }
    }

    /// A passkey authentication at `auth_time_unix_micros` (issue #65).
    ///
    /// `backup_eligible` MUST be the credential's REGISTRATION-time, stored BE
    /// value, never the mutable BE bit of the presented assertion: WebAuthn L3
    /// requires BE to be immutable across a credential's life, and deriving the
    /// assurance from the assertion's flag would let a synced authenticator claim
    /// the device-bound `phrh`. It chooses the honest ACR: a backup-eligible
    /// (synced) authenticator earns EAP `phr` (amr `swk`+`user`); a device-bound
    /// one earns EAP `phrh` (amr `hwk`+`user`).
    ///
    /// `user_verified` is the assertion's user-verification result. When true the
    /// amr additionally carries `mfa` (the possession of the key plus the
    /// verification the authenticator performed); when false (a user-presence-only
    /// login, reachable only when `webauthn_require_user_verification` is off) the
    /// amr carries no verification factor. Either way the acr stays `phr`/`phrh`,
    /// which assert phishing resistance, not user verification.
    #[must_use]
    pub fn passkey(auth_time_unix_micros: i64, backup_eligible: bool, user_verified: bool) -> Self {
        let method = match (backup_eligible, user_verified) {
            (true, true) => AuthMethod::PasskeyVerified,
            (true, false) => AuthMethod::Passkey,
            (false, true) => AuthMethod::PasskeyHardwareVerified,
            (false, false) => AuthMethod::PasskeyHardware,
        };
        Self {
            methods: vec![method],
            auth_time_unix_micros,
        }
    }

    /// An ATTESTED passkey authentication at `auth_time_unix_micros` (issue #66),
    /// mirroring [`AuthenticationEvent::passkey`] but recording the attested rung.
    ///
    /// Like `passkey`, `backup_eligible` MUST be the credential's REGISTRATION-time,
    /// stored BE value (never the mutable assertion bit), and `user_verified` is the
    /// assertion's user-verification result: the same covenant, so an attested login
    /// can no more inflate its BE than a plain passkey can.
    ///
    /// DORMANT in PR A: the attested [`AuthMethod`] rows this records are not
    /// [`AuthMethod::is_active`] until PR B lands the attestation writer, so an event
    /// built here has its methods DROPPED by [`parse_methods`] and derives no attested
    /// claim yet. It exists so PR B can activate the rung by flipping `is_active`
    /// alone, with the recording constructor already in place.
    #[must_use]
    pub fn attested_passkey(
        auth_time_unix_micros: i64,
        backup_eligible: bool,
        user_verified: bool,
    ) -> Self {
        let method = match (backup_eligible, user_verified) {
            (true, true) => AuthMethod::AttestedPasskeyVerified,
            (true, false) => AuthMethod::AttestedPasskey,
            (false, true) => AuthMethod::AttestedPasskeyHardwareVerified,
            (false, false) => AuthMethod::AttestedPasskeyHardware,
        };
        Self {
            methods: vec![method],
            auth_time_unix_micros,
        }
    }

    /// A password-plus-TOTP multi-factor authentication at `auth_time_unix_micros`
    /// (issue #69): the user proved a knowledge factor (the password) AND a
    /// possession factor (a current TOTP code), so the event records both methods
    /// and derives the honest multi-factor ACR with amr `pwd`+`otp`+`mfa`.
    #[must_use]
    pub fn password_and_totp(auth_time_unix_micros: i64) -> Self {
        Self {
            methods: vec![AuthMethod::Password, AuthMethod::Totp],
            auth_time_unix_micros,
        }
    }

    /// A password-plus-recovery-code multi-factor authentication at
    /// `auth_time_unix_micros` (issue #69): a one-time recovery code stood in for the
    /// second factor. Recorded DISTINCTLY from TOTP (amr `pwd`+`kba`+`mfa`), so a
    /// recovery-code login is never conflated with a live authenticator.
    #[must_use]
    pub fn password_and_recovery_code(auth_time_unix_micros: i64) -> Self {
        Self {
            methods: vec![AuthMethod::Password, AuthMethod::RecoveryCode],
            auth_time_unix_micros,
        }
    }

    /// An authentication event from an explicit set of recorded methods at
    /// `auth_time_unix_micros` (issue #72), used by a step-up that COMBINES a prior
    /// factor already proven in the session with a fresh one just verified (for
    /// example a password login stepped up with a live TOTP: `[Password, Totp]`).
    ///
    /// The methods are de-duplicated preserving first-seen order, and only active
    /// methods are kept, so the derived `amr`/`acr` can never over-claim; an empty
    /// input falls back to a bare password event (the honest floor). `auth_time`
    /// MUST be the instant the step-up COMPLETED, so a stepped-up token carries a
    /// fresh `auth_time` reflecting the authentication that actually occurred.
    #[must_use]
    pub fn from_methods(methods: &[AuthMethod], auth_time_unix_micros: i64) -> Self {
        let mut kept: Vec<AuthMethod> = Vec::new();
        for &method in methods {
            if method.is_active() && !kept.contains(&method) {
                kept.push(method);
            }
        }
        if kept.is_empty() {
            kept.push(AuthMethod::Password);
        }
        Self {
            methods: kept,
            auth_time_unix_micros,
        }
    }

    /// The recorded methods.
    #[must_use]
    pub fn methods(&self) -> &[AuthMethod] {
        &self.methods
    }

    /// When the subject authenticated, in microseconds since the Unix epoch.
    #[must_use]
    pub fn auth_time_unix_micros(&self) -> i64 {
        self.auth_time_unix_micros
    }

    /// The persistence token string for the recorded methods.
    #[must_use]
    pub fn methods_token(&self) -> String {
        methods_token(&self.methods)
    }
}

impl fmt::Debug for AuthenticationEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The methods and auth_time are not secret, but they are end-user
        // authentication detail; render the methods and the time terse.
        f.debug_struct("AuthenticationEvent")
            .field("methods", &self.methods)
            .field("auth_time_unix_micros", &self.auth_time_unix_micros)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_maps_to_pwd_amr_and_the_password_acr() {
        let methods = parse_methods("pwd");
        assert_eq!(methods, vec![AuthMethod::Password]);
        assert_eq!(amr_values(&methods), vec!["pwd"]);
        assert_eq!(achieved_acr(&methods), ACR_PWD);
    }

    #[test]
    fn sms_maps_to_the_sms_amr_and_the_password_acr() {
        // Issue #70: SMS reports `sms` HONESTLY (RFC 8176), DISTINCT from the email/app
        // `otp`, and as a single primary factor achieves the `pwd`-level ACR.
        let event = AuthenticationEvent::sms(1_700_000_000_000_000);
        assert_eq!(event.methods(), &[AuthMethod::Sms]);
        assert_eq!(amr_values(event.methods()), vec!["sms"]);
        assert_ne!(
            amr_values(event.methods()),
            vec!["otp"],
            "sms is never conflated with otp"
        );
        assert_eq!(achieved_acr(event.methods()), ACR_PWD);
        // The token round-trips and the method is active.
        assert_eq!(AuthMethod::from_token("sms"), Some(AuthMethod::Sms));
        assert!(AuthMethod::Sms.is_active());
    }

    #[test]
    fn methods_token_round_trips_through_parse() {
        for method in AuthMethod::ALL {
            let token = method.as_token();
            // Every method's token round-trips through from_token / methods_token; these
            // are pure serialization and hold for dormant rows too.
            assert_eq!(AuthMethod::from_token(token), Some(method), "{token}");
            assert_eq!(methods_token(&[method]), token);
            // parse_methods additionally drops INACTIVE methods (the achievability
            // guard), so only an ACTIVE method survives a parse as itself. A dormant
            // method parses to the honest password floor, never itself. Every method is
            // active in PR B (the attested rows were activated), so every token survives.
            if method.is_active() {
                assert_eq!(parse_methods(token), vec![method]);
            } else {
                assert_eq!(
                    parse_methods(token),
                    vec![AuthMethod::Password],
                    "a dormant method's token must be dropped by parse_methods"
                );
            }
        }
        // Sanity: no method is dormant in PR B.
        assert!(AuthMethod::ALL.into_iter().all(AuthMethod::is_active));
    }

    #[test]
    fn amr_values_are_deduplicated_in_first_seen_order() {
        // Two methods sharing the `user` token contribute it exactly once.
        let methods = vec![AuthMethod::Passkey, AuthMethod::PasskeyHardware];
        assert_eq!(amr_values(&methods), vec!["swk", "user", "hwk"]);
    }

    #[test]
    fn achieved_acr_is_the_strongest_method() {
        assert_eq!(achieved_acr(&[AuthMethod::Password]), ACR_PWD);
        assert_eq!(achieved_acr(&[AuthMethod::Passkey]), ACR_PHR);
        assert_eq!(
            achieved_acr(&[AuthMethod::Password, AuthMethod::PasskeyHardware]),
            ACR_PHRH,
            "the strongest method's ACR wins"
        );
    }

    #[test]
    fn every_amr_token_is_rfc8176_vocabulary() {
        // The full RFC 8176 registry of authentication method reference values.
        const RFC8176: &[&str] = &[
            "face", "fpt", "geo", "hwk", "iris", "kba", "mca", "mfa", "otp", "pin", "pop", "pwd",
            "rba", "retina", "sc", "sms", "swk", "tel", "user", "vbm", "wia",
        ];
        for method in AuthMethod::ALL {
            for token in method.amr() {
                assert!(
                    RFC8176.contains(token),
                    "amr token {token} is not RFC 8176 vocabulary"
                );
            }
        }
    }

    #[test]
    fn acr_values_supported_advertises_the_active_methods_including_passkeys() {
        // M7 activated the passkey methods (issue #65) and the TOTP / recovery-code
        // second factors (issue #69), and PR B (issue #66) activated the attested rung,
        // so their ACRs are advertised alongside the password ACR, in registry (strength)
        // order. TOTP and recovery code share the multi-factor ACR, so it appears once.
        // The attested ACR is LAST (strongest), which is what ranks it at the top of the
        // default step-up order.
        assert_eq!(
            acr_values_supported(),
            vec![ACR_PWD, ACR_MFA, ACR_PHR, ACR_PHRH, ACR_ATTESTED]
        );
    }

    #[test]
    fn totp_is_a_second_factor_with_honest_amr_and_the_mfa_acr() {
        // A password-plus-TOTP event records both methods, derives the multi-factor
        // ACR, and carries pwd+otp+mfa amr (issue #69).
        let event = AuthenticationEvent::password_and_totp(1_700_000_000_000_000);
        assert_eq!(event.methods(), &[AuthMethod::Password, AuthMethod::Totp]);
        assert_eq!(achieved_acr(event.methods()), ACR_MFA);
        assert_eq!(amr_values(event.methods()), vec!["pwd", "otp", "mfa"]);
        assert_eq!(event.methods_token(), "pwd totp");
        assert_eq!(parse_methods("pwd totp"), event.methods());
    }

    #[test]
    fn recovery_code_is_distinct_from_totp_in_amr() {
        // A recovery-code login is knowledge-based (kba), NEVER otp, so it can never
        // masquerade as a live authenticator, while still achieving the mfa ACR.
        let event = AuthenticationEvent::password_and_recovery_code(1_700_000_000_000_000);
        assert_eq!(
            event.methods(),
            &[AuthMethod::Password, AuthMethod::RecoveryCode]
        );
        assert_eq!(achieved_acr(event.methods()), ACR_MFA);
        assert_eq!(amr_values(event.methods()), vec!["pwd", "kba", "mfa"]);
        assert!(!amr_values(event.methods()).contains(&"otp"));
        assert_eq!(event.methods_token(), "pwd recovery_code");
    }

    #[test]
    fn empty_or_unknown_methods_fall_back_to_password() {
        assert_eq!(parse_methods(""), vec![AuthMethod::Password]);
        assert_eq!(parse_methods("   "), vec![AuthMethod::Password]);
        assert_eq!(parse_methods("totally-unknown"), vec![AuthMethod::Password]);
    }

    #[test]
    fn a_uv_passkey_login_maps_to_phr_or_phrh_by_backup_eligibility() {
        // A user-verified synced (backup-eligible) passkey -> phr with swk+user+mfa
        // amr (the mfa reflects the verification the authenticator performed).
        let synced = AuthenticationEvent::passkey(1_700_000_000_000_000, true, true);
        assert_eq!(synced.methods(), &[AuthMethod::PasskeyVerified]);
        assert_eq!(achieved_acr(synced.methods()), ACR_PHR);
        assert_eq!(amr_values(synced.methods()), vec!["swk", "user", "mfa"]);
        assert_eq!(synced.methods_token(), "passkey_uv");
        // A user-verified device-bound passkey -> phrh with hwk+user+mfa amr.
        let device_bound = AuthenticationEvent::passkey(1_700_000_000_000_000, false, true);
        assert_eq!(
            device_bound.methods(),
            &[AuthMethod::PasskeyHardwareVerified]
        );
        assert_eq!(achieved_acr(device_bound.methods()), ACR_PHRH);
        assert_eq!(
            amr_values(device_bound.methods()),
            vec!["hwk", "user", "mfa"]
        );
        assert_eq!(device_bound.methods_token(), "passkey_hw_uv");
    }

    #[test]
    fn a_presence_only_passkey_login_never_claims_a_verification_factor() {
        // With user verification NOT performed (user presence only, reachable only
        // when webauthn_require_user_verification is off), the amr keeps `user`
        // (presence, per RFC 8176) but carries NO `mfa` (no verification happened).
        // The acr stays phishing-resistant either way: phr/phrh assert phishing
        // resistance, not user verification.
        let synced = AuthenticationEvent::passkey(1_700_000_000_000_000, true, false);
        assert_eq!(synced.methods(), &[AuthMethod::Passkey]);
        assert_eq!(achieved_acr(synced.methods()), ACR_PHR);
        assert_eq!(amr_values(synced.methods()), vec!["swk", "user"]);
        assert!(!amr_values(synced.methods()).contains(&"mfa"));
        assert_eq!(synced.methods_token(), "passkey");
        let device_bound = AuthenticationEvent::passkey(1_700_000_000_000_000, false, false);
        assert_eq!(device_bound.methods(), &[AuthMethod::PasskeyHardware]);
        assert_eq!(achieved_acr(device_bound.methods()), ACR_PHRH);
        assert_eq!(amr_values(device_bound.methods()), vec!["hwk", "user"]);
        assert!(!amr_values(device_bound.methods()).contains(&"mfa"));
        assert_eq!(device_bound.methods_token(), "passkey_hw");
    }

    #[test]
    fn a_recorded_passkey_token_round_trips_now_that_it_is_active() {
        // The achievability guard drops inactive methods; passkeys are active in
        // M7, so their tokens survive parse and derive the passkey ACR.
        assert_eq!(parse_methods("passkey"), vec![AuthMethod::Passkey]);
        assert_eq!(
            parse_methods("passkey_uv"),
            vec![AuthMethod::PasskeyVerified]
        );
        assert_eq!(
            parse_methods("passkey_hw"),
            vec![AuthMethod::PasskeyHardware]
        );
        assert_eq!(
            parse_methods("passkey_hw_uv"),
            vec![AuthMethod::PasskeyHardwareVerified]
        );
        assert_eq!(achieved_acr(&parse_methods("passkey_uv")), ACR_PHR);
        assert_eq!(achieved_acr(&parse_methods("passkey_hw_uv")), ACR_PHRH);
    }

    #[test]
    fn event_carries_methods_and_time() {
        let event = AuthenticationEvent::password(1_700_000_000_000_000);
        assert_eq!(event.methods(), &[AuthMethod::Password]);
        assert_eq!(event.auth_time_unix_micros(), 1_700_000_000_000_000);
        assert_eq!(event.methods_token(), "pwd");
    }

    // ---- Credential-class ladder (issue #66, PR A) ----

    const TIME: i64 = 1_700_000_000_000_000;

    #[test]
    fn the_ladder_is_ordered_and_max_is_strictest_wins() {
        // The declared order is the ladder order; Ord is derived, so a plain compare
        // and max() implement the "stronger rung wins" semantics.
        assert!(CredentialClass::Any < CredentialClass::Mfa);
        assert!(CredentialClass::Mfa < CredentialClass::Passkey);
        assert!(CredentialClass::Passkey < CredentialClass::AttestedPasskey);
        assert_eq!(
            CredentialClass::Mfa.max(CredentialClass::AttestedPasskey),
            CredentialClass::AttestedPasskey
        );
    }

    #[test]
    fn credential_class_token_round_trips() {
        for class in [
            CredentialClass::Any,
            CredentialClass::Mfa,
            CredentialClass::Passkey,
            CredentialClass::AttestedPasskey,
        ] {
            assert_eq!(CredentialClass::from_token(class.as_str()), Some(class));
        }
        assert_eq!(CredentialClass::from_token("nonsense"), None);
    }

    #[test]
    fn required_class_composes_strictest_wins_over_synthetic_group_rows() {
        // The acceptance example at the COMPOSITION-ALGORITHM level: a subject in two
        // groups with `mfa` and `attested_passkey` minimums is held to
        // `attested_passkey`. End-to-end group attachment is M10-gated; the algorithm
        // that will fold those rows is proven here over synthetic minimums.
        let two_group_minimums = [CredentialClass::Mfa, CredentialClass::AttestedPasskey];
        assert_eq!(
            required_class(two_group_minimums),
            CredentialClass::AttestedPasskey
        );
        // No applicable policy is the honest floor.
        assert_eq!(required_class(std::iter::empty()), CredentialClass::Any);
        // A single tenant row (PR A's only applicable row) composes to itself.
        assert_eq!(
            required_class([CredentialClass::Passkey]),
            CredentialClass::Passkey
        );
    }

    #[test]
    fn satisfied_class_is_computed_purely_from_stored_facts() {
        let facts = CredentialFacts::default();
        // A single primary factor -> Any.
        assert_eq!(
            satisfied_class(&AuthenticationEvent::password(TIME), &facts),
            CredentialClass::Any
        );
        assert_eq!(
            satisfied_class(&AuthenticationEvent::email_otp(TIME), &facts),
            CredentialClass::Any
        );
        // A verified second factor -> Mfa (the multi-factor ACR was achieved).
        assert_eq!(
            satisfied_class(&AuthenticationEvent::password_and_totp(TIME), &facts),
            CredentialClass::Mfa
        );
        assert_eq!(
            satisfied_class(
                &AuthenticationEvent::password_and_recovery_code(TIME),
                &facts
            ),
            CredentialClass::Mfa
        );
        // A user-verified passkey (synced or device-bound) -> Passkey.
        assert_eq!(
            satisfied_class(&AuthenticationEvent::passkey(TIME, true, true), &facts),
            CredentialClass::Passkey
        );
        assert_eq!(
            satisfied_class(&AuthenticationEvent::passkey(TIME, false, true), &facts),
            CredentialClass::Passkey
        );
    }

    #[test]
    fn a_presence_only_passkey_reaches_passkey_only_when_uv_is_not_required() {
        // When the tenant does NOT require user verification, a presence-only passkey
        // is phishing-resistant possession and reaches the Passkey rung.
        let no_uv_required = CredentialFacts::default();
        assert_eq!(
            satisfied_class(
                &AuthenticationEvent::passkey(TIME, true, false),
                &no_uv_required
            ),
            CredentialClass::Passkey
        );
        // When the tenant REQUIRES user verification, a presence-only passkey does NOT
        // reach the Passkey rung: satisfied_class refuses to over-claim the posture.
        let uv_required = CredentialFacts {
            require_user_verification: true,
            attestation_verified: false,
        };
        assert_eq!(
            satisfied_class(
                &AuthenticationEvent::passkey(TIME, true, false),
                &uv_required
            ),
            CredentialClass::Any,
            "a presence-only passkey cannot claim the passkey class when UV is required"
        );
        // A UV passkey still reaches it under the same requirement.
        assert_eq!(
            satisfied_class(
                &AuthenticationEvent::passkey(TIME, true, true),
                &uv_required
            ),
            CredentialClass::Passkey
        );
    }

    #[test]
    fn the_attested_rung_is_active_and_reconciled_with_the_acr_in_pr_b() {
        // PR B activates the attested rung. An attested login records an attested method
        // (its token now survives parse_methods) and, with the stored attestation fact,
        // folds to AttestedPasskey. Crucially the SATISFIED class and the ACHIEVED acr
        // AGREE: both read the same recorded attested method.
        let attested_fact = CredentialFacts {
            require_user_verification: true,
            attestation_verified: true,
        };
        let attested = AuthenticationEvent::attested_passkey(TIME, false, true);
        assert_eq!(
            satisfied_class(&attested, &attested_fact),
            CredentialClass::AttestedPasskey
        );
        assert_eq!(achieved_acr(attested.methods()), ACR_ATTESTED);
        // The attested token now round-trips (the rung is active), unlike PR A.
        assert_eq!(
            parse_methods(&attested.methods_token()),
            vec![AuthMethod::AttestedPasskeyHardwareVerified]
        );
        assert_eq!(
            achieved_acr(&parse_methods(&attested.methods_token())),
            ACR_ATTESTED
        );
        // The attested ACR is now advertised (the rung is active).
        assert!(acr_values_supported().contains(&ACR_ATTESTED));
    }

    #[test]
    fn a_plain_passkey_never_reaches_the_attested_rung_even_with_a_stored_fact() {
        // The disjoint-representation fix: the attested rung is METHOD-driven, so a PLAIN
        // passkey login can never fold to AttestedPasskey even if a (spurious) stored
        // attestation fact is passed. This keeps satisfied_class in lockstep with the
        // achieved acr (a plain passkey achieves phr/phrh, never attested_passkey), so
        // the two enforcement views can never diverge.
        let spurious_fact = CredentialFacts {
            require_user_verification: true,
            attestation_verified: true,
        };
        let plain = AuthenticationEvent::passkey(TIME, false, true);
        assert_eq!(
            satisfied_class(&plain, &spurious_fact),
            CredentialClass::Passkey,
            "a plain passkey stays Passkey even with a stored fact (method-driven rung)"
        );
        assert_eq!(achieved_acr(plain.methods()), ACR_PHRH);
        // Conversely, an attested method WITHOUT the stored fact also stays below the
        // attested rung (the fact is a required co-condition), never over-claiming.
        let attested = AuthenticationEvent::attested_passkey(TIME, false, true);
        assert_eq!(
            satisfied_class(&attested, &CredentialFacts::default()),
            CredentialClass::Passkey
        );
    }

    #[test]
    fn acr_for_class_is_the_canonical_mapping() {
        assert_eq!(acr_for_class(CredentialClass::Any), ACR_PWD);
        assert_eq!(acr_for_class(CredentialClass::Mfa), ACR_MFA);
        assert_eq!(acr_for_class(CredentialClass::Passkey), ACR_PHR);
        assert_eq!(
            acr_for_class(CredentialClass::AttestedPasskey),
            ACR_ATTESTED
        );
        // The Mfa class maps to the SAME URN acr_for_mfa exposes, so the step-up gate
        // and the class enforcer compare against one canonical value.
        assert_eq!(acr_for_class(CredentialClass::Mfa), acr_for_mfa());
    }

    #[test]
    fn a_frozen_below_class_session_cannot_mint_a_higher_acr() {
        // The covenant, end to end at the derivation layer: a frozen Any-class session
        // (a bare password) derives ACR_PWD, and NOTHING a relying party asks for can
        // change that, because the acr derives from the FROZEN methods, never a request.
        // Simulate a token-mint deriving the acr from the persisted methods token.
        let frozen = AuthenticationEvent::password(TIME);
        assert_eq!(
            satisfied_class(&frozen, &CredentialFacts::default()),
            CredentialClass::Any
        );
        let persisted = frozen.methods_token();
        // A relying party "asks" for mfa / phr / phrh / attested by requesting them, but
        // the derivation only ever reads the frozen methods, so it stays at pwd.
        let derived = achieved_acr(&parse_methods(&persisted));
        assert_eq!(derived, ACR_PWD);
        for higher in [ACR_MFA, ACR_PHR, ACR_PHRH, ACR_ATTESTED] {
            assert_ne!(
                derived, higher,
                "a frozen Any session cannot claim {higher}"
            );
        }
        // The persisted token is derived from the FROZEN event, never from a request or a
        // client value: a password login records exactly `pwd`, so the higher-class
        // tokens are simply not present to derive. (Now that PR B activated the attested
        // rung, parse_methods no longer strips those tokens; the anti-inflation guarantee
        // is that a below-class session's frozen event never CONTAINS them, and the
        // achievability guard still fails closed for any FUTURE dormant method.)
        assert_eq!(persisted, "pwd");
        assert!(!persisted.contains("passkey"));
    }

    #[test]
    fn a_wire_be_bit_cannot_upgrade_phr_to_phrh() {
        // Extending the AuthenticationEvent::passkey invariant (authn.rs BE covenant):
        // the class/acr derive from the STORED registration-time backup-eligibility the
        // constructor is GIVEN, never a mutable assertion bit. A synced (backup-eligible)
        // authenticator passes be=true and earns phr; it can never reach the device-bound
        // phrh, because that would require the constructor to be given be=false, which is
        // the stored fact, not a wire value the client controls.
        let synced = AuthenticationEvent::passkey(TIME, true, true);
        assert_eq!(achieved_acr(synced.methods()), ACR_PHR);
        assert_ne!(
            achieved_acr(synced.methods()),
            ACR_PHRH,
            "a backup-eligible passkey can never claim the hardware-protected phrh"
        );
        // The same holds for the attested constructor.
        let attested_synced = AuthenticationEvent::attested_passkey(TIME, true, true);
        assert_eq!(
            attested_synced.methods(),
            &[AuthMethod::AttestedPasskeyVerified]
        );
    }

    #[test]
    fn no_class_emits_an_amr_factor_the_ceremony_did_not_prove() {
        // A presence-only passkey (no verification) must never carry the `mfa` amr, so a
        // Passkey class reached without UV cannot masquerade as a verified login.
        let presence = AuthenticationEvent::passkey(TIME, true, false);
        assert!(!amr_values(presence.methods()).contains(&"mfa"));
        // The attested constructor mirrors the passkey amr exactly (attestation is not
        // an amr factor): a presence-only attested passkey carries no `mfa` either.
        let attested_presence = AuthenticationEvent::attested_passkey(TIME, false, false);
        assert_eq!(
            attested_presence.methods(),
            &[AuthMethod::AttestedPasskeyHardware]
        );
        assert!(
            !attested_presence
                .methods()
                .iter()
                .any(|m| m.amr().contains(&"mfa"))
        );
    }
}
