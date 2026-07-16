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
}

impl AuthMethod {
    /// Every method in the registry, in ascending order of the ACR it achieves.
    /// The order is load-bearing: [`achieved_acr`] reflects the STRONGEST method
    /// of an event, so a later entry outranks an earlier one. Methods sharing an
    /// ACR (the verified and presence-only variants of one passkey class) sit
    /// adjacent; their relative order does not matter to [`achieved_acr`] because
    /// their ACR is identical.
    const ALL: [AuthMethod; 5] = [
        AuthMethod::Password,
        AuthMethod::Passkey,
        AuthMethod::PasskeyVerified,
        AuthMethod::PasskeyHardware,
        AuthMethod::PasskeyHardwareVerified,
    ];

    /// The stable persistence token for this method (the value recorded in the
    /// session's and code's `auth_methods`, and parsed back by [`parse_methods`]).
    #[must_use]
    pub fn as_token(self) -> &'static str {
        match self {
            AuthMethod::Password => "pwd",
            AuthMethod::Passkey => "passkey",
            AuthMethod::PasskeyVerified => "passkey_uv",
            AuthMethod::PasskeyHardware => "passkey_hw",
            AuthMethod::PasskeyHardwareVerified => "passkey_hw_uv",
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
            // `swk`: a software-secured key (a synced passkey); `user`: presence.
            AuthMethod::Passkey => &["swk", "user"],
            // `mfa`: possession of the key + the user verification performed.
            AuthMethod::PasskeyVerified => &["swk", "user", "mfa"],
            // `hwk`: a hardware-secured key (a device-bound passkey); `user`: presence.
            AuthMethod::PasskeyHardware => &["hwk", "user"],
            AuthMethod::PasskeyHardwareVerified => &["hwk", "user", "mfa"],
        }
    }

    /// The authentication context class (`acr`) this method achieves on its own.
    /// The verified and presence-only variants of one passkey class share an ACR:
    /// `phr`/`phrh` assert phishing resistance (and hardware protection), NOT user
    /// verification, so user verification changes the amr, never the acr.
    #[must_use]
    pub fn acr(self) -> &'static str {
        match self {
            AuthMethod::Password => ACR_PWD,
            AuthMethod::Passkey | AuthMethod::PasskeyVerified => ACR_PHR,
            AuthMethod::PasskeyHardware | AuthMethod::PasskeyHardwareVerified => ACR_PHRH,
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
    #[must_use]
    pub fn is_active(self) -> bool {
        matches!(
            self,
            AuthMethod::Password
                | AuthMethod::Passkey
                | AuthMethod::PasskeyVerified
                | AuthMethod::PasskeyHardware
                | AuthMethod::PasskeyHardwareVerified
        )
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
    fn methods_token_round_trips_through_parse() {
        for method in AuthMethod::ALL {
            let token = method.as_token();
            assert_eq!(AuthMethod::from_token(token), Some(method), "{token}");
            assert_eq!(parse_methods(token), vec![method]);
            assert_eq!(methods_token(&[method]), token);
        }
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
        // M7 (issue #65) activated the passkey methods, so their EAP ACRs are now
        // advertised alongside the password ACR, in registry (strength) order.
        assert_eq!(acr_values_supported(), vec![ACR_PWD, ACR_PHR, ACR_PHRH]);
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
}
