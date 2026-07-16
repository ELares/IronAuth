// SPDX-License-Identifier: MIT OR Apache-2.0

//! The public value types of the credential-abuse defenses (issue #64): the
//! regulated dimension ([`AbuseSubjectKind`], [`AbuseSubject`]), the authentication
//! path a ban or a counter is scoped to ([`AuthPath`]), and the ban lifecycle
//! records ([`NewBan`], [`AbuseBanView`]).
//!
//! The SQL that reads and writes these lives on the repositories in
//! `repository.rs` (the single scoped-table SQL module, enforced by
//! `scripts/query-audit.sh`); this module carries only the types the store's
//! callers name.

use crate::id::AbuseBanId;

/// The regulated dimension a ban or a layered failure counter keys on (issue #64).
///
/// Bans and counters are keyed per dimension so regulation can target the ATTACKER
/// (an IP) rather than only the victim (an account or identifier), and so the
/// per-path account-DoS safeguard composes with a per-dimension one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AbuseSubjectKind {
    /// The non-forgeable resolved socket peer IP (issue #31): the attacker's own
    /// dimension, the one escalating responses primarily target.
    Ip,
    /// A specific account (its `usr_` id).
    Account,
    /// A canonical login identifier (the #54 seam output), so a case/unicode variant
    /// of one identity shares regulation state and cannot bypass a ban.
    Identifier,
}

impl AbuseSubjectKind {
    /// The stable wire tag stored in `abuse_bans.subject_kind` and bound into the
    /// blind index and the seal associated data.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AbuseSubjectKind::Ip => "ip",
            AbuseSubjectKind::Account => "account",
            AbuseSubjectKind::Identifier => "identifier",
        }
    }

    /// Parse a stored wire tag back to the typed kind. Returns [`None`] for any
    /// unknown value (the caller treats it as a uniform not-found / skip).
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "ip" => Some(AbuseSubjectKind::Ip),
            "account" => Some(AbuseSubjectKind::Account),
            "identifier" => Some(AbuseSubjectKind::Identifier),
            _ => None,
        }
    }
}

/// A regulated subject: a dimension and its value (issue #64).
///
/// For [`AbuseSubjectKind::Identifier`] the value MUST be the canonical form from the
/// #54 seam (so a mixed-case or unicode variant of the same identity keys to the same
/// counter and ban); for the IP and account dimensions it is the resolved peer IP and
/// the `usr_` id string respectively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbuseSubject {
    /// The regulated dimension.
    pub kind: AbuseSubjectKind,
    /// The dimension value (canonical for an identifier).
    pub value: String,
}

impl AbuseSubject {
    /// A per-IP subject over the resolved socket peer.
    #[must_use]
    pub fn ip(value: impl Into<String>) -> Self {
        Self {
            kind: AbuseSubjectKind::Ip,
            value: value.into(),
        }
    }

    /// A per-account subject over a `usr_` id string.
    #[must_use]
    pub fn account(value: impl Into<String>) -> Self {
        Self {
            kind: AbuseSubjectKind::Account,
            value: value.into(),
        }
    }

    /// A per-identifier subject over a CANONICAL identifier (the #54 seam output).
    #[must_use]
    pub fn identifier(canonical: impl Into<String>) -> Self {
        Self {
            kind: AbuseSubjectKind::Identifier,
            value: canonical.into(),
        }
    }
}

/// The authentication PATH a ban or a layered counter is scoped to (issue #64).
///
/// Per-path scoping is the account-DoS safeguard (Keycloak CVE-2024-1722): failed
/// password spray raises only the [`AuthPath::Password`] counters and can place only a
/// [`AuthPath::Password`] ban, so it can never lock the legitimate owner out of the
/// [`AuthPath::Passkey`] or [`AuthPath::Recovery`] path. [`AuthPath::All`] is the
/// explicit, operator-chosen path-spanning ban (the rare "this IP is purely hostile"
/// case), never reached by automatic regulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthPath {
    /// The password login path (`/login`, device-verify sign-in, `/register`-adjacent
    /// password use).
    Password,
    /// The passkey / WebAuthn login path (issue #65), governed INDEPENDENTLY of the
    /// password path.
    Passkey,
    /// The account-recovery path, governed INDEPENDENTLY of the password path.
    Recovery,
    /// The self-service registration path.
    Register,
    /// Every path (an explicit, operator-chosen path-spanning ban only).
    All,
}

impl AuthPath {
    /// The stable wire tag stored in `abuse_bans.auth_path` and used in a counter key.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AuthPath::Password => "password",
            AuthPath::Passkey => "passkey",
            AuthPath::Recovery => "recovery",
            AuthPath::Register => "register",
            AuthPath::All => "all",
        }
    }

    /// Parse a stored wire tag back to the typed path. Returns [`None`] for any
    /// unknown value.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "password" => Some(AuthPath::Password),
            "passkey" => Some(AuthPath::Passkey),
            "recovery" => Some(AuthPath::Recovery),
            "register" => Some(AuthPath::Register),
            "all" => Some(AuthPath::All),
            _ => None,
        }
    }
}

/// The specification for placing a durable ban (issue #64): the freshly minted `abn_`
/// id, the regulated subject, the path it governs, an operator-safe reason, and an
/// optional auto-expiry.
#[derive(Debug)]
pub struct NewBan<'a> {
    /// The freshly minted `abn_` id (the ban's primary key, CLI/admin handle, and
    /// audit target).
    pub id: &'a AbuseBanId,
    /// The regulated subject.
    pub subject: &'a AbuseSubject,
    /// The path this ban governs.
    pub auth_path: AuthPath,
    /// The operator-supplied, operator-safe reason (never attacker free text).
    pub reason: &'a str,
    /// The auto-expiry instant, or [`None`] for a permanent ban.
    pub expires_at_unix_micros: Option<i64>,
}

/// A ban row opened for a CLI/admin listing (issue #64): the sealed subject is
/// decrypted back to its plaintext for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbuseBanView {
    /// The `abn_` id.
    pub id: AbuseBanId,
    /// The regulated dimension.
    pub subject_kind: AbuseSubjectKind,
    /// The opened subject value (a canonical identifier, an account id, or an IP).
    pub subject: String,
    /// The path the ban governs.
    pub auth_path: AuthPath,
    /// The operator-safe reason.
    pub reason: String,
    /// The auto-expiry instant, or [`None`] for a permanent ban.
    pub expires_at_unix_micros: Option<i64>,
    /// When the ban was placed.
    pub created_at_unix_micros: i64,
}
