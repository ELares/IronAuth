// SPDX-License-Identifier: MIT OR Apache-2.0

//! The per-organization authentication policy document, its resolution engine, and
//! its validator (issue #95, milestone M10).
//!
//! Everything here is PURE: no I/O, no `sqlx`, no clock, no entropy, and no
//! dependency on deployment configuration. The caller performs the scoped reads and
//! hands in a candidate document per level, which is the shape the only other pure
//! precedence resolver in the tree already uses. Per-field merge semantics belong in
//! a function that is exhaustively testable with no database, which is the rule the
//! repository states about its own hierarchy arithmetic.
//!
//! It lives in `ironauth-store` rather than `ironauth-oidc` because the store's
//! `Acting` repository must refuse a contradictory write, and the crate dependency
//! runs `ironauth-oidc -> ironauth-store`.
//!
//! # What this engine is, and what it is not
//!
//! It is a NEW LEVEL WALK that REUSES the existing merge primitives and feeds the
//! existing single authentication gate. It is deliberately NOT:
//!
//!   * an extension of `step_up::requirement_for_request`, which is a FLAT
//!     assembler: all four of its sources live inside ONE scope, with no levels, no
//!     precedence, and no notion of "nearest". Issue #95's resolved policy becomes
//!     one MORE source folded into that assembler at the enforcement PR, which
//!     inherits its whole contract (the fault flag, the best-effort at `/authorize`
//!     versus fail-closed at `/token` asymmetry, and re-evaluation on refresh) for
//!     free.
//!   * an extension of issue #97's `OrgGroupRepo::resolve_effective`, which resolves
//!     ANCESTRY INSIDE ONE ORGANIZATION by UNION, an operator that GROWS its result.
//!     Every operator here NARROWS. A role reachable by any path is granted; a
//!     factor must be permitted by EVERY level.
//!
//! # The empty-intersection hazard, and where each half is caught
//!
//! Three distinct failures all look like "no factor available" and conflating them
//! is the design error to avoid.
//!
//!   * **Intra-document** (decidable from one submitted row): a policy requiring MFA
//!     whose factor list carries no method able to perform a genuine second factor.
//!     Caught at WRITE time by [`validate`], with the `org_auth_policies_mfa_reachable`
//!     CHECK as the unreachable latch behind it.
//!   * **Cross-level** (NOT decidable at any single write): each document is
//!     individually valid and the INTERSECTION across levels is empty. Caught at
//!     RESOLUTION time as [`AllowedFactors::Empty`] and a non-satisfiable
//!     [`Satisfiability`]. It is a typed VALUE, never an error, so [`resolve`] stays
//!     total and infallible and `#[must_use]` makes ignoring the verdict a build
//!     failure under pedantic `-D warnings`.
//!   * **Deployment availability** (not a policy contradiction at all): the resolved
//!     set names a factor the deployment has switched off. Already handled by the
//!     existing achievability guard, unchanged. [`validate`] must NOT read deployment
//!     configuration, or one policy document would be valid on one deployment and
//!     invalid on another.

use std::collections::BTreeSet;
use std::fmt;

use crate::custom_domain::domain_is_registrable;
use crate::identifier::normalize_routing_domain;

/// Every authentication method token an organization may name in
/// [`AuthPolicy::allowed_factors`], byte-identical to `AuthMethod::as_token()` in
/// `ironauth-oidc`.
///
/// ONE registry: an operator-facing synonym set would be a second one. The
/// `org_auth_policies_factors_known` CHECK in migration 0090 carries the same set,
/// and a test in `ironauth-oidc` (the only crate that can see both) pins this
/// constant equal to the live `AuthMethod` registry, so a new method fails that test
/// until it is classified here and added to the CHECK.
///
/// Pinning a closed vocabulary into a migration costs a migration to admit a new
/// method, and that cost degrades SAFELY: the list is an allowlist INTERSECTED
/// across levels, so being unable to ADD a value can only ever refuse more, never
/// permit more.
pub const KNOWN_FACTOR_TOKENS: [&str; 15] = [
    "pwd",
    "federated",
    "email_otp",
    "sms",
    "trusted_device",
    "totp",
    "recovery_code",
    "passkey",
    "passkey_uv",
    "passkey_hw",
    "passkey_hw_uv",
    "attested_passkey",
    "attested_passkey_uv",
    "attested_passkey_hw",
    "attested_passkey_hw_uv",
];

/// The authentication methods that can carry a GENUINE SECOND FACTOR: exactly the
/// `AuthMethod` values whose RFC 8176 `amr` contains `mfa`, which is what
/// `authn::performed_second_factor` tests.
///
/// Note what is ABSENT and would be the plausible mistake: `email_otp` and `sms` are
/// single PRIMARY factors in this codebase (their `amr` is `["otp"]` and `["sms"]`
/// with no `mfa`), so a policy requiring MFA whose factor list is exactly
/// `{email_otp, sms}` is UNSATISFIABLE. A validator or CHECK built on the wrong set
/// would ACCEPT that policy, which is the precise defect this constant exists to
/// prevent.
///
/// `trusted_device` is absent for the same honest reason: a remembered device merely
/// ATTESTS a prior second factor and performs none this login.
pub const SECOND_FACTOR_TOKENS: [&str; 6] = [
    "totp",
    "recovery_code",
    "passkey_uv",
    "passkey_hw_uv",
    "attested_passkey_uv",
    "attested_passkey_hw_uv",
];

/// The hard ceiling on any session lifetime an organization policy may state, in
/// seconds.
///
/// A MIRROR of `ironauth_config::OIDC_MAX_SESSION_TTL_SECS`, kept here because
/// `ironauth-store` deliberately has no dependency on the config crate: the ceiling
/// arrives at [`validate`] as a call parameter, exactly as the group depth bound
/// does. A cross-crate test in `ironauth-admin` (the crate that can see both) pins
/// the two constants equal, so a config change that drifted from this value fails
/// there rather than silently letting a policy state a lifetime the deployment
/// refuses.
pub const ORG_POLICY_MAX_SESSION_TTL_SECS: u32 = 2_592_000;

/// Whether `token` names an authentication method this policy vocabulary knows.
#[must_use]
pub fn is_known_factor_token(token: &str) -> bool {
    KNOWN_FACTOR_TOKENS.contains(&token)
}

/// Whether `token` names an authentication method that can carry a genuine second
/// factor. See [`SECOND_FACTOR_TOKENS`] for what is deliberately excluded.
#[must_use]
pub fn is_second_factor_token(token: &str) -> bool {
    SECOND_FACTOR_TOKENS.contains(&token)
}

/// One level's policy DOCUMENT (issue #95).
///
/// Every field is optional and `None` means UNSET, which resolution reads as
/// "inherit the next level up unchanged". An all-`None` document is the identity
/// element of every combinator, so an EMPTY policy object restricts nothing. That is
/// not a coincidence, it is the point, and it matches four existing precedents in
/// this codebase: the empty credential-class fold is `Any`, a computed `Any` floor
/// maps back to "no floor", the broker overlay DROPS an honest floor that constrains
/// nothing, and an empty deployment acr order falls back to the canonical one.
///
/// There is deliberately NO `min_class` field. The organization's minimum credential
/// class lives in `credential_class_policies` as a `subject_kind = 'org'` row (see
/// migration 0090's header): exactly one ladder, no second source of truth for one
/// authorization decision.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthPolicy {
    /// Whether a genuine SECOND FACTOR is required.
    ///
    /// At enforcement this rides the `mfa_baseline_required` channel and must NEVER
    /// become an `mfa` acr floor: the acr ladder ranks `phr` ABOVE `mfa`, so an
    /// `mfa` floor is silently satisfiable by a presence-only, non user-verified
    /// passkey that performed no second factor at all. Riding the flag also inherits
    /// the conditional-credential skip and the remembered-device path for free.
    pub mfa_required: Option<bool>,
    /// The permitted authentication methods, as `AuthMethod` persistence tokens.
    /// `None` means unconstrained; a present set may only ever REMOVE options.
    pub allowed_factors: Option<BTreeSet<String>>,
    /// The email domains this level accepts, in the normalized form
    /// [`normalize`] produces. `None` means unconstrained.
    ///
    /// NOTHING reads this in issue #95's store layer. It is an UNVERIFIED OPERATOR
    /// ASSERTION, usable only as a NARROWING FILTER on an address that has already
    /// been verified by other means, and never as authority for the address itself.
    /// Matching, when enforcement lands, is EXACT on the normalized form and never a
    /// suffix match. Migration 0090's header carries the full argument.
    pub allowed_email_domains: Option<BTreeSet<String>>,
    /// Whether a matching login may be provisioned into the organization with no
    /// administrator acting. Read by nothing in issue #95's store layer.
    pub jit_provisioning: Option<bool>,
    /// Whether invitations (issue #94) may be issued.
    pub invitations_enabled: Option<bool>,
    /// The absolute session lifetime in seconds.
    pub session_ttl_secs: Option<u32>,
    /// The idle session window in seconds.
    pub session_idle_ttl_secs: Option<u32>,
}

impl AuthPolicy {
    /// Whether this document states nothing at all, and therefore restricts nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == AuthPolicy::default()
    }
}

/// The four levels of issue #95's resolution order, weakest precedence first.
///
/// A NAMED STRUCT rather than an ordered slice, deliberately: mis-ordering the levels
/// is the failure mode most worth making unrepresentable, and a slice pushes the
/// ordering contract onto every caller.
///
/// # `tenant` is RESERVED and is always `None` in v1
///
/// `Scope` is `(tenant_id, environment_id)` JOINTLY and every policy table in this
/// schema keys on BOTH columns, so there is no above-environment storage level
/// today. Tenant and environment are therefore ONE level in v1, backed by the
/// existing scope-keyed rows, and only THREE levels are live: environment,
/// organization, and client.
///
/// **This knowingly deviates from the issue's acceptance criterion "verified by
/// tests at all four levels": only three are live.** The fourth slot is kept so the
/// ordering is written once and correctly and so the property tests sweep all four
/// immediately; lighting it up later is a STORE change (a genuinely tenant-wide
/// table with a one-column row-level-security shape, a read path outside
/// `ScopedStore`, and its own promotion classification), not an ENGINE change. A
/// real tenant level is a separate issue.
///
/// Note also that the word is already taken in the other direction:
/// `credential_class_policies.subject_kind = 'tenant'` means "this whole (tenant,
/// environment) scope", which is what issue #95 calls the ENVIRONMENT level.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyLevels {
    /// RESERVED. Always `None` in v1; see the type documentation.
    pub tenant: Option<AuthPolicy>,
    /// The whole `(tenant, environment)` scope's policy.
    pub environment: Option<AuthPolicy>,
    /// The acting organization's policy.
    pub organization: Option<AuthPolicy>,
    /// The acting client's policy.
    pub client: Option<AuthPolicy>,
}

impl PolicyLevels {
    /// The four slots in resolution order, weakest precedence first.
    ///
    /// Every combinator in this module is commutative, associative, and idempotent
    /// with an identity element, so the RESULT does not depend on this order. The
    /// order is written once anyway, here, so a future field that is NOT
    /// order-independent cannot be added without confronting the ordering
    /// explicitly.
    fn slots(&self) -> [&Option<AuthPolicy>; 4] {
        [
            &self.tenant,
            &self.environment,
            &self.organization,
            &self.client,
        ]
    }
}

/// The resolved allowed-factor set.
///
/// Three cases, distinguished in the TYPE so an empty INTERSECTION can never be
/// confused with "no restriction". Collapsing the two is the fail-OPEN mistake: a
/// policy set that narrowed to nothing would permit everything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowedFactors {
    /// No level constrained the set: every factor the deployment enables.
    Unconstrained,
    /// At least one level constrained it and the intersection is NONEMPTY. Never
    /// carries an empty set by construction.
    Restricted(BTreeSet<String>),
    /// At least one level constrained it and the intersection is EMPTY: NO factor is
    /// permitted. A total lockout, never a silent empty allow.
    Empty,
}

/// The resolved allowed-email-domain set, with the same three cases and the same
/// reasoning as [`AllowedFactors`].
///
/// Nothing reads this in issue #95's store layer; see [`AuthPolicy::allowed_email_domains`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowedDomains {
    /// No level constrained the set: any verified address is admissible.
    Unconstrained,
    /// At least one level constrained it and the intersection is NONEMPTY.
    Restricted(BTreeSet<String>),
    /// At least one level constrained it and the intersection is EMPTY: NO address
    /// is admissible.
    Empty,
}

/// Whether a resolved policy can be satisfied by any login at all.
///
/// Deliberately NOT `#[non_exhaustive]`: this is a fail-closed authentication
/// decision, so a future variant SHOULD break every consumer until each one decides
/// what to do about it. A wildcard arm is exactly the wrong default here.
///
/// The domain list is deliberately absent from this verdict in v1. Nothing reads
/// `allowed_email_domains` yet, so an empty domain intersection cannot refuse a
/// login; it is still REPRESENTED, as [`AllowedDomains::Empty`], and the PR that
/// starts enforcing domains adds the corresponding variant here (which will not
/// compile until every consumer handles it, which is the point).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Satisfiability {
    /// Some login can satisfy this policy.
    Satisfiable,
    /// The allowed-factor intersection across the levels is empty, so no login of
    /// any shape is permitted.
    NoFactorPermitted,
    /// MFA is required and every PERMITTED factor is a single primary factor, so no
    /// login can ever carry a genuine second factor.
    MfaRequiredWithNoSecondFactor,
}

/// The effective policy for one authentication, resolved from every level.
///
/// The fields are private so the ABSENT DEFAULTS cannot be bypassed: the combinator
/// identity and the safe default disagree for `jit_provisioning`, and reading the
/// raw fold would ship JIT enabled. Every reader goes through an accessor that
/// applies the documented default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAuthPolicy {
    mfa_required: Option<bool>,
    allowed_factors: AllowedFactors,
    allowed_email_domains: AllowedDomains,
    jit_provisioning: Option<bool>,
    invitations_enabled: Option<bool>,
    session_ttl_secs: Option<u32>,
    session_idle_ttl_secs: Option<u32>,
}

impl ResolvedAuthPolicy {
    /// Whether this policy can be satisfied by any login at all.
    ///
    /// `#[must_use]` is load-bearing rather than decoration: under clippy pedantic
    /// with `-D warnings` an enforcement path that computes this and ignores it does
    /// not compile.
    ///
    /// [`Satisfiability::NoFactorPermitted`] takes precedence over
    /// [`Satisfiability::MfaRequiredWithNoSecondFactor`]: an empty set trivially
    /// contains no second factor too, and "nothing is permitted" is the accurate
    /// diagnosis with the different remedy.
    #[must_use]
    pub fn satisfiability(&self) -> Satisfiability {
        match &self.allowed_factors {
            AllowedFactors::Empty => Satisfiability::NoFactorPermitted,
            AllowedFactors::Unconstrained => Satisfiability::Satisfiable,
            AllowedFactors::Restricted(permitted) => {
                if self.mfa_required()
                    && !permitted
                        .iter()
                        .any(|token| is_second_factor_token(token.as_str()))
                {
                    Satisfiability::MfaRequiredWithNoSecondFactor
                } else {
                    Satisfiability::Satisfiable
                }
            }
        }
    }

    /// Whether a genuine second factor is required.
    ///
    /// Defaults to `false` when no level spoke: the honest floor, and the same
    /// default the combinator identity (OR) yields, so the two agree here.
    #[must_use]
    pub fn mfa_required(&self) -> bool {
        self.mfa_required.unwrap_or(false)
    }

    /// Whether just-in-time provisioning is permitted.
    ///
    /// Defaults to `false` when no level spoke, which is NOT the combinator identity
    /// (AND) of `true`. This is the trap in the whole engine: folding with AND over
    /// zero levels yields `true`, so a design that returned the bare fold would ship
    /// JIT ENABLED by accident, silently admitting people to an organization with
    /// no administrator acting. The fold is therefore `Option<bool>` and the safe
    /// default is applied HERE.
    #[must_use]
    pub fn jit_provisioning(&self) -> bool {
        self.jit_provisioning.unwrap_or(false)
    }

    /// Whether invitations may be issued.
    ///
    /// Defaults to `true` when no level spoke. Invitations are a SHIPPED issue #94
    /// capability, and issue #95 must not disable them merely by arriving.
    #[must_use]
    pub fn invitations_enabled(&self) -> bool {
        self.invitations_enabled.unwrap_or(true)
    }

    /// The resolved factor set.
    #[must_use]
    pub fn allowed_factors(&self) -> &AllowedFactors {
        &self.allowed_factors
    }

    /// The resolved email-domain set. Read by nothing in issue #95's store layer.
    #[must_use]
    pub fn allowed_email_domains(&self) -> &AllowedDomains {
        &self.allowed_email_domains
    }

    /// The resolved absolute session lifetime, or `None` when no level stated one
    /// (in which case the deployment's own configured lifetime applies unchanged).
    #[must_use]
    pub fn session_ttl_secs(&self) -> Option<u32> {
        self.session_ttl_secs
    }

    /// The resolved idle session window, or `None` when no level stated one.
    #[must_use]
    pub fn session_idle_ttl_secs(&self) -> Option<u32> {
        self.session_idle_ttl_secs
    }

    /// The absolute session lifetime to actually apply, given the deployment's own
    /// configured lifetime: the SMALLER of the two.
    ///
    /// This is where "an organization may only SHORTEN a session, never lengthen
    /// one" becomes executable rather than a claim. It is a plain MIN, so a policy
    /// stating a longer lifetime than the deployment simply has no effect, and a
    /// resolution that stated nothing returns the deployment value unchanged.
    #[must_use]
    pub fn effective_session_ttl_secs(&self, deployment_secs: u32) -> u32 {
        self.session_ttl_secs
            .map_or(deployment_secs, |policy| policy.min(deployment_secs))
    }

    /// The idle session window to actually apply, given the deployment's own
    /// configured window: the SMALLER of the two.
    ///
    /// This is the half issue #95's enforcement PR wires FIRST, because it needs no
    /// migration and no column write: `SessionRepo::get` already takes the idle
    /// window as a caller parameter on every read, so an organization-scoped idle
    /// timeout takes effect on the NEXT REQUEST of an existing session, which is
    /// genuinely "without a global logout". The absolute cap is a separate, later
    /// decision because `sessions.absolute_expires_at` has no UPDATE grant for
    /// either role.
    #[must_use]
    pub fn effective_session_idle_ttl_secs(&self, deployment_secs: u32) -> u32 {
        self.session_idle_ttl_secs
            .map_or(deployment_secs, |policy| policy.min(deployment_secs))
    }
}

/// Resolve the levels into one effective policy.
///
/// TOTAL and INFALLIBLE: an unsatisfiable combination is REPRESENTED IN THE RESULT
/// (see [`ResolvedAuthPolicy::satisfiability`]), never returned as an error, so the
/// enforcement path cannot plumb it away.
///
/// # The per-field merge table
///
/// The governing rule, stated once so no field is decided ad hoc:
///
/// > A field is STRICTEST WINS if and only if a nearer level being able to relax it
/// > would let a less privileged operator weaken a more privileged operator's
/// > security decision.
///
/// Under that rule EVERY issue #95 field is strictest wins. The uniformity is not
/// tidiness, it is a property: see the determinism section below.
///
/// | Field | Rule | "Strictest" defined precisely | Combinator identity | Absent default |
/// |---|---|---|---|---|
/// | `mfa_required` | strictest wins | `true` is strictest: once any level requires MFA, no nearer level can turn it off | `false` (OR) | `false` |
/// | `allowed_factors` | strictest wins | set INTERSECTION: each present level may only REMOVE options, absent means the universe | universe | [`AllowedFactors::Unconstrained`] |
/// | `allowed_email_domains` | strictest wins | set INTERSECTION on the NORMALIZED form | universe | [`AllowedDomains::Unconstrained`] |
/// | `jit_provisioning` | strictest wins | `false` is strictest: JIT admits people without an administrator acting | `true` (AND) | **`false`**, NOT the identity |
/// | `invitations_enabled` | strictest wins | `false` is strictest | `true` (AND) | `true` |
/// | `session_ttl_secs` | strictest wins | MIN: shorter is strictest, mirroring `merge_stronger`'s `current.min(candidate)` | none | `None` (the deployment value) |
/// | `session_idle_ttl_secs` | strictest wins | MIN | none | `None` (the deployment value) |
///
/// The COMBINATOR IDENTITY and the ABSENT DEFAULT are two different things and for
/// `jit_provisioning` they DISAGREE. The fold therefore produces `Option<bool>` and
/// the accessor applies the documented default; see
/// [`ResolvedAuthPolicy::jit_provisioning`].
///
/// Do not confuse `session_ttl_secs` with the step-up `max_auth_age_secs`. The
/// latter is an authentication FRESHNESS floor that already folds through
/// `merge_stronger`; this is an operational session duration. Both are MIN-folded
/// and they are different fields, named distinctly so a future reader does not merge
/// them.
///
/// # Determinism
///
/// Every combinator (OR, AND, MIN, set intersection) is commutative, associative,
/// and idempotent with an identity element, so:
///
///   1. the fold is ORDER INDEPENDENT: any permutation of the levels resolves equal,
///      which is strictly stronger than "we iterate in a fixed order" and is
///      directly testable with a shuffle oracle;
///   2. the fold is IDEMPOTENT: supplying one level twice changes nothing;
///   3. the fold is MONOTONE NARROWING: adding any level can only tighten, on every
///      field;
///   4. the output is BYTE STABLE: sets are [`BTreeSet`], the issue #97 convention.
///
/// Order independence is forfeited the moment any field becomes NEAREST OVERRIDE.
/// That is the concrete cost of the session-lifetime decision, and the shuffle
/// oracle is the test that would have to be deleted to accept it.
#[must_use]
pub fn resolve(levels: &PolicyLevels) -> ResolvedAuthPolicy {
    let mut mfa_required: Option<bool> = None;
    let mut jit_provisioning: Option<bool> = None;
    let mut invitations_enabled: Option<bool> = None;
    let mut session_ttl_secs: Option<u32> = None;
    let mut session_idle_ttl_secs: Option<u32> = None;
    let mut factors: Option<BTreeSet<String>> = None;
    let mut domains: Option<BTreeSet<String>> = None;

    for slot in levels.slots() {
        let Some(level) = slot.as_ref() else {
            // An ABSENT level and an EMPTY policy document are structurally the same
            // thing: both are the identity element and both inherit unchanged.
            continue;
        };
        fold_or(&mut mfa_required, level.mfa_required);
        fold_and(&mut jit_provisioning, level.jit_provisioning);
        fold_and(&mut invitations_enabled, level.invitations_enabled);
        fold_min(&mut session_ttl_secs, level.session_ttl_secs);
        fold_min(&mut session_idle_ttl_secs, level.session_idle_ttl_secs);
        fold_intersect(&mut factors, level.allowed_factors.as_ref());
        fold_intersect(&mut domains, level.allowed_email_domains.as_ref());
    }

    ResolvedAuthPolicy {
        mfa_required,
        allowed_factors: match factors {
            None => AllowedFactors::Unconstrained,
            Some(set) if set.is_empty() => AllowedFactors::Empty,
            Some(set) => AllowedFactors::Restricted(set),
        },
        allowed_email_domains: match domains {
            None => AllowedDomains::Unconstrained,
            Some(set) if set.is_empty() => AllowedDomains::Empty,
            Some(set) => AllowedDomains::Restricted(set),
        },
        jit_provisioning,
        invitations_enabled,
        session_ttl_secs,
        session_idle_ttl_secs,
    }
}

/// Fold a boolean where `true` is strictest (logical OR over the levels that spoke).
fn fold_or(slot: &mut Option<bool>, candidate: Option<bool>) {
    if let Some(value) = candidate {
        *slot = Some(slot.unwrap_or(false) || value);
    }
}

/// Fold a boolean where `false` is strictest (logical AND over the levels that
/// spoke).
fn fold_and(slot: &mut Option<bool>, candidate: Option<bool>) {
    if let Some(value) = candidate {
        *slot = Some(slot.unwrap_or(true) && value);
    }
}

/// Fold a duration where SHORTER is strictest (MIN over the levels that spoke).
fn fold_min(slot: &mut Option<u32>, candidate: Option<u32>) {
    if let Some(value) = candidate {
        *slot = Some(slot.map_or(value, |current| current.min(value)));
    }
}

/// Fold an allowlist by INTERSECTION: absent means the universe, present narrows.
///
/// The shape is `federation::resolve_alg_allowlist`'s, applied across levels instead
/// of once: absent means the full set, present means intersect. The result may be
/// EMPTY, and that emptiness is preserved rather than collapsed, which is what keeps
/// the resolved type able to distinguish "no restriction" from "nothing permitted".
fn fold_intersect(slot: &mut Option<BTreeSet<String>>, candidate: Option<&BTreeSet<String>>) {
    let Some(values) = candidate else {
        return;
    };
    match slot.take() {
        None => *slot = Some(values.clone()),
        Some(current) => {
            *slot = Some(current.intersection(values).cloned().collect());
        }
    }
}

/// A refusal of a policy DOCUMENT (issue #95).
///
/// Every variant is OPERATOR SAFE and VALUE FREE: it names the DIMENSION, never the
/// offending value, so no rendered message can report anything the caller did not
/// already send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum AuthPolicyError {
    /// The factor list names a token outside [`KNOWN_FACTOR_TOKENS`].
    UnknownFactor,
    /// The factor list is present and EMPTY. An explicitly empty list would mean
    /// "permit nothing", a lockout dressed as a configuration; unconstrained is
    /// spelled by omitting the list.
    EmptyFactorList,
    /// The email-domain list is present and EMPTY, for the same reason.
    EmptyDomainList,
    /// MFA is required and the factor list contains no method able to carry a
    /// genuine second factor, so no login could ever satisfy this document.
    MfaRequiredWithNoSecondFactor,
    /// The idle window is longer than the absolute lifetime, so it could never fire.
    IdleExceedsAbsolute,
    /// A stated session lifetime exceeds the deployment ceiling.
    SessionTtlAboveCeiling,
    /// A stated session lifetime is ZERO, which would expire every session the
    /// instant it was minted. Unconstrained is spelled by omitting the dimension.
    NonPositiveSessionLifetime,
    /// An email-domain entry is not a plain registrable hostname.
    InvalidEmailDomain,
}

impl AuthPolicyError {
    /// The stable, value-free description of this refusal.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AuthPolicyError::UnknownFactor => {
                "allowed_factors names an unknown authentication method"
            }
            AuthPolicyError::EmptyFactorList => {
                "allowed_factors is present but empty (omit it to leave factors unconstrained)"
            }
            AuthPolicyError::EmptyDomainList => {
                "allowed_email_domains is present but empty (omit it to leave domains unconstrained)"
            }
            AuthPolicyError::MfaRequiredWithNoSecondFactor => {
                "mfa_required is set but allowed_factors permits no second factor"
            }
            AuthPolicyError::IdleExceedsAbsolute => {
                "session_idle_ttl_secs exceeds session_ttl_secs"
            }
            AuthPolicyError::SessionTtlAboveCeiling => {
                "a session lifetime exceeds the deployment maximum"
            }
            AuthPolicyError::NonPositiveSessionLifetime => {
                "a session lifetime is zero (omit it to leave the lifetime unconstrained)"
            }
            AuthPolicyError::InvalidEmailDomain => {
                "allowed_email_domains contains a value that is not a registrable domain"
            }
        }
    }
}

impl fmt::Display for AuthPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for AuthPolicyError {}

/// Normalize a submitted policy document to its stored form.
///
/// Only the email-domain list is normalizable: every entry is folded through
/// [`normalize_routing_domain`], the ONE seam this codebase has for the domain half
/// of an identifier. It applies the same strip, NFKC, whitespace-removal, and
/// case-fold steps `canonicalize_identifier` applies to the domain half of an email,
/// which is exactly what makes a stored entry comparable to a submitted address
/// later. Two normalizers of one concept already exist elsewhere in the tree and a
/// third disagreement is precisely the drift the canonicalization seam exists to
/// prevent, so `custom_domain::normalize_domain` (ASCII lowercase only) and the
/// disposable-domain helper are deliberately NOT used.
///
/// A value that normalizes to nothing at all (an empty or all-invisible entry) is
/// kept VERBATIM rather than dropped, so [`validate`] refuses it as
/// [`AuthPolicyError::InvalidEmailDomain`]. Dropping it would silently accept
/// garbage and, if it were the only entry, would silently turn a restriction into no
/// restriction.
///
/// Two entries that normalize to the same form COLLAPSE, because the list is a set.
///
/// Factor tokens are NOT normalized: they are byte-exact members of a closed
/// vocabulary, exactly as issue #97's slugs are byte-exact and deliberately outside
/// the identifier seam.
///
/// # Inherited limitation, restated rather than silently diverged from
///
/// [`normalize_routing_domain`] performs NO IDNA or punycode mapping and NO
/// trailing-dot stripping, so `xn--caf-dma.example` and the unicode spelling of the
/// same name are DISTINCT selectors. Combined with the registrable-hostname shape
/// check in [`validate`] (which is ASCII only), the practical rule is that an
/// operator lists the A-label (punycode) form. That refuses more than it admits,
/// which is the safe direction.
#[must_use]
pub fn normalize(policy: &AuthPolicy) -> AuthPolicy {
    let mut normalized = policy.clone();
    normalized.allowed_email_domains = policy.allowed_email_domains.as_ref().map(|domains| {
        domains
            .iter()
            .map(|domain| normalize_routing_domain(domain).unwrap_or_else(|| domain.clone()))
            .collect()
    });
    normalized
}

/// Validate ONE policy document.
///
/// Collects EVERY failure, in a fixed variant order and deduplicated, so an operator
/// learns all of them in one round trip and the rendered message is a deterministic
/// function of the input.
///
/// `session_ttl_ceiling_secs` arrives as a PARAMETER because `ironauth-store`
/// deliberately has no dependency on `ironauth-config`; the store keeps
/// [`ORG_POLICY_MAX_SESSION_TTL_SECS`] as its mirror and a cross-crate test pins the
/// two equal.
///
/// # This validator is INTRA-DOCUMENT ONLY
///
/// It does NOT, and CANNOT, detect a contradiction that arises only from the
/// INTERSECTION ACROSS LEVELS. An organization narrowing its factors to
/// `{passkey_uv}` under an environment that already allows only `{totp}` produces an
/// empty intersection that no single write can see. That is
/// [`ResolvedAuthPolicy::satisfiability`] and it fails closed at authentication.
///
/// Reading the ancestor chain here would NOT be sound as a guarantee: an ancestor can
/// change AFTER the child is written, so it would prevent only the ordering where the
/// child is written last; it would make a write's acceptance depend on rows the
/// writer may not administer; and a validator that IMPLIED it prevented the
/// cross-level case would be the more dangerous defect, because an operator would
/// trust it. This matches how the codebase already decides achievability: at LOGIN,
/// not at write.
///
/// It also does NOT read deployment configuration beyond the ceiling parameter. A
/// policy naming a factor the deployment has switched off is a DEPLOYMENT
/// AVAILABILITY question the existing achievability guard already answers; deciding
/// it here would make one document valid on one deployment and invalid on another.
///
/// # Errors
///
/// Every [`AuthPolicyError`] the document trips, sorted and deduplicated.
pub fn validate(
    policy: &AuthPolicy,
    session_ttl_ceiling_secs: u32,
) -> Result<(), Vec<AuthPolicyError>> {
    let mut errors: Vec<AuthPolicyError> = Vec::new();

    if let Some(factors) = policy.allowed_factors.as_ref() {
        if factors.is_empty() {
            errors.push(AuthPolicyError::EmptyFactorList);
        }
        if factors
            .iter()
            .any(|token| !is_known_factor_token(token.as_str()))
        {
            errors.push(AuthPolicyError::UnknownFactor);
        }
        // The intra-document contradiction. Only meaningful for a NONEMPTY list: an
        // empty one is already refused above, and reporting both would tell the
        // operator two things about one mistake.
        if policy.mfa_required == Some(true)
            && !factors.is_empty()
            && !factors
                .iter()
                .any(|token| is_second_factor_token(token.as_str()))
        {
            errors.push(AuthPolicyError::MfaRequiredWithNoSecondFactor);
        }
    }

    if let Some(domains) = policy.allowed_email_domains.as_ref() {
        if domains.is_empty() {
            errors.push(AuthPolicyError::EmptyDomainList);
        }
        if domains
            .iter()
            .any(|domain| !domain_is_registrable(domain.as_str()))
        {
            errors.push(AuthPolicyError::InvalidEmailDomain);
        }
    }

    // Both halves of the pair are checked against the ceiling: the config crate
    // validates its own absolute AND idle lifetimes against the same maximum, so a
    // policy that could state an idle window above it would be stating something the
    // deployment itself refuses.
    if policy
        .session_ttl_secs
        .is_some_and(|ttl| ttl > session_ttl_ceiling_secs)
        || policy
            .session_idle_ttl_secs
            .is_some_and(|idle| idle > session_ttl_ceiling_secs)
    {
        errors.push(AuthPolicyError::SessionTtlAboveCeiling);
    }

    // The FLOOR, and the other half of what makes the CHECK constraints behind this
    // guard a latch rather than the primary refusal. A stated lifetime of zero would
    // expire every session the instant it was minted, and
    // `org_auth_policies_session_ttl_positive` / `_session_idle_positive` refuse it
    // at the storage engine; without this rule the guard would ACCEPT the document
    // and the CHECK would raise MID-transaction, which aborts the transaction the
    // audit row still has to be written in and surfaces as an opaque database fault
    // instead of the typed refusal. Unconstrained is spelled by omitting the
    // dimension, exactly as it is for the two lists.
    if policy.session_ttl_secs == Some(0) || policy.session_idle_ttl_secs == Some(0) {
        errors.push(AuthPolicyError::NonPositiveSessionLifetime);
    }

    // Row-local only: an organization may state ONE of the pair and inherit the
    // other, which no single-document check (and no CHECK constraint) can see. The
    // resolved pair is where that case is caught.
    if let (Some(absolute), Some(idle)) = (policy.session_ttl_secs, policy.session_idle_ttl_secs) {
        if idle > absolute {
            errors.push(AuthPolicyError::IdleExceedsAbsolute);
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        errors.sort_unstable();
        errors.dedup();
        Err(errors)
    }
}

/// Whether the RESOLVED pair is coherent: an idle window never beyond the absolute
/// lifetime.
///
/// The cross-level half of the same rule [`validate`] enforces row-locally. An
/// organization may state only the idle window and inherit a shorter absolute
/// lifetime from its environment, which produces a pair no single document and no
/// CHECK constraint could have seen.
///
/// It is a QUERY on the resolved value rather than an error, for the same reason
/// [`Satisfiability`] is: resolution stays total. An incoherent pair is harmless in
/// practice (the absolute cap fires first) but it means the stated idle window is
/// dead, which an operator wants to be told.
#[must_use]
pub fn resolved_session_pair_is_coherent(resolved: &ResolvedAuthPolicy) -> bool {
    match (
        resolved.session_ttl_secs(),
        resolved.session_idle_ttl_secs(),
    ) {
        (Some(absolute), Some(idle)) => idle <= absolute,
        _ => true,
    }
}

/// The operator-safe `detail` dimension recorded on an `organization.policy.set`
/// audit row.
///
/// A CLOSED TOKEN vocabulary plus operator-supplied integers, and NOTHING else:
///
///   * `inherit` when the dimension is unset in the submitted document;
///   * `true` / `false` for a stated boolean;
///   * `restricted` when a factor list is stated, `set` when a domain list is;
///   * the integer the operator supplied, for the two durations.
///
/// A domain is caller-typed free text and is PII adjacent, and a factor list can be
/// long, so NEITHER is ever written: the repository's rule for a persisted detail is
/// that only issuer-minted ids and structural values may be recorded, never
/// attacker-authored text. There is deliberately no `cleared` token: `set` replaces
/// the WHOLE document, so an unset dimension means "inherit" and there is no partial
/// patch shape that could mean anything else.
///
/// Pure, so the exact string is testable with no database, and a deterministic
/// function of the document, so the audit trail is byte stable.
#[must_use]
pub fn audit_detail(policy: &AuthPolicy) -> String {
    fn flag(value: Option<bool>) -> &'static str {
        match value {
            None => "inherit",
            Some(true) => "true",
            Some(false) => "false",
        }
    }
    fn list(value: Option<&BTreeSet<String>>, present: &'static str) -> &'static str {
        if value.is_some() { present } else { "inherit" }
    }
    fn secs(value: Option<u32>) -> String {
        value.map_or_else(|| "inherit".to_owned(), |seconds| seconds.to_string())
    }

    format!(
        "mfa_required={} factors={} domains={} jit={} invitations={} session_ttl={} \
         session_idle={}",
        flag(policy.mfa_required),
        list(policy.allowed_factors.as_ref(), "restricted"),
        list(policy.allowed_email_domains.as_ref(), "set"),
        flag(policy.jit_provisioning),
        flag(policy.invitations_enabled),
        secs(policy.session_ttl_secs),
        secs(policy.session_idle_ttl_secs),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        AllowedDomains, AllowedFactors, AuthPolicy, AuthPolicyError, KNOWN_FACTOR_TOKENS,
        ORG_POLICY_MAX_SESSION_TTL_SECS, PolicyLevels, ResolvedAuthPolicy, SECOND_FACTOR_TOKENS,
        Satisfiability, audit_detail, normalize, resolve, resolved_session_pair_is_coherent,
        validate,
    };
    use std::collections::BTreeSet;

    /// A deterministic `SplitMix64` stream, seeded from a hard-coded constant so a
    /// failure in CI is reproducible from the log alone.
    ///
    /// A file-local generator rather than a crate: the workspace has no
    /// property-testing dependency, and `scripts/invariant-lints.sh` bans the `rand`
    /// family outright so randomness in tests is always seeded and replayable. This
    /// is the repository's existing convention for randomized corpora, and these are
    /// simple invariants over small structures with no need for shrinking.
    struct Rng(u64);

    impl Rng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        /// A value in `0..bound`. `bound` must be nonzero.
        fn below(&mut self, bound: usize) -> usize {
            let bound_u64 = u64::try_from(bound).expect("bound fits u64");
            usize::try_from(self.next_u64() % bound_u64).expect("modulus fits usize")
        }

        fn flip(&mut self) -> bool {
            self.next_u64() & 1 == 1
        }

        /// A randomly present, randomly valued boolean.
        fn tri_bool(&mut self) -> Option<bool> {
            match self.below(3) {
                0 => None,
                1 => Some(false),
                _ => Some(true),
            }
        }
    }

    fn set(tokens: &[&str]) -> BTreeSet<String> {
        tokens.iter().map(|t| (*t).to_owned()).collect()
    }

    /// A random policy document over the closed factor vocabulary. Domains are drawn
    /// from a tiny fixed pool so intersections actually overlap sometimes.
    fn random_policy(rng: &mut Rng) -> AuthPolicy {
        const DOMAINS: [&str; 4] = [
            "acme.example",
            "contractor.example",
            "partner.example",
            "vendor.example",
        ];
        let allowed_factors = if rng.flip() {
            let mut chosen: BTreeSet<String> = BTreeSet::new();
            for token in KNOWN_FACTOR_TOKENS {
                if rng.flip() {
                    chosen.insert(token.to_owned());
                }
            }
            Some(chosen)
        } else {
            None
        };
        let allowed_email_domains = if rng.flip() {
            let mut chosen: BTreeSet<String> = BTreeSet::new();
            for domain in DOMAINS {
                if rng.flip() {
                    chosen.insert(domain.to_owned());
                }
            }
            Some(chosen)
        } else {
            None
        };
        AuthPolicy {
            mfa_required: rng.tri_bool(),
            allowed_factors,
            allowed_email_domains,
            jit_provisioning: rng.tri_bool(),
            invitations_enabled: rng.tri_bool(),
            session_ttl_secs: if rng.flip() {
                Some(u32::try_from(rng.below(100_000) + 1).expect("fits u32"))
            } else {
                None
            },
            session_idle_ttl_secs: if rng.flip() {
                Some(u32::try_from(rng.below(100_000) + 1).expect("fits u32"))
            } else {
                None
            },
        }
    }

    fn random_slots(rng: &mut Rng) -> [Option<AuthPolicy>; 4] {
        [
            if rng.flip() {
                Some(random_policy(rng))
            } else {
                None
            },
            if rng.flip() {
                Some(random_policy(rng))
            } else {
                None
            },
            if rng.flip() {
                Some(random_policy(rng))
            } else {
                None
            },
            if rng.flip() {
                Some(random_policy(rng))
            } else {
                None
            },
        ]
    }

    fn levels_from(slots: &[Option<AuthPolicy>]) -> PolicyLevels {
        let at = |index: usize| slots.get(index).cloned().flatten();
        PolicyLevels {
            tenant: at(0),
            environment: at(1),
            organization: at(2),
            client: at(3),
        }
    }

    /// Every permutation of four slots, generated rather than written out so a
    /// missing one cannot silently weaken the shuffle oracle.
    fn permutations_of_four() -> Vec<[usize; 4]> {
        let mut out = Vec::new();
        for a in 0..4 {
            for b in 0..4 {
                for c in 0..4 {
                    for d in 0..4 {
                        let candidate = [a, b, c, d];
                        let distinct: BTreeSet<usize> = candidate.iter().copied().collect();
                        if distinct.len() == 4 {
                            out.push(candidate);
                        }
                    }
                }
            }
        }
        out
    }

    /// Whether `after` is no wider than `before` on the factor dimension.
    ///
    /// The three cases form a chain (`Unconstrained` is widest, `Empty` narrowest),
    /// so anything but two restricted sets is decided by rank alone; two restricted
    /// sets need the subset test.
    fn factors_narrow(before: &AllowedFactors, after: &AllowedFactors) -> bool {
        fn rank(value: &AllowedFactors) -> u8 {
            match value {
                AllowedFactors::Unconstrained => 2,
                AllowedFactors::Restricted(_) => 1,
                AllowedFactors::Empty => 0,
            }
        }
        if let (AllowedFactors::Restricted(old), AllowedFactors::Restricted(new)) = (before, after)
        {
            return new.is_subset(old);
        }
        rank(after) <= rank(before)
    }

    /// The domain counterpart of [`factors_narrow`], with the same chain.
    fn domains_narrow(before: &AllowedDomains, after: &AllowedDomains) -> bool {
        fn rank(value: &AllowedDomains) -> u8 {
            match value {
                AllowedDomains::Unconstrained => 2,
                AllowedDomains::Restricted(_) => 1,
                AllowedDomains::Empty => 0,
            }
        }
        if let (AllowedDomains::Restricted(old), AllowedDomains::Restricted(new)) = (before, after)
        {
            return new.is_subset(old);
        }
        rank(after) <= rank(before)
    }

    /// The AND fold of `jit_provisioning` over a set of slots, computed by an
    /// INDEPENDENT model rather than by calling the engine, so the property below
    /// tests the engine against something other than itself.
    fn stated_jit(slots: &[Option<AuthPolicy>]) -> Option<bool> {
        let mut folded: Option<bool> = None;
        for policy in slots.iter().flatten() {
            if let Some(value) = policy.jit_provisioning {
                folded = Some(folded.unwrap_or(true) && value);
            }
        }
        folded
    }

    /// Every field for which the ACCESSOR is monotone narrowing.
    ///
    /// `jit_provisioning` is deliberately absent and is checked separately: it is
    /// the ONE field whose safe default (`false`) is NARROWER than its combinator
    /// identity (`true`), so with nobody speaking it reads `false` and a level that
    /// explicitly turns JIT ON legitimately moves it to `true`. What is monotone for
    /// JIT is the STATED value, not the defaulted one. This distinction was found by
    /// the property sweep below rather than reasoned out in advance, which is
    /// exactly what the sweep is for.
    fn assert_narrows(before: &ResolvedAuthPolicy, after: &ResolvedAuthPolicy) {
        assert!(
            factors_narrow(before.allowed_factors(), after.allowed_factors()),
            "adding a level widened the factor set: {before:?} -> {after:?}"
        );
        assert!(
            domains_narrow(
                before.allowed_email_domains(),
                after.allowed_email_domains()
            ),
            "adding a level widened the domain set: {before:?} -> {after:?}"
        );
        assert!(
            !before.mfa_required() || after.mfa_required(),
            "adding a level turned mfa_required OFF: {before:?} -> {after:?}"
        );
        assert!(
            before.invitations_enabled() || !after.invitations_enabled(),
            "adding a level turned invitations_enabled ON: {before:?} -> {after:?}"
        );
        for (old, new) in [
            (before.session_ttl_secs(), after.session_ttl_secs()),
            (
                before.session_idle_ttl_secs(),
                after.session_idle_ttl_secs(),
            ),
        ] {
            match (old, new) {
                (Some(old_secs), Some(new_secs)) => assert!(
                    new_secs <= old_secs,
                    "adding a level LENGTHENED a session lifetime: {old_secs} -> {new_secs}"
                ),
                (Some(_), None) => panic!("adding a level erased a session lifetime"),
                _ => {}
            }
        }
    }

    // -----------------------------------------------------------------------
    // The absent-default and identity behaviour (property P2 and P7).
    // -----------------------------------------------------------------------

    #[test]
    fn no_level_speaking_restricts_nothing_and_never_enables_jit() {
        // The single most consequential assertion in the module. Folding
        // jit_provisioning with AND over ZERO levels yields the identity `true`, so
        // a design that returned the bare fold would ship JIT ENABLED by default,
        // admitting people to an organization with nobody acting. The accessor
        // applies the SAFE default instead, and this pins the difference.
        let resolved = resolve(&PolicyLevels::default());
        assert!(!resolved.mfa_required(), "the honest MFA floor is off");
        assert!(
            !resolved.jit_provisioning(),
            "JIT must default OFF, NOT to the AND identity"
        );
        assert!(
            resolved.invitations_enabled(),
            "invitations are a shipped capability and must not be disabled by arrival"
        );
        assert_eq!(resolved.allowed_factors(), &AllowedFactors::Unconstrained);
        assert_eq!(
            resolved.allowed_email_domains(),
            &AllowedDomains::Unconstrained
        );
        assert_eq!(resolved.session_ttl_secs(), None);
        assert_eq!(resolved.session_idle_ttl_secs(), None);
        assert_eq!(resolved.satisfiability(), Satisfiability::Satisfiable);

        // An EMPTY policy document at every level is structurally the same thing.
        let empty_everywhere = PolicyLevels {
            tenant: Some(AuthPolicy::default()),
            environment: Some(AuthPolicy::default()),
            organization: Some(AuthPolicy::default()),
            client: Some(AuthPolicy::default()),
        };
        assert!(AuthPolicy::default().is_empty());
        assert_eq!(resolve(&empty_everywhere), resolved);
    }

    #[test]
    fn property_inserting_an_empty_level_changes_nothing() {
        // P2. An all-None document is the identity element of every combinator, at
        // ANY position.
        let mut rng = Rng(0x9515_1995_0007_0095);
        for _ in 0..2_000 {
            let slots = random_slots(&mut rng);
            let base = resolve(&levels_from(&slots));
            for position in 0..4 {
                let mut with_empty = slots.clone();
                with_empty[position] = Some(with_empty[position].clone().unwrap_or_default());
                // Only meaningful when the slot really was empty; when it held a
                // document, replace a DIFFERENT empty slot instead.
                if slots[position].is_some() {
                    continue;
                }
                assert_eq!(
                    resolve(&levels_from(&with_empty)),
                    base,
                    "an empty policy object must restrict nothing at position {position}"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Order independence, idempotence, monotonicity (P1, P3, P4).
    // -----------------------------------------------------------------------

    #[test]
    fn property_resolution_is_order_independent() {
        // P1, the shuffle oracle. This test IS the guard on the decision that every
        // field is strictest-wins: any field silently becoming NEAREST OVERRIDE
        // makes some permutation disagree.
        let mut rng = Rng(0x0000_0095_5555_0001);
        let permutations = permutations_of_four();
        assert_eq!(permutations.len(), 24, "all 4! orderings are swept");
        for _ in 0..1_000 {
            let slots = random_slots(&mut rng);
            let expected = resolve(&levels_from(&slots));
            for permutation in &permutations {
                let shuffled: Vec<Option<AuthPolicy>> =
                    permutation.iter().map(|&i| slots[i].clone()).collect();
                assert_eq!(
                    resolve(&levels_from(&shuffled)),
                    expected,
                    "resolution must not depend on which slot a document occupies"
                );
            }
        }
    }

    #[test]
    fn property_resolution_is_idempotent() {
        // P4. Supplying one level twice changes nothing, so the fold COMBINES rather
        // than ACCUMULATES.
        let mut rng = Rng(0x0000_0095_5555_0002);
        for _ in 0..2_000 {
            let policy = random_policy(&mut rng);
            let once = resolve(&PolicyLevels {
                organization: Some(policy.clone()),
                ..PolicyLevels::default()
            });
            let twice = resolve(&PolicyLevels {
                environment: Some(policy.clone()),
                organization: Some(policy.clone()),
                client: Some(policy),
                ..PolicyLevels::default()
            });
            assert_eq!(once, twice, "the fold must be idempotent");
        }
    }

    #[test]
    fn property_adding_a_level_never_widens() {
        // P3. An `or` written where an `and` was meant (and the reverse) shows up
        // here and almost nowhere else.
        let mut rng = Rng(0x0000_0095_5555_0003);
        for _ in 0..2_000 {
            let slots = random_slots(&mut rng);
            let before = resolve(&levels_from(&slots));
            let extra = random_policy(&mut rng);
            for position in 0..4 {
                if slots[position].is_some() {
                    continue;
                }
                let mut widened = slots.clone();
                widened[position] = Some(extra.clone());
                let after = resolve(&levels_from(&widened));
                assert_narrows(&before, &after);
                // The JIT half, on the STATED value: once any level has said false,
                // no later level can say true.
                if stated_jit(&slots) == Some(false) {
                    assert!(
                        !after.jit_provisioning(),
                        "a later level re-enabled JIT after one had disabled it: {after:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn jit_is_the_one_field_whose_default_is_narrower_than_its_identity() {
        // With NOBODY speaking, JIT is off: the safe default, deliberately NOT the
        // AND identity, because folding AND over zero levels yields `true` and a
        // design that returned the bare fold would admit people to an
        // organization with no administrator acting.
        assert!(!resolve(&PolicyLevels::default()).jit_provisioning());

        // A level that explicitly turns JIT ON legitimately does so. This is the
        // ONE place in the engine where adding a level makes an accessor read
        // WIDER, and it is a consequence of the safe default, not of the fold.
        let enabled = resolve(&PolicyLevels {
            organization: Some(AuthPolicy {
                jit_provisioning: Some(true),
                ..AuthPolicy::default()
            }),
            ..PolicyLevels::default()
        });
        assert!(enabled.jit_provisioning());

        // But once ANY level has said false, no nearer level can say true: that is
        // the strictest-wins guarantee, and it is what actually protects the
        // organization.
        let vetoed = resolve(&PolicyLevels {
            environment: Some(AuthPolicy {
                jit_provisioning: Some(false),
                ..AuthPolicy::default()
            }),
            organization: Some(AuthPolicy {
                jit_provisioning: Some(true),
                ..AuthPolicy::default()
            }),
            client: Some(AuthPolicy {
                jit_provisioning: Some(true),
                ..AuthPolicy::default()
            }),
            ..PolicyLevels::default()
        });
        assert!(
            !vetoed.jit_provisioning(),
            "a nearer level must not be able to re-enable JIT"
        );
    }

    // -----------------------------------------------------------------------
    // The empty intersection and the MFA reachability verdict (P5, P6).
    // -----------------------------------------------------------------------

    #[test]
    fn disjoint_factor_sets_resolve_to_empty_and_never_to_unconstrained() {
        // P5. The fail-OPEN mistake this guards is an empty intersection collapsing
        // into "no restriction", which would permit EVERYTHING.
        let levels = PolicyLevels {
            environment: Some(AuthPolicy {
                allowed_factors: Some(set(&["totp", "passkey_uv"])),
                ..AuthPolicy::default()
            }),
            organization: Some(AuthPolicy {
                allowed_factors: Some(set(&["passkey_uv"])),
                ..AuthPolicy::default()
            }),
            client: Some(AuthPolicy {
                allowed_factors: Some(set(&["totp"])),
                ..AuthPolicy::default()
            }),
            ..PolicyLevels::default()
        };
        let resolved = resolve(&levels);
        assert_eq!(
            resolved.allowed_factors(),
            &AllowedFactors::Empty,
            "three individually valid documents can intersect to nothing"
        );
        assert_eq!(
            resolved.satisfiability(),
            Satisfiability::NoFactorPermitted,
            "an empty intersection must fail closed"
        );
    }

    #[test]
    fn property_disjoint_levels_are_always_empty_and_never_satisfiable() {
        // P5 swept: whenever two PRESENT levels state disjoint factor sets, the
        // result is Empty and the verdict is never Satisfiable.
        let mut rng = Rng(0x0000_0095_5555_0005);
        for _ in 0..4_000 {
            let slots = random_slots(&mut rng);
            let stated: Vec<&BTreeSet<String>> = slots
                .iter()
                .filter_map(|slot| slot.as_ref())
                .filter_map(|policy| policy.allowed_factors.as_ref())
                .collect();
            let disjoint_pair = stated.iter().enumerate().any(|(index, left)| {
                stated
                    .iter()
                    .skip(index + 1)
                    .any(|right| left.is_disjoint(right))
            });
            if !disjoint_pair {
                continue;
            }
            let resolved = resolve(&levels_from(&slots));
            assert_eq!(resolved.allowed_factors(), &AllowedFactors::Empty);
            assert_ne!(resolved.satisfiability(), Satisfiability::Satisfiable);
        }
    }

    #[test]
    fn mfa_required_with_only_primary_factors_is_never_satisfiable() {
        // P6, and the sharpest single trap in the issue: `email_otp` and `sms` are
        // SINGLE PRIMARY factors in this codebase. Their amr carries no `mfa`, so a
        // policy requiring MFA that permits only those two can never be satisfied by
        // any login. A verdict built on the wrong set would call this Satisfiable.
        let levels = PolicyLevels {
            organization: Some(AuthPolicy {
                mfa_required: Some(true),
                allowed_factors: Some(set(&["pwd", "email_otp", "sms"])),
                ..AuthPolicy::default()
            }),
            ..PolicyLevels::default()
        };
        assert_eq!(
            resolve(&levels).satisfiability(),
            Satisfiability::MfaRequiredWithNoSecondFactor
        );

        // The same shape reached ACROSS levels, which no single write could see.
        let cross_level = PolicyLevels {
            environment: Some(AuthPolicy {
                allowed_factors: Some(set(&["pwd", "email_otp", "totp"])),
                ..AuthPolicy::default()
            }),
            organization: Some(AuthPolicy {
                mfa_required: Some(true),
                allowed_factors: Some(set(&["pwd", "email_otp", "sms"])),
                ..AuthPolicy::default()
            }),
            ..PolicyLevels::default()
        };
        assert_eq!(
            resolve(&cross_level).satisfiability(),
            Satisfiability::MfaRequiredWithNoSecondFactor,
            "each document is individually valid; only the intersection contradicts"
        );

        // Adding one genuine second factor makes it satisfiable again.
        let repaired = PolicyLevels {
            organization: Some(AuthPolicy {
                mfa_required: Some(true),
                allowed_factors: Some(set(&["pwd", "email_otp", "sms", "totp"])),
                ..AuthPolicy::default()
            }),
            ..PolicyLevels::default()
        };
        assert_eq!(
            resolve(&repaired).satisfiability(),
            Satisfiability::Satisfiable
        );
    }

    #[test]
    fn property_mfa_reachability_matches_the_second_factor_set() {
        // P6 swept over randomized combinations.
        let mut rng = Rng(0x0000_0095_5555_0006);
        for _ in 0..4_000 {
            let slots = random_slots(&mut rng);
            let resolved = resolve(&levels_from(&slots));
            match resolved.allowed_factors() {
                AllowedFactors::Empty => {
                    assert_eq!(resolved.satisfiability(), Satisfiability::NoFactorPermitted);
                }
                AllowedFactors::Unconstrained => {
                    assert_eq!(resolved.satisfiability(), Satisfiability::Satisfiable);
                }
                AllowedFactors::Restricted(permitted) => {
                    let reachable = permitted
                        .iter()
                        .any(|token| SECOND_FACTOR_TOKENS.contains(&token.as_str()));
                    let expected = if resolved.mfa_required() && !reachable {
                        Satisfiability::MfaRequiredWithNoSecondFactor
                    } else {
                        Satisfiability::Satisfiable
                    };
                    assert_eq!(resolved.satisfiability(), expected);
                }
            }
        }
    }

    #[test]
    fn a_lower_level_can_never_switch_mfa_back_off() {
        // The strictest-wins direction for the one field an organization admin would
        // most like to relax.
        let levels = PolicyLevels {
            environment: Some(AuthPolicy {
                mfa_required: Some(true),
                ..AuthPolicy::default()
            }),
            organization: Some(AuthPolicy {
                mfa_required: Some(false),
                ..AuthPolicy::default()
            }),
            client: Some(AuthPolicy {
                mfa_required: Some(false),
                ..AuthPolicy::default()
            }),
            ..PolicyLevels::default()
        };
        assert!(
            resolve(&levels).mfa_required(),
            "a nearer level must not be able to turn MFA off"
        );
    }

    #[test]
    fn a_lower_level_can_never_switch_invitations_back_on() {
        // The invitations counterpart of the MFA direction, pinned by name rather
        // than only by the property sweep: `false` is strictest, so once any level
        // has disabled invitations no nearer level can re-enable them. The default
        // with nobody speaking stays `true`, because invitations are a SHIPPED issue
        // #94 capability and issue #95 must not disable them merely by arriving.
        let vetoed = resolve(&PolicyLevels {
            environment: Some(AuthPolicy {
                invitations_enabled: Some(false),
                ..AuthPolicy::default()
            }),
            organization: Some(AuthPolicy {
                invitations_enabled: Some(true),
                ..AuthPolicy::default()
            }),
            client: Some(AuthPolicy {
                invitations_enabled: Some(true),
                ..AuthPolicy::default()
            }),
            ..PolicyLevels::default()
        });
        assert!(
            !vetoed.invitations_enabled(),
            "a nearer level must not be able to re-enable invitations"
        );
        // Nobody speaking leaves the shipped capability on.
        assert!(resolve(&PolicyLevels::default()).invitations_enabled());
        // And a single level turning them off is honored.
        assert!(
            !resolve(&PolicyLevels {
                organization: Some(AuthPolicy {
                    invitations_enabled: Some(false),
                    ..AuthPolicy::default()
                }),
                ..PolicyLevels::default()
            })
            .invitations_enabled()
        );
    }

    // -----------------------------------------------------------------------
    // Session lifetime (the shorten-only guarantee).
    // -----------------------------------------------------------------------

    #[test]
    fn an_organization_may_shorten_a_session_but_never_lengthen_one() {
        // ACROSS LEVELS first, because this is where MIN and MAX actually differ: a
        // single level states its value either way, so a one-level test cannot tell a
        // strictest-wins fold from a nearest-override one.
        let across = resolve(&PolicyLevels {
            environment: Some(AuthPolicy {
                session_ttl_secs: Some(1_800),
                session_idle_ttl_secs: Some(600),
                ..AuthPolicy::default()
            }),
            organization: Some(AuthPolicy {
                session_ttl_secs: Some(28_800),
                session_idle_ttl_secs: Some(7_200),
                ..AuthPolicy::default()
            }),
            ..PolicyLevels::default()
        });
        assert_eq!(
            across.session_ttl_secs(),
            Some(1_800),
            "an organization asking for a LONGER session than its environment gets the \
             environment's, not its own"
        );
        assert_eq!(across.session_idle_ttl_secs(), Some(600));

        // And in the shortening direction the organization's value does apply.
        let tightened = resolve(&PolicyLevels {
            environment: Some(AuthPolicy {
                session_ttl_secs: Some(28_800),
                ..AuthPolicy::default()
            }),
            organization: Some(AuthPolicy {
                session_ttl_secs: Some(1_800),
                ..AuthPolicy::default()
            }),
            ..PolicyLevels::default()
        });
        assert_eq!(tightened.session_ttl_secs(), Some(1_800));

        let deployment = 3_600_u32;
        let shorter = resolve(&PolicyLevels {
            organization: Some(AuthPolicy {
                session_ttl_secs: Some(900),
                session_idle_ttl_secs: Some(300),
                ..AuthPolicy::default()
            }),
            ..PolicyLevels::default()
        });
        assert_eq!(shorter.effective_session_ttl_secs(deployment), 900);
        assert_eq!(shorter.effective_session_idle_ttl_secs(deployment), 300);

        let longer = resolve(&PolicyLevels {
            organization: Some(AuthPolicy {
                session_ttl_secs: Some(86_400),
                session_idle_ttl_secs: Some(86_400),
                ..AuthPolicy::default()
            }),
            ..PolicyLevels::default()
        });
        assert_eq!(
            longer.effective_session_ttl_secs(deployment),
            deployment,
            "a policy stating a LONGER lifetime has no effect"
        );
        assert_eq!(
            longer.effective_session_idle_ttl_secs(deployment),
            deployment
        );

        // A level that states nothing leaves the deployment value untouched.
        let silent = resolve(&PolicyLevels::default());
        assert_eq!(silent.effective_session_ttl_secs(deployment), deployment);
        assert_eq!(
            silent.effective_session_idle_ttl_secs(deployment),
            deployment
        );
    }

    #[test]
    fn the_resolved_session_pair_catches_what_no_single_document_could() {
        // The organization states ONLY an idle window; the environment states only a
        // shorter absolute lifetime. Each document is row-locally valid and the
        // RESOLVED pair is incoherent, which is exactly the case a CHECK constraint
        // cannot see.
        let levels = PolicyLevels {
            environment: Some(AuthPolicy {
                session_ttl_secs: Some(600),
                ..AuthPolicy::default()
            }),
            organization: Some(AuthPolicy {
                session_idle_ttl_secs: Some(1_800),
                ..AuthPolicy::default()
            }),
            ..PolicyLevels::default()
        };
        let both_valid = validate(
            levels.environment.as_ref().expect("present"),
            ORG_POLICY_MAX_SESSION_TTL_SECS,
        )
        .is_ok()
            && validate(
                levels.organization.as_ref().expect("present"),
                ORG_POLICY_MAX_SESSION_TTL_SECS,
            )
            .is_ok();
        assert!(both_valid, "each document is individually valid");
        assert!(
            !resolved_session_pair_is_coherent(&resolve(&levels)),
            "the resolved pair must report the incoherence the documents could not"
        );

        assert!(resolved_session_pair_is_coherent(&resolve(
            &PolicyLevels::default()
        )));
    }

    // -----------------------------------------------------------------------
    // Validation.
    // -----------------------------------------------------------------------

    #[test]
    fn an_empty_document_and_a_well_formed_one_validate() {
        assert_eq!(
            validate(&AuthPolicy::default(), ORG_POLICY_MAX_SESSION_TTL_SECS),
            Ok(())
        );
        let good = AuthPolicy {
            mfa_required: Some(true),
            allowed_factors: Some(set(&["pwd", "totp"])),
            allowed_email_domains: Some(set(&["acme.example"])),
            jit_provisioning: Some(false),
            invitations_enabled: Some(true),
            session_ttl_secs: Some(3_600),
            session_idle_ttl_secs: Some(900),
        };
        assert_eq!(validate(&good, ORG_POLICY_MAX_SESSION_TTL_SECS), Ok(()));
    }

    #[test]
    fn every_refusal_is_reachable_and_value_free() {
        let ceiling = ORG_POLICY_MAX_SESSION_TTL_SECS;

        assert_eq!(
            validate(
                &AuthPolicy {
                    allowed_factors: Some(set(&["pwd", "not_a_factor"])),
                    ..AuthPolicy::default()
                },
                ceiling
            ),
            Err(vec![AuthPolicyError::UnknownFactor])
        );
        assert_eq!(
            validate(
                &AuthPolicy {
                    allowed_factors: Some(BTreeSet::new()),
                    ..AuthPolicy::default()
                },
                ceiling
            ),
            Err(vec![AuthPolicyError::EmptyFactorList])
        );
        assert_eq!(
            validate(
                &AuthPolicy {
                    allowed_email_domains: Some(BTreeSet::new()),
                    ..AuthPolicy::default()
                },
                ceiling
            ),
            Err(vec![AuthPolicyError::EmptyDomainList])
        );
        // The intra-document contradiction, on the exact set that is the trap:
        // email_otp and sms carry no `mfa` amr.
        assert_eq!(
            validate(
                &AuthPolicy {
                    mfa_required: Some(true),
                    allowed_factors: Some(set(&["pwd", "email_otp", "sms"])),
                    ..AuthPolicy::default()
                },
                ceiling
            ),
            Err(vec![AuthPolicyError::MfaRequiredWithNoSecondFactor])
        );
        assert_eq!(
            validate(
                &AuthPolicy {
                    session_ttl_secs: Some(600),
                    session_idle_ttl_secs: Some(900),
                    ..AuthPolicy::default()
                },
                ceiling
            ),
            Err(vec![AuthPolicyError::IdleExceedsAbsolute])
        );
        assert_eq!(
            validate(
                &AuthPolicy {
                    session_ttl_secs: Some(ceiling + 1),
                    ..AuthPolicy::default()
                },
                ceiling
            ),
            Err(vec![AuthPolicyError::SessionTtlAboveCeiling])
        );
        assert_eq!(
            validate(
                &AuthPolicy {
                    session_idle_ttl_secs: Some(ceiling + 1),
                    ..AuthPolicy::default()
                },
                ceiling
            ),
            Err(vec![AuthPolicyError::SessionTtlAboveCeiling]),
            "the idle half is checked against the ceiling too"
        );
    }

    #[test]
    fn a_zero_session_lifetime_is_refused_on_both_halves() {
        // The FLOOR, and the half the guard originally left to the storage engine.
        // `org_auth_policies_session_ttl_positive` and `_session_idle_positive` refuse
        // a zero, so a guard that accepted one would hand the document to the INSERT
        // and take a CHECK violation MID-transaction: that aborts the transaction the
        // audit row still has to be written in, and reaches the caller as an opaque
        // database fault instead of this typed refusal.
        let ceiling = ORG_POLICY_MAX_SESSION_TTL_SECS;

        // Both halves INDEPENDENTLY: a zero idle window with no absolute lifetime
        // stated trips nothing else, so a rule written on the PAIR rather than on
        // each value would miss it.
        assert_eq!(
            validate(
                &AuthPolicy {
                    session_ttl_secs: Some(0),
                    ..AuthPolicy::default()
                },
                ceiling
            ),
            Err(vec![AuthPolicyError::NonPositiveSessionLifetime])
        );
        assert_eq!(
            validate(
                &AuthPolicy {
                    session_idle_ttl_secs: Some(0),
                    ..AuthPolicy::default()
                },
                ceiling
            ),
            Err(vec![AuthPolicyError::NonPositiveSessionLifetime]),
            "the idle half has a floor too"
        );
        // ONE is the smallest writable lifetime, so this is a floor at exactly the
        // value the CHECK constraints draw it at rather than a bound the two could
        // disagree about.
        assert_eq!(
            validate(
                &AuthPolicy {
                    session_ttl_secs: Some(1),
                    session_idle_ttl_secs: Some(1),
                    ..AuthPolicy::default()
                },
                ceiling
            ),
            Ok(())
        );
        // Omitting the dimension is how "unconstrained" is spelled, exactly as it is
        // for the two lists; it is NOT a zero.
        assert_eq!(validate(&AuthPolicy::default(), ceiling), Ok(()));
    }

    #[test]
    fn an_unregistrable_email_domain_is_refused_at_the_write_boundary() {
        // A shapeless entry is refused before it is ever written, so a value that
        // could never match a real address cannot sit in a policy looking effective.
        // The check is the SAME registrable-hostname predicate the custom-domain
        // surface uses; a fourth domain validator is exactly the drift the
        // canonicalization seam exists to prevent.
        for bad in [
            "localhost",
            "not a domain",
            "https://acme.example",
            "acme.example:443",
            "10.0.0.1",
            "",
        ] {
            assert_eq!(
                validate(
                    &AuthPolicy {
                        allowed_email_domains: Some(set(&[bad])),
                        ..AuthPolicy::default()
                    },
                    ORG_POLICY_MAX_SESSION_TTL_SECS
                ),
                Err(vec![AuthPolicyError::InvalidEmailDomain]),
                "{bad:?} is not a registrable domain"
            );
        }
    }

    #[test]
    fn every_refusal_message_names_a_dimension_and_never_a_value() {
        for error in [
            AuthPolicyError::UnknownFactor,
            AuthPolicyError::EmptyFactorList,
            AuthPolicyError::EmptyDomainList,
            AuthPolicyError::MfaRequiredWithNoSecondFactor,
            AuthPolicyError::IdleExceedsAbsolute,
            AuthPolicyError::SessionTtlAboveCeiling,
            AuthPolicyError::NonPositiveSessionLifetime,
            AuthPolicyError::InvalidEmailDomain,
        ] {
            let rendered = error.to_string();
            assert!(!rendered.is_empty());
            assert!(
                !rendered.contains("not_a_factor") && !rendered.contains("acme.example"),
                "a refusal must never echo a submitted value: {rendered}"
            );
        }
    }

    #[test]
    fn validation_collects_every_failure_in_a_deterministic_order() {
        // An operator learns all of them in ONE round trip, and the rendered order is
        // a pure function of the input rather than of iteration order.
        let broken = AuthPolicy {
            mfa_required: Some(true),
            allowed_factors: Some(set(&["email_otp", "nope"])),
            allowed_email_domains: Some(set(&["localhost"])),
            session_ttl_secs: Some(600),
            session_idle_ttl_secs: Some(900),
            ..AuthPolicy::default()
        };
        let errors = validate(&broken, ORG_POLICY_MAX_SESSION_TTL_SECS).expect_err("refused");
        assert_eq!(
            errors,
            vec![
                AuthPolicyError::UnknownFactor,
                AuthPolicyError::MfaRequiredWithNoSecondFactor,
                AuthPolicyError::IdleExceedsAbsolute,
                AuthPolicyError::InvalidEmailDomain,
            ]
        );
        // Deterministic across runs.
        assert_eq!(
            validate(&broken, ORG_POLICY_MAX_SESSION_TTL_SECS).expect_err("refused"),
            errors
        );
    }

    #[test]
    fn validation_is_intra_document_and_never_reads_ancestors() {
        // The limitation the doc comment states, made executable: the organization's
        // document is individually VALID and its RESOLUTION with the environment is
        // unsatisfiable. A validator that claimed to prevent this would be the more
        // dangerous defect, because an operator would trust it.
        let environment = AuthPolicy {
            allowed_factors: Some(set(&["totp"])),
            ..AuthPolicy::default()
        };
        let organization = AuthPolicy {
            allowed_factors: Some(set(&["passkey_uv"])),
            ..AuthPolicy::default()
        };
        assert_eq!(
            validate(&environment, ORG_POLICY_MAX_SESSION_TTL_SECS),
            Ok(())
        );
        assert_eq!(
            validate(&organization, ORG_POLICY_MAX_SESSION_TTL_SECS),
            Ok(())
        );
        let resolved = resolve(&PolicyLevels {
            environment: Some(environment),
            organization: Some(organization),
            ..PolicyLevels::default()
        });
        assert_eq!(resolved.allowed_factors(), &AllowedFactors::Empty);
        assert_eq!(
            resolved.satisfiability(),
            Satisfiability::NoFactorPermitted,
            "what the write could not see, resolution must"
        );
    }

    #[test]
    fn every_known_factor_token_validates_and_the_second_factor_set_is_a_subset() {
        // The whole closed vocabulary is writable, and the second-factor set is not
        // allowed to drift outside it.
        assert_eq!(
            validate(
                &AuthPolicy {
                    allowed_factors: Some(
                        KNOWN_FACTOR_TOKENS
                            .iter()
                            .map(|t| (*t).to_owned())
                            .collect()
                    ),
                    ..AuthPolicy::default()
                },
                ORG_POLICY_MAX_SESSION_TTL_SECS
            ),
            Ok(())
        );
        for token in SECOND_FACTOR_TOKENS {
            assert!(
                KNOWN_FACTOR_TOKENS.contains(&token),
                "{token} must be part of the closed vocabulary"
            );
        }
        // The two tokens a naive reading would wrongly include.
        for token in ["email_otp", "sms", "trusted_device", "pwd", "federated"] {
            assert!(
                !SECOND_FACTOR_TOKENS.contains(&token),
                "{token} performs no genuine second factor in this codebase"
            );
        }
        // No duplicates in either registry.
        let known: BTreeSet<&str> = KNOWN_FACTOR_TOKENS.iter().copied().collect();
        assert_eq!(known.len(), KNOWN_FACTOR_TOKENS.len());
        let second: BTreeSet<&str> = SECOND_FACTOR_TOKENS.iter().copied().collect();
        assert_eq!(second.len(), SECOND_FACTOR_TOKENS.len());
    }

    // -----------------------------------------------------------------------
    // Normalization and the audit detail.
    // -----------------------------------------------------------------------

    #[test]
    fn domains_normalize_through_the_one_seam_and_collapse_to_a_set() {
        let policy = AuthPolicy {
            allowed_email_domains: Some(set(&["ACME.example", "acme.EXAMPLE", " acme.example "])),
            ..AuthPolicy::default()
        };
        let normalized = normalize(&policy);
        assert_eq!(
            normalized.allowed_email_domains,
            Some(set(&["acme.example"])),
            "three spellings of one domain collapse to one normalized entry"
        );
        assert_eq!(
            validate(&normalized, ORG_POLICY_MAX_SESSION_TTL_SECS),
            Ok(())
        );
        // Normalization is idempotent.
        assert_eq!(normalize(&normalized), normalized);
        // A value that normalizes to NOTHING is kept verbatim so validation refuses
        // it, rather than silently dropped (which, as the only entry, would turn a
        // restriction into no restriction).
        let invisible = AuthPolicy {
            allowed_email_domains: Some(set(&["\u{200b}"])),
            ..AuthPolicy::default()
        };
        let normalized_invisible = normalize(&invisible);
        assert_eq!(
            normalized_invisible.allowed_email_domains,
            Some(set(&["\u{200b}"]))
        );
        assert_eq!(
            validate(&normalized_invisible, ORG_POLICY_MAX_SESSION_TTL_SECS),
            Err(vec![AuthPolicyError::InvalidEmailDomain])
        );
        // Nothing but the domain list moves.
        let untouched = AuthPolicy {
            mfa_required: Some(true),
            allowed_factors: Some(set(&["totp"])),
            jit_provisioning: Some(false),
            invitations_enabled: Some(true),
            session_ttl_secs: Some(60),
            session_idle_ttl_secs: Some(30),
            allowed_email_domains: None,
        };
        assert_eq!(normalize(&untouched), untouched);
    }

    #[test]
    fn the_audit_detail_is_a_closed_vocabulary_and_never_echoes_a_value() {
        let stated = AuthPolicy {
            mfa_required: Some(true),
            allowed_factors: Some(set(&["totp", "passkey_uv"])),
            allowed_email_domains: Some(set(&["acme.example"])),
            jit_provisioning: Some(false),
            invitations_enabled: None,
            session_ttl_secs: Some(3_600),
            session_idle_ttl_secs: Some(900),
        };
        let detail = audit_detail(&stated);
        assert_eq!(
            detail,
            "mfa_required=true factors=restricted domains=set jit=false invitations=inherit \
             session_ttl=3600 session_idle=900"
        );
        // No domain string and no factor token ever reaches the audit log.
        assert!(!detail.contains("acme.example"));
        assert!(!detail.contains("totp"));
        assert!(!detail.contains("passkey_uv"));
        // The all-unset document.
        assert_eq!(
            audit_detail(&AuthPolicy::default()),
            "mfa_required=inherit factors=inherit domains=inherit jit=inherit \
             invitations=inherit session_ttl=inherit session_idle=inherit"
        );
    }

    #[test]
    fn property_resolution_and_audit_detail_are_byte_stable() {
        // P8. A HashSet creeping into either would show up here as a run-to-run
        // difference in the rendered form.
        let mut rng = Rng(0x0000_0095_5555_0008);
        for _ in 0..2_000 {
            let slots = random_slots(&mut rng);
            let levels = levels_from(&slots);
            assert_eq!(
                format!("{:?}", resolve(&levels)),
                format!("{:?}", resolve(&levels))
            );
            for slot in slots.iter().flatten() {
                assert_eq!(audit_detail(slot), audit_detail(slot));
                // The detail is a pure function of the document, so an equal
                // document renders an equal string.
                assert_eq!(audit_detail(slot), audit_detail(&slot.clone()));
            }
        }
    }
}
