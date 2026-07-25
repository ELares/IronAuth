// SPDX-License-Identifier: MIT OR Apache-2.0

//! The store's error type.
//!
//! The isolation-critical property here is uniformity: a resource that belongs
//! to another tenant, a resource in another environment, and a resource that
//! never existed all surface as [`StoreError::NotFound`]. Nothing a caller can
//! observe distinguishes them, so the persistence layer never becomes an
//! existence oracle.

use std::fmt;

use crate::environment::GuardrailViolation;
use crate::id::NotInScope;
use crate::migrate::MigrationError;

/// Why a store operation failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum StoreError {
    /// The requested resource is not visible in the current scope. Returned
    /// identically whether the resource is absent, belongs to another tenant,
    /// belongs to another environment, or was presented with a malformed
    /// identifier. This uniformity is the anti-IDOR contract.
    NotFound,
    /// A database or connection error. Never carries tenant data.
    Database(sqlx::Error),
    /// A schema migration could not be applied or was refused (out of order or
    /// checksum drift). Returned only by [`crate::Store::migrate`].
    Migration(MigrationError),
    /// A concurrent request already stored a result under this Idempotency-Key
    /// (a unique-key race on the idempotency table). The caller re-reads the
    /// now-committed original response and replays it; the mutation did not run
    /// a second time. Returned only by the management-plane create paths.
    IdempotencyConflict,
    /// A create violated a uniqueness constraint that is NOT an anti-oracle
    /// concern: for example registering a bootstrap user whose login identifier
    /// already exists in the scope (issue #20). Distinct from [`NotFound`] because
    /// the caller (the interactive registration surface) legitimately tells the
    /// user the handle is taken; it is not a cross-scope existence probe.
    ///
    /// [`NotFound`]: StoreError::NotFound
    Conflict,
    /// A client tried to register a redirect URI that is not a valid RFC 8252
    /// redirect target (issue #13): not a claimed `https` URL, an `http` loopback
    /// IP-literal URL, or a reverse-domain private-use scheme. Malformed schemes
    /// are rejected at registration time (as they are at authorization time), so a
    /// value that could never be a safe redirect target never reaches the
    /// registered set. Carries no tenant data.
    InvalidRedirectUri,
    /// A config write violated one of the environment's TYPED guardrails (issue
    /// #42): for example registering an `http` loopback redirect URI in a
    /// PRODUCTION environment, which the two-class asymmetry forbids (dev and
    /// staging relax it; prod hard-requires `https`). DELIBERATELY distinct from
    /// [`InvalidRedirectUri`], which is a shape failure (not a registrable RFC 8252
    /// target at all): a guardrail violation is a well-formed value the
    /// environment's KIND rejects, so the caller can name the exact failed
    /// guardrail. Carries the failed [`GuardrailViolation`] (a stable wire code and
    /// an operator-safe message, no tenant data).
    ///
    /// [`InvalidRedirectUri`]: StoreError::InvalidRedirectUri
    GuardrailViolation(GuardrailViolation),
    /// A dynamic client registration would exceed the environment's configured
    /// registered-client quota (issue #31). Enforced atomically inside the
    /// registration transaction (under a per-scope advisory lock, so a concurrent
    /// pair of registrations cannot both slip past the cap), so nothing is written
    /// when it fires. The registration endpoint maps it to a typed refusal and a
    /// `dcr.quota_hit` audit event.
    QuotaExceeded,
    /// An envelope-encryption operation failed (issue #48): a wrapped key or a
    /// sealed payload could not be authenticated and decrypted. This is
    /// DELIBERATELY distinct from [`NotFound`]: a caller can tell "this ciphertext
    /// did not authenticate" (a wrong or crypto-shredded tenant key, a tampered
    /// blob, or a ciphertext replayed from another row/tenant/column) apart from
    /// "there is no such record". It carries no key material, plaintext, or
    /// ciphertext, so it is safe to log. A crypto-shredded tenant's data surfaces
    /// here (its KEK is unrecoverable), never as recovered plaintext.
    ///
    /// [`NotFound`]: StoreError::NotFound
    Encryption,
    /// An invitation was created with an `org_context` that is not a usable
    /// organization reference in this scope (issue #94): a value that is not a
    /// parseable `org_` id, or one minted in another scope. A clean early error at
    /// invitation CREATE, distinct from [`NotFound`] so the management surface can
    /// tell the caller the org-context is the problem (never a cross-scope existence
    /// probe: a malformed value and a foreign-scope value are rejected identically).
    /// The membership foreign key is the ultimate backstop at accept.
    ///
    /// [`NotFound`]: StoreError::NotFound
    InvalidOrgContext,
    /// A custom-domain registration submitted a value that is not a plain
    /// registrable hostname (issue #47): an IP literal, an internal single-label
    /// name, or a value carrying a scheme, port, path, or whitespace. Rejected
    /// before it is ever written, so a tenant-controlled domain can never be used
    /// to point serving or an ACME/CA request at internal infrastructure. Carries
    /// no tenant data.
    InvalidCustomDomain,
    /// An environment secret or variable was submitted with a name that is not a
    /// valid reference key (issue #45): empty, too long, or carrying a character
    /// outside the reference-name alphabet, so a config field could never name it.
    /// Rejected before it is written. Carries no tenant data.
    InvalidName,
    /// A login identifier was submitted whose canonical form is not storable (issue
    /// #54): an all-invisible / whitespace-only value that canonicalizes to the EMPTY
    /// form (which would squat the degenerate "empty" slot and resolve to that
    /// account), or an email with no usable `@` shape (which must not be stored as a
    /// username-like fold). Rejected at the write boundary before anything is
    /// persisted, deterministically and independent of any existing row (so it is
    /// never an existence oracle). Carries no tenant data.
    InvalidIdentifier,
    /// A submitted trait schema is not a well-formed JSON Schema of the supported
    /// draft 2020-12 vocabulary (issue #53): a malformed keyword, a non-object
    /// sub-schema, or a nesting past the depth bound. Carries the offending location
    /// and a stable reason (never attacker-controlled instance data), so the
    /// management surface can report exactly what is malformed.
    SchemaMalformed(crate::trait_schema::SchemaError),
    /// A user's traits do not validate against the active trait-schema version
    /// (issue #53). Carries the per-field failures, each an RFC 6901 JSON Pointer to
    /// the offending location and a stable reason (never the offending value, so no
    /// trait PII is carried). The write is refused before anything is persisted.
    TraitsInvalid(Vec<crate::trait_schema::ValidationFailure>),
    /// A trait-schema version cannot become the active default because a dry-run or
    /// migration still reports unresolved invalid identities (issue #53): the cutover
    /// rule. Carries the count of identities that fail the target schema. No mutation
    /// happens when it fires.
    CutoverBlocked {
        /// The number of existing identities whose traits fail the target schema.
        invalid_identities: i64,
    },
    /// A trait write or a migration job targeted a scope with no active trait schema
    /// version (issue #53): there is nothing to validate against. Distinct from
    /// [`NotFound`] so the management surface can tell the operator to register and
    /// activate a schema first.
    ///
    /// [`NotFound`]: StoreError::NotFound
    NoActiveTraitSchema,
    /// A migration-run state transition was refused because it is not a legal edge of
    /// the state machine (issue #59): for example advancing a `complete` or
    /// `abandoned` run, or skipping a state. Carries the current and attempted state
    /// wire strings so the caller can report the illegal edge. No mutation happens
    /// when it fires. Distinct from the invariant-gated completion refusal, which is
    /// a legitimate NON-error outcome the caller inspects (see
    /// [`crate::CompletionOutcome`]).
    IllegalMigrationTransition {
        /// The run's current state (wire string).
        from: &'static str,
        /// The refused target state (wire string).
        to: &'static str,
    },
    /// A custom-journey artifact submitted to the version registry is not a load-valid journey
    /// (issue #92, PR 5): it does not parse as a journey document, or it fails
    /// [`ironauth_journey::validate`] / compile (an unknown step kind or node group, a dangling
    /// or ambiguous transition, an unreachable step, a dead end, or no reachable completion).
    /// Carries every [`ironauth_journey::JourneyError`], each an operator-safe, value-free RFC
    /// 6901 pointer and reason, so the management surface can report exactly what is invalid. The
    /// write is refused before anything is persisted.
    JourneyInvalid(Vec<ironauth_journey::JourneyError>),
    /// A group create or reparent would close a CYCLE in the organization's group
    /// forest (issue #97): the group being placed IS the proposed parent, or is an
    /// ancestor of it, so the new edge would make the group its own ancestor.
    /// NOTHING is written. The check runs inside the audited write transaction and
    /// under a per-organization advisory lock, so returning this rolls the
    /// attempted write AND its audit row back together, and no concurrent reparent
    /// can have slipped a second half of the same cycle past it.
    ///
    /// Deliberately distinct from [`NotFound`], and NOT an existence oracle: both
    /// endpoints are resolved as LIVE rows in the caller's own scope AND in the
    /// same organization BEFORE any cycle reasoning runs, so a caller who sees
    /// this has already proven they can see both groups. An absent, soft-deleted,
    /// foreign-scope, or cross-organization group id is refused earlier and
    /// uniformly as [`NotFound`].
    ///
    /// Carries no ids and no tenant data: the offending pair is the caller's own
    /// request, so naming it back adds nothing and keeps the Display arm data
    /// free.
    ///
    /// [`NotFound`]: StoreError::NotFound
    OrgGroupCycle,
    /// A group create or reparent would produce a nesting depth greater than the
    /// configured maximum (issue #97). The bound is over the WHOLE affected
    /// subtree (the proposed parent's own depth, plus the new edge, plus the
    /// height of the moved group's subtree), so it fires even when neither the
    /// parent nor the moved group individually exceeded it. NOTHING is written.
    ///
    /// Deliberately distinct from [`NotFound`] for the same reason as
    /// [`OrgGroupCycle`], and distinct from that variant because it is a different
    /// operator problem with a different remedy: a cycle is a malformed request,
    /// an over-deep tree is a structural limit an operator can raise.
    ///
    /// This is NOT a cap on the NUMBER of groups, which is uncapped by covenant.
    /// It bounds tree DEPTH only, because the depth is what makes the ancestor
    /// walk on the token-issuance path terminate.
    ///
    /// `max` is the configured bound and `attempted` the depth the write would
    /// have produced. Both are operator-supplied or structural numbers, never
    /// tenant data. `attempted` may report a SATURATED value when the walk hit its
    /// bound (the walk observes one level past the bound and stops), which is
    /// deliberate: it is a floor on how deep the result would have been, and the
    /// refusal is correct either way.
    ///
    /// [`NotFound`]: StoreError::NotFound
    /// [`OrgGroupCycle`]: StoreError::OrgGroupCycle
    OrgGroupDepthExceeded {
        /// The configured maximum nesting depth, in edges from a root.
        max: u32,
        /// A FLOOR on the depth the refused write would have produced, equal to it
        /// unless a walk saturated (see the variant doc). Never an exact value to be
        /// arithmetic on.
        attempted: i64,
    },
    /// A submitted per-organization authentication policy DOCUMENT is malformed or
    /// self-contradictory (issue #95): an unknown factor token, an explicitly empty
    /// allowlist, a session lifetime above the deployment ceiling, an idle window
    /// longer than the absolute one, an unregistrable email domain, or the one that
    /// matters most, a document requiring MFA whose factor list permits no method
    /// able to carry a genuine second factor. NOTHING is written: the pure validator
    /// runs inside the audited write transaction, so returning this rolls the
    /// attempted mutation and its audit row back together.
    ///
    /// Deliberately distinct from [`NotFound`]: the caller submitted a well-formed
    /// request naming an organization they can see, and the DOCUMENT is what is
    /// wrong, so telling them which dimension is wrong is the whole point. It is
    /// distinct from [`Conflict`] too, because nothing collided; this is a
    /// structural refusal of a value.
    ///
    /// NOT an existence oracle. The organization is resolved as a LIVE, in-scope row
    /// BEFORE any document reasoning runs, so a caller who sees this has already
    /// proven they can see the organization. An absent, soft-deleted, foreign-scope,
    /// or foreign-tenant organization is refused earlier and uniformly as
    /// [`NotFound`].
    ///
    /// The carried errors are VALUE FREE by construction: each names a DIMENSION and
    /// never the offending value, so nothing here can report anything the caller did
    /// not already send. The list is sorted and deduplicated, so the rendered form is
    /// a deterministic function of the submitted document.
    ///
    /// This refusal is INTRA-DOCUMENT ONLY and deliberately does not claim more: a
    /// contradiction that arises only from the intersection ACROSS levels is not
    /// decidable at any single write and is carried instead on the resolved policy
    /// (`org_policy::Satisfiability`), where it fails closed at authentication.
    ///
    /// [`NotFound`]: StoreError::NotFound
    /// [`Conflict`]: StoreError::Conflict
    OrgAuthPolicyInvalid(Vec<crate::org_policy::AuthPolicyError>),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::NotFound => f.write_str("resource not found"),
            StoreError::Database(_) => f.write_str("database error"),
            StoreError::Migration(_) => f.write_str("migration error"),
            StoreError::IdempotencyConflict => f.write_str("idempotency-key conflict"),
            StoreError::Conflict => f.write_str("uniqueness conflict"),
            StoreError::InvalidRedirectUri => f.write_str("invalid redirect uri"),
            StoreError::GuardrailViolation(violation) => {
                write!(f, "guardrail violation: {violation}")
            }
            StoreError::QuotaExceeded => f.write_str("registration quota exceeded"),
            StoreError::Encryption => f.write_str("envelope decryption failed"),
            StoreError::InvalidOrgContext => f.write_str("invalid organization context"),
            StoreError::InvalidCustomDomain => f.write_str("invalid custom domain"),
            StoreError::InvalidName => f.write_str("invalid secret or variable name"),
            StoreError::InvalidIdentifier => f.write_str("invalid login identifier"),
            StoreError::SchemaMalformed(error) => write!(f, "malformed trait schema: {error}"),
            StoreError::TraitsInvalid(failures) => {
                write!(f, "traits failed validation ({} failures)", failures.len())
            }
            StoreError::CutoverBlocked { invalid_identities } => write!(
                f,
                "activation blocked: {invalid_identities} identities fail the target schema"
            ),
            StoreError::NoActiveTraitSchema => f.write_str("no active trait schema"),
            StoreError::IllegalMigrationTransition { from, to } => {
                write!(f, "illegal migration-run transition from {from} to {to}")
            }
            StoreError::JourneyInvalid(errors) => {
                write!(
                    f,
                    "journey artifact failed validation ({} errors)",
                    errors.len()
                )
            }
            StoreError::OrgGroupCycle => {
                f.write_str("the requested parent would create a cycle in the group hierarchy")
            }
            StoreError::OrgGroupDepthExceeded { max, attempted } => write!(
                f,
                "the requested parent would nest groups at least {attempted} levels deep, \
                 exceeding the configured maximum of {max}"
            ),
            StoreError::OrgAuthPolicyInvalid(errors) => {
                // Every carried error is value free, so naming them all is safe and
                // is what makes the refusal actionable in ONE round trip. The list is
                // already sorted and deduplicated by the validator, so this render is
                // a deterministic function of the submitted document.
                f.write_str("the organization authentication policy is invalid: ")?;
                for (index, error) in errors.iter().enumerate() {
                    if index > 0 {
                        f.write_str("; ")?;
                    }
                    write!(f, "{error}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StoreError::NotFound
            | StoreError::IdempotencyConflict
            | StoreError::Conflict
            | StoreError::InvalidRedirectUri
            | StoreError::GuardrailViolation(_)
            | StoreError::QuotaExceeded
            | StoreError::Encryption
            | StoreError::InvalidOrgContext
            | StoreError::InvalidCustomDomain
            | StoreError::InvalidName
            | StoreError::InvalidIdentifier
            | StoreError::TraitsInvalid(_)
            | StoreError::CutoverBlocked { .. }
            | StoreError::NoActiveTraitSchema
            | StoreError::IllegalMigrationTransition { .. }
            | StoreError::JourneyInvalid(_)
            | StoreError::OrgGroupCycle
            | StoreError::OrgGroupDepthExceeded { .. }
            // The carried refusals are a LIST, so there is no single source to
            // return; every one of them is already rendered by the Display arm.
            | StoreError::OrgAuthPolicyInvalid(_) => None,
            StoreError::Database(source) => Some(source),
            StoreError::Migration(source) => Some(source),
            StoreError::SchemaMalformed(source) => Some(source),
        }
    }
}

impl From<crate::trait_schema::SchemaError> for StoreError {
    fn from(source: crate::trait_schema::SchemaError) -> Self {
        StoreError::SchemaMalformed(source)
    }
}

impl From<MigrationError> for StoreError {
    fn from(source: MigrationError) -> Self {
        StoreError::Migration(source)
    }
}

impl From<sqlx::Error> for StoreError {
    fn from(source: sqlx::Error) -> Self {
        // `RowNotFound` from a scoped query is an in-scope miss: report it as
        // the uniform not-found, not as a database fault.
        match source {
            sqlx::Error::RowNotFound => StoreError::NotFound,
            other => StoreError::Database(other),
        }
    }
}

impl From<NotInScope> for StoreError {
    fn from(_: NotInScope) -> Self {
        StoreError::NotFound
    }
}

impl From<crate::custom_domain::CustomDomainError> for StoreError {
    fn from(source: crate::custom_domain::CustomDomainError) -> Self {
        use crate::custom_domain::CustomDomainError;
        match source {
            // An unsafe or malformed submitted domain: a caller-facing validation
            // failure the registration surface reports.
            CustomDomainError::InvalidDomain => StoreError::InvalidCustomDomain,
            // A stored wire token failed to decode. The schema CHECK constraints
            // make this unreachable for a row the platform wrote; if it ever
            // fires it is an internal invariant break, reported as the uniform
            // not-found rather than becoming an existence oracle.
            CustomDomainError::Decode => StoreError::NotFound,
        }
    }
}

impl From<ironauth_jose::EnvelopeError> for StoreError {
    fn from(_: ironauth_jose::EnvelopeError) -> Self {
        // Collapse the envelope primitive's Format/Decrypt distinction to the one
        // store-facing encryption error: a caller never learns WHY a ciphertext
        // failed to authenticate, only that it did (never an oracle), and the
        // envelope error carries no key material or plaintext to forward.
        StoreError::Encryption
    }
}
