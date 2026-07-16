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
            | StoreError::InvalidCustomDomain
            | StoreError::InvalidName
            | StoreError::InvalidIdentifier
            | StoreError::TraitsInvalid(_)
            | StoreError::CutoverBlocked { .. }
            | StoreError::NoActiveTraitSchema
            | StoreError::IllegalMigrationTransition { .. } => None,
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
