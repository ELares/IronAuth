// SPDX-License-Identifier: MIT OR Apache-2.0

//! Environment secret and variable REFERENCES and their resolution (issue #45).
//!
//! A promotable config field may carry a NAMED REFERENCE to an environment-scoped
//! secret or variable instead of a literal value. One canonical config snapshot
//! (issue #43) then applies to every environment, with the reference resolved
//! against the TARGET environment's store at apply time, so promoting dev to prod
//! uses prod's value, never dev's. This module owns two things:
//!
//! - the reference SYNTAX and its parser ([`Reference::parse`]), a pure function
//!   that fails CLOSED on anything malformed (an importer must never guess at a
//!   half-formed reference); and
//! - RESOLUTION against a bound scope: [`reference_resolves`] is the plan-time
//!   existence check (issue #45: the plan step validates that every reference
//!   resolves in the target environment, and an unresolved reference fails the
//!   plan, never the apply), and [`resolve_value`] is the apply-time value
//!   injection (a variable's plaintext value, or a secret's value opened from its
//!   envelope ciphertext under the platform master key).
//!
//! The reference syntax is `${var:NAME}` for a variable and `${secret:NAME}` for
//! a secret, where `NAME` is a [`name_is_valid`] key. A field VALUE is a reference
//! only when the whole value is one reference token; a literal value that merely
//! contains the sequence is not treated as a reference (references are declared,
//! not pattern-matched, so a literal `${var:x}` display string cannot accidentally
//! resolve). The resolution reader is scope-bound, so it can only ever read the
//! bound environment's own secrets and variables (row-level security confines it),
//! which is exactly the "resolution reads the right env's value" property.

use ironauth_jose::MasterKey;

use crate::error::StoreError;
use crate::repository::ScopedStore;

/// The maximum length of a reference NAME (a secret or variable key). Bounds the
/// key space so a name is always a compact, indexable token.
pub const MAX_NAME_LEN: usize = 128;

/// The literal opening the reference syntax (`${`).
const OPEN: &str = "${";
/// The literal closing the reference syntax (`}`).
const CLOSE: &str = "}";
/// The `var:` selector introducing a variable reference.
const VAR_SELECTOR: &str = "var:";
/// The `secret:` selector introducing a secret reference.
const SECRET_SELECTOR: &str = "secret:";

/// Whether `name` is a valid reference key (a secret or variable name): a
/// non-empty, at-most-[`MAX_NAME_LEN`] run of ASCII letters, digits, `_`, `.`, or
/// `-`. The alphabet is deliberately narrow so a name is unambiguous inside the
/// `${...}` syntax and safe as a stable key; it is the SAME rule the store applies
/// on write, so a stored name is always a resolvable reference key.
#[must_use]
pub fn name_is_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
}

/// The kind of resource a [`Reference`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReferenceKind {
    /// A non-secret environment variable (`${var:NAME}`).
    Variable,
    /// An environment secret (`${secret:NAME}`).
    Secret,
}

impl ReferenceKind {
    /// The stable wire selector (`var` or `secret`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ReferenceKind::Variable => "var",
            ReferenceKind::Secret => "secret",
        }
    }
}

/// A parsed reference: the kind of resource and the name it points at.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Reference {
    /// Whether this names a variable or a secret.
    pub kind: ReferenceKind,
    /// The referenced resource's name (a [`name_is_valid`] key).
    pub name: String,
}

impl Reference {
    /// Parse a config field value as a whole reference token (issue #45).
    ///
    /// Fails CLOSED: any value that is not exactly `${var:NAME}` or
    /// `${secret:NAME}` with a valid `NAME` returns a [`ReferenceError`], never a
    /// partial or guessed result. A plain literal value (one that is not a
    /// reference at all) returns [`ReferenceError::NotAReference`], which a caller
    /// distinguishes from a MALFORMED reference to decide whether the field is a
    /// literal or a broken reference.
    ///
    /// # Errors
    ///
    /// [`ReferenceError`] describing why `raw` is not a valid reference.
    pub fn parse(raw: &str) -> Result<Self, ReferenceError> {
        let Some(inner) = raw.strip_prefix(OPEN) else {
            return Err(ReferenceError::NotAReference);
        };
        let Some(inner) = inner.strip_suffix(CLOSE) else {
            // It opened `${` but never closed: a malformed reference, not a literal.
            return Err(ReferenceError::Malformed);
        };
        let (kind, name) = if let Some(name) = inner.strip_prefix(VAR_SELECTOR) {
            (ReferenceKind::Variable, name)
        } else if let Some(name) = inner.strip_prefix(SECRET_SELECTOR) {
            (ReferenceKind::Secret, name)
        } else {
            return Err(ReferenceError::UnknownKind);
        };
        if !name_is_valid(name) {
            return Err(ReferenceError::InvalidName);
        }
        Ok(Self {
            kind,
            name: name.to_string(),
        })
    }

    /// Whether `raw` is a reference token at all (well formed or not): it opens
    /// with the reference syntax. A literal value returns false. Used by the
    /// referent check to decide whether a stored field is a reference before
    /// parsing it strictly.
    #[must_use]
    pub fn looks_like_reference(raw: &str) -> bool {
        raw.starts_with(OPEN)
    }

    /// Render this reference back to its canonical `${kind:name}` token (the form
    /// a snapshot stores and a config field carries).
    #[must_use]
    pub fn render(&self) -> String {
        format!("{OPEN}{}:{}{CLOSE}", self.kind.as_str(), self.name)
    }
}

/// Why a value is not a valid reference (issue #45). The parser fails closed with
/// one of these rather than ever returning a partial reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceError {
    /// The value is a plain literal, not a reference (it does not open `${`). A
    /// caller treats the field as a literal value.
    NotAReference,
    /// The value opened the reference syntax but is otherwise broken (for example
    /// it never closed with `}`).
    Malformed,
    /// The value is a reference token but names an unknown kind (not `var:` or
    /// `secret:`).
    UnknownKind,
    /// The value is a reference of a known kind but carries an invalid name.
    InvalidName,
}

impl core::fmt::Display for ReferenceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            ReferenceError::NotAReference => "value is a literal, not a reference",
            ReferenceError::Malformed => "malformed reference (unterminated ${...})",
            ReferenceError::UnknownKind => {
                "reference names an unknown kind (expected var or secret)"
            }
            ReferenceError::InvalidName => "reference names an invalid key",
        };
        f.write_str(message)
    }
}

impl std::error::Error for ReferenceError {}

/// A resolved reference value (issue #45): the concrete value injected at apply
/// time. A variable resolves to its plaintext string; a secret resolves to its
/// value opened from envelope ciphertext (bytes, never rendered into a snapshot,
/// a plan, a diff, or a log).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// A variable's non-secret string value.
    Variable(String),
    /// A secret's opened value (raw bytes; a secret value is never a UTF-8-forced
    /// string here so a binary secret round-trips exactly).
    Secret(Vec<u8>),
}

/// Why a reference could not be resolved to a value (issue #45).
#[derive(Debug)]
pub enum ResolveError {
    /// The reference does not resolve in the target environment: no variable or
    /// secret of that name exists in the bound scope. This is the plan-step
    /// failure the promotion engine reports per reference (issue #45); the apply
    /// step is never attempted for an unresolved reference.
    Unresolved(Reference),
    /// A secret reference cannot be opened because no platform master key is wired
    /// on this store handle (the envelope read path fails closed rather than
    /// return ciphertext or plaintext it cannot authenticate).
    MasterKeyMissing,
    /// A persistence or decryption fault while resolving.
    Store(StoreError),
}

impl From<StoreError> for ResolveError {
    fn from(source: StoreError) -> Self {
        ResolveError::Store(source)
    }
}

impl core::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ResolveError::Unresolved(reference) => {
                write!(f, "reference {} does not resolve", reference.render())
            }
            ResolveError::MasterKeyMissing => {
                f.write_str("no platform master key wired to open a secret reference")
            }
            ResolveError::Store(source) => write!(f, "resolution failed: {source}"),
        }
    }
}

impl std::error::Error for ResolveError {}

/// Whether `reference` RESOLVES in `scoped`'s target environment WITHOUT reading
/// or decrypting any secret value (issue #45): the plan-time existence check. A
/// variable resolves when a variable of that name exists in the scope; a secret
/// resolves when a secret of that name exists (its presence is metadata, checked
/// without opening the ciphertext, so a plan never touches a secret value).
///
/// # Errors
///
/// [`StoreError`] on a persistence fault (never a not-found: an absent reference
/// is `Ok(false)`, not an error, so the caller can enumerate every unresolved
/// reference at once rather than aborting on the first).
pub async fn reference_resolves(
    scoped: &ScopedStore<'_>,
    reference: &Reference,
) -> Result<bool, StoreError> {
    match reference.kind {
        ReferenceKind::Variable => scoped.environment_variables().exists(&reference.name).await,
        ReferenceKind::Secret => scoped.environment_secrets().exists(&reference.name).await,
    }
}

/// Resolve `reference` to its concrete value in `scoped`'s target environment
/// (issue #45): the apply-time injection. A variable resolves to its plaintext
/// string; a secret resolves to its value opened from envelope ciphertext under
/// `master`. Reads only the bound scope, so it can never resolve a reference
/// against another environment's value.
///
/// # Errors
///
/// [`ResolveError::Unresolved`] if no such variable or secret exists in the
/// scope; [`ResolveError::MasterKeyMissing`] if a secret reference is asked for
/// but no master key is wired; [`ResolveError::Store`] on a persistence or
/// decryption fault.
pub async fn resolve_value(
    scoped: &ScopedStore<'_>,
    master: Option<&MasterKey>,
    reference: &Reference,
) -> Result<Resolved, ResolveError> {
    match reference.kind {
        ReferenceKind::Variable => {
            match scoped.environment_variables().get(&reference.name).await {
                Ok(record) => Ok(Resolved::Variable(record.value)),
                Err(StoreError::NotFound) => Err(ResolveError::Unresolved(reference.clone())),
                Err(other) => Err(ResolveError::Store(other)),
            }
        }
        ReferenceKind::Secret => {
            let master = master.ok_or(ResolveError::MasterKeyMissing)?;
            match scoped
                .environment_secrets()
                .open_value(master, &reference.name)
                .await
            {
                Ok(value) => Ok(Resolved::Secret(value)),
                Err(StoreError::NotFound) => Err(ResolveError::Unresolved(reference.clone())),
                Err(other) => Err(ResolveError::Store(other)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_NAME_LEN, Reference, ReferenceError, ReferenceKind, name_is_valid};

    #[test]
    fn parses_variable_and_secret_references() {
        let variable = Reference::parse("${var:api-base-url}").expect("variable reference");
        assert_eq!(variable.kind, ReferenceKind::Variable);
        assert_eq!(variable.name, "api-base-url");

        let secret = Reference::parse("${secret:connector_key}").expect("secret reference");
        assert_eq!(secret.kind, ReferenceKind::Secret);
        assert_eq!(secret.name, "connector_key");
    }

    #[test]
    fn round_trips_through_render() {
        for raw in ["${var:endpoint}", "${secret:webhook.signing.key}"] {
            let parsed = Reference::parse(raw).expect("parse");
            assert_eq!(parsed.render(), raw, "render round-trips {raw}");
        }
    }

    #[test]
    fn malformed_references_fail_closed() {
        // A plain literal is NOT a reference (distinct from a malformed one).
        assert_eq!(
            Reference::parse("https://example.test").unwrap_err(),
            ReferenceError::NotAReference
        );
        // Opened but never closed: malformed, not a literal.
        assert_eq!(
            Reference::parse("${var:x").unwrap_err(),
            ReferenceError::Malformed
        );
        // A closed token of an unknown kind.
        assert_eq!(
            Reference::parse("${config:x}").unwrap_err(),
            ReferenceError::UnknownKind
        );
        // A known kind with an empty or illegal name.
        assert_eq!(
            Reference::parse("${var:}").unwrap_err(),
            ReferenceError::InvalidName
        );
        assert_eq!(
            Reference::parse("${secret:has space}").unwrap_err(),
            ReferenceError::InvalidName
        );
        assert_eq!(
            Reference::parse("${var:has/slash}").unwrap_err(),
            ReferenceError::InvalidName
        );
    }

    #[test]
    fn name_alphabet_is_narrow_and_bounded() {
        assert!(name_is_valid("db-password"));
        assert!(name_is_valid("Feature_Toggle.v2"));
        assert!(!name_is_valid(""));
        assert!(!name_is_valid("has space"));
        assert!(!name_is_valid("emoji\u{1F600}"));
        assert!(name_is_valid(&"a".repeat(MAX_NAME_LEN)));
        assert!(!name_is_valid(&"a".repeat(MAX_NAME_LEN + 1)));
    }

    #[test]
    fn looks_like_reference_distinguishes_literals() {
        assert!(Reference::looks_like_reference("${var:x}"));
        assert!(Reference::looks_like_reference("${broken"));
        assert!(!Reference::looks_like_reference("a literal value"));
    }
}
