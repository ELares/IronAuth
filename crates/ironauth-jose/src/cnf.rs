// SPDX-License-Identifier: MIT OR Apache-2.0

//! The generalized proof-of-possession confirmation model (RFC 7800).
//!
//! A token can be BOUND to a key its holder must prove possession of, via the
//! `cnf` (confirmation) claim. IronAuth models every binding type through this
//! one type and one pair of functions, so issuance (embed a `cnf` when signing),
//! verification (read the `cnf` off a verified token), and introspection (report
//! the `cnf`) all traverse identical code. Adding a future binding type is a new
//! [`Confirmation`] variant plus two match arms, never a new parsing path.
//!
//! Two binding types ship as the initial members, each exercised in the tests.
//! In both, this model CARRIES a caller-computed base64url thumbprint; it does
//! not compute or canonicalize one:
//!
//! - `jkt`: the caller-computed JWK SHA-256 thumbprint of a `DPoP` proof key
//!   (RFC 9449).
//! - `x5t#S256`: the caller-computed SHA-256 thumbprint of a client certificate
//!   (RFC 8705, mutual-TLS certificate-bound access tokens).
//!
//! This is the shared `cnf` plumbing only. The future `DPoP` and mTLS features
//! own the RFC 7638 JWK thumbprint canonicalization and the certificate
//! thumbprinting; this core does not validate the thumbprint, so it will not
//! catch a malformed one. Those features PRODUCE and CHECK the values here.

use serde_json::{Map, Value};

use crate::claims::VerifiedClaims;

/// The `cnf` claim member name for the confirmation.
const JKT: &str = "jkt";
/// The `cnf` claim member name for the confirmation.
const X5T_S256: &str = "x5t#S256";

/// A proof-of-possession confirmation (the contents of a `cnf` claim).
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Confirmation {
    /// `jkt`: the caller-computed base64url JWK SHA-256 thumbprint of a `DPoP`
    /// proof key (RFC 9449). This model carries the value; it does not compute
    /// the RFC 7638 thumbprint or check that it is well formed.
    Jkt(String),
    /// `x5t#S256`: the caller-computed base64url SHA-256 thumbprint of a client
    /// certificate (RFC 8705). Carried as given; not computed or validated here.
    X5tS256(String),
}

impl Confirmation {
    /// The `cnf` member name this confirmation serializes under.
    #[must_use]
    pub fn member_name(&self) -> &'static str {
        match self {
            Confirmation::Jkt(_) => JKT,
            Confirmation::X5tS256(_) => X5T_S256,
        }
    }

    /// The thumbprint value.
    #[must_use]
    pub fn value(&self) -> &str {
        match self {
            Confirmation::Jkt(v) | Confirmation::X5tS256(v) => v,
        }
    }

    /// The `cnf` object `{ member: value }` for this confirmation.
    ///
    /// The single issuance-side primitive: minting a bound token inserts this
    /// under the `cnf` claim.
    #[must_use]
    pub fn to_cnf_object(&self) -> Map<String, Value> {
        let mut object = Map::new();
        object.insert(
            self.member_name().to_owned(),
            Value::String(self.value().to_owned()),
        );
        object
    }

    /// Insert this confirmation as the `cnf` claim of a claims object.
    ///
    /// The issuance-side convenience over [`Confirmation::to_cnf_object`].
    pub fn embed_in_claims(&self, claims: &mut Map<String, Value>) {
        claims.insert("cnf".to_owned(), Value::Object(self.to_cnf_object()));
    }

    /// Parse a `cnf` object into a confirmation.
    ///
    /// The single verification/introspection-side primitive. Recognizes the
    /// shipped binding members; a `jkt` takes precedence if both are present.
    ///
    /// # Errors
    ///
    /// [`CnfError::NotAnObject`] if `cnf` is not a JSON object,
    /// [`CnfError::MalformedMember`] if a recognized member is not a string, or
    /// [`CnfError::NoRecognizedBinding`] if no shipped binding member is present.
    pub fn from_cnf_object(cnf: &Value) -> Result<Self, CnfError> {
        let object = cnf.as_object().ok_or(CnfError::NotAnObject)?;
        if let Some(value) = object.get(JKT) {
            let thumb = value.as_str().ok_or(CnfError::MalformedMember)?;
            return Ok(Confirmation::Jkt(thumb.to_owned()));
        }
        if let Some(value) = object.get(X5T_S256) {
            let thumb = value.as_str().ok_or(CnfError::MalformedMember)?;
            return Ok(Confirmation::X5tS256(thumb.to_owned()));
        }
        Err(CnfError::NoRecognizedBinding)
    }

    /// Read the confirmation off a verified token's claims, if it carries one.
    ///
    /// The verification-side convenience over [`Confirmation::from_cnf_object`],
    /// reading through the same [`VerifiedClaims`] accessor the rest of the crate
    /// uses, so a bound token's `cnf` is recovered by exactly this path.
    ///
    /// # Errors
    ///
    /// [`CnfError`] as for [`Confirmation::from_cnf_object`], when a `cnf` claim
    /// is present but malformed.
    pub fn from_claims(claims: &VerifiedClaims) -> Result<Option<Self>, CnfError> {
        match claims.get("cnf") {
            None | Some(Value::Null) => Ok(None),
            Some(cnf) => Self::from_cnf_object(cnf).map(Some),
        }
    }
}

/// A failure parsing a `cnf` confirmation claim.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum CnfError {
    /// The `cnf` claim was not a JSON object.
    NotAnObject,
    /// A recognized `cnf` member was present but not a string thumbprint.
    MalformedMember,
    /// The `cnf` object carried no binding member this core recognizes.
    NoRecognizedBinding,
}

impl std::fmt::Display for CnfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CnfError::NotAnObject => "cnf claim is not a JSON object",
            CnfError::MalformedMember => "cnf binding member is not a string thumbprint",
            CnfError::NoRecognizedBinding => "cnf claim carries no recognized binding member",
        })
    }
}

impl std::error::Error for CnfError {}

#[cfg(test)]
mod tests {
    use super::{CnfError, Confirmation};
    use serde_json::{Value, json};

    #[test]
    fn both_binding_members_round_trip_through_one_path() {
        for confirmation in [
            Confirmation::Jkt("thumb-a".to_owned()),
            Confirmation::X5tS256("thumb-b".to_owned()),
        ] {
            let object = Value::Object(confirmation.to_cnf_object());
            assert_eq!(
                Confirmation::from_cnf_object(&object).expect("parses"),
                confirmation
            );
        }
    }

    #[test]
    fn jkt_takes_precedence_when_both_members_are_present() {
        let cnf = json!({ "jkt": "j", "x5t#S256": "x" });
        assert_eq!(
            Confirmation::from_cnf_object(&cnf).expect("parses"),
            Confirmation::Jkt("j".to_owned())
        );
    }

    #[test]
    fn malformed_cnf_shapes_are_distinct_errors() {
        assert_eq!(
            Confirmation::from_cnf_object(&json!("not-an-object")).unwrap_err(),
            CnfError::NotAnObject
        );
        assert_eq!(
            Confirmation::from_cnf_object(&json!({ "jkt": 5 })).unwrap_err(),
            CnfError::MalformedMember
        );
        assert_eq!(
            Confirmation::from_cnf_object(&json!({ "unknown": "v" })).unwrap_err(),
            CnfError::NoRecognizedBinding
        );
    }
}
