// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `claims` request parameter (OIDC Core 5.5 and 5.5.1.1).
//!
//! An RP can ask for individual claims at the authorization request through a
//! JSON `claims` parameter with two members, `userinfo` and `id_token`, each a map
//! of claim name to a request rule:
//!
//! ```json
//! {
//!   "userinfo": { "email": { "essential": true }, "name": null },
//!   "id_token": { "acr": { "essential": true, "values": ["l2", "l3"] } }
//! }
//! ```
//!
//! A `null` rule is a plain (voluntary) request for the claim. An object rule may
//! carry `essential` (default `false`), a single `value`, or a set of `values`.
//! The `userinfo` member steers what `UserInfo` returns; the `id_token` member steers
//! what the ID token carries. The parameter is parsed and validated at the
//! authorization endpoint, persisted with the grant, and applied later at both
//! placements, so a request survives from authorization to the eventual `UserInfo`
//! call.
//!
//! # The one binding rule: essential `acr`
//!
//! Almost every claim request is best-effort: an unmet voluntary OR essential
//! claim is simply omitted, never an error (Core 5.5.1). The single exception is
//! `acr`. An essential `acr` with `value`/`values` is a binding authentication
//! requirement: if the achieved authentication context is not among the requested
//! values, the request MUST NOT be silently downgraded to a lower level. This
//! module exposes the pinned values of such a binding ([`ClaimsRequest::essential_acr_values`]);
//! the authorization endpoint owns the decision (issue #16), returning
//! `unmet_authentication_requirements` when no method can satisfy the binding and
//! failing closed via `access_denied` for the residual step-up case.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

/// One requested claim's rule (OIDC Core 5.5.1). A `null` rule in the request
/// deserializes to the default (voluntary, no value filter).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaimSpec {
    essential: bool,
    value: Option<Value>,
    values: Option<Vec<Value>>,
}

impl ClaimSpec {
    /// A plain voluntary request (the `null` rule, or `{}`).
    #[must_use]
    pub fn voluntary() -> Self {
        Self::default()
    }

    /// An essential request with no value filter. A test constructor: production
    /// specs are parsed from the wire, never hand built.
    #[cfg(test)]
    #[must_use]
    pub fn essential() -> Self {
        Self {
            essential: true,
            value: None,
            values: None,
        }
    }

    /// A voluntary request pinned to a single `value`. A test constructor.
    #[cfg(test)]
    #[must_use]
    pub fn with_value(value: Value) -> Self {
        Self {
            essential: false,
            value: Some(value),
            values: None,
        }
    }

    /// A voluntary request pinned to a set of acceptable `values`. A test
    /// constructor.
    #[cfg(test)]
    #[must_use]
    pub fn with_values(values: Vec<Value>) -> Self {
        Self {
            essential: false,
            value: None,
            values: Some(values),
        }
    }

    /// Whether the request marked this claim essential.
    #[must_use]
    pub fn is_essential(&self) -> bool {
        self.essential
    }

    /// Whether the request pins a `value` or `values` filter on the claim.
    #[must_use]
    pub fn has_value_filter(&self) -> bool {
        self.value.is_some() || self.values.is_some()
    }

    /// Whether `candidate` satisfies this request's value filter. With no filter,
    /// any value matches; with a single `value`, the candidate must equal it; with
    /// `values`, the candidate must be one of them. When both are present (unusual),
    /// either satisfying is a match.
    #[must_use]
    pub fn value_matches(&self, candidate: &Value) -> bool {
        let single_ok = self.value.as_ref().is_none_or(|v| v == candidate);
        let set_ok = self
            .values
            .as_ref()
            .is_none_or(|vs| vs.iter().any(|v| v == candidate));
        // No filter at all: both are None, both clauses are true.
        match (&self.value, &self.values) {
            (None, None) => true,
            (Some(_), None) => single_ok,
            (None, Some(_)) => set_ok,
            (Some(_), Some(_)) => single_ok || set_ok,
        }
    }

    /// The acceptable string values this request pins (from `value` and `values`),
    /// used for the essential-`acr` binding check.
    fn accepted_string_values(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(Value::String(s)) = &self.value {
            out.push(s.clone());
        }
        if let Some(values) = &self.values {
            for v in values {
                if let Value::String(s) = v {
                    out.push(s.clone());
                }
            }
        }
        out
    }

    /// Parse one claim rule value: `null` or `{}` is voluntary; an object may carry
    /// `essential`, `value`, and `values` (unknown members ignored, per Core 5.5).
    fn parse(value: &Value) -> Result<Self, ClaimsRequestError> {
        match value {
            Value::Null => Ok(Self::voluntary()),
            Value::Object(object) => {
                let essential = match object.get("essential") {
                    None | Some(Value::Null) => false,
                    Some(Value::Bool(b)) => *b,
                    Some(_) => return Err(ClaimsRequestError::MalformedRule),
                };
                let value = match object.get("value") {
                    None | Some(Value::Null) => None,
                    Some(other) => Some(other.clone()),
                };
                let values = match object.get("values") {
                    None | Some(Value::Null) => None,
                    Some(Value::Array(array)) => Some(array.clone()),
                    Some(_) => return Err(ClaimsRequestError::MalformedRule),
                };
                Ok(Self {
                    essential,
                    value,
                    values,
                })
            }
            _ => Err(ClaimsRequestError::MalformedRule),
        }
    }

    /// Re-serialize this rule to its canonical JSON form (only understood members,
    /// and only when they carry information), so the persisted request is bounded
    /// and junk-free. A fully-default voluntary rule serializes to `null`.
    fn to_json(&self) -> Value {
        let mut object = Map::new();
        if self.essential {
            object.insert("essential".to_owned(), Value::Bool(true));
        }
        if let Some(value) = &self.value {
            object.insert("value".to_owned(), value.clone());
        }
        if let Some(values) = &self.values {
            object.insert("values".to_owned(), Value::Array(values.clone()));
        }
        if object.is_empty() {
            Value::Null
        } else {
            Value::Object(object)
        }
    }
}

/// A parsed `claims` request parameter: the `userinfo` and `id_token` members.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaimsRequest {
    userinfo: BTreeMap<String, ClaimSpec>,
    id_token: BTreeMap<String, ClaimSpec>,
}

impl ClaimsRequest {
    /// The `userinfo` member: the claims requested at the `UserInfo` endpoint.
    #[must_use]
    pub fn userinfo(&self) -> &BTreeMap<String, ClaimSpec> {
        &self.userinfo
    }

    /// The `id_token` member: the claims requested in the ID token.
    #[must_use]
    pub fn id_token(&self) -> &BTreeMap<String, ClaimSpec> {
        &self.id_token
    }

    /// Whether the request carries no claims at all (empty on both members).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.userinfo.is_empty() && self.id_token.is_empty()
    }

    /// Parse a `claims` request-parameter JSON string (OIDC Core 5.5). Unknown
    /// top-level members are ignored; a `userinfo`/`id_token` member must be a JSON
    /// object of claim rules.
    ///
    /// # Errors
    ///
    /// [`ClaimsRequestError::MalformedJson`] if the value is not valid JSON;
    /// [`ClaimsRequestError::NotAnObject`] if the top level or a member is not a
    /// JSON object; [`ClaimsRequestError::MalformedRule`] if a claim rule is not
    /// `null` or an object, or carries a wrong-typed `essential`/`values`.
    pub fn parse(input: &str) -> Result<Self, ClaimsRequestError> {
        let value: Value =
            serde_json::from_str(input).map_err(|_| ClaimsRequestError::MalformedJson)?;
        let Value::Object(top) = value else {
            return Err(ClaimsRequestError::NotAnObject);
        };
        Ok(Self {
            userinfo: parse_member(top.get("userinfo"))?,
            id_token: parse_member(top.get("id_token"))?,
        })
    }

    /// Re-serialize to a canonical, bounded JSON string carrying only the
    /// understood members, for persistence with the grant. Empty members are
    /// omitted; a fully-empty request serializes to `{}`.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut top = Map::new();
        if !self.userinfo.is_empty() {
            top.insert("userinfo".to_owned(), member_to_json(&self.userinfo));
        }
        if !self.id_token.is_empty() {
            top.insert("id_token".to_owned(), member_to_json(&self.id_token));
        }
        Value::Object(top).to_string()
    }

    /// The acceptable `acr` values an ESSENTIAL `acr` request in the ID token member
    /// pins (OIDC Core 5.5.1.1), used by the authorization endpoint to decide the
    /// `unmet_authentication_requirements` surface (issue #16). Empty when there is
    /// no essential `acr` request, or the essential `acr` pins no string values (a
    /// level-report request, not a specific-level binding). A non-empty result is a
    /// binding requirement: the request must be met by one of these values.
    ///
    /// The binding decision (whether the achieved level satisfies these values, and
    /// whether ANY method can, which distinguishes `access_denied` from
    /// `unmet_authentication_requirements`) lives at the authorization endpoint,
    /// which knows the achievable set (issue #16).
    #[must_use]
    pub fn essential_acr_values(&self) -> Vec<String> {
        match self.id_token.get("acr") {
            Some(spec) if spec.is_essential() => spec.accepted_string_values(),
            _ => Vec::new(),
        }
    }
}

/// Parse one top-level member (`userinfo` or `id_token`) into its claim rules.
/// An absent or null member is empty; anything other than an object is malformed.
fn parse_member(value: Option<&Value>) -> Result<BTreeMap<String, ClaimSpec>, ClaimsRequestError> {
    match value {
        None | Some(Value::Null) => Ok(BTreeMap::new()),
        Some(Value::Object(object)) => {
            let mut out = BTreeMap::new();
            for (name, rule) in object {
                out.insert(name.clone(), ClaimSpec::parse(rule)?);
            }
            Ok(out)
        }
        Some(_) => Err(ClaimsRequestError::NotAnObject),
    }
}

/// Serialize one member's rules to a canonical JSON object.
fn member_to_json(member: &BTreeMap<String, ClaimSpec>) -> Value {
    let mut object = Map::new();
    for (name, spec) in member {
        object.insert(name.clone(), spec.to_json());
    }
    Value::Object(object)
}

/// Why a `claims` request parameter was rejected. All are request malformations
/// the authorization endpoint maps to `invalid_request`; none carries a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimsRequestError {
    /// The parameter was not valid JSON.
    MalformedJson,
    /// The top level, or a `userinfo`/`id_token` member, was not a JSON object.
    NotAnObject,
    /// A claim rule was neither `null` nor an object, or carried a wrong-typed
    /// `essential` or `values`.
    MalformedRule,
}

impl ClaimsRequestError {
    /// A short, non-secret description for the `error_description`.
    #[must_use]
    pub fn as_description(self) -> &'static str {
        match self {
            ClaimsRequestError::MalformedJson => "the claims parameter is not valid JSON",
            ClaimsRequestError::NotAnObject => {
                "the claims parameter and its members must be JSON objects"
            }
            ClaimsRequestError::MalformedRule => "a claims request rule is malformed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn null_rule_is_voluntary() {
        let req = ClaimsRequest::parse(r#"{"userinfo":{"email":null}}"#).expect("parse");
        assert_eq!(req.userinfo().get("email"), Some(&ClaimSpec::voluntary()));
        assert!(req.id_token().is_empty());
    }

    #[test]
    fn essential_value_and_values_parse_on_both_members() {
        let input = r#"{
            "userinfo": { "email": { "essential": true }, "name": null },
            "id_token": { "acr": { "essential": true, "values": ["l2", "l3"] },
                          "sub": { "value": "abc" } }
        }"#;
        let req = ClaimsRequest::parse(input).expect("parse");
        assert!(req.userinfo().get("email").expect("email").is_essential());
        assert_eq!(req.userinfo().get("name"), Some(&ClaimSpec::voluntary()));
        let acr = req.id_token().get("acr").expect("acr");
        assert!(acr.is_essential());
        assert!(acr.value_matches(&json!("l2")));
        assert!(!acr.value_matches(&json!("l1")));
        assert!(
            req.id_token()
                .get("sub")
                .expect("sub")
                .value_matches(&json!("abc"))
        );
    }

    #[test]
    fn malformed_inputs_are_classified() {
        assert_eq!(
            ClaimsRequest::parse("not json"),
            Err(ClaimsRequestError::MalformedJson)
        );
        assert_eq!(
            ClaimsRequest::parse("[]"),
            Err(ClaimsRequestError::NotAnObject)
        );
        assert_eq!(
            ClaimsRequest::parse(r#"{"userinfo":[]}"#),
            Err(ClaimsRequestError::NotAnObject)
        );
        assert_eq!(
            ClaimsRequest::parse(r#"{"userinfo":{"email":{"essential":"yes"}}}"#),
            Err(ClaimsRequestError::MalformedRule)
        );
        assert_eq!(
            ClaimsRequest::parse(r#"{"userinfo":{"email":{"values":"l1"}}}"#),
            Err(ClaimsRequestError::MalformedRule)
        );
    }

    #[test]
    fn unknown_top_level_members_are_ignored() {
        let req = ClaimsRequest::parse(r#"{"userinfo":{"email":null},"extra":42}"#).expect("parse");
        assert!(req.userinfo().contains_key("email"));
    }

    #[test]
    fn round_trips_through_canonical_json() {
        let input = r#"{
            "userinfo": { "email": { "essential": true } },
            "id_token": { "acr": { "essential": true, "values": ["l2"] } }
        }"#;
        let req = ClaimsRequest::parse(input).expect("parse");
        let reparsed = ClaimsRequest::parse(&req.to_json()).expect("reparse canonical");
        assert_eq!(req, reparsed, "canonical form round-trips");
    }

    #[test]
    fn essential_acr_values_exposes_only_a_binding_requirement() {
        // An essential acr with pinned values is a binding requirement.
        let binding =
            ClaimsRequest::parse(r#"{"id_token":{"acr":{"essential":true,"values":["l2","l3"]}}}"#)
                .expect("parse");
        assert_eq!(
            binding.essential_acr_values(),
            vec!["l2".to_owned(), "l3".to_owned()]
        );

        // A voluntary acr, an essential acr with no pinned value, and an absent acr
        // are all NOT binding, so they expose no values.
        for not_binding in [
            r#"{"id_token":{"acr":{"values":["l2"]}}}"#,
            r#"{"id_token":{"acr":{"essential":true}}}"#,
            r#"{"userinfo":{"email":null}}"#,
        ] {
            assert!(
                ClaimsRequest::parse(not_binding)
                    .expect("parse")
                    .essential_acr_values()
                    .is_empty(),
                "{not_binding} is not a binding acr requirement"
            );
        }
    }
}
