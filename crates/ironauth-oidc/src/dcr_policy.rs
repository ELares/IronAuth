// SPDX-License-Identifier: MIT OR Apache-2.0

//! The DCR registration-policy engine (issue #31).
//!
//! A policy is a named, reusable object composed of an ORDERED list of primitives
//! over registration-metadata properties. A policy CHAIN is that ordered list,
//! flattened from one or more policies attached to an initial access token. Applying
//! a chain to a submitted RFC 7591 metadata document either TRANSFORMS it (forcing
//! values, filling defaults) or REJECTS it (a restricted value out of its allowed
//! set, or a rejected property present).
//!
//! # Primitives
//!
//! Each primitive is a typed variant serialized to a small JSON object (the form
//! stored in the `dcr_policies.primitives` column and snapshotted onto the initial
//! access token and the client):
//!
//! - [`PolicyPrimitive::Force`] sets a property to a fixed value, OVERRIDING whatever
//!   the client submitted (for example forcing `token_endpoint_auth_method` to
//!   `private_key_jwt`).
//! - [`PolicyPrimitive::Restrict`] constrains a property to an allowed value set (for
//!   example allowed `id_token_signed_response_alg` values or `grant_types`); a
//!   present value outside the set is a rejection. An array-valued property must have
//!   EVERY element in the set.
//! - [`PolicyPrimitive::Reject`] refuses a property outright when it is present (for
//!   example forbidding a self-hosted `jwks_uri`).
//! - [`PolicyPrimitive::Default`] fills a property with a value only when the client
//!   OMITTED it, leaving a submitted value untouched.
//!
//! # Ordering
//!
//! Primitives apply strictly in list order, each transforming or validating the
//! running metadata map, so an operator composes deterministic behavior (for example
//! a `Default` that fills a value followed by a `Restrict` that validates it). The
//! engine is pure and synchronous, with no store or clock dependency, so it is
//! unit-testable in isolation.
//!
//! # Opaque on the wire, actionable out of band (AC5)
//!
//! A [`PolicyRejection`] carries the offending property and a bounded reason so the
//! caller can log an actionable diagnostic OUT OF BAND (a `dcr.policy_rejected` audit
//! event plus a structured log line). The wire response stays a generic
//! `invalid_client_metadata` with no policy detail, so the endpoint never becomes an
//! oracle for the operator's policy.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// One policy primitive over a named registration-metadata property.
///
/// Serialized with a `kind` tag, so the stored JSON is self-describing, for example
/// `{"kind":"force","property":"token_endpoint_auth_method","value":"private_key_jwt"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyPrimitive {
    /// Force `property` to `value`, overriding any submitted value.
    Force {
        /// The metadata property to set.
        property: String,
        /// The value to set it to.
        value: Value,
    },
    /// Restrict `property` to the `allowed` value set. A present scalar value must be
    /// in the set; a present array value must have every element in the set.
    Restrict {
        /// The metadata property to constrain.
        property: String,
        /// The permitted values.
        allowed: Vec<Value>,
    },
    /// Reject `property` outright when it is present (and non-null).
    Reject {
        /// The metadata property to forbid.
        property: String,
    },
    /// Default `property` to `value` only when the client omitted it.
    Default {
        /// The metadata property to fill.
        property: String,
        /// The value to fill it with.
        value: Value,
    },
}

/// A bounded reason a policy rejected a submitted metadata document. Carries no
/// attacker-controlled free text, so it is safe as a metric-like dimension and never
/// an oracle on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyRejectReason {
    /// A [`PolicyPrimitive::Reject`] property was present.
    PropertyRejected,
    /// A [`PolicyPrimitive::Restrict`] property held a value outside its allowed set.
    ValueNotAllowed,
}

impl PolicyRejectReason {
    /// A short, stable label for the out-of-band diagnostic.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            PolicyRejectReason::PropertyRejected => "property_rejected",
            PolicyRejectReason::ValueNotAllowed => "value_not_allowed",
        }
    }
}

/// A policy rejection: the offending property and the bounded reason, for the
/// out-of-band diagnostic. The wire stays a generic `invalid_client_metadata`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRejection {
    /// The metadata property that failed the policy.
    pub property: String,
    /// The bounded reason.
    pub reason: PolicyRejectReason,
}

impl PolicyRejection {
    /// A one-line actionable diagnostic for a structured log line (out of band).
    #[must_use]
    pub fn diagnostic(&self) -> String {
        format!(
            "registration metadata rejected by policy: property `{}` ({})",
            self.property,
            self.reason.as_str()
        )
    }
}

/// Parse a stored policy-chain JSON snapshot (a JSON array of primitives) into the
/// primitive list. An empty or `"[]"` snapshot yields an empty chain (unconstrained).
///
/// # Errors
///
/// [`serde_json::Error`] if the text is not a JSON array of well-formed primitives.
pub fn parse_chain(json: &str) -> Result<Vec<PolicyPrimitive>, serde_json::Error> {
    let trimmed = json.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(trimmed)
}

/// Serialize a primitive list to its JSON-array snapshot form (the text stored in a
/// policy row and snapshotted onto an initial access token and a client).
///
/// # Errors
///
/// [`serde_json::Error`] if serialization fails (never in practice for these types).
pub fn serialize_chain(chain: &[PolicyPrimitive]) -> Result<String, serde_json::Error> {
    serde_json::to_string(chain)
}

/// Apply a policy chain to a submitted metadata document in place, in list order.
///
/// On success `metadata` has been transformed (forced values set, defaults filled)
/// and every restriction and rejection satisfied. On failure it returns the first
/// [`PolicyRejection`], leaving `metadata` partially transformed (the caller
/// discards it and returns the opaque wire error).
///
/// # Errors
///
/// [`PolicyRejection`] on the first restricted-value or rejected-property violation.
pub fn apply_chain(
    chain: &[PolicyPrimitive],
    metadata: &mut Map<String, Value>,
) -> Result<(), PolicyRejection> {
    for primitive in chain {
        apply_one(primitive, metadata)?;
    }
    Ok(())
}

/// Apply a single primitive to the running metadata map.
fn apply_one(
    primitive: &PolicyPrimitive,
    metadata: &mut Map<String, Value>,
) -> Result<(), PolicyRejection> {
    match primitive {
        PolicyPrimitive::Force { property, value } => {
            metadata.insert(property.clone(), value.clone());
            Ok(())
        }
        PolicyPrimitive::Default { property, value } => {
            // Fill only when the client omitted the property (a present null counts
            // as omitted, so a client cannot dodge a default by sending null).
            let absent = metadata.get(property).is_none_or(Value::is_null);
            if absent {
                metadata.insert(property.clone(), value.clone());
            }
            Ok(())
        }
        PolicyPrimitive::Reject { property } => {
            let present = metadata.get(property).is_some_and(|value| !value.is_null());
            if present {
                Err(PolicyRejection {
                    property: property.clone(),
                    reason: PolicyRejectReason::PropertyRejected,
                })
            } else {
                Ok(())
            }
        }
        PolicyPrimitive::Restrict { property, allowed } => {
            match metadata.get(property) {
                // An absent (or null) property is unconstrained by Restrict; pair it
                // with a Default or Force to make it mandatory.
                None | Some(Value::Null) => Ok(()),
                Some(Value::Array(values)) => {
                    // Every element of an array-valued property must be allowed.
                    if values.iter().all(|value| allowed.contains(value)) {
                        Ok(())
                    } else {
                        Err(PolicyRejection {
                            property: property.clone(),
                            reason: PolicyRejectReason::ValueNotAllowed,
                        })
                    }
                }
                Some(scalar) => {
                    if allowed.contains(scalar) {
                        Ok(())
                    } else {
                        Err(PolicyRejection {
                            property: property.clone(),
                            reason: PolicyRejectReason::ValueNotAllowed,
                        })
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn meta(value: &Value) -> Map<String, Value> {
        value.as_object().expect("object").clone()
    }

    #[test]
    fn force_overrides_a_submitted_value() {
        let chain = vec![PolicyPrimitive::Force {
            property: "token_endpoint_auth_method".to_owned(),
            value: json!("private_key_jwt"),
        }];
        let mut m = meta(&json!({ "token_endpoint_auth_method": "client_secret_basic" }));
        apply_chain(&chain, &mut m).expect("force applies");
        assert_eq!(m["token_endpoint_auth_method"], json!("private_key_jwt"));
    }

    #[test]
    fn default_fills_only_when_absent_or_null() {
        let chain = vec![PolicyPrimitive::Default {
            property: "application_type".to_owned(),
            value: json!("native"),
        }];
        // Absent: filled.
        let mut absent = meta(&json!({}));
        apply_chain(&chain, &mut absent).expect("default fills absent");
        assert_eq!(absent["application_type"], json!("native"));
        // Null: treated as absent, filled.
        let mut null = meta(&json!({ "application_type": null }));
        apply_chain(&chain, &mut null).expect("default fills null");
        assert_eq!(null["application_type"], json!("native"));
        // Present: left untouched.
        let mut present = meta(&json!({ "application_type": "web" }));
        apply_chain(&chain, &mut present).expect("default leaves present");
        assert_eq!(present["application_type"], json!("web"));
    }

    #[test]
    fn reject_refuses_a_present_property_only() {
        let chain = vec![PolicyPrimitive::Reject {
            property: "jwks_uri".to_owned(),
        }];
        // Present: rejected out of band with the property named.
        let mut present = meta(&json!({ "jwks_uri": "https://rp.example/jwks" }));
        let rejection = apply_chain(&chain, &mut present).expect_err("reject fires");
        assert_eq!(rejection.property, "jwks_uri");
        assert_eq!(rejection.reason, PolicyRejectReason::PropertyRejected);
        assert!(rejection.diagnostic().contains("jwks_uri"));
        // Absent: passes.
        let mut absent = meta(&json!({ "redirect_uris": ["https://rp.example/cb"] }));
        apply_chain(&chain, &mut absent).expect("reject passes when absent");
    }

    #[test]
    fn restrict_allows_a_member_and_rejects_a_non_member_scalar() {
        let chain = vec![PolicyPrimitive::Restrict {
            property: "id_token_signed_response_alg".to_owned(),
            allowed: vec![json!("EdDSA"), json!("RS256")],
        }];
        let mut ok = meta(&json!({ "id_token_signed_response_alg": "EdDSA" }));
        apply_chain(&chain, &mut ok).expect("allowed alg passes");
        let mut bad = meta(&json!({ "id_token_signed_response_alg": "ES256" }));
        let rejection = apply_chain(&chain, &mut bad).expect_err("disallowed alg rejected");
        assert_eq!(rejection.reason, PolicyRejectReason::ValueNotAllowed);
    }

    #[test]
    fn restrict_on_an_array_requires_every_element_allowed() {
        let chain = vec![PolicyPrimitive::Restrict {
            property: "grant_types".to_owned(),
            allowed: vec![json!("authorization_code")],
        }];
        let mut ok = meta(&json!({ "grant_types": ["authorization_code"] }));
        apply_chain(&chain, &mut ok).expect("allowed grant types pass");
        let mut bad = meta(&json!({ "grant_types": ["authorization_code", "client_credentials"] }));
        assert!(
            apply_chain(&chain, &mut bad).is_err(),
            "an array with a disallowed element is rejected"
        );
    }

    #[test]
    fn primitives_apply_in_order_so_default_then_restrict_compose() {
        // Default fills a value, then Restrict validates it: the composed chain
        // forces a client that omitted the property onto an allowed value.
        let chain = vec![
            PolicyPrimitive::Default {
                property: "id_token_signed_response_alg".to_owned(),
                value: json!("EdDSA"),
            },
            PolicyPrimitive::Restrict {
                property: "id_token_signed_response_alg".to_owned(),
                allowed: vec![json!("EdDSA")],
            },
        ];
        let mut m = meta(&json!({ "redirect_uris": ["https://rp.example/cb"] }));
        apply_chain(&chain, &mut m).expect("default then restrict composes");
        assert_eq!(m["id_token_signed_response_alg"], json!("EdDSA"));
    }

    #[test]
    fn chain_round_trips_through_json() {
        let chain = vec![
            PolicyPrimitive::Force {
                property: "token_endpoint_auth_method".to_owned(),
                value: json!("private_key_jwt"),
            },
            PolicyPrimitive::Reject {
                property: "jwks_uri".to_owned(),
            },
        ];
        let text = serialize_chain(&chain).expect("serialize");
        let parsed = parse_chain(&text).expect("parse");
        assert_eq!(parsed, chain);
        // An empty snapshot is an unconstrained chain.
        assert!(parse_chain("[]").expect("empty").is_empty());
        assert!(parse_chain("").expect("blank").is_empty());
    }
}
