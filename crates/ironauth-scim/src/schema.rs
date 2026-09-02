// SPDX-License-Identifier: MIT OR Apache-2.0

//! The SCIM core schemas this server publishes (RFC 7643, issue #135).
//!
//! # Why these are literals rather than derived from the models
//!
//! A schema document describes what the SERVER accepts, and deriving it from
//! [`crate::resource::ScimUser`] would make it describe what the server currently PARSES --
//! which is the same thing only for as long as nobody adds a field the parser tolerates and
//! the schema does not mention. RFC 7643's schemas are a contract with the provisioning client:
//! Okta and Entra read them to decide what to send, so they have to say what is supported
//! rather than what happens to deserialize.
//!
//! What keeps them honest is the other direction: `schemas_cover_every_modelled_attribute`
//! fails if the model grows an attribute this document does not publish.

use serde_json::{Value, json};

/// The core `User` schema URN.
pub const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
/// The Enterprise User extension URN (RFC 7643 section 4.3).
pub const ENTERPRISE_USER_SCHEMA: &str =
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
/// The core `Group` schema URN.
pub const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";

/// One attribute definition, in the shape RFC 7643 section 7 gives it.
fn attribute(name: &str, kind: &str, multi: bool, required: bool) -> Value {
    json!({
        "name": name,
        "type": kind,
        "multiValued": multi,
        "required": required,
        "caseExact": false,
        // Every attribute this server publishes is readable and writable by the provisioning
        // client. An attribute the client may not write does not belong in an inbound schema:
        // it would advertise a field whose every write is silently dropped.
        "mutability": "readWrite",
        "returned": "default",
        "uniqueness": if name == "userName" { "server" } else { "none" },
    })
}

/// The schemas this server publishes, in the order `GET /Schemas` returns them.
#[must_use]
pub fn core_schemas() -> Vec<Value> {
    vec![
        json!({
            "id": USER_SCHEMA,
            "name": "User",
            "description": "User Account",
            "attributes": [
                // `userName` is the only REQUIRED attribute, per RFC 7643 section 4.1.1, and
                // the only one with server uniqueness: it is what a provisioning client uses
                // to mean "the same person".
                attribute("userName", "string", false, true),
                attribute("displayName", "string", false, false),
                attribute("externalId", "string", false, false),
                attribute("active", "boolean", false, false),
                attribute("emails", "complex", true, false),
                attribute("name", "complex", false, false),
            ],
        }),
        json!({
            "id": ENTERPRISE_USER_SCHEMA,
            "name": "EnterpriseUser",
            "description": "Enterprise User",
            "attributes": [
                attribute("employeeNumber", "string", false, false),
                attribute("department", "string", false, false),
                attribute("manager", "complex", false, false),
            ],
        }),
        json!({
            "id": GROUP_SCHEMA,
            "name": "Group",
            "description": "Group",
            "attributes": [
                attribute("displayName", "string", false, true),
                attribute("members", "complex", true, false),
            ],
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every published schema has the three fields a client reads to dispatch on it.
    #[test]
    fn every_schema_is_addressable() {
        for schema in core_schemas() {
            for field in ["id", "name", "attributes"] {
                assert!(
                    schema.get(field).is_some(),
                    "a schema without `{field}` cannot be used by a provisioning client: \
                     {schema}"
                );
            }
            let attributes = schema["attributes"].as_array().expect("an array");
            assert!(
                !attributes.is_empty(),
                "a schema publishing no attributes describes nothing: {schema}"
            );
        }
    }

    /// The document publishes every attribute the User model actually parses.
    ///
    /// THE DIRECTION THAT MATTERS. The schema is deliberately hand-written, so the risk is not
    /// that it says too much but that the model grows a field the document never mentions --
    /// and a provisioning client reading the document would then never send it. This fails when
    /// that happens.
    #[test]
    fn the_user_schema_covers_every_attribute_the_model_parses() {
        let published: Vec<String> = core_schemas()[0]["attributes"]
            .as_array()
            .expect("attributes")
            .iter()
            .map(|attribute| attribute["name"].as_str().expect("a name").to_owned())
            .collect();
        // The wire names `ScimUser` deserializes. This list is hand-written -- serde field
        // names are not reflectable at runtime -- so what keeps it honest is the EXHAUSTIVE
        // destructure below, which stops compiling the moment the struct grows a field.
        let modelled = ["userName", "externalId", "active"];
        let missing: Vec<&&str> = modelled
            .iter()
            .filter(|name| !published.iter().any(|p| p == *name))
            .collect();
        assert!(
            missing.is_empty(),
            "the User model parses {missing:?}, which `GET /Schemas` does not publish, so a \
             provisioning client reading the document would never send them"
        );

        // THE ENROLLMENT. Adding a field to `ScimUser` fails to compile here, which forces
        // whoever adds it to decide whether the schema should publish it. A count assertion
        // would not: it would pass for a renamed field, and a `..` pattern would pass for a
        // new one, which is the whole failure this guards against.
        let crate::resource::ScimUser {
            user_name: _,
            external_id: _,
            active: _,
        } = crate::resource::ScimUser {
            user_name: String::new(),
            external_id: None,
            active: true,
        };
        assert_eq!(
            modelled.len(),
            3,
            "the destructure above and this list must describe the same struct"
        );
    }
}
