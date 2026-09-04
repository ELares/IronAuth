// SPDX-License-Identifier: MIT OR Apache-2.0

//! Turning an IronAuth subject into the SCIM resource a downstream is sent (issue #137).
//!
//! # What is operator-configurable and what is not
//!
//! A connection carries an `attribute_mapping`, because every downstream wants a different shape:
//! one takes `userName` as an e-mail, another as a short login, a third wants
//! `name.givenName` split out of a trait. That flexibility is the point of the column.
//!
//! But three attributes are NOT the operator's to choose, and this module refuses a mapping that
//! tries:
//!
//!   * `externalId` is how the client finds a resource it has already provisioned. RFC 7644
//!     section 3.4.2 filtering on it is the whole idempotency mechanism, and the merged client
//!     looks a subject up by it before every write. An operator who mapped `externalId` to a
//!     trait would change it the moment somebody edited that trait, and the next convergence
//!     would miss and create a SECOND resource for the same person. The mapping would look
//!     harmless in the console and would duplicate the directory.
//!   * `id` and `meta` are SERVER issued (RFC 7643 section 3.1). Sending them is at best ignored
//!     and at worst honoured, and a downstream that honours a client-chosen `id` breaks every
//!     later address.
//!   * `schemas` describes the resource. A mapping that rewrote it would send a body the
//!     downstream cannot interpret as the type it was posted to.
//!
//! Refusing at MAPPING time rather than at write time matters: the operator finds out when they
//! save the connection, not when a sync has already duplicated three thousand people.

use serde_json::{Map, Value};

/// Attributes the protocol owns, which an `attribute_mapping` may not target.
///
/// They are reserved for three different reasons, and the differences are worth keeping in view.
///
/// `id`, `meta` and `schemas` are the SERVER's (RFC 7643 section 3.1).
///
/// `externalId` is the CLIENT's, and is what makes a replay converge instead of duplicating.
///
/// `active` is the DEPROVISIONING flag, and it was missing from this list. A connection whose
/// operator mapped `active` onto a trait would have that trait decide departures: a subject the
/// worker is deactivating would be re-stamped active by the mapping on the way out, so the
/// deprovision would write a body saying the person is still enabled and the downstream would
/// keep them. The module header, the connection view's own field doc, and a test named
/// `a_deactivated_subject_maps_to_an_inactive_resource` all said `active` comes from the
/// subject's state rather than from the mapping. The constant did not enforce it, so all three
/// were claims about a rule nothing applied.
pub const RESERVED_ATTRIBUTES: &[&str] = &["id", "meta", "schemas", "externalId", "active"];

/// Attributes taken from the SUBJECT when the mapping does not set them.
///
/// # Defaulted, not reserved, and the difference is the whole design
///
/// A RESERVED attribute is one the operator may not touch, because letting them decide it breaks
/// something: `active` decides departures, `externalId` decides whether a replay converges.
/// A DEFAULTED one is an attribute the subject already answers and the schema needs, where an
/// operator may still know better.
///
/// Every one of these is REQUIRED of its resource by RFC 7643. `userName` is required of a User
/// (section 4.1) and `displayName` of a Group (section 4.2), and `members` is what makes a group
/// a group rather than an empty shell the downstream would enforce access against.
///
/// Leaving them to the mapping meant the OUT-OF-THE-BOX connection -- created with no mapping,
/// which is the default the management surface allows -- built a body the downstream refuses on
/// the required attribute. It was invisible because every test that exercised the mapper passed
/// it a mapping, and the one place a default connection reaches a real downstream did not exist
/// until the production directory did.
///
/// Reserving them instead would be wrong in the other direction: `userName` is the attribute
/// operators most often want to point somewhere else (a work email rather than a login handle),
/// and refusing that mapping would make the connection unusable for them.
#[must_use]
fn defaulted_attributes(schema_urn: &str) -> &'static [&'static str] {
    if schema_urn.ends_with(":Group") {
        return &["displayName", "members"];
    }
    if schema_urn.ends_with(":User") {
        return &["userName"];
    }
    &[]
}

/// Why a mapping cannot be applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappingError {
    /// The mapping targets an attribute the protocol owns.
    Reserved {
        /// The attribute the operator tried to map.
        attribute: String,
    },
    /// The mapping is not a JSON object of `scim path -> source path`.
    NotAnObject,
    /// A mapping value was not a string source path.
    NotAPath {
        /// The SCIM attribute whose source was malformed.
        attribute: String,
    },
    /// A SCIM attribute path was empty, or nested deeper than this mapper supports.
    ///
    /// One level of nesting (`name.givenName`) is supported because RFC 7643 uses it for the
    /// complex attributes that matter here. Deeper paths are refused rather than silently
    /// flattened into a literal key containing dots, which is what the reference downstream
    /// caught the first draft of the client doing.
    UnsupportedPath {
        /// The path as the operator wrote it.
        path: String,
    },
}

/// The subject as IronAuth holds it, flattened for mapping.
///
/// A plain `Value` rather than a typed record because the source of a mapped attribute can be a
/// column, a trait, or a computed field, and the set differs between users and groups. What keeps
/// it honest is that the caller builds it, so nothing here reads the database.
pub type Source = Value;

/// Builds the SCIM resource for one subject.
///
/// `schemas`, `externalId` and `active` are set by this function and cannot be overridden: see the
/// module header.
///
/// # Errors
///
/// [`MappingError`] if the connection's mapping targets a reserved attribute, is not an object of
/// string paths, or uses a path this mapper does not support.
pub fn resource_for(
    schema_urn: &str,
    external_id: &str,
    active: bool,
    mapping: &Value,
    source: &Source,
) -> Result<Value, MappingError> {
    let Some(entries) = mapping.as_object() else {
        // An absent mapping is an empty one, which is a connection that sends only the attributes
        // below. Explicit null is the house convention for absent (0189 records being caught
        // asserting otherwise), so it is accepted rather than refused.
        if mapping.is_null() {
            return Ok(base_resource(schema_urn, external_id, active, source));
        }
        return Err(MappingError::NotAnObject);
    };

    let mut resource = base_resource(schema_urn, external_id, active, source);
    for (attribute, source_path) in entries {
        let head = attribute.split('.').next().unwrap_or_default();
        if RESERVED_ATTRIBUTES.contains(&head) {
            return Err(MappingError::Reserved {
                attribute: attribute.clone(),
            });
        }
        let Some(source_path) = source_path.as_str() else {
            return Err(MappingError::NotAPath {
                attribute: attribute.clone(),
            });
        };
        let Some(value) = read_path(source, source_path) else {
            // A source the subject does not carry is an ABSENT attribute, not an error and not a
            // null. Sending `null` would ask the downstream to clear it, and RFC 7644 section
            // 3.5.1 makes a PUT a full replace, so an absent trait must simply not appear.
            continue;
        };
        write_path(&mut resource, attribute, value.clone())?;
    }
    Ok(resource)
}

/// The attributes every outbound resource carries, whatever the mapping says.
fn base_resource(schema_urn: &str, external_id: &str, active: bool, source: &Source) -> Value {
    let mut resource = Map::new();
    resource.insert(
        "schemas".to_owned(),
        Value::Array(vec![Value::String(schema_urn.to_owned())]),
    );
    resource.insert(
        "externalId".to_owned(),
        Value::String(external_id.to_owned()),
    );
    // `active` ONLY WHERE THE SCHEMA HAS IT. RFC 7643 section 4.2 gives Group no `active`
    // attribute, and the first version stamped it onto every resource regardless.
    //
    // That is not a harmless extra field. The merged client refuses a Group deactivation
    // precisely by checking whether the stored representation carries `active`, so a Group this
    // mapper built came back carrying one, the refusal was disarmed, and the deprovision reported
    // success while every member stayed in the group. The guard and the mapper were each correct
    // alone and wrong together, which is why the condition belongs beside the schema rather than
    // at the call site.
    if schema_urn.ends_with(":User") {
        resource.insert("active".to_owned(), Value::Bool(active));
    }
    // THE SCHEMA'S REQUIRED ATTRIBUTES, from the subject, BEFORE the mapping runs so an operator
    // who names one still wins. See `defaulted_attributes`.
    for attribute in defaulted_attributes(schema_urn) {
        // ABSENT RATHER THAN NULL when the subject does not carry one. RFC 7644 section 3.5.1
        // makes a PUT a full replace, so sending `null` asks the downstream to clear it.
        if let Some(value) = source.get(*attribute) {
            resource.insert((*attribute).to_owned(), value.clone());
        }
    }
    Value::Object(resource)
}

/// Reads `a.b` out of the source, or `None` if any step is missing.
fn read_path<'a>(source: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cursor = source;
    for step in path.split('.') {
        cursor = cursor.get(step)?;
    }
    Some(cursor)
}

/// Writes `a` or `a.b` into the resource, creating the intermediate object if needed.
fn write_path(resource: &mut Value, path: &str, value: Value) -> Result<(), MappingError> {
    let steps: Vec<&str> = path.split('.').collect();
    if steps.is_empty() || steps.iter().any(|s| s.is_empty()) || steps.len() > 2 {
        return Err(MappingError::UnsupportedPath {
            path: path.to_owned(),
        });
    }
    let object = resource
        .as_object_mut()
        .expect("the base resource is an object");
    if steps.len() == 1 {
        object.insert(steps[0].to_owned(), value);
        return Ok(());
    }
    let parent = object
        .entry(steps[0].to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(parent) = parent.as_object_mut() else {
        // The mapping asked for `name.givenName` where `name` is already a scalar, which happens
        // when one mapping targets both `name` and `name.givenName`. Refused rather than silently
        // discarding whichever came second, because map iteration order would decide the winner.
        return Err(MappingError::UnsupportedPath {
            path: path.to_owned(),
        });
    };
    parent.insert(steps[1].to_owned(), value);
    Ok(())
}
