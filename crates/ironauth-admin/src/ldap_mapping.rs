// SPDX-License-Identifier: MIT OR Apache-2.0

//! Turning a directory entry into the identity IronAuth stores (issue #142).
//!
//! The inbound counterpart of [`crate::scim_push_mapping`], which does the same job outbound. The
//! connector's `attribute_mapping` has the same shape in both directions -- a JSON object of
//! canonical name to source path -- because #142 asks for one attribute-mapping mental model
//! across both directory paths rather than two divergent systems.
//!
//! # The stable identifier is not the operator's to choose
//!
//! Every other field here is configurable, and this one is not. A directory entry has two
//! candidate identities and they behave very differently:
//!
//!   * the **DN**, which is a PATH. `cn=Ada,ou=Engineering,dc=x` becomes
//!     `cn=Ada,ou=Sales,dc=x` when Ada changes team, and `cn=Ada Lovelace,...` when she marries.
//!     Neither is a new person. A sync keyed on the DN sees the old entry vanish and a new one
//!     appear, so it deactivates Ada and creates a second Ada -- and if the connector's absence
//!     policy is `delete`, it deletes her.
//!   * **`objectGUID`** (Active Directory) or **`entryUUID`** (RFC 4530, `OpenLDAP`), which are
//!     assigned once and never change, including across a move or a rename.
//!
//! So the UUID wins wherever the directory publishes one, and the DN is the fallback for a server
//! that publishes neither. [`crate::scim_push_mapping`] withholds `externalId` from the operator
//! for the same REASON -- both are the handle a later run uses to recognise somebody it has
//! already seen -- though by a different mechanism: that module names it on a reserved list,
//! while here the choice is simply not expressible in the mapping. The consequence of getting it
//! wrong is identical: a duplicated directory nobody notices until the licence count is double.
//!
//! # An entry is multi-valued everywhere
//!
//! LDAP attributes are sets, not scalars. `mail` routinely carries three addresses and `cn` two.
//! Taking "the value" means taking the FIRST in the order the server returned, which is not
//! stable across servers or even across searches. Where one value is required this module takes
//! the first and says so; where the order would change identity -- the stable id -- a
//! multi-valued attribute is refused outright rather than resolved by luck.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

/// One entry as the directory returned it: attribute name to its values, plus the DN.
///
/// ATTRIBUTE NAMES ARE CASE-INSENSITIVE in LDAP (RFC 4512 section 2.5), and servers disagree
/// about the case they echo: Active Directory answers `sAMAccountName`, `OpenLDAP` echoes whatever
/// was asked for. An operator writing `samaccountname` in a mapping means the same attribute, so
/// lookups here fold case rather than making the operator guess the server's spelling.
#[derive(Debug, Clone)]
pub struct DirectoryEntry {
    /// The entry's distinguished name, as the server rendered it.
    pub dn: String,
    /// Attribute values, keyed by LOWERCASED attribute name.
    values: BTreeMap<String, Vec<String>>,
    /// Attribute values the server returned as octet strings rather than text.
    ///
    /// NOT AN EDGE CASE, and the reason this map exists: Active Directory's `objectGUID` is a
    /// raw 16-byte value, not UTF-8. It arrives in `ldap3`'s `bin_attrs` and never in `attrs`, so
    /// a mapper that only read text would find no `objectGUID` on any AD entry and quietly fall
    /// through to the rename-fragile DN -- which is the whole failure this module exists to
    /// prevent, arriving on the single most important directory in the world for it.
    binary: BTreeMap<String, Vec<Vec<u8>>>,
}

impl DirectoryEntry {
    /// Build an entry, folding attribute names to lowercase.
    #[must_use]
    pub fn new(dn: impl Into<String>, attributes: Vec<(String, Vec<String>)>) -> Self {
        Self {
            dn: dn.into(),
            values: attributes
                .into_iter()
                .map(|(name, values)| (name.to_ascii_lowercase(), values))
                .collect(),
            binary: BTreeMap::new(),
        }
    }

    /// Add the attributes the server returned as octet strings.
    #[must_use]
    pub fn with_binary(mut self, attributes: Vec<(String, Vec<Vec<u8>>)>) -> Self {
        self.binary = attributes
            .into_iter()
            .map(|(name, values)| (name.to_ascii_lowercase(), values))
            .collect();
        self
    }

    /// Every octet-string value of one attribute, or an empty slice.
    #[must_use]
    pub fn binary_values(&self, attribute: &str) -> &[Vec<u8>] {
        self.binary
            .get(&attribute.to_ascii_lowercase())
            .map_or(&[], Vec::as_slice)
    }

    /// Every value of one attribute, or an empty slice.
    #[must_use]
    pub fn values(&self, attribute: &str) -> &[String] {
        self.values
            .get(&attribute.to_ascii_lowercase())
            .map_or(&[], Vec::as_slice)
    }

    /// The FIRST value of one attribute, if it has any.
    ///
    /// First in the server's order, which is not guaranteed stable -- see the module header. Use
    /// it only where an arbitrary choice among equals is acceptable.
    #[must_use]
    pub fn first(&self, attribute: &str) -> Option<&str> {
        self.values(attribute).first().map(String::as_str)
    }
}

/// Why an entry could not be mapped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LdapMappingError {
    /// The connector's `attribute_mapping` is not a JSON object of canonical name to source.
    NotAnObject,
    /// A mapping value was not a string attribute name.
    NotAnAttributeName {
        /// The canonical field whose source was malformed.
        field: String,
    },
    /// The mapping tries to choose the stable identifier.
    ///
    /// A separate refusal from [`Self::UnknownField`] because the honest answer is different: the
    /// field is not unknown, it is not the operator's to pick. Telling somebody who mapped
    /// `stable_id` that "no field named `stable_id` is synced" would send them looking for a
    /// spelling mistake.
    StableIdNotMappable {
        /// What they wrote.
        field: String,
    },
    /// The mapping names a field this build does not write.
    ///
    /// Refused rather than ignored: an operator who mapped `manager` and saw it silently
    /// dropped would believe the field was synced.
    UnknownField {
        /// What they wrote.
        field: String,
    },
    /// The entry carries no value for a required field.
    Missing {
        /// The canonical field.
        field: String,
        /// The attribute the mapping pointed at.
        attribute: String,
    },
    /// The attribute chosen as the stable identifier carries more than one value.
    ///
    /// Refused rather than resolved by taking the first: which value comes first is the server's
    /// choice and can differ between two searches, so "first" would make the identity of a
    /// person depend on the order a directory happened to answer in.
    AmbiguousStableId {
        /// The attribute that carried them.
        attribute: String,
        /// How many values were present.
        count: usize,
    },
}

impl std::fmt::Display for LdapMappingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnObject => write!(f, "attribute_mapping is not a JSON object"),
            Self::NotAnAttributeName { field } => {
                write!(f, "the mapping for {field} is not an attribute name")
            }
            Self::StableIdNotMappable { field } => write!(
                f,
                "{field} cannot be mapped: the stable identifier is taken from objectGUID, then \
                 entryUUID, then the DN, so that a rename does not create a second person"
            ),
            Self::UnknownField { field } => write!(f, "no field named {field} is synced"),
            Self::Missing { field, attribute } => {
                write!(f, "the entry has no {attribute} to map to {field}")
            }
            Self::AmbiguousStableId { attribute, count } => write!(
                f,
                "{attribute} carries {count} values and cannot identify one person"
            ),
        }
    }
}

impl std::error::Error for LdapMappingError {}

/// What one directory entry becomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedPrincipal {
    /// The value that identifies this person across renames and moves.
    pub stable_id: String,
    /// Where it came from, so a later sync can tell a UUID-keyed directory from a DN-keyed one.
    pub stable_id_source: StableIdSource,
    /// The DN, kept for diagnostics and for group membership resolution.
    pub dn: String,
    /// The canonical login identifier.
    pub username: String,
    /// The e-mail, if the mapping supplies one and the entry carries it.
    pub email: Option<String>,
    /// The display name, if mapped and present.
    pub display_name: Option<String>,
}

/// Which attribute identified a principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StableIdSource {
    /// Active Directory's `objectGUID`.
    ObjectGuid,
    /// RFC 4530's `entryUUID`.
    EntryUuid,
    /// The DN, because the server published neither UUID.
    ///
    /// A DEGRADED MODE, and callers should say so: on this server a rename IS a new person, and
    /// the absence policy will fire for the old DN.
    DistinguishedName,
}

impl StableIdSource {
    /// Whether identity on this source survives a rename or a move.
    #[must_use]
    pub fn survives_rename(self) -> bool {
        !matches!(self, Self::DistinguishedName)
    }
}

/// The canonical fields a mapping may name.
///
/// A CLOSED SET, so a typo is refused at mapping time rather than silently dropping a field the
/// operator believed was synced.
///
/// This is STRICTER than [`crate::scim_push_mapping`], which refuses a five-name reserved list
/// and passes everything else through to the outbound body. It can afford that: an unrecognised
/// SCIM attribute is still sent and the downstream decides. Inbound there is no downstream to
/// decide, so a field this build cannot write has nowhere to go and refusing is the only honest
/// answer.
const MAPPABLE: &[&str] = &["username", "email", "display_name"];

/// Names an operator might reach for to steer the stable identifier, refused by name so the
/// message can say why rather than reporting them as typos.
const RESERVED: &[&str] = &["stable_id", "stable_id_source", "dn"];

/// The attributes searched for a stable identifier, in preference order.
const STABLE_ID_ATTRIBUTES: &[(&str, StableIdSource)] = &[
    ("objectguid", StableIdSource::ObjectGuid),
    ("entryuuid", StableIdSource::EntryUuid),
];

/// Map one entry through a connector's `attribute_mapping`.
///
/// # Errors
///
/// [`LdapMappingError`], and every variant is a configuration or directory problem an operator
/// can act on rather than a transient fault.
pub fn principal_for(
    entry: &DirectoryEntry,
    mapping: &Value,
) -> Result<MappedPrincipal, LdapMappingError> {
    let object = mapping.as_object().ok_or(LdapMappingError::NotAnObject)?;
    for field in object.keys() {
        if RESERVED.contains(&field.as_str()) {
            return Err(LdapMappingError::StableIdNotMappable {
                field: field.clone(),
            });
        }
        if !MAPPABLE.contains(&field.as_str()) {
            return Err(LdapMappingError::UnknownField {
                field: field.clone(),
            });
        }
    }

    let source_for = |field: &str| -> Result<Option<&str>, LdapMappingError> {
        match object.get(field) {
            None => Ok(None),
            Some(Value::String(attribute)) => Ok(Some(attribute.as_str())),
            Some(_) => Err(LdapMappingError::NotAnAttributeName {
                field: field.to_owned(),
            }),
        }
    };

    // THE STABLE IDENTIFIER, chosen by the directory rather than the operator. See the header.
    let mut stable = None;
    for (attribute, source) in STABLE_ID_ATTRIBUTES {
        // The text and octet-string forms are the SAME attribute: `OpenLDAP` sends `entryUUID` as
        // text, Active Directory sends `objectGUID` as sixteen raw bytes, and a server sending
        // both would be describing one identity twice. Counting them together means two values
        // are ambiguous whichever form they arrived in.
        let text = entry.values(attribute);
        let raw = entry.binary_values(attribute);
        match text.len() + raw.len() {
            0 => {}
            1 => {
                let value = text
                    .first()
                    .map_or_else(|| identifier_from_octets(attribute, &raw[0]), Clone::clone);
                stable = Some((value, *source));
                break;
            }
            count => {
                return Err(LdapMappingError::AmbiguousStableId {
                    attribute: (*attribute).to_owned(),
                    count,
                });
            }
        }
    }
    let (stable_id, stable_id_source) =
        stable.unwrap_or_else(|| (entry.dn.clone(), StableIdSource::DistinguishedName));

    // USERNAME IS REQUIRED, because a principal with no login identifier is a row nobody can
    // sign in as -- created, counted, and useless.
    let username_attribute = source_for("username")?.unwrap_or("uid");
    let username = entry
        .first(username_attribute)
        .ok_or_else(|| LdapMappingError::Missing {
            field: "username".to_owned(),
            attribute: username_attribute.to_owned(),
        })?
        .to_owned();

    let email = source_for("email")?.and_then(|a| entry.first(a).map(str::to_owned));
    let display_name = source_for("display_name")?.and_then(|a| entry.first(a).map(str::to_owned));

    Ok(MappedPrincipal {
        stable_id,
        stable_id_source,
        dn: entry.dn.clone(),
        username,
        email,
        display_name,
    })
}

/// Render an octet-string identifier as the text this build stores.
///
/// `objectGUID` gets Active Directory's own display form, mixed-endian and all: the first three
/// groups are little-endian and the last two big-endian (the layout of a Microsoft `GUID`
/// struct). Matching it matters because an operator debugging a sync compares what IronAuth
/// stored against what `Get-ADUser` prints, and a hex dump of the same bytes in memory order
/// looks like a different person.
///
/// Anything else is taken as text when it is valid UTF-8 and hex-encoded when it is not, so an
/// unexpected binary identifier is still stable rather than lossy.
fn identifier_from_octets(attribute: &str, raw: &[u8]) -> String {
    if attribute == "objectguid" && raw.len() == 16 {
        return format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-\
             {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            raw[3],
            raw[2],
            raw[1],
            raw[0],
            raw[5],
            raw[4],
            raw[7],
            raw[6],
            raw[8],
            raw[9],
            raw[10],
            raw[11],
            raw[12],
            raw[13],
            raw[14],
            raw[15]
        );
    }
    std::str::from_utf8(raw).map_or_else(
        |_| {
            use std::fmt::Write as _;
            raw.iter().fold(String::new(), |mut acc, b| {
                let _ = write!(acc, "{b:02x}");
                acc
            })
        },
        str::to_owned,
    )
}

/// The attributes a search must request in order for [`principal_for`] to be able to do its job.
///
/// DERIVED FROM THE MAPPING, never written at the call site. The reason is a property of the
/// protocol rather than of this code: `entryUUID` and `objectGUID` are OPERATIONAL attributes,
/// and a search that does not name them does not receive them. Verified against a live
/// `OpenLDAP`: `ldapsearch "(uid=grace)"` returns no `entryUUID`, while
/// `ldapsearch "(uid=grace)" entryUUID` returns it.
///
/// A caller that hand-listed the attributes and forgot the identifier would get entries that all
/// appear to have no UUID, so all of them would take the DN fallback. Every person in the
/// directory would silently become rename-fragile, and nothing would report it: the mapping still
/// succeeds, the sync still runs, and the breakage shows up only when somebody changes their name
/// and gets deprovisioned.
///
/// The returned list is deduplicated and lowercased, matching how [`DirectoryEntry`] keys itself.
#[must_use]
pub fn attributes_to_request(mapping: &Value) -> Vec<String> {
    let mut wanted: BTreeSet<String> = STABLE_ID_ATTRIBUTES
        .iter()
        .map(|(attribute, _)| (*attribute).to_owned())
        .collect();

    // The default username source, which applies when the mapping does not override it. Omitting
    // it would break exactly the connectors that configured nothing.
    wanted.insert("uid".to_owned());

    if let Some(object) = mapping.as_object() {
        for (field, source) in object {
            if !MAPPABLE.contains(&field.as_str()) {
                continue;
            }
            if let Value::String(attribute) = source {
                wanted.insert(attribute.to_ascii_lowercase());
            }
        }
    }

    wanted.into_iter().collect()
}
