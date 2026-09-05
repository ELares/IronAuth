// SPDX-License-Identifier: MIT OR Apache-2.0

//! What an assertion says ABOUT the person, as opposed to who they are.
//!
//! [`crate::check`] answers who signed in and whether the assertion may be believed.
//! `AttributeStatement` is everything else the identity provider chose to send -- a display
//! name, a department, group memberships -- and it is what a deployment maps into its own
//! identity traits.
//!
//! # Why this is a separate step from `check`
//!
//! Because it is a DIFFERENT KIND OF ANSWER. Everything `check` reads decides admission, and a
//! value it cannot read means refuse the sign-in. An attribute a caller does not understand is
//! not a reason to refuse anybody: an identity provider adds attributes without telling the
//! relying party, and a service provider that refused every assertion carrying an attribute it
//! had no mapping for would break on the day somebody edited a profile schema.
//!
//! So this reads what is there, refuses what is AMBIGUOUS, and leaves what to do with it to the
//! mapping.
//!
//! # And why it answers Rust rather than JSON
//!
//! The mapping this feeds is `ironauth-connector`'s, which resolves dotted paths through
//! `serde_json` maps. Projecting into that shape is a caller's job on purpose: this crate is the
//! choke point through which hostile SAML XML enters, and its dependency list is part of the
//! argument. A JSON library here would be a second parser reachable from the same bytes.

use crate::verify::VerifiedAssertion;

/// The SAML 2.0 assertion namespace.
const ASSERTION: &str = crate::ASSERTION_NS;

/// One `saml:Attribute` an identity provider sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// The `Name`, which SAML requires and which is what a mapping keys on.
    pub name: String,
    /// The `NameFormat`, where the identity provider gave one.
    ///
    /// NOT DEFAULTED to `unspecified`. SAML says an absent `NameFormat` MEANS unspecified, and
    /// filling it in here would make "the provider said unspecified" and "the provider said
    /// nothing" the same answer to a caller trying to tell one Entra tenant's configuration from
    /// another's. A caller that wants the default can apply it; one that wants to know cannot
    /// recover it.
    pub name_format: Option<String>,
    /// The `AttributeValue` children, in document order.
    ///
    /// EMPTY IS A REAL ANSWER AND NOT AN ABSENCE. An `Attribute` with no values is how SAML says
    /// "this attribute is not populated for this person", which is different from the attribute
    /// not being sent -- and a directory that clears a field emits exactly that.
    pub values: Vec<Value>,
}

/// One `saml:AttributeValue`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Text, which is what every mappable attribute is.
    Text(String),
    /// A value carrying ELEMENT children, which this does not flatten.
    ///
    /// `AttributeValue` is `xs:anyType`, so a conformant assertion may put a whole XML subtree
    /// in one -- Entra does it for some claim types, and `saml:NameID` inside an
    /// `AttributeValue` is common enough to have its own interoperability notes.
    ///
    /// FLATTENING IT TO TEXT WOULD INVENT A VALUE. Concatenating the descendants of
    /// `<AttributeValue><a>x</a><b>y</b></AttributeValue>` gives `"xy"`, which no other reader
    /// produces and which a mapping would then write into somebody's profile. So the shape is
    /// reported and the text is not, and a caller that has no use for it skips the value rather
    /// than being handed a fiction.
    Structured,
}

/// Why an `AttributeStatement` could not be read.
///
/// # One variant, because there is one thing to do about it
///
/// Every case here is an assertion that says two contradictory things about one attribute name.
/// An operator's fix is the same each time -- their identity provider is emitting a shape this
/// server will not guess at -- and naming which of them occurred would describe the attacker's
/// probe rather than the operator's problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ambiguous {
    /// The attribute name the ambiguity is about, or `None` when an `Attribute` carried no
    /// `Name` at all.
    pub name: Option<String>,
}

impl core::fmt::Display for Ambiguous {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.name {
            Some(name) => write!(f, "the assertion says two different things about {name:?}"),
            None => f.write_str("the assertion carries an attribute with no name"),
        }
    }
}

impl core::error::Error for Ambiguous {}

/// Every attribute in the assertion's `AttributeStatement`s, in document order.
///
/// # What is refused, and what is merely absent
///
/// - An `Attribute` with no `Name` is REFUSED. `Name` is required, and an attribute nothing can
///   key on is one a mapping could never reach -- so silently dropping it would hide a
///   misconfiguration behind a trait that is simply never populated.
/// - TWO `Attribute`s WITH THE SAME `Name` are REFUSED, the same rule this crate applies
///   everywhere: taking either is choosing which half of a contradiction to believe, and
///   somebody who can append chooses for the reader. SAML Core 2.7.3.1 says an attribute's
///   values belong in ONE `Attribute` element, so a second one is not a longer list, it is a
///   second claim.
/// - NO `AttributeStatement` AT ALL is not an error and answers an empty list. An authentication
///   assertion that carries only an `AuthnStatement` is ordinary, and it is what an identity
///   provider sends when a relying party asked for nothing.
///
/// # Errors
///
/// [`Ambiguous`], naming the attribute if it had a name.
pub fn attributes(assertion: &VerifiedAssertion) -> Result<Vec<Attribute>, Ambiguous> {
    let mut out: Vec<Attribute> = Vec::new();
    // DIRECT CHILDREN, at both levels. `saml:Advice` carries whole assertions and an
    // `AttributeValue` may itself contain an `AttributeStatement`, so a descendant search would
    // collect somebody else's attributes -- which are inside this signature just as much as the
    // real ones. The condition layer learned this the expensive way.
    for statement in assertion.children(ASSERTION, "AttributeStatement") {
        for attribute in statement.children(ASSERTION, "Attribute") {
            let Some(name) = attribute.attribute("Name") else {
                return Err(Ambiguous { name: None });
            };
            if out.iter().any(|seen| seen.name == name) {
                return Err(Ambiguous {
                    name: Some(name.to_owned()),
                });
            }
            let values = attribute
                .children(ASSERTION, "AttributeValue")
                .iter()
                .map(|value| match value.text_simple() {
                    Some(text) => Value::Text(text),
                    None => Value::Structured,
                })
                .collect();
            out.push(Attribute {
                name: name.to_owned(),
                name_format: attribute.attribute("NameFormat").map(ToOwned::to_owned),
                values,
            });
        }
    }
    Ok(out)
}
