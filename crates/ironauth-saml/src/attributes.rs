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
//! So this reads what is there, refuses only what is AMBIGUOUS -- two claims about one
//! attribute, or an attribute nothing can key on -- and reports what it could not read
//! ALONGSIDE what it could, leaving the decision to the mapping.
//!
//! # And why it answers Rust rather than JSON
//!
//! The mapping this is meant to feed is `ironauth-connector`'s, which resolves paths through
//! `serde_json` maps. Projecting into that shape is a caller's job on purpose: this crate is the
//! choke point through which hostile SAML XML enters, and its dependency list is part of the
//! argument. A JSON library here would be a second parser reachable from the same bytes.
//!
//! # A SAML attribute cannot yet be ADDRESSED by that mapper, and this says so
//!
//! `claim_mapping::resolve_path` splits a mapping path on `.`, and a SAML attribute `Name` is a
//! URI full of them: ADFS and Entra send
//! `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`, which the resolver
//! reads as a key called `http://schemas` followed by five more segments. So no real SAML
//! attribute is addressable by a mapping path as the language stands.
//!
//! AN EARLIER VERSION OF THIS PR CHANGED THE RESOLVER and it was a security defect, which is
//! worth recording here rather than only in a commit message. Preferring a literal key let the
//! UPSTREAM choose which reading a mapping got: a provider emitting a claim named
//! `https://app.example.com/roles.1` captured a mapping that meant element 1 of `roles`, on the
//! OIDC callback that runs today. Trying traversal first and the literal key second moved the
//! defect rather than removing it, because for a URI path the first segment is never a
//! top-level key -- traversal always fails, so the literal key always answers, which is the
//! rule that was supposed to have been removed.
//!
//! ANY PRECEDENCE RULE HAS THIS SHAPE: if the document's key names decide which reading wins,
//! the document participates in the choice. What criterion 6 needs is an EXPLICIT escape in the
//! mapping path language -- a way for an author to say "this segment is a literal key" -- and
//! that is a change to a stored configuration format, which belongs with the endpoint that has
//! a real mapping in hand rather than with this reader. Recorded on the issue.

use crate::verify::VerifiedAssertion;

/// The SAML 2.0 assertion namespace.
const ASSERTION: &str = crate::ASSERTION_NS;

/// The `NameFormat` an absent one MEANS, per SAML Core 2.7.3.1.
///
/// Used for COMPARING two attributes, never for filling in [`Attribute::name_format`]: a caller
/// that wants to know whether the provider said it can still tell, and one that wants the
/// effective value can apply this itself.
const UNSPECIFIED: &str = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified";

/// One `saml:Attribute` an identity provider sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// The `Name`, which SAML requires and which is what a mapping keys on.
    pub name: String,
    /// The `NameFormat`, where the identity provider gave one.
    ///
    /// NOT DEFAULTED to `unspecified`. SAML says an absent `NameFormat` MEANS unspecified, and
    /// filling it in here would make "the provider said unspecified" and "the provider said
    /// nothing" the same answer to a caller trying to tell one tenant's configuration from
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
    /// A value that says the person has none of this attribute.
    ///
    /// COVERS BOTH `<AttributeValue/>` AND `<AttributeValue xsi:nil="true"/>`, and does NOT
    /// distinguish them -- reading `xsi:nil` needs the attribute's NAMESPACE resolved, and this
    /// crate deliberately exposes attributes by their literal spelling only, because a prefix is
    /// not an identity and resolving one for attributes is a surface it has not needed.
    ///
    /// SAML DOES DISTINGUISH THEM, so this is a documented narrowing rather than a reading of
    /// the specification: an `xsi:nil` value is the absence of a value, and an empty one is a
    /// value that happens to be the empty string. Collapsing them loses that, and the loss is in
    /// the SAFE direction for the decision a mapping makes -- both are treated as "no value
    /// here", which is what an absent value would do -- but a caller that needs the difference
    /// does not get it from this type. Said out loud rather than left to be discovered.
    ///
    /// SEPARATE FROM `Text(String::new())` BECAUSE A MAPPING TREATS THEM DIFFERENTLY. The
    /// connector's rules take the first source that resolves to a non-null value, so an empty
    /// STRING wins a fallback that an absent value would lose -- and a person whose department
    /// was cleared would get `""` written into their profile instead of the next source's value,
    /// or instead of nothing.
    Empty,
    /// A value carrying ELEMENT children, each as its resolved name AND its text.
    ///
    /// `AttributeValue` is `xs:anyType`, so a conformant assertion may put a whole XML subtree
    /// in one. `saml:NameID` inside an `AttributeValue` is the case with published
    /// interoperability notes -- it is how a SAML attribute carries a subject reference.
    ///
    /// FLATTENING IT TO TEXT WOULD INVENT A VALUE. Concatenating the descendants of
    /// `<AttributeValue><a>x</a><b>y</b></AttributeValue>` gives `"xy"`, which no other reader
    /// produces and which a mapping would then write into somebody's profile. So the SHAPE is
    /// reported instead: the child names let a caller log what it declined to map, and decide
    /// whether the attribute is one it should be handling at all, rather than being handed
    /// either a fiction or a silence.
    ///
    /// WITH THE NAMESPACE, because a local name is not an identity. An earlier version answered
    /// local names alone, so a caller deciding "is this a `NameID` I should read?" would have
    /// been making the allowlist-on-spelling decision this crate removed from its own condition
    /// layer -- `evil:NameID` and `saml:NameID` are different elements and a bare `"NameID"`
    /// cannot tell them apart. The namespace is the empty string for a child in none.
    ///
    /// AND WITH EACH CHILD'S OWN TEXT, because the case this doc names as the reason the variant
    /// exists is `saml:NameID` inside an `AttributeValue` -- and a caller that has identified it
    /// wants the name inside it. An earlier version answered the shape and threw the value away,
    /// so the one attribute it described as common was the one nothing could be done with. The
    /// text is that child's own, not its descendants' concatenated: a child that itself has
    /// element children answers an empty string, for the reason this whole variant exists.
    Structured(Vec<Child>),
}

/// One element child of an `AttributeValue` this module did not turn into text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Child {
    /// The resolved namespace, empty for a child in none.
    pub namespace: String,
    /// The local name.
    pub local: String,
    /// This child's own text, empty when it has element children of its own.
    pub text: String,
}

/// Why an `AttributeStatement` could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unreadable {
    /// The element handed in is not a `saml:Assertion`.
    ///
    /// [`crate::verify`] takes the element to read as an ARGUMENT and hands back whatever was
    /// signed, so a caller may hold a verified `samlp:Response`. Its direct children hold no
    /// `AttributeStatement`, so without this guard the answer was an empty list.
    ///
    /// NOT ATTRIBUTED TO A VENDOR, and an earlier version of this sentence was: it claimed Okta
    /// and ADFS emit a Response-only-signed profile, which `crate::test_util::sign_response`'s
    /// own doc contradicts -- they sign the Response AND the assertion, which is why that helper
    /// exists. Response-only signing is a real configuration and the only shape where a
    /// Response is the ONLY verified element available, but the guard does not need it: a
    /// caller holding the wrong element is enough, and that needs no provider to behave in any
    /// particular way.
    ///
    /// AND AN EMPTY LIST IS A REAL ANSWER HERE, which is what makes the silence dangerous: this
    /// module documents "no attributes" as "the identity provider sent none", so a mapping that
    /// clears traits on absence would have wiped a department and a group list on a document
    /// that verified. [`crate::check`] guards its own input for the same reason.
    NotAnAssertion,
    /// An `Attribute` with no `Name`, or with an empty one.
    ///
    /// `Name` is required and is what a mapping keys on, so an attribute without a usable one
    /// could never be reached. Dropping it silently would hide a misconfiguration behind a trait
    /// that is simply never populated -- and send the operator to look at their mapping, which
    /// is fine, rather than at their identity provider, which is where the fault is.
    ///
    /// THE EMPTY STRING IS THE DEGENERATE INPUT the presence check alone does not catch, and a
    /// mapping keyed on `""` is not one anybody wrote on purpose.
    NamelessAttribute,
    /// Two `Attribute`s that name the same thing.
    ///
    /// SAML Core 2.7.3.1 identifies an attribute by its `Name` AND its `NameFormat`, so this
    /// compares BOTH: same `Name` under two different formats is two attributes, not a
    /// contradiction, and refusing that pair would refuse a conformant assertion. Under one
    /// format, a second element is a second CLAIM -- and taking either is choosing which half to
    /// believe, which somebody who can append chooses for the reader.
    Duplicate {
        /// The `Name` both carried.
        name: String,
        /// The `NameFormat` both carried, if any.
        name_format: Option<String>,
    },
}

impl core::fmt::Display for Unreadable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAnAssertion => {
                f.write_str("the signed element handed in is not a SAML assertion")
            }
            Self::NamelessAttribute => {
                f.write_str("the assertion carries an attribute with no usable name")
            }
            Self::Duplicate { name, name_format } => match name_format {
                Some(format) => write!(
                    f,
                    "the assertion says two different things about {name:?} in format {format:?}"
                ),
                None => write!(f, "the assertion says two different things about {name:?}"),
            },
        }
    }
}

impl core::error::Error for Unreadable {}

/// What an assertion's `AttributeStatement`s said, and what they said that this cannot read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Statement {
    /// The plaintext attributes, in document order.
    pub attributes: Vec<Attribute>,
    /// How many `saml:EncryptedAttribute` elements were present and not decrypted.
    ///
    /// A COUNT RATHER THAN A REFUSAL, and rather than nothing. Refusing the whole assertion for
    /// one encrypted attribute contradicts this module's opening rule -- an attribute a caller
    /// cannot use is not a reason to refuse anybody -- and skipping them silently means an
    /// attribute an operator configured, that the provider sent, never arrives with nothing
    /// said.
    ///
    /// # What a caller can and CANNOT decide from it
    ///
    /// A count says only THAT something was withheld, never WHICH. The `Name` is inside the
    /// ciphertext -- an `EncryptedAttribute` carries an `xenc:EncryptedData` and nothing this
    /// layer can read -- so a field promising names would be one that could never be filled.
    ///
    /// So the decision this supports is coarse, and saying otherwise would be a contract nobody
    /// can honour: a caller can tell that a mapped trait's absence MIGHT be explained by an
    /// encrypted attribute rather than by the provider not sending it, and can log or surface
    /// that. It CANNOT tell whether the withheld attribute is one it maps. An earlier version of
    /// this doc claimed a deployment "mapping a name it can no longer see stops", which is a
    /// decision a `usize` makes impossible.
    ///
    /// A DEPLOYMENT THAT NEEDS THE DIFFERENCE has to decrypt, which needs the connection's
    /// private key -- the ACS endpoint's to hold, not this function's.
    pub encrypted: usize,
}

/// Every attribute in the assertion's `AttributeStatement`s, in document order.
///
/// # What is refused, and what is merely absent
///
/// Each refusal is an [`Unreadable`] variant with its own reason; see that type. What is NOT an
/// error:
///
/// - NO `AttributeStatement` AT ALL answers an empty list. An authentication assertion carrying
///   only an `AuthnStatement` is ordinary, and it is what an identity provider sends when a
///   relying party asked for nothing.
/// - An `Attribute` with no VALUES answers an attribute with an empty value list, for the reason
///   [`Attribute::values`] gives.
/// - An `AttributeValue` this module cannot turn into text answers [`Value::Structured`] rather
///   than failing the whole assertion.
///
/// # Errors
///
/// [`Unreadable`].
pub fn attributes(assertion: &VerifiedAssertion) -> Result<Statement, Unreadable> {
    // IT MUST BE AN ASSERTION, resolved rather than spelled, and [`crate::check`] guards its own
    // input with the identical line for the identical reason: `verify` takes the element to read
    // as an argument, so what arrives here is not necessarily an assertion -- and answering an
    // empty list for a `samlp:Response` is a silence this module's own semantics read as "the
    // identity provider sent no attributes".
    if !assertion.is(ASSERTION, "Assertion") {
        return Err(Unreadable::NotAnAssertion);
    }

    let mut out = Statement::default();
    // DIRECT CHILDREN, at both levels. `AttributeValue` is `xs:anyType`, so an assertion may
    // legitimately carry a whole `AttributeStatement` inside one -- and it is inside this
    // signature just as much as the real one, so a descendant search would collect somebody
    // else's attributes. The condition layer learned this the expensive way.
    //
    // (`saml:Advice` would be the other route to a nested statement, and `verify` closes it
    // upstream by refusing a document with two `saml:Assertion` candidates. Named as unreachable
    // rather than offered as the reason, because a guard justified by an example no fixture can
    // build is a guard nobody will keep.)
    for statement in assertion.children(ASSERTION, "AttributeStatement") {
        // AN ENCRYPTED ATTRIBUTE IS THE SIBLING OF A PLAINTEXT ONE and this reads only the
        // second, so the presence of one is COUNTED rather than stepped over -- and counted
        // rather than refused, because refusing would discard every attribute this assertion
        // does carry in the clear.
        out.encrypted += statement.children(ASSERTION, "EncryptedAttribute").len();
        for attribute in statement.children(ASSERTION, "Attribute") {
            // TRIMMED FOR THE CHECK, NOT FOR THE VALUE. `Name=" "` is present and non-empty,
            // so a check on emptiness alone admits it -- and a mapping keyed on a space is no
            // more usable than one keyed on the empty string. The value handed back stays
            // untrimmed, because a Name is compared as a string and this crate does not get to
            // decide two providers' names are the same.
            let name = attribute.attribute("Name").unwrap_or_default();
            if name.trim().is_empty() {
                return Err(Unreadable::NamelessAttribute);
            }
            let name_format = attribute.attribute("NameFormat").map(ToOwned::to_owned);
            // ACROSS THE WHOLE ASSERTION, not per statement: an identity provider assembling a
            // response from two sources emits two statements, and that is exactly where a
            // collision arrives.
            // COMPARED ON THE EFFECTIVE FORMAT, not the surface spelling. SAML Core 2.7.3.1
            // says an absent `NameFormat` MEANS `unspecified` -- which this file states in
            // [`Attribute::name_format`]'s own doc -- so comparing `Option<String>` made one
            // attribute sent twice into two attributes, and adding the optional attribute to
            // the second element turned a refusal into a silent choice between two values.
            // COLLAPSED BEFORE COMPARING, because `NameFormat` is an `xsd:anyURI` and XSD gives
            // that type the `collapse` whiteSpace facet -- so ` urn:...:unspecified ` and the
            // flush spelling are one value to every schema-aware reader. Comparing them raw
            // re-opens the hole this rule was written to close, one space at a time.
            let effective = collapse(name_format.as_deref().unwrap_or(UNSPECIFIED));
            if out.attributes.iter().any(|seen| {
                seen.name == name
                    && collapse(seen.name_format.as_deref().unwrap_or(UNSPECIFIED)) == effective
            }) {
                return Err(Unreadable::Duplicate {
                    name: name.to_owned(),
                    name_format,
                });
            }
            let values = attribute
                .children(ASSERTION, "AttributeValue")
                .iter()
                .map(value_of)
                .collect();
            out.attributes.push(Attribute {
                name: name.to_owned(),
                name_format,
                values,
            });
        }
    }
    Ok(out)
}

/// XSD `whiteSpace="collapse"`, over the four characters the specification names.
///
/// Not `split_whitespace`, which splits on the whole Unicode whitespace property: XML Schema
/// Part 2 names exactly `#x9`, `#xA`, `#xD` and `#x20`, and everything else is a character of
/// the value. The same rule `ironauth-saml`'s condition layer applies to `saml:Audience`.
fn collapse(text: &str) -> String {
    text.split(['\t', '\n', '\r', ' '])
        .filter(|piece| !piece.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// One `AttributeValue`, as text, emptiness, or a shape.
fn value_of(value: &crate::verify::SignedElement<'_>) -> Value {
    let children = value.element_children_resolved();
    if !children.is_empty() {
        return Value::Structured(
            children
                .into_iter()
                .map(|(namespace, local, element)| Child {
                    namespace,
                    local,
                    // `text_simple` and not `text`: a child that itself has element children
                    // answers an empty string rather than its descendants concatenated, for the
                    // reason this whole variant exists.
                    text: element.text_simple().unwrap_or_default(),
                })
                .collect(),
        );
    }
    match value.text_simple() {
        Some(text) if !text.is_empty() => Value::Text(text),
        // No text and no elements. `<AttributeValue/>`, `<AttributeValue></AttributeValue>` and
        // `<AttributeValue xsi:nil="true"/>` all land here; see [`Value::Empty`].
        _ => Value::Empty,
    }
}
