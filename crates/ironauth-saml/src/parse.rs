// SPDX-License-Identifier: MIT OR Apache-2.0

//! Parsing posture: what a document must survive before anything looks at a signature.

use quick_xml::events::Event;
use quick_xml::reader::Reader;

/// The bounds a document must fit inside, and the reason each exists.
///
/// # These are refusals, not truncations
///
/// Every bound here rejects the whole document. A parser that truncated instead would hand the
/// next stage a prefix, and the next stage is signature verification: a prefix that verifies is
/// exactly the "validate one thing, consume another" defect this crate exists to make
/// impossible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The largest document accepted, in bytes.
    ///
    /// A SAML response carrying an encrypted assertion and a certificate chain is a few tens of
    /// kilobytes; a megabyte is generous by two orders of magnitude and still small enough that
    /// a parse cannot be a memory attack. The bound is checked BEFORE parsing begins, so an
    /// oversized document costs one length comparison rather than a parse.
    pub max_bytes: usize,
    /// The deepest element nesting accepted.
    ///
    /// SAML's own schema nests about ten deep at its worst. This bound is what stops a document
    /// whose only content is nesting: without entity expansion (see the crate doc) that is the
    /// remaining way to make a small document expensive, and a recursive consumer of the tree
    /// would blow its stack long before memory ran out.
    pub max_depth: usize,
    /// The most elements accepted, counted across the whole document.
    ///
    /// Depth alone does not bound work: a flat document of a million empty elements is shallow
    /// and still a million allocations. This is the bound on the total, and the two together
    /// bound the tree.
    pub max_elements: usize,
}

impl Default for Limits {
    /// Bounds sized for real SAML rather than for the schema's theoretical maximum.
    ///
    /// A deployment that needs more can say so; the point of a default is that a deployment
    /// that has not thought about it is not the one running unbounded.
    fn default() -> Self {
        Self {
            max_bytes: 1024 * 1024,
            max_depth: 64,
            max_elements: 10_000,
        }
    }
}

/// Why a document was refused.
///
/// EVERY VARIANT IS A REFUSAL OF THE WHOLE DOCUMENT. There is no partial success in this
/// module, and no variant carries a fragment of the input: an error message that quoted the
/// document would be a way to read an unverified value out of it, which is precisely what
/// [`Document`] exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamlError {
    /// The document declares a `DOCTYPE`.
    ///
    /// Refused outright rather than parsed and ignored. A DTD is the carrier for external
    /// entities (XXE) and for entity expansion (billion laughs), and while this crate's parser
    /// resolves neither, "the parser happens not to implement the attack" is a weaker statement
    /// than "the document that would carry it is refused". This is the one that makes XXE
    /// structurally impossible rather than merely unimplemented.
    DoctypeForbidden,
    /// The document is larger than [`Limits::max_bytes`].
    TooLarge,
    /// Elements nest deeper than [`Limits::max_depth`].
    TooDeep,
    /// The document holds more elements than [`Limits::max_elements`].
    TooManyElements,
    /// The document carries an unresolved entity reference.
    ///
    /// With no `DOCTYPE` there is nothing that could have defined one, so a reference to
    /// anything but the five XML built-ins names an entity that does not exist. The parser
    /// hands it back unresolved; this refuses it rather than letting it reach a consumer as an
    /// empty string, because "the value silently became empty" is how a `NameID` becomes
    /// somebody else.
    UnknownEntity,
    /// The bytes are not well-formed XML, or the document holds no element.
    ///
    /// One variant for every malformedness on purpose: a caller cannot act on the difference,
    /// and a taxonomy of parse failures is a taxonomy an attacker can use to learn what the
    /// parser is.
    Malformed,
}

impl core::fmt::Display for SamlError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::DoctypeForbidden => "the document declares a DOCTYPE",
            Self::TooLarge => "the document is too large",
            Self::TooDeep => "the document nests too deeply",
            Self::TooManyElements => "the document holds too many elements",
            Self::UnknownEntity => "the document references an undefined entity",
            Self::Malformed => "the document is not well-formed XML",
        })
    }
}

impl core::error::Error for SamlError {}

/// One element of a parsed document.
///
/// # It has a name and it has children, and that is all
///
/// There is no attribute accessor and no text accessor here, and their absence is the point of
/// this type rather than an omission to be filled in later. Everything an attacker wants out of
/// a SAML document is an attribute value or a text node -- the `NameID`, the attribute
/// statements, the `Destination`, the `InResponseTo` -- and none of it may be readable from a
/// document nobody has verified.
///
/// The values live behind the verified type that the signature half of #138 introduces. A
/// caller that has a [`Document`] can see the SHAPE of what it was sent, which is what a
/// signature step needs in order to find the node it must verify, and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    name: String,
    children: Vec<Element>,
}

impl Element {
    /// The element's qualified name, exactly as it appeared.
    ///
    /// Deliberately the RAW qualified name and not a resolved namespace: resolution is a
    /// decision about what the document means, and this module makes no such decisions. The
    /// signature half resolves namespaces against the specification's own bindings.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The element's children, in document order.
    #[must_use]
    pub fn children(&self) -> &[Element] {
        &self.children
    }
}

/// A document that survived the bounds and carries no DOCTYPE.
///
/// UNVERIFIED, and the type says so by what it cannot do. See [`Element`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    root: Element,
}

impl Document {
    /// The document element.
    #[must_use]
    pub fn root(&self) -> &Element {
        &self.root
    }
}

/// Parse `bytes` as a SAML document, refusing anything outside `limits`.
///
/// This is the only way to turn bytes into a [`Document`], and the only way to obtain a
/// [`Document`] at all.
///
/// # The order is the contract
///
/// Size, then DOCTYPE, then structure. Nothing about a signature happens here, and no consumer
/// of this crate can reach a signature check without having come through this function first,
/// because the type a signature check takes is the one only this function makes.
///
/// # Errors
///
/// [`SamlError`], one variant per refusal. No error carries any part of the input.
pub fn parse(bytes: &[u8], limits: &Limits) -> Result<Document, SamlError> {
    // FIRST, and before a parser sees a byte: an oversized document costs one comparison.
    if bytes.len() > limits.max_bytes {
        return Err(SamlError::TooLarge);
    }
    let text = core::str::from_utf8(bytes).map_err(|_| SamlError::Malformed)?;
    let mut reader = Reader::from_str(text);
    // `check_end_names` is the well-formedness rule that makes a start tag and its end tag one
    // fact rather than two. Without it a document could open `<Assertion>` and close
    // `</Response>` and the tree would still build, which is a way to make the shape a
    // signature step reasons about differ from the shape a schema validator would see.
    reader.config_mut().check_end_names = true;
    // Whitespace-only text is not content here. The signature half canonicalises the exact
    // bytes it verifies from the ORIGINAL document rather than from this tree, so trimming here
    // cannot move what gets signed.
    reader.config_mut().trim_text(true);

    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    let mut elements = 0_usize;
    loop {
        match reader.read_event() {
            Err(_) => return Err(SamlError::Malformed),
            Ok(Event::Eof) => break,
            // THE REFUSAL THAT CLOSES XXE. A DOCTYPE is where an external entity would be
            // declared, so the document that could carry one never gets parsed.
            Ok(Event::DocType(_)) => return Err(SamlError::DoctypeForbidden),
            // AN ENTITY REFERENCE, and the parser hands over every one of them: it resolves
            // nothing itself, which is the property this crate chose it for.
            //
            // The five XML built-ins (`amp`, `lt`, `gt`, `quot`, `apos`) and numeric character
            // references are CONTENT: they are defined by the XML specification itself, need no
            // DTD, and appear in ordinary SAML (an `&` in a `NameID`). Everything else names an
            // entity that could only have been declared in a DOCTYPE, and this crate accepts no
            // DOCTYPE, so it names something that cannot exist.
            //
            // Refused rather than passed through, because the alternative is a value silently
            // becoming shorter: `<`NameID`>a&whoami;b</`NameID`>` would read as `ab` and a consumer
            // would have no way to know it had been handed a truncation.
            Ok(Event::GeneralRef(reference)) => {
                if !reference.is_char_ref() && !is_xml_builtin(reference.as_ref()) {
                    return Err(SamlError::UnknownEntity);
                }
            }
            Ok(Event::Start(start)) => {
                elements += 1;
                if elements > limits.max_elements {
                    return Err(SamlError::TooManyElements);
                }
                if stack.len() >= limits.max_depth {
                    return Err(SamlError::TooDeep);
                }
                stack.push(Element {
                    name: qualified_name(start.name().as_ref())?,
                    children: Vec::new(),
                });
            }
            Ok(Event::Empty(empty)) => {
                elements += 1;
                if elements > limits.max_elements {
                    return Err(SamlError::TooManyElements);
                }
                // An empty element is a start and an end at once, so it occupies a level while
                // it exists: a document of nothing but empty elements at the bound must not be
                // able to exceed it.
                if stack.len() >= limits.max_depth {
                    return Err(SamlError::TooDeep);
                }
                let leaf = Element {
                    name: qualified_name(empty.name().as_ref())?,
                    children: Vec::new(),
                };
                match stack.last_mut() {
                    Some(parent) => parent.children.push(leaf),
                    None if root.is_none() => root = Some(leaf),
                    // A second element at the top level: not well-formed XML.
                    None => return Err(SamlError::Malformed),
                }
            }
            Ok(Event::End(_)) => {
                let Some(done) = stack.pop() else {
                    return Err(SamlError::Malformed);
                };
                match stack.last_mut() {
                    Some(parent) => parent.children.push(done),
                    None if root.is_none() => root = Some(done),
                    None => return Err(SamlError::Malformed),
                }
            }
            // Text, CDATA, comments, processing instructions and the XML declaration carry no
            // structure this module records. They are NOT dropped from the document a signature
            // step verifies: that step reads the original bytes, not this tree.
            Ok(_) => {}
        }
    }
    if !stack.is_empty() {
        return Err(SamlError::Malformed);
    }
    root.map(|root| Document { root })
        .ok_or(SamlError::Malformed)
}

/// Whether `name` is one of the five entities the XML specification defines itself.
///
/// These need no DTD, so a document may use them with no DOCTYPE and this crate must accept
/// them. Numeric character references are handled by `is_char_ref` and are not here.
fn is_xml_builtin(name: &[u8]) -> bool {
    matches!(name, b"amp" | b"lt" | b"gt" | b"quot" | b"apos")
}

/// The element name as a `String`, refusing a name that is not UTF-8.
fn qualified_name(raw: &[u8]) -> Result<String, SamlError> {
    core::str::from_utf8(raw)
        .map(ToOwned::to_owned)
        .map_err(|_| SamlError::Malformed)
}
