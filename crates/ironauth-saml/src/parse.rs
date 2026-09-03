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
    /// and still a million allocations.
    pub max_elements: usize,
    /// The most attributes accepted on any one element.
    ///
    /// A review measured one element carrying five thousand attributes, and a megabyte of them,
    /// passing every other bound: depth and element count say nothing about what hangs off a
    /// single element. `xml-rs` bounds this by default and an earlier version of this crate did
    /// not, which the library evaluation now says out loud.
    pub max_attributes: usize,
    /// The longest element or attribute NAME accepted, in bytes.
    ///
    /// Names are the one thing [`Element`] retains, so an unbounded name is the one input that
    /// can make the retained tree large without making the document deep or wide. A review
    /// measured a half-megabyte element name surviving.
    pub max_name_bytes: usize,
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
            max_attributes: 128,
            max_name_bytes: 256,
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
    /// An element carries more attributes than [`Limits::max_attributes`], or a name longer
    /// than [`Limits::max_name_bytes`].
    ///
    /// One variant for both because both are the same statement about one element: it is
    /// bigger than anything SAML describes.
    ElementTooLarge,
    /// The document declares an encoding this crate does not accept.
    ///
    /// UTF-8 only, and a declaration naming anything else is refused rather than ignored. The
    /// bytes are already required to be UTF-8, so a document saying `UTF-16` is telling a
    /// conforming peer to read it differently from how this reads it -- and a parser
    /// differential is the seed of the disagreement this crate exists to prevent.
    EncodingNotUtf8,
    /// The document carries an entity or character reference this crate does not accept.
    ///
    /// With no `DOCTYPE` there is nothing that could have defined an entity, so a reference to
    /// anything but the five XML built-ins names one that does not exist. A NUMERIC character
    /// reference is accepted only when it names a legal character.
    ///
    /// Refused rather than passed through, because "the value silently became shorter" is how a
    /// `NameID` becomes somebody else. IN TEXT AND IN ATTRIBUTE VALUES ALIKE, which is worth
    /// saying because the parser only reports the first: a reference inside an attribute rides
    /// in the raw start tag and is checked by this crate rather than by it.
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
            Self::ElementTooLarge => "an element carries too many attributes or too long a name",
            Self::EncodingNotUtf8 => "the document declares an encoding other than UTF-8",
            Self::UnknownEntity => "the document carries an unacceptable reference",
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

/// Drop the tree ITERATIVELY, because the derived one recurses and the depth is a caller's
/// number.
///
/// [`parse`] is iterative and cannot overflow, but the tree's own destructor is a recursive
/// consumer, and [`Limits::max_depth`] is a public field with no ceiling whose documentation
/// invites raising it. A review measured a document parsed at depth 60000 aborting the process
/// on drop -- `fatal runtime error: stack overflow` -- which is a misconfiguration cliff with a
/// hard abort at the end of it and not a refusal anybody can catch.
///
/// So the destructor takes the children out and drops them from a worklist. Each child is left
/// with no children of its own by the time it is dropped, so the recursive drop it would
/// otherwise perform bottoms out immediately.
impl Drop for Element {
    fn drop(&mut self) {
        let mut pending = core::mem::take(&mut self.children);
        while let Some(mut element) = pending.pop() {
            pending.append(&mut element.children);
        }
    }
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
    // NO `trim_text`. It was set here with a justification, and a review measured that it had no
    // observable effect: every text event is discarded anyway. It matters now that it is OFF,
    // because whitespace between the prolog and the document element is legal `Misc` and the
    // rule below has to be able to tell it from content.

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
            Ok(Event::GeneralRef(reference)) => check_reference(reference.as_ref())?,
            Ok(Event::Start(start)) => {
                elements += 1;
                if elements > limits.max_elements {
                    return Err(SamlError::TooManyElements);
                }
                if stack.len() >= limits.max_depth {
                    return Err(SamlError::TooDeep);
                }
                stack.push(Element {
                    name: element_name(&start, limits)?,
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
                    name: element_name(&empty, limits)?,
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
            // AN ENCODING DECLARATION THAT IS NOT UTF-8 IS REFUSED, not ignored. The bytes are
            // already required to be UTF-8, so a document declaring `UTF-16` is telling a
            // conforming peer to read it differently from how this reads it, and two components
            // reading one document differently is the whole defect class this crate is about.
            Ok(Event::Decl(decl)) => {
                if let Some(Ok(encoding)) = decl.encoding() {
                    if !encoding.eq_ignore_ascii_case(b"utf-8") {
                        return Err(SamlError::EncodingNotUtf8);
                    }
                }
            }
            // Text, CDATA, comments and processing instructions carry no structure this module
            // records -- but WHERE they appear is structure. XML 1.0's `document` production is
            // `prolog element Misc*`, so anything other than a comment, a processing instruction
            // or whitespace outside the document element makes this not a document. A review
            // measured `<Response/>TRAILING JUNK` and a leading-text variant being accepted here
            // while every conforming processor rejects them, which is a parser differential
            // against exactly the peer a signature has to agree with.
            Ok(Event::Text(text)) if stack.is_empty() => {
                if !text.as_ref().iter().all(u8::is_ascii_whitespace) {
                    return Err(SamlError::Malformed);
                }
            }
            Ok(Event::CData(_)) if stack.is_empty() => return Err(SamlError::Malformed),
            Ok(_) => {}
        }
    }
    // NO UNCLOSED-STACK CHECK HERE. `check_end_names` refuses an unclosed element at EOF, so a
    // check on the stack afterwards is unreachable -- a review deleted one that used to sit here
    // and no test noticed, which is what an unreachable guard looks like.
    root.map(|root| Document { root })
        .ok_or(SamlError::Malformed)
}

/// Accept a reference the XML specification defines itself; refuse everything else.
///
/// The five built-in entities need no DTD, so a document may use them with no DOCTYPE. A
/// NUMERIC CHARACTER REFERENCE is likewise defined by the specification, but only when it names
/// a legal character, and this is where an earlier version was too generous: it delegated to
/// `is_char_ref`, which tests for a leading `#` and nothing more. A review measured `&#zzz;`,
/// `&#xD800;` (a surrogate) and `&#x110000;` (out of range) all walking through -- none of them
/// a character reference at all, and each rejected by any conforming processor.
///
/// Everything else names an entity that could only have been declared in a DOCTYPE, and this
/// crate accepts no DOCTYPE, so it names something that cannot exist.
fn check_reference(name: &[u8]) -> Result<(), SamlError> {
    if matches!(name, b"amp" | b"lt" | b"gt" | b"quot" | b"apos") {
        return Ok(());
    }
    let Some(digits) = name.strip_prefix(b"#") else {
        return Err(SamlError::UnknownEntity);
    };
    let (digits, radix) = match digits
        .strip_prefix(b"x")
        .or_else(|| digits.strip_prefix(b"X"))
    {
        Some(hex) => (hex, 16),
        None => (digits, 10),
    };
    let text = core::str::from_utf8(digits).map_err(|_| SamlError::UnknownEntity)?;
    if text.is_empty() {
        return Err(SamlError::UnknownEntity);
    }
    let code = u32::from_str_radix(text, radix).map_err(|_| SamlError::UnknownEntity)?;
    // `char::from_u32` is exactly the specification's `Char` production minus the control
    // characters: it refuses surrogates and anything above the last code point. The remaining
    // exclusions (NUL and the other forbidden controls) are checked here because a reference
    // that produced one would be a document a conforming peer rejects.
    let Some(resolved) = char::from_u32(code) else {
        return Err(SamlError::UnknownEntity);
    };
    if is_forbidden_char(resolved) {
        return Err(SamlError::UnknownEntity);
    }
    Ok(())
}

/// Whether `value` is outside XML 1.0's `Char` production.
///
/// The production admits tab, newline and carriage return and no other C0 control, and excludes
/// the surrogate range (which `char` already cannot hold) and the two non-characters at the end
/// of the BMP.
fn is_forbidden_char(value: char) -> bool {
    matches!(value, '\u{0}'..='\u{8}' | '\u{b}' | '\u{c}' | '\u{e}'..='\u{1f}' | '\u{fffe}' | '\u{ffff}')
}

/// The element's name, having checked everything about the element this module bounds.
///
/// THE ATTRIBUTES ARE WALKED HERE AND NOWHERE ELSE, and that is the point of the function. An
/// entity reference inside an ATTRIBUTE value does not produce a `GeneralRef` event: quick-xml
/// only tokenises references in text, so `Destination="&whoami;"` rode straight through an
/// earlier version of this parser while the identical reference in a text node was refused.
/// Same bytes, one position change, opposite verdict -- and attributes are where SAML actually
/// carries its attacker-controlled values (`Destination`, `ID`, `InResponseTo`, `Format`).
///
/// Names are bounded because they are the one thing [`Element`] retains, and attributes are
/// counted because nothing else in this module says anything about what hangs off one element.
fn element_name(
    start: &quick_xml::events::BytesStart<'_>,
    limits: &Limits,
) -> Result<String, SamlError> {
    let raw = start.name();
    let raw = raw.as_ref();
    if raw.len() > limits.max_name_bytes {
        return Err(SamlError::ElementTooLarge);
    }
    // A NAME MUST LOOK LIKE A NAME. quick-xml does not validate the `Name` production, so a NUL
    // or any other control byte sits happily inside one: a review measured `<Signature\0/>`
    // parsing, with `name()` not equal to `"Signature"`. A signature-locating step matching on
    // the name would not see that node while a C-based verifier reading the same bytes would,
    // which is a wrapping primitive to close before the signature half exists.
    if raw.iter().any(|byte| !is_name_byte(*byte)) {
        return Err(SamlError::Malformed);
    }
    let mut attributes = 0_usize;
    for attribute in start.attributes() {
        // A malformed or DUPLICATED attribute. The duplicate is the one worth naming: two `ID`
        // attributes on one element is a wrapping primitive, and quick-xml's own checker is what
        // catches it.
        let attribute = attribute.map_err(|_| SamlError::Malformed)?;
        attributes += 1;
        if attributes > limits.max_attributes {
            return Err(SamlError::ElementTooLarge);
        }
        if attribute.key.as_ref().len() > limits.max_name_bytes {
            return Err(SamlError::ElementTooLarge);
        }
        check_attribute_value(&attribute.value)?;
    }
    core::str::from_utf8(raw)
        .map(ToOwned::to_owned)
        .map_err(|_| SamlError::Malformed)
}

/// Whether `byte` may appear in an element or attribute name.
///
/// Deliberately CONSERVATIVE rather than the full `NameChar` production: everything SAML and
/// XML Signature name is ASCII letters, digits, `-`, `.`, `_` and the `:` of a prefix, and a
/// multi-byte UTF-8 sequence is admitted wholesale because refusing it would refuse legal
/// documents this crate has no reason to refuse. What is closed is the control range, the
/// space, and the delimiters, which is where the parser differentials live.
fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b':') || byte >= 0x80
}

/// Apply the entity rule to a raw attribute value.
///
/// The parser hands attribute values over untouched, so this is the only place the rule can be
/// applied to them. A bare `&` is refused too: it is not well-formed XML, and quick-xml does not
/// refuse it inside an attribute the way it does in text.
fn check_attribute_value(value: &[u8]) -> Result<(), SamlError> {
    let mut rest = value;
    while let Some(start) = rest.iter().position(|byte| *byte == b'&') {
        let after = &rest[start + 1..];
        let Some(end) = after.iter().position(|byte| *byte == b';') else {
            return Err(SamlError::Malformed);
        };
        check_reference(&after[..end])?;
        rest = &after[end + 1..];
    }
    Ok(())
}
