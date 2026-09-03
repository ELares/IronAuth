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
    /// kilobytes; a megabyte is twenty to fifty times that and still small enough that a parse
    /// cannot be a memory attack. The bound is checked BEFORE parsing begins, so an
    /// oversized document costs one length comparison rather than a parse.
    pub max_bytes: usize,
    /// The deepest element nesting accepted, clamped at [`DEPTH_CEILING`].
    ///
    /// CLAMPED RATHER THAN TRUSTED: the tree is walked recursively by three derived impls, so a
    /// caller who raised this past what a stack can hold would arm a process abort rather than a
    /// refusal. Asking for more than the ceiling is not an error; it gets the ceiling.
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
    /// THIS CRATE HAS NO PER-VALUE OR PER-TEXT BOUND, which is worth saying beside the ones it
    /// does have: a single attribute value or text node is bounded only in aggregate by
    /// [`Limits::max_bytes`]. That is defensible -- neither is retained, so neither can outlive
    /// the parse -- and `xml-rs` bounds both by default, which the library evaluation now says.
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

/// Drop the tree ITERATIVELY, because the derived one recurses.
///
/// [`parse`] is iterative and cannot overflow; the tree's own destructor is a recursive
/// consumer. A review measured a document parsed at depth 60000 aborting the process on drop --
/// `fatal runtime error: stack overflow` -- which is not a refusal anybody can catch.
///
/// The destructor takes the children out and drops them from a worklist, so each child is left
/// with no children of its own before its own drop runs.
///
/// IT IS NOT THE ONLY RECURSIVE CONSUMER, which is why [`DEPTH_CEILING`] exists: `Clone`,
/// `Debug` and `PartialEq` are derived and recurse too, and a later review measured all three
/// aborting at the same depth. Writing three more manual impls would leave the next derive to
/// find; capping the depth disarms every one of them at once.
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

/// The deepest nesting [`parse`] will produce, whatever a caller asks for.
///
/// [`Limits::max_depth`] is a public field a caller sets, and the tree is walked recursively by
/// three DERIVED impls (`Clone`, `Debug`, `PartialEq`) as well as by any consumer that writes
/// its own recursion. A review measured all of them aborting the process at depth 60000. This is
/// the ceiling that makes those unreachable rather than merely undocumented.
///
/// 512 is about fifty times what SAML's own schema nests. The stack a recursive walk costs at
/// that depth was MEASURED rather than estimated, because an earlier version of this sentence
/// said "a few tens of kilobytes" and was wrong by four to sixteen times: the derived `Debug`,
/// `Clone` and `PartialEq` overflow a 128 KiB stack in release and a 256 KiB one in debug, and
/// survive at 256 KiB and 512 KiB respectively. On a spawned thread's default two megabytes --
/// what a tokio worker gets -- one walk takes about a quarter. That is a real margin and not the
/// hundredfold the old sentence implied, and the constant is chosen knowing it.
pub const DEPTH_CEILING: usize = 512;

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
    // AND THE CALLER'S DEPTH IS CLAMPED, not trusted. See `DEPTH_CEILING`.
    let max_depth = limits.max_depth.min(DEPTH_CEILING);
    let text = core::str::from_utf8(bytes).map_err(|_| SamlError::Malformed)?;
    let mut reader = Reader::from_str(text);
    // `check_end_names` is the well-formedness rule that makes a start tag and its end tag one
    // fact rather than two. Without it a document could open `<Assertion>` and close
    // `</Response>` and the tree would still build, which is a way to make the shape a
    // signature step reasons about differ from the shape a schema validator would see.
    reader.config_mut().check_end_names = true;
    // AND COMMENT WELL-FORMEDNESS, which quick-xml leaves off by default. `--` inside a comment
    // is not well-formed XML, and #138 names a comment-truncation corpus as its own criterion:
    // comments are a declared attack surface for this crate, so the one switch the library
    // offers about them is not the one to leave at its default.
    reader.config_mut().check_comments = true;
    // NO `trim_text`. It was set here with a justification, and a review measured that it had no
    // observable effect: every text event is discarded anyway. It matters now that it is OFF,
    // because whitespace between the prolog and the document element is legal `Misc` and the
    // rule below has to be able to tell it from content.

    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    let mut elements = 0_usize;
    let mut seen_anything = false;
    loop {
        let event = reader.read_event();
        match event {
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
                // A REFERENCE IS CONTENT, so it obeys the same rule as text about WHERE it may
                // appear. An earlier version checked the reference and not its position, so
                // `<Response/>&#84;&#82;&#65;` was accepted while the same three characters
                // written literally were refused: the prolog rule had been applied to `Text` and
                // `CData` and not to the third thing that carries characters.
                if stack.is_empty() {
                    return Err(SamlError::Malformed);
                }
                check_reference(reference.as_ref())?;
            }
            Ok(Event::Start(start)) => {
                elements += 1;
                if elements > limits.max_elements {
                    return Err(SamlError::TooManyElements);
                }
                if stack.len() >= max_depth {
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
                if stack.len() >= max_depth {
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
                // AND IT MUST BE FIRST. XML 1.0 puts the declaration at the very start of the
                // document, before any comment, whitespace or element. The prolog rule was
                // extended to text, CDATA and references and not to this, so `<R><?xml
                // version="1.0"?></R>` and three other placements were accepted -- the same
                // class of differential as the trailing junk that rule exists to close.
                if seen_anything {
                    return Err(SamlError::Malformed);
                }
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
            // LITERAL CONTROL CHARACTERS ARE REFUSED WHEREVER THEY APPEAR, which an earlier
            // version did only for REFERENCES: `&#0;` was refused and a literal NUL in the same
            // `NameID` was accepted, so one byte reached opposite verdicts by how it was written
            // -- and the literal is the easier one to send. A NUL in a `NameID` is the classic
            // truncation primitive against a C consumer.
            Ok(Event::Text(ref text)) if !stack.is_empty() => {
                check_literal_characters(text.as_ref())?;
            }
            Ok(Event::CData(ref data)) if !stack.is_empty() => {
                check_literal_characters(data.as_ref())?;
            }
            // COMMENTS AND PROCESSING INSTRUCTIONS CARRY CHARACTER DATA TOO, and an earlier
            // version said "wherever they appear" while checking three of the five places. A
            // review measured `<NameID>a<!--\0-->b</NameID>` and `<NameID>a<?p \0?>b</NameID>`
            // accepted beside the literal NUL in the text being refused, and #138 names a
            // comment-truncation corpus as its own criterion: comments are a declared attack
            // surface here.
            Ok(Event::Comment(ref text)) => check_literal_characters(text.as_ref())?,
            Ok(Event::PI(ref pi)) => check_literal_characters(pi.as_ref())?,
            Ok(Event::Text(text)) if stack.is_empty() => {
                // XML's `S` production is space, tab, carriage return and newline. Rust's
                // `is_ascii_whitespace` also admits form feed, which is not even a legal `Char`:
                // `<Response/>` followed by 0x0C was accepted while `&#12;` was refused, the
                // same character reaching two verdicts by how it was written.
                if !text.as_ref().iter().all(|byte| is_xml_space(*byte)) {
                    return Err(SamlError::Malformed);
                }
            }
            Ok(Event::CData(_)) if stack.is_empty() => return Err(SamlError::Malformed),
            Ok(_) => {}
        }
        seen_anything = true;
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
    // THE PRODUCTION, NOT SOMETHING NEAR IT. XML 1.0 [66] is
    // `'&#' [0-9]+ ';' | '&#x' [0-9a-fA-F]+ ';'`: lowercase `x` only, and no sign. Rust's
    // `from_str_radix` accepts a leading `+`, and an earlier version of this also took `X`, so
    // `&#+65;`, `&#x+41;` and `&#X41;` were all accepted here and rejected by every conforming
    // processor. A test even pinned the last one as legal.
    let (digits, radix) = match digits.strip_prefix(b"x") {
        Some(hex) => (hex, 16),
        None => (digits, 10),
    };
    if digits.is_empty() {
        return Err(SamlError::UnknownEntity);
    }
    let legal = |byte: &u8| {
        if radix == 16 {
            byte.is_ascii_hexdigit()
        } else {
            byte.is_ascii_digit()
        }
    };
    if !digits.iter().all(legal) {
        return Err(SamlError::UnknownEntity);
    }
    let text = core::str::from_utf8(digits).map_err(|_| SamlError::UnknownEntity)?;
    let code = u32::from_str_radix(text, radix).map_err(|_| SamlError::UnknownEntity)?;
    // `char::from_u32` refuses surrogates and anything above the last code point, which is two
    // of `Char`'s exclusions and not all of them: it admits the forbidden C0 controls AND
    // U+FFFE and U+FFFF, none of which is in the production. `is_forbidden_char` is what covers
    // the rest, and an earlier version of this comment described it as covering "the control
    // characters" only.
    let Some(resolved) = char::from_u32(code) else {
        return Err(SamlError::UnknownEntity);
    };
    if is_forbidden_char(resolved) {
        return Err(SamlError::UnknownEntity);
    }
    Ok(())
}

/// Refuse any character outside XML 1.0's `Char` production, written literally.
///
/// `check_reference` already refuses a REFERENCE to one. This is the same rule for the bytes
/// themselves, and without it the two disagree: `&#0;` refused, a literal NUL accepted.
fn check_literal_characters(raw: &[u8]) -> Result<(), SamlError> {
    let text = core::str::from_utf8(raw).map_err(|_| SamlError::Malformed)?;
    if text.chars().any(is_forbidden_char) {
        return Err(SamlError::Malformed);
    }
    Ok(())
}

/// Whether `byte` is XML's `S`: space, tab, carriage return, newline, and nothing else.
fn is_xml_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
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
    check_name(raw)?;
    let mut attributes = 0_usize;
    for attribute in start.attributes() {
        // A malformed or DUPLICATED attribute. The duplicate is the one worth naming: two `ID`
        // attributes on one element is a wrapping primitive, and quick-xml's own checker is what
        // catches it.
        //
        // ON THE RAW NAME, NOT THE EXPANDED ONE, which is the limit of what this catches:
        // `<A xmlns:a="u" xmlns:b="u" a:ID="1" b:ID="2"/>` carries two attributes with the same
        // EXPANDED name, violates Namespaces in XML section 6.3, and is accepted here because
        // the two raw keys differ. It cannot duplicate SAML's own `ID`, which is unprefixed, and
        // closing it needs namespace resolution -- which the signature half performs and this
        // module deliberately does not.
        let attribute = attribute.map_err(|_| SamlError::Malformed)?;
        attributes += 1;
        if attributes > limits.max_attributes {
            return Err(SamlError::ElementTooLarge);
        }
        if attribute.key.as_ref().len() > limits.max_name_bytes {
            return Err(SamlError::ElementTooLarge);
        }
        // THE SAME NAME RULE AS THE ELEMENT, and an earlier version applied it only to the
        // element. That is the half of the tag where SAML does NOT keep `ID`: a review sent
        // `<Assertion ID="_real" ID\0="_forged"/>` and the duplicate check saw two different
        // names, so one NUL walked around the guard whose own comment explains why a NUL in a
        // name is a wrapping primitive. `ID` is what `XMLDSig`'s `Reference URI="#..."` resolves
        // against.
        check_name(attribute.key.as_ref())?;
        check_attribute_value(&attribute.value)?;
    }
    core::str::from_utf8(raw)
        .map(ToOwned::to_owned)
        .map_err(|_| SamlError::Malformed)
}

/// Hold a name to something close enough to XML's `Name` production to close the differentials.
///
/// Deliberately CONSERVATIVE rather than the full production, which is pages of Unicode ranges:
/// everything SAML and XML Signature name is ASCII letters, digits, `-`, `.`, `_` and the `:`
/// of a prefix. What must be closed is anything that lets one reader see a different name from
/// another, so this refuses the ASCII control range, the delimiters, and -- decoding the name,
/// which is cheap and already necessary -- every Unicode whitespace character and the byte-order
/// mark. An earlier version admitted every byte at or above 0x80 wholesale and claimed to have
/// closed "the control range, the space, and the delimiters"; a review sent `Sig\u{a0}nature`,
/// `Sig\u{2000}nature` and `Signature\u{feff}` straight through it.
///
/// The FIRST character is checked separately, because `9Signature` and `.Signature` are not
/// names in any XML processor and were accepted here.
fn check_name(raw: &[u8]) -> Result<(), SamlError> {
    let name = core::str::from_utf8(raw).map_err(|_| SamlError::Malformed)?;
    let mut characters = name.chars();
    let Some(first) = characters.next() else {
        return Err(SamlError::Malformed);
    };
    if !is_name_start(first) {
        return Err(SamlError::Malformed);
    }
    if !characters.all(is_name_char) {
        return Err(SamlError::Malformed);
    }
    Ok(())
}

/// Whether `value` may START a name: a letter, `_` or `:`.
///
/// ASCII AND NON-ASCII ALIKE, which an earlier version got wrong: it delegated to
/// [`is_name_char`] above 0x7F, so there was effectively no start rule for a non-ASCII name and
/// `<\u{301}a/>` (a leading combining acute), `<\u{b7}a/>` and `<\u{660}a/>` (an Arabic-Indic
/// digit) were all accepted. A review measured each; none is a `NameStartChar`.
fn is_name_start(value: char) -> bool {
    if value.is_ascii() {
        return value.is_ascii_alphabetic() || matches!(value, '_' | ':');
    }
    value.is_alphabetic()
}

/// Whether `value` may appear anywhere in a name.
///
/// # An ALLOWLIST, because a denylist kept missing invisible characters
///
/// The previous rule was "not whitespace, not a control, not the byte-order mark", and a review
/// walked `Sig\u{202e}nature` (a right-to-left override), `Sig\u{200b}nature` (a zero-width
/// space), `Sig\u{ad}nature` (a soft hyphen) and `Sig\u{2064}nature` through it, plus
/// `a\u{ffff}b` -- which this crate's own [`is_forbidden_char`] refuses in text and in a
/// reference. One character, five positions, and the name was the position that accepted it.
/// The name is exactly what a signature-locating step matches on.
///
/// So this admits only what a name is made of: letters and digits in any script, the four ASCII
/// name punctuation characters, and the combining marks and middle dot XML's `NameChar` adds.
/// Everything else is out, which is the direction that cannot be wrong by omission.
///
/// It is CONSERVATIVE in one known place and that is deliberate: `\u{1680}` (OGHAM SPACE MARK)
/// is a legal `NameStartChar` and is refused here, because Rust reports it as whitespace.
/// Refusing a legal name nobody sends is the safe side of this trade.
fn is_name_char(value: char) -> bool {
    if value.is_ascii() {
        return value.is_ascii_alphanumeric() || matches!(value, '-' | '.' | '_' | ':');
    }
    if value.is_whitespace() || value.is_control() || is_forbidden_char(value) {
        return false;
    }
    // `NameChar` beyond `NameStartChar`: the combining-mark block, the middle dot, and the two
    // joiners the production names.
    value.is_alphanumeric()
        || matches!(
            value,
            '\u{b7}' | '\u{300}'..='\u{36f}' | '\u{203f}' | '\u{2040}'
        )
}

/// Apply the entity rule to a raw attribute value.
///
/// The parser hands attribute values over untouched, so this is the only place the rule can be
/// applied to them. A bare `&` is refused too: it is not well-formed XML, and quick-xml does not
/// refuse it inside an attribute the way it does in text.
fn check_attribute_value(value: &[u8]) -> Result<(), SamlError> {
    // NO RAW `<`. XML's "No `<` in Attribute Values" well-formedness constraint, and this
    // scanner already refuses a bare `&` on exactly the reasoning that it is not well-formed --
    // and then let the more dangerous delimiter through. A review sent
    // `Destination="x<Assertion ID=&quot;_a&quot;/>"` and it parsed.
    if value.contains(&b'<') {
        return Err(SamlError::Malformed);
    }
    check_literal_characters(value)?;
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
