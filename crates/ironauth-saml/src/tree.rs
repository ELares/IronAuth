// SPDX-License-Identifier: MIT OR Apache-2.0

//! The RICH tree, built by the same hostile posture as [`crate::parse`] and never handed out.
//!
//! # Why there are two trees
//!
//! [`crate::Document`] is what a caller gets, and it holds a name and its children so that a
//! parsed-but-unverified document cannot leak a value. Verification needs more than that: XML
//! Signature digests the CANONICAL FORM of a subtree, which is built from the element's
//! namespaces, its attributes and its text, so a verifier that could not see those could not
//! compute the digest at all.
//!
//! So the rich tree exists, and it is `pub(crate)`. Nothing outside this crate can name it, and
//! the only values that ever cross the boundary are the ones a
//! [`crate::VerifiedAssertion`] exposes after a signature has been checked.
//!
//! # This is where the crate doc's old claim about byte ranges was wrong
//!
//! The parser's evaluation used to say the signature half would need each node's byte range,
//! because XML Signature verifies "the exact bytes". It does not: it verifies the digest of the
//! node's CANONICAL FORM, which is re-serialised from the infoset by the rules in the
//! canonicalization specification, precisely so that two documents that differ only in
//! insignificant ways produce one digest. Byte ranges would in fact be the WRONG input.
//!
//! What the issue's "validate the signature over the exact node consumed afterward" asks for is
//! an IDENTITY property, not a byte one: the node whose digest was checked must be the node the
//! values are later read from. That is enforced here by construction --
//! [`crate::verify`] hands [`crate::VerifiedAssertion`] the very subtree it digested.

use quick_xml::events::Event;
use quick_xml::events::attributes::Attribute;
use quick_xml::reader::Reader;

use crate::parse::{DEPTH_CEILING, Limits, SamlError, check_document_event, check_name};

/// One attribute, as it appeared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RichAttribute {
    /// The qualified name, prefix included.
    pub(crate) name: String,
    /// The value, with references resolved to the characters they name.
    pub(crate) value: String,
}

/// One element of the rich tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RichElement {
    /// The qualified name, prefix included.
    pub(crate) name: String,
    /// Attributes in document order. Namespace declarations are here too: canonicalization
    /// treats them separately, and separating them at parse time would lose the order the
    /// document had.
    pub(crate) attributes: Vec<RichAttribute>,
    /// Children in document order.
    pub(crate) children: Vec<RichNode>,
}

/// A child of an element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RichNode {
    /// A nested element.
    Element(RichElement),
    /// Character data, with references resolved. CDATA sections are text here: the
    /// canonicalization specification replaces them with their content.
    Text(String),
    /// A processing instruction, target and instruction as written.
    ///
    /// KEPT, because the canonical form keeps it. Only COMMENTS are removed by the algorithm
    /// this crate accepts, and an earlier version dropped processing instructions here -- so a
    /// processing instruction could be added to or removed from the signed subtree without
    /// changing its digest, which is content inside the signature's coverage that the signature
    /// did not cover.
    ProcessingInstruction(String),
}

/// Drop the tree iteratively, for the reason `crate::parse::Element` does.
impl Drop for RichElement {
    fn drop(&mut self) {
        let mut pending = core::mem::take(&mut self.children);
        while let Some(node) = pending.pop() {
            if let RichNode::Element(mut element) = node {
                pending.append(&mut element.children);
            }
        }
    }
}

/// Build the rich tree, applying every refusal [`crate::parse`] applies.
///
/// # The two parsers agree because they share their rules
///
/// A second parser with its own copy of the posture is a second parser to keep in step, and two
/// parsers that disagree about what a document says is this crate's entire subject. So the
/// checks live in [`crate::parse`] and both callers run the same ones: `check_document_event`
/// decides what an event means for the document's structure, and this adds only the retention.
///
/// # Errors
///
/// [`SamlError`], exactly as [`crate::parse`] would answer for the same document.
pub(crate) fn build(bytes: &[u8], limits: &Limits) -> Result<RichElement, SamlError> {
    if bytes.len() > limits.max_bytes {
        return Err(SamlError::TooLarge);
    }
    let max_depth = limits.max_depth.min(DEPTH_CEILING);
    let text = core::str::from_utf8(bytes).map_err(|_| SamlError::Malformed)?;
    // END-OF-LINE NORMALISATION, which XML 1.0 section 2.11 makes the processor's job and which
    // quick-xml does not do: CRLF and a lone CR both become a single LF before anything else
    // sees them. Without it a document delivered with CRLF line endings emits `&#xD;` for every
    // line break inside a text node and its digest differs from every conforming signer's -- a
    // per-identity-provider interop failure that looks like "our SAML does not work with yours".
    //
    // A `&#xD;` written as a reference is NOT touched, which is the distinction the canonical
    // form draws: only a surviving carriage return is escaped, and only a reference can survive.
    let normalised = normalise_line_endings(text);
    let mut reader = Reader::from_str(&normalised);
    reader.config_mut().check_end_names = true;
    reader.config_mut().check_comments = true;

    let mut stack: Vec<RichElement> = Vec::new();
    let mut root: Option<RichElement> = None;
    let mut elements = 0_usize;
    let mut seen_anything = false;
    let mut pending_text = String::new();
    loop {
        let event = reader.read_event().map_err(|_| SamlError::Malformed)?;
        check_document_event(&event, stack.len(), root.is_some(), seen_anything)?;
        match event {
            Event::Eof => break,
            Event::Start(start) => {
                flush_text(&mut stack, &mut pending_text);
                elements += 1;
                if elements > limits.max_elements {
                    return Err(SamlError::TooManyElements);
                }
                if stack.len() >= max_depth {
                    return Err(SamlError::TooDeep);
                }
                stack.push(rich_element(&start, limits)?);
            }
            Event::Empty(empty) => {
                flush_text(&mut stack, &mut pending_text);
                elements += 1;
                if elements > limits.max_elements {
                    return Err(SamlError::TooManyElements);
                }
                if stack.len() >= max_depth {
                    return Err(SamlError::TooDeep);
                }
                let leaf = rich_element(&empty, limits)?;
                close(&mut stack, &mut root, leaf)?;
            }
            Event::End(_) => {
                flush_text(&mut stack, &mut pending_text);
                let Some(done) = stack.pop() else {
                    return Err(SamlError::Malformed);
                };
                close(&mut stack, &mut root, done)?;
            }
            Event::Text(ref content) if !stack.is_empty() => {
                pending_text.push_str(&decode(content.as_ref())?);
            }
            Event::CData(ref content) if !stack.is_empty() => {
                // CDATA is TEXT in the canonical form: the specification replaces the section
                // with its content, so keeping it as a distinct node would digest differently
                // from every conforming implementation.
                pending_text.push_str(
                    core::str::from_utf8(content.as_ref()).map_err(|_| SamlError::Malformed)?,
                );
            }
            Event::GeneralRef(ref reference) if !stack.is_empty() => {
                pending_text.push(resolve_reference(reference.as_ref())?);
            }
            Event::PI(ref pi) if !stack.is_empty() => {
                flush_text(&mut stack, &mut pending_text);
                let text = decode(pi.as_ref())?;
                if let Some(open) = stack.last_mut() {
                    open.children.push(RichNode::ProcessingInstruction(text));
                }
            }
            _ => {}
        }
        seen_anything = true;
    }
    root.ok_or(SamlError::Malformed)
}

/// Attach `done` to its parent, or make it the document element.
fn close(
    stack: &mut [RichElement],
    root: &mut Option<RichElement>,
    done: RichElement,
) -> Result<(), SamlError> {
    match stack.last_mut() {
        Some(parent) => parent.children.push(RichNode::Element(done)),
        None if root.is_none() => *root = Some(done),
        None => return Err(SamlError::Malformed),
    }
    Ok(())
}

/// Move any accumulated characters into the open element.
///
/// Accumulated rather than pushed per event, because one run of characters can arrive as
/// several events (text, then a reference, then more text) and the canonical form has ONE text
/// node there. A verifier that emitted three would digest differently from every conforming
/// implementation.
fn flush_text(stack: &mut [RichElement], pending: &mut String) {
    if pending.is_empty() {
        return;
    }
    if let Some(open) = stack.last_mut() {
        open.children.push(RichNode::Text(core::mem::take(pending)));
    } else {
        pending.clear();
    }
}

/// Build one element, applying the name and attribute rules.
fn rich_element(
    start: &quick_xml::events::BytesStart<'_>,
    limits: &Limits,
) -> Result<RichElement, SamlError> {
    let raw = start.name();
    let raw = raw.as_ref();
    if raw.len() > limits.max_name_bytes {
        return Err(SamlError::ElementTooLarge);
    }
    check_name(raw)?;
    let mut attributes = Vec::new();
    for attribute in start.attributes() {
        let attribute: Attribute<'_> = attribute.map_err(|_| SamlError::Malformed)?;
        if attributes.len() >= limits.max_attributes {
            return Err(SamlError::ElementTooLarge);
        }
        if attribute.key.as_ref().len() > limits.max_name_bytes {
            return Err(SamlError::ElementTooLarge);
        }
        check_name(attribute.key.as_ref())?;
        crate::parse::check_attribute_value(&attribute.value)?;
        attributes.push(RichAttribute {
            name: decode(attribute.key.as_ref())?,
            value: decode_attribute(&attribute.value)?,
        });
    }
    Ok(RichElement {
        name: decode(raw)?,
        attributes,
        children: Vec::new(),
    })
}

/// Translate CRLF and lone CR to LF, as XML 1.0 section 2.11 requires of a processor.
fn normalise_line_endings(text: &str) -> String {
    if !text.contains('\r') {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\r' {
            if characters.peek() == Some(&'\n') {
                characters.next();
            }
            out.push('\n');
        } else {
            out.push(character);
        }
    }
    out
}

/// Decode UTF-8 that the parser has already accepted.
fn decode(raw: &[u8]) -> Result<String, SamlError> {
    core::str::from_utf8(raw)
        .map(ToOwned::to_owned)
        .map_err(|_| SamlError::Malformed)
}

/// Decode an attribute value, resolving references and normalising whitespace.
///
/// # Both, and in this order, because the specification distinguishes them
///
/// XML 1.0 section 3.3.3 has the processor replace each LITERAL tab, newline or carriage return
/// in an attribute value with a single space. A character REFERENCE to the same character is
/// exempt and survives. The canonical form then escapes what survived -- which is why
/// `write_attribute_value` emitting `&#x9;` is correct for a reference and wrong for a literal.
///
/// An earlier version normalised neither, so a pretty-printed or line-wrapped attribute value
/// digested differently from every conforming signer. Doing it here rather than in the
/// canonicalizer is what makes the two cases distinguishable at all: after this runs, a tab in
/// the string can only have come from `&#x9;`.
fn decode_attribute(raw: &[u8]) -> Result<String, SamlError> {
    let text = core::str::from_utf8(raw).map_err(|_| SamlError::Malformed)?;
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('&') {
        push_normalised(&mut out, &rest[..start]);
        let after = &rest[start + 1..];
        let end = after.find(';').ok_or(SamlError::Malformed)?;
        // NOT normalised: a reference is exempt.
        out.push(resolve_reference(&after.as_bytes()[..end])?);
        rest = &after[end + 1..];
    }
    push_normalised(&mut out, rest);
    Ok(out)
}

/// Append literal attribute text with tab, newline and carriage return replaced by a space.
fn push_normalised(out: &mut String, text: &str) {
    for character in text.chars() {
        out.push(match character {
            '\t' | '\n' | '\r' => ' ',
            other => other,
        });
    }
}

/// The character a permitted reference names.
fn resolve_reference(name: &[u8]) -> Result<char, SamlError> {
    match name {
        b"amp" => return Ok('&'),
        b"lt" => return Ok('<'),
        b"gt" => return Ok('>'),
        b"quot" => return Ok('"'),
        b"apos" => return Ok('\''),
        _ => {}
    }
    let digits = name.strip_prefix(b"#").ok_or(SamlError::UnknownEntity)?;
    let (digits, radix) = match digits.strip_prefix(b"x") {
        Some(hex) => (hex, 16),
        None => (digits, 10),
    };
    let text = core::str::from_utf8(digits).map_err(|_| SamlError::UnknownEntity)?;
    let code = u32::from_str_radix(text, radix).map_err(|_| SamlError::UnknownEntity)?;
    char::from_u32(code).ok_or(SamlError::UnknownEntity)
}
