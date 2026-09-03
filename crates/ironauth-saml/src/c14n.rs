// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exclusive XML canonicalization, which is what a signature is actually over.
//!
//! # Why this exists rather than a byte range
//!
//! XML Signature does not digest the bytes a node occupied. It digests the node's CANONICAL
//! FORM: a re-serialisation under fixed rules, so that two documents differing only in
//! insignificant ways (attribute order, namespace declarations nothing uses, whether a section
//! was written as CDATA) produce one digest. A verifier that compared bytes would reject valid
//! signatures.
//!
//! # EXCLUSIVE, and why SAML needs it
//!
//! Inclusive canonicalization pulls every in-scope namespace declaration down into the subtree.
//! An assertion signed inside one response and then delivered inside another would canonicalise
//! differently and its signature would break -- which is the case SAML lives in. So SAML's
//! default is exclusive, which renders only the declarations the subtree VISIBLY USES.
//!
//! # TWO SETS, and conflating them was this file's original defect
//!
//! Exclusive canonicalization needs two distinct stacks and an earlier version of this file had
//! one:
//!
//!   * the IN-SCOPE set: every `xmlns` on the element and on all its ancestors, INCLUDING
//!     ancestors outside the signed subtree. This is what a prefix RESOLVES against.
//!   * the RENDERED set: what an output ancestor has already emitted. This is what SUPPRESSES a
//!     redundant declaration.
//!
//! The old code used the rendered set for both and started it empty, defending that as "no
//! inherited scope". The empty OUTPUT context is right; an empty IN-SCOPE set is not. A review
//! measured what it cost: `<ds:SignedInfo>` whose `xmlns:ds` sits on the enclosing
//! `<samlp:Response>` could not resolve `ds` at all, so the declaration was dropped and EVERY
//! conforming signature was rejected. The same conflation made a namespace REDECLARATION
//! invisible, so two documents whose attributes are genuinely in different namespaces digested
//! identically -- a collision, which is the worse direction.
//!
//! # What this does NOT implement
//!
//! `InclusiveNamespaces PrefixList`. It is legal, it is rare in SAML, and honouring it wrongly
//! would compute a different digest from the signer -- so [`crate::verify`] REFUSES a transform
//! that carries one rather than ignoring it.

use crate::tree::{RichAttribute, RichElement, RichNode};

/// The prefix XML binds by definition, which no document declares and every document may use.
const XML_PREFIX: &str = "xml";
/// What [`XML_PREFIX`] is bound to.
const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";

/// A namespace declaration: the prefix, and what it is bound to. The default namespace is the
/// empty prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Binding {
    /// The prefix, or empty for the default namespace.
    pub(crate) prefix: String,
    /// The namespace URI, or empty for an undeclaration.
    pub(crate) uri: String,
}

/// A prefix used by the subtree that nothing in scope binds.
///
/// AN ERROR, not something to serialise. An earlier version skipped it silently and wrote the
/// prefix anyway, which put the namespace URI outside the digest entirely: two documents binding
/// one prefix to different URIs then produced identical octets, which is how a mismatch becomes
/// a collision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnboundPrefix;

/// Canonicalise `element` exclusively, resolving prefixes against `inherited`.
///
/// `inherited` is every declaration in scope at the element, gathered from its ancestors --
/// including ancestors OUTSIDE the signed subtree, which is the whole reason a subtree signed in
/// one document verifies in another.
///
/// # Errors
///
/// [`UnboundPrefix`] if the subtree uses a prefix nothing binds.
pub(crate) fn canonicalize(
    element: &RichElement,
    inherited: &[Binding],
) -> Result<Vec<u8>, UnboundPrefix> {
    let mut out = String::new();
    // The output context starts EMPTY -- nothing has been rendered yet -- while the in-scope set
    // starts with the ancestors' declarations. Those are the two different things.
    write_element(&mut out, element, inherited, &[])?;
    Ok(out.into_bytes())
}

/// Write one element and its descendants.
fn write_element(
    out: &mut String,
    element: &RichElement,
    in_scope: &[Binding],
    rendered: &[Binding],
) -> Result<(), UnboundPrefix> {
    let (declared, attributes) = split_attributes(element);
    // The in-scope set for THIS element: the ancestors' declarations, with the element's own
    // overriding any it repeats.
    let mut scope = in_scope.to_vec();
    for binding in &declared {
        scope.retain(|existing| existing.prefix != binding.prefix);
        scope.push(binding.clone());
    }

    // THE VISIBLY-UTILISED SET. A prefix is visibly utilised by the element's own name and by
    // its attributes' names, and by nothing else -- a prefix that appears only inside an
    // attribute VALUE is not utilised, which is where implementations differ from each other.
    let mut used: Vec<&str> = vec![prefix_of(&element.name).unwrap_or("")];
    for attribute in &attributes {
        // AN UNPREFIXED ATTRIBUTE IS IN NO NAMESPACE, so it does not make the default
        // declaration visibly utilised. Getting this wrong in either direction changes the
        // digest.
        if let Some(prefix) = prefix_of(&attribute.name) {
            if !used.contains(&prefix) {
                used.push(prefix);
            }
        }
    }

    let mut emitted: Vec<Binding> = Vec::new();
    for prefix in &used {
        // The `xml` prefix is bound by definition and is never declared, so it is never
        // rendered either. Resolving it is what stops it dangling.
        if *prefix == XML_PREFIX {
            continue;
        }
        let binding = scope
            .iter()
            .find(|candidate| candidate.prefix == *prefix)
            .cloned();
        match binding {
            Some(binding) => {
                // AN EMPTY DEFAULT DECLARATION IS RENDERED ONLY TO UNDECLARE. With no default
                // namespace rendered by an output ancestor there is nothing to undeclare, and
                // emitting `xmlns=""` there adds six bytes no conforming implementation writes.
                if binding.prefix.is_empty() && binding.uri.is_empty() {
                    let ancestor_default = rendered
                        .iter()
                        .find(|candidate| candidate.prefix.is_empty());
                    if ancestor_default.is_none_or(|candidate| candidate.uri.is_empty()) {
                        continue;
                    }
                }
                if rendered.contains(&binding) {
                    continue;
                }
                emitted.push(binding);
            }
            // An unprefixed name with no default namespace in scope is ordinary, not an error.
            None if prefix.is_empty() => {}
            None => return Err(UnboundPrefix),
        }
    }
    emitted.sort_by(|left, right| left.prefix.cmp(&right.prefix));

    out.push('<');
    out.push_str(&element.name);
    for binding in &emitted {
        out.push(' ');
        if binding.prefix.is_empty() {
            out.push_str("xmlns=\"");
        } else {
            out.push_str("xmlns:");
            out.push_str(&binding.prefix);
            out.push_str("=\"");
        }
        write_attribute_value(out, &binding.uri);
        out.push('"');
    }

    // ATTRIBUTES SORT BY (NAMESPACE URI, LOCAL NAME), which is not the same as sorting the
    // qualified name. An earlier version sorted the qualified name and defended it as
    // equivalent; a review produced two counterexamples, one of them the WS-Security-wrapped
    // SAML shape (`ds:Id` beside `wsu:Id`, whose prefix order and URI order disagree).
    let mut keyed: Vec<(String, &str, &RichAttribute)> = Vec::with_capacity(attributes.len());
    for attribute in &attributes {
        let uri = match prefix_of(&attribute.name) {
            None => String::new(),
            Some(XML_PREFIX) => XML_NAMESPACE.to_owned(),
            Some(prefix) => scope
                .iter()
                .find(|candidate| candidate.prefix == prefix)
                .map(|candidate| candidate.uri.clone())
                .ok_or(UnboundPrefix)?,
        };
        keyed.push((uri, local_name(&attribute.name), attribute));
    }
    keyed.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(right.1)));
    for (_, _, attribute) in &keyed {
        out.push(' ');
        out.push_str(&attribute.name);
        out.push_str("=\"");
        write_attribute_value(out, &attribute.value);
        out.push('"');
    }
    out.push('>');

    let mut child_rendered = rendered.to_vec();
    for binding in emitted {
        child_rendered.retain(|existing| existing.prefix != binding.prefix);
        child_rendered.push(binding);
    }
    for child in &element.children {
        match child {
            RichNode::Element(nested) => write_element(out, nested, &scope, &child_rendered)?,
            RichNode::Text(text) => write_text(out, text),
            // A PROCESSING INSTRUCTION IS PART OF THE CANONICAL FORM. Only COMMENTS are removed
            // by the algorithm this crate accepts, and an earlier version dropped processing
            // instructions at parse time -- so content inside the signature's own coverage could
            // be added or removed without changing the digest.
            RichNode::ProcessingInstruction(pi) => {
                out.push_str("<?");
                out.push_str(pi);
                out.push_str("?>");
            }
        }
    }
    out.push_str("</");
    out.push_str(&element.name);
    out.push('>');
    Ok(())
}

/// Separate namespace declarations from ordinary attributes.
fn split_attributes(element: &RichElement) -> (Vec<Binding>, Vec<RichAttribute>) {
    let mut declarations = Vec::new();
    let mut attributes = Vec::new();
    for attribute in &element.attributes {
        if attribute.name == "xmlns" {
            declarations.push(Binding {
                prefix: String::new(),
                uri: attribute.value.clone(),
            });
        } else if let Some(prefix) = attribute.name.strip_prefix("xmlns:") {
            declarations.push(Binding {
                prefix: prefix.to_owned(),
                uri: attribute.value.clone(),
            });
        } else {
            attributes.push(attribute.clone());
        }
    }
    (declarations, attributes)
}

/// The prefix of a qualified name, or `None` for an unprefixed one.
fn prefix_of(name: &str) -> Option<&str> {
    name.split_once(':').map(|(prefix, _)| prefix)
}

/// The local part of a qualified name.
fn local_name(name: &str) -> &str {
    name.split_once(':').map_or(name, |(_, local)| local)
}

/// Escape text by the canonical form's rules.
///
/// The set is exactly `&`, `<`, `>` and carriage return, and NOT the apostrophe or the quote:
/// escaping more than the specification names produces a different digest from every conforming
/// implementation, so "escape everything to be safe" is the one thing this must not do.
///
/// A carriage return here can only have come from a `&#xD;` in the source, because the parser
/// normalises literal line endings before this ever runs.
fn write_text(out: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            other => out.push(other),
        }
    }
}

/// Escape an attribute value: a different set from text, and deliberately so. The quote is
/// escaped and `>` is not, and the three whitespace characters become references so a parser
/// cannot normalise them away a second time.
///
/// Whitespace reaching here is whitespace that survived attribute-value normalisation, which
/// means it came from a character reference in the source.
fn write_attribute_value(out: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            other => out.push(other),
        }
    }
}
