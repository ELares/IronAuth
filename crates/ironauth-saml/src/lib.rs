// SPDX-License-Identifier: MIT OR Apache-2.0

//! The hostile-input SAML harness (issue #138): the only path by which SAML XML may enter
//! IronAuth.
//!
//! # Why this crate exists before any SAML feature does
//!
//! Every broad identity provider bleeds on SAML parsing, and the bleeding is always the same
//! shape: the document is parsed by one component, signed-ness is decided by a second, and the
//! values are read by a third, and the three disagree about which bytes they were talking
//! about. That is XML Signature Wrapping, and it is an authenticate-as-anyone bug every time.
//! Kanidm's answer is to refuse SAML outright.
//!
//! IronAuth's answer is that SAML is a hostile-input parser problem, so the parser comes first
//! and the feature comes later. This crate is the named precondition for SAML SP inbound
//! (#139), which is itself a precondition for the self-service portal (#140).
//!
//! # The library evaluation, and what was rejected
//!
//! ONE library handles XML, and it is [`quick_xml`]. The alternatives were read rather than
//! recalled, because a written evaluation that is wrong about what it rejected is worse than
//! none: it justifies a security-critical dependency for the life of the feature.
//!
//! * **`libxml2` / `xmlsec1` bindings** (`libxml`, `xmlsec`). What most of the field uses, and
//!   the reason most of the field has SAML CVEs. A large C surface with a long history of
//!   parser memory-safety issues, a build-time system dependency, and DTD and external-entity
//!   processing that is on unless correctly switched off. Rejected on memory safety first: a
//!   parser for attacker-controlled bytes is where a C dependency costs most.
//! * **`xml-rs`.** Pure Rust, long-lived, and BETTER DEFENDED BY DEFAULT THAN THIS CRATE IS: its
//!   config block is headed "Limits to defend from billion laughs attack" and ships
//!   `max_entity_expansion_length`, `max_entity_expansion_depth`, `max_name_length`,
//!   `max_attributes`, `max_attribute_length` and `max_data_length`, all on by default. An
//!   earlier draft of this paragraph said entity-expansion bounds "become this crate's problem"
//!   under it; the opposite is true, and four of those bounds are ones this crate had to add
//!   for itself.
//! * **`roxmltree`.** Pure Rust, a pleasant tree API, and `ParsingOptions::allow_dtd` defaults
//!   to FALSE with a `nodes_limit` beside it. An earlier draft said it "handles DTD internal
//!   subsets and entity expansion", which is what it does when a caller opts in; by default it
//!   answers `Error::DtdDetected`, which is the same posture this crate presents as its own.
//! * **An existing Rust SAML crate.** None carries a signature-wrapping regression corpus, an
//!   algorithm allowlist, or a misuse-resistant API, which is the content of #138. Adopting one
//!   would move the problem and would put a third party in the position of deciding what
//!   "verified" means here.
//!
//! # So why `quick-xml`, given that two of those are also safe by default
//!
//! Because of what the SIGNATURE half needs, which is the half this crate exists for.
//!
//! XML Signature verifies a canonicalisation of an exact subtree, so the verifier must be able
//! to say which BYTES of the original document a node occupied. `quick-xml` is a pull parser
//! over a borrowed buffer and reports the position of every event, so that mapping is available.
//! A tree library that owns its own decoded nodes gives a tree and not a byte range, and
//! recovering the range afterwards means re-serialising -- which is the "one component parses,
//! a second decides signed-ness" split this crate opens by condemning.
//!
//! The second reason is retention: with a pull parser this crate decides what is KEPT, which is
//! how [`Element`] can hold a name and nothing else. A tree library hands back every attribute
//! and every text node whether or not anybody should be able to read them.
//!
//! `quick-xml` is pure Rust, actively maintained, MIT licensed, and built here with default
//! features off. What it does NOT do is resolve entities automatically or perform any I/O: an
//! entity reference in TEXT arrives as its own event, which this crate refuses, and a `DOCTYPE`
//! arrives as an event this crate refuses outright. It does ship an internal-subset parser and
//! unescaping helpers; this crate calls neither, so calling it a parser with "no entity
//! resolution machinery" would be too strong -- what is true is that it resolves nothing on its
//! own, and this crate never asks it to.
//!
//! ONE CONSEQUENCE HAS TO BE HANDLED HERE RATHER THAN BY THE PARSER. Only references in TEXT
//! become events; an attribute value arrives inside the raw start tag and is never tokenised. So
//! `Destination="&whoami;"` would ride straight through a parser that trusted the event stream,
//! while the identical reference in a `NameID` is refused. [`parse`] applies the same rule to
//! attribute values itself, and `tests/hostile.rs` drives both halves.
//!
//! # Version 0.41, and the honest reason
//!
//! 0.41 reports an unresolved entity reference in text as `Event::GeneralRef`, so it can be
//! refused AT PARSE TIME. 0.37 reports the same reference inside the text node and surfaces it
//! only when a caller unescapes -- where it is, to be fair, also an error rather than a silent
//! truncation (measured: `unescape()` on `a&whoami;b` under 0.37.5 answers
//! `UnrecognizedEntity`). An earlier draft of this note claimed it read as `ab`, which is false.
//!
//! The reason to prefer the parse-time refusal is that THIS CRATE NEVER UNESCAPES. A refusal
//! that only fires when somebody calls a method is a refusal that depends on every future caller
//! remembering to call it.
//!
//! # The choke point has an upstream, and it is not here
//!
//! [`parse`] takes decoded bytes. The HTTP-Redirect binding delivers base64 of a DEFLATE
//! stream, and the classic SAML compression bomb lands in that inflate: [`Limits::max_bytes`]
//! measures the buffer AFTER something else produced it. Whatever performs that decode has to
//! carry its own output bound, and it is not written yet.
//!
//! # What this crate does NOT do yet
//!
//! Signature verification, the XSW corpus, comment-truncation handling, and encrypted
//! assertions are the rest of #138 and are not here. This crate currently gives a caller a
//! parsed document and NO way to read a value out of it, which is deliberate: see
//! [`Document`].

#![forbid(unsafe_code)]

mod parse;

pub use parse::{Document, Element, Limits, SamlError, parse};
