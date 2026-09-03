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
//! * **`xml-rs`.** Pure Rust, long-lived, and better defended than an earlier draft of this
//!   paragraph gave it credit for: its config block is headed "Limits to defend from billion
//!   laughs attack" and ships `max_entity_expansion_length`, `max_entity_expansion_depth`,
//!   `max_name_length`, `max_attributes`, `max_attribute_length` and `max_data_length`, all on
//!   by default. That draft said entity-expansion bounds "become this crate's problem" under it;
//!   the opposite is true. Two of those six are bounds this crate had to add for itself
//!   (`max_name_length` and `max_attributes`); it still has no per-value or per-text bound, and
//!   bounds those only in aggregate through [`Limits::max_bytes`].
//!
//!   Neither library dominates the other: `xml-rs` has no document-size, depth or element-count
//!   bound, which this crate does have. The comparison is a trade, not a ranking, and the
//!   deciding property is below.
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
//! RETENTION. With a pull parser this crate decides what is KEPT, which is the only reason
//! [`Element`] can hold a name and nothing else. A tree library hands back a tree with every
//! attribute and every text node in it, and "there is no accessor for the value" then becomes a
//! promise about an API rather than a fact about what exists in memory. That is the property
//! criterion 6 of #138 is about, and it is the one a later reader will most want to have been
//! decided structurally.
//!
//! AN EARLIER DRAFT GAVE A DIFFERENT REASON AND IT WAS FALSE. It said XML Signature needs byte
//! ranges for the exact subtree it verifies, which is true, and that a tree library "gives a
//! tree and not a byte range", which is not: `roxmltree` has `Node::range()`,
//! `Attribute::range()`, `range_qname()` and `range_value()`, each documented as a byte range in
//! the original document, behind a `positions` feature that is ON by default. `quick-xml` has no
//! per-event span at all -- only `Reader::buffer_position()`, a single cursor a caller must keep
//! its own books against. On that axis the rejected library is BETTER equipped than the chosen
//! one, and the signature half will have to do that bookkeeping.
//!
//! So the honest summary is that `roxmltree` is a credible alternative that was not chosen, on
//! retention, and that the choice costs this crate the position bookkeeping it would have got
//! for free. If the signature half finds that bookkeeping is where its bugs live, the decision
//! is worth reopening, and this paragraph is what a reader would reopen it against.
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

pub use parse::{DEPTH_CEILING, Document, Element, Limits, SamlError, parse};
