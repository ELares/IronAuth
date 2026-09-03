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
//! ONE library handles XML, and it is [`quick_xml`]. The alternatives, and why not:
//!
//! * **`libxml2` / `xmlsec1` bindings** (`libxml`, `xmlsec`). This is what most of the field
//!   uses, and it is the reason most of the field has SAML CVEs. It is a large C surface with a
//!   long history of parser memory-safety issues, it resolves DTDs and external entities unless
//!   correctly told not to (so XXE is a configuration property rather than a structural one),
//!   and it brings a build-time system dependency. Rejected on memory safety first: a parser
//!   for attacker-controlled bytes is exactly where a C dependency costs most.
//! * **`xml-rs`.** Pure Rust and long-lived, but it PROCESSES internal DTD subsets and expands
//!   internal entities, so entity-expansion bounds become this crate's problem rather than
//!   being absent by construction. Rejected because the safest posture available is "the parser
//!   has no entity machinery at all".
//! * **`roxmltree`.** Pure Rust, a pleasant tree API, and it also handles DTD internal subsets
//!   and entity expansion. Same rejection as `xml-rs`, for the same sentence.
//! * **An existing Rust SAML crate.** None of the published ones carries a signature-wrapping
//!   regression corpus, an algorithm allowlist, or a misuse-resistant API, which is the entire
//!   content of this issue. Adopting one would move the problem, not solve it, and would put a
//!   third party in the position of deciding what "verified" means here.
//!
//! `quick-xml` is a pull parser with NO entity resolution machinery: an internal or external
//! entity reference is returned to the caller as an unresolved event, and a `DOCTYPE` is
//! returned as a `DocType` event this crate refuses outright. XXE and billion-laughs are
//! therefore closed by the absence of a feature rather than by remembering to switch one off,
//! which is the property [`parse`] is built on and `tests/hostile.rs`
//! measures. It is pure Rust, actively maintained, MIT licensed, and built here with default
//! features off so no serialisation or async surface is compiled at all.
//!
//! # Maintenance posture
//!
//! One library, pinned in the workspace dependency table with a comment naming this crate as
//! its only consumer. A second XML dependency arriving anywhere in the tree is visible in that
//! table, which is the point of it being there rather than here.
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
