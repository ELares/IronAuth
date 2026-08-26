// SPDX-License-Identifier: MIT OR Apache-2.0
//! Stored declarative claim mappings (issue #113 criterion 4).
//!
//! The RULES live in `ironauth-oidc::claims_mapping`, which is where they are validated and
//! applied. This module is only the persistence shape: what a stored rule set looks like coming
//! out of `claims_mappings`, so the config-snapshot export can project it and the issuance path
//! can read it.
//!
//! # Why the rules are a JSON string here and not a parsed type
//!
//! `ironauth-store` cannot depend on `ironauth-oidc`; the dependency runs the other way. Parsing
//! into `MappingRule` here would require a second definition of the rule shape in this crate,
//! and two definitions of one wire format is exactly the drift criterion 5 exists to prevent.
//!
//! So the store carries the document verbatim and the OIDC layer parses it against the one
//! definition that governs it. That is the same split `signup_forms` uses for its field list,
//! and it has the same consequence worth stating: **this crate cannot tell a valid rule set from
//! an invalid one.** The fence is at the WRITE, in the admin path that validates before storing,
//! and at issuance, where a document that no longer parses fails closed rather than minting a
//! token from a rule set nobody could read.

/// One stored rule set: a client and the rules that shape its tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimsMappingRecord {
    /// The OAuth client these rules shape tokens for, unique per scope: the stable natural key
    /// the config-snapshot export orders by.
    pub client_id: String,
    /// The ordered rule list, as the JSON encoding of `Vec<MappingRule>`.
    ///
    /// Verbatim, for the reason the module header gives: this crate has no definition of a rule
    /// to parse it against, and inventing one would make two.
    pub rules_json: String,
}
