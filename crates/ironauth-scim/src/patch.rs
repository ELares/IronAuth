// SPDX-License-Identifier: MIT OR Apache-2.0

//! The RFC 7644 section 3.5.2 PATCH path grammar (issue #135, criteria 1 and 2).
//!
//! A PATCH operation addresses part of a resource: `name.givenName`, or
//! `members[value eq "usr_a"].display`. The bracketed part is a FILTER, and it is parsed by
//! the same [`crate::parse_filter`] the query surface uses rather than by a second parser
//! written for this position.
//!
//! That reuse is the point rather than a convenience. Two parsers for one grammar disagree
//! eventually, and a filter that means one thing in `?filter=` and another inside `path=` is
//! precisely the two-readings-of-one-input shape that [`crate::parse_resource_path`] exists
//! to remove from the path surface. Having removed it there, it would be strange to
//! reintroduce it here.
//!
//! # The Entra dialect
//!
//! Entra sends `"path":"members"` with the target in `value`, where Okta sends
//! `"path":"members[value eq \"x\"]"`. Both are legal RFC 7644; the difference is which half
//! of the operation carries the selector. This module parses BOTH into the same shape, so a
//! consumer never branches on which provisioning system sent the request. A consumer that had
//! to branch would be one dialect away from a bug the other dialect never reaches.

use crate::filter::{Filter, FilterError, parse_filter};

/// A parsed PATCH path.
///
/// Like the filter and the resource path, this cannot hold text that was not understood.
#[derive(Debug, Clone, PartialEq)]
pub struct PatchPath {
    /// The attribute being patched, for example `members` or `name`.
    pub attribute: String,
    /// The value selector, when the path carried one: `members[value eq "x"]`.
    pub selector: Option<Filter>,
    /// The sub-attribute, when the path named one: `...].display` or `name.givenName`.
    pub sub_attribute: Option<String>,
}

/// Why a PATCH path was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchPathError {
    /// The path was empty.
    Empty,
    /// An attribute or sub-attribute name was not a legal SCIM name.
    IllegalAttribute,
    /// The bracketed selector did not close.
    UnclosedSelector,
    /// The selector was not a valid filter.
    ///
    /// Carries the filter's own refusal, so a caller renders ONE `invalidPath` error whose
    /// detail came from the one parser rather than from a second opinion about the grammar.
    InvalidSelector(FilterError),
    /// Trailing input after the path.
    Trailing,
}

/// The maximum PATCH path length in bytes, bounded for the same reason the filter is.
const MAX_LEN: usize = 1024;

/// A legal SCIM attribute name: ALPHA followed by alphanumerics, `-`, `_`, or `$`.
///
/// An allowlist, matching the resource-path parser's reasoning: a name outside it is refused
/// rather than escaped, so no encoding nobody thought of gets a second reading.
fn is_legal_attribute(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '$' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '$'))
}

/// Parse a PATCH path.
///
/// # Errors
///
/// [`PatchPathError`], never echoing the rejected input.
pub fn parse_patch_path(raw: &str) -> Result<PatchPath, PatchPathError> {
    if raw.len() > MAX_LEN {
        return Err(PatchPathError::IllegalAttribute);
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(PatchPathError::Empty);
    }

    // A URN-qualified path keeps its URN with the attribute: splitting on the LAST colon, as
    // the filter parser does, because a SCIM URN contains colons of its own.
    let (prefix, rest) = match trimmed.rfind(':') {
        Some(index) => (Some(&trimmed[..index]), &trimmed[index + 1..]),
        None => (None, trimmed),
    };

    let Some(open) = rest.find('[') else {
        // No selector: `attr` or `attr.sub`.
        let (attribute, sub) = split_attribute(rest)?;
        return Ok(PatchPath {
            attribute: qualify(prefix, attribute),
            selector: None,
            sub_attribute: sub,
        });
    };

    let Some(close) = rest.rfind(']') else {
        return Err(PatchPathError::UnclosedSelector);
    };
    if close < open {
        return Err(PatchPathError::UnclosedSelector);
    }
    let attribute = &rest[..open];
    if !is_legal_attribute(attribute) {
        return Err(PatchPathError::IllegalAttribute);
    }
    // The SAME filter parser the query surface uses. See the module docs for why this is not
    // a second parser tuned for this position.
    let selector = parse_filter(&rest[open + 1..close]).map_err(PatchPathError::InvalidSelector)?;

    let tail = &rest[close + 1..];
    let sub_attribute = if tail.is_empty() {
        None
    } else {
        let Some(sub) = tail.strip_prefix('.') else {
            return Err(PatchPathError::Trailing);
        };
        if !is_legal_attribute(sub) {
            return Err(PatchPathError::IllegalAttribute);
        }
        Some(sub.to_owned())
    };

    Ok(PatchPath {
        attribute: qualify(prefix, attribute),
        selector: Some(selector),
        sub_attribute,
    })
}

fn qualify(prefix: Option<&str>, attribute: &str) -> String {
    match prefix {
        Some(urn) => format!("{urn}:{attribute}"),
        None => attribute.to_owned(),
    }
}

fn split_attribute(rest: &str) -> Result<(&str, Option<String>), PatchPathError> {
    if let Some((attribute, sub)) = rest.split_once('.') {
        if !is_legal_attribute(attribute) || !is_legal_attribute(sub) {
            return Err(PatchPathError::IllegalAttribute);
        }
        return Ok((attribute, Some(sub.to_owned())));
    }
    if !is_legal_attribute(rest) {
        return Err(PatchPathError::IllegalAttribute);
    }
    Ok((rest, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::{CompareOp, Value};

    #[test]
    fn both_provisioning_dialects_parse_into_the_same_shape() {
        // Okta puts the selector in the path; Entra puts the target in `value` and sends a
        // bare attribute. Both are legal RFC 7644, and a consumer must not have to branch on
        // which system sent the request: one that branched would be one dialect away from a
        // bug the other never reaches.
        let okta = parse_patch_path(r#"members[value eq "usr_a"]"#).expect("okta dialect");
        assert_eq!(okta.attribute, "members");
        assert!(okta.selector.is_some());

        let entra = parse_patch_path("members").expect("entra dialect");
        assert_eq!(entra.attribute, "members");
        assert!(entra.selector.is_none());

        // The same struct, differing only in whether a selector was present.
        assert_eq!(okta.attribute, entra.attribute);
        assert_eq!(okta.sub_attribute, entra.sub_attribute);
    }

    #[test]
    fn a_selector_with_a_sub_attribute_parses_all_three_parts() {
        let parsed = parse_patch_path(r#"members[value eq "usr_a"].display"#).expect("valid");
        assert_eq!(parsed.attribute, "members");
        assert_eq!(parsed.sub_attribute.as_deref(), Some("display"));
        let Some(Filter::Compare { op, value, .. }) = parsed.selector else {
            panic!("a comparison selector");
        };
        assert_eq!(op, CompareOp::Equal);
        assert_eq!(value, Value::String("usr_a".to_owned()));
    }

    #[test]
    fn the_selector_is_parsed_by_the_one_filter_parser() {
        // A selector the filter grammar refuses is refused HERE with the filter's own reason,
        // rather than being accepted by a second parser that happens to be laxer. Two parsers
        // for one grammar disagree eventually, and that disagreement is a filter meaning one
        // thing in `?filter=` and another inside `path=`.
        let refused = parse_patch_path(r#"members[value eq "a" DROP TABLE]"#)
            .expect_err("the filter parser refuses trailing input");
        assert!(matches!(refused, PatchPathError::InvalidSelector(_)));
    }

    #[test]
    fn a_urn_qualified_path_keeps_its_urn() {
        let parsed = parse_patch_path(
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber",
        )
        .expect("valid");
        assert_eq!(
            parsed.attribute,
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber",
            "split on the LAST colon, so a URN containing colons survives"
        );
    }

    #[test]
    fn malformed_paths_are_refused() {
        for hostile in [
            "",
            "   ",
            "members[",
            "members]",
            "members[value eq \"a\"]garbage",
            "members[value eq \"a\"].",
            ".givenName",
            "9members",
            "mem bers",
            "members[]",
            "members[value eq \"a\"].sub.sub",
        ] {
            assert!(
                parse_patch_path(hostile).is_err(),
                "must refuse {hostile:?}"
            );
        }
    }

    #[test]
    fn a_legitimate_path_is_not_refused() {
        // The control: every refusal test above passes on a parser that refuses everything.
        for path in [
            "userName",
            "name.givenName",
            "members",
            r#"emails[type eq "work"].value"#,
            "$ref",
        ] {
            assert!(parse_patch_path(path).is_ok(), "must accept {path:?}");
        }
    }
}
