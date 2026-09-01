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
    attribute: String,
    selector: Option<Filter>,
    sub_attribute: Option<String>,
}

impl PatchPath {
    /// The attribute being patched, for example `members` or `name`.
    #[must_use]
    pub fn attribute(&self) -> &str {
        &self.attribute
    }

    /// The value selector, when the path carried one.
    #[must_use]
    pub fn selector(&self) -> Option<&Filter> {
        self.selector.as_ref()
    }

    /// The sub-attribute, when the path named one.
    #[must_use]
    pub fn sub_attribute(&self) -> Option<&str> {
        self.sub_attribute.as_deref()
    }
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
    /// The path exceeded [`MAX_LEN`].
    TooLong {
        /// The bound that was exceeded.
        limit: usize,
    },
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
        return Err(PatchPathError::TooLong { limit: MAX_LEN });
    }
    // ASCII space only. Trimming Unicode whitespace would silently accept a path a client did
    // not send, which is the normalize-rather-than-refuse behaviour this crate argues against
    // everywhere else.
    let trimmed = raw.trim_matches(' ');
    if trimmed.is_empty() {
        return Err(PatchPathError::Empty);
    }

    // THE BRACKET SCAN COMES FIRST. It used to run on the post-colon remainder, which meant
    // where the path split depended on data INSIDE the selector, and that was wrong twice
    // over:
    //
    //   - a selector value containing a colon broke the path. `$ref` and `photos.value` are
    //     URIs in RFC 7643, so `photos[value eq "https://ex/p.png"].display` is ordinary
    //     Okta traffic and it was REFUSED.
    //   - a colon after an unclosed `[` bypassed the unclosed-bracket guard entirely, so
    //     `members[:x` parsed with the unbalanced bracket sitting in `attribute` and the
    //     filter parser never invoked.
    //
    // Splitting the head from the selector first, and looking for the URN only in the head,
    // removes both: nothing inside the brackets can decide how the outside is read.
    let (head, bracketed) = if let Some(open) = trimmed.find('[') {
        let Some(close) = trimmed.rfind(']') else {
            return Err(PatchPathError::UnclosedSelector);
        };
        if close < open {
            return Err(PatchPathError::UnclosedSelector);
        }
        (
            &trimmed[..open],
            Some((&trimmed[open + 1..close], &trimmed[close + 1..])),
        )
    } else {
        // A `]` with no `[` is unbalanced in the other direction, and is refused rather than
        // treated as an ordinary character: it is only ever the tail of a selector somebody
        // truncated.
        if trimmed.contains(']') {
            return Err(PatchPathError::UnclosedSelector);
        }
        (trimmed, None)
    };

    // The URN split happens in the HEAD only, on the last colon, because a SCIM URN contains
    // colons of its own.
    let (urn, attribute_part) = match head.rfind(':') {
        Some(index) => (Some(&head[..index]), &head[index + 1..]),
        None => (None, head),
    };
    // THE URN IS VALIDATED. It used to be passed through untouched, so everything before the
    // last colon -- a NUL, a newline, a quote, `../`, `%2e%2e`, a whole SQL fragment -- landed
    // in `attribute` and the type's promise that it holds nothing unparsed was false for that
    // half. The filter parser never had this hole: it constrains its scan alphabet before
    // splitting, so the two parsers for one grammar disagreed exactly where this module's own
    // header argues they must not.
    if let Some(urn) = urn {
        if !is_legal_urn(urn) {
            return Err(PatchPathError::IllegalAttribute);
        }
    }

    match bracketed {
        None => {
            let (attribute, sub) = split_attribute(attribute_part)?;
            Ok(PatchPath {
                attribute: qualify(urn, attribute),
                selector: None,
                sub_attribute: sub,
            })
        }
        Some((selector_text, tail)) => {
            if !is_legal_attribute(attribute_part) {
                return Err(PatchPathError::IllegalAttribute);
            }
            // The SAME filter parser the query surface uses. See the module docs for why this
            // is not a second parser tuned for this position.
            let selector = parse_filter(selector_text).map_err(PatchPathError::InvalidSelector)?;
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
                attribute: qualify(urn, attribute_part),
                selector: Some(selector),
                sub_attribute,
            })
        }
    }
}

/// A legal SCIM schema URN: the alphabet RFC 7643 URNs are written in, and nothing else.
///
/// The same allowlist reasoning as everywhere else here. A URN outside it is refused rather
/// than escaped, because an allowlist cannot be bypassed by an encoding nobody thought of.
fn is_legal_urn(urn: &str) -> bool {
    !urn.is_empty()
        && urn
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '-' | '_' | '$'))
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
        assert_eq!(okta.attribute(), "members");
        assert!(okta.selector().is_some());

        let entra = parse_patch_path("members").expect("entra dialect");
        assert_eq!(entra.attribute(), "members");
        assert!(entra.selector().is_none());

        // EXHAUSTIVE, by struct pattern rather than by picking accessors. An earlier version
        // compared `attribute` and `sub_attribute`, which are the two fields the assertions
        // above had already pinned, so it could not fail; worse, a field added later would
        // have been silently excluded from "the same shape". Destructuring means a new field
        // stops this compiling until somebody says which dialect it differs on.
        let PatchPath {
            attribute: okta_attribute,
            selector: okta_selector,
            sub_attribute: okta_sub,
        } = &okta;
        let PatchPath {
            attribute: entra_attribute,
            selector: entra_selector,
            sub_attribute: entra_sub,
        } = &entra;
        assert_eq!(okta_attribute, entra_attribute, "the target attribute");
        assert_eq!(okta_sub, entra_sub, "the sub-attribute");
        assert!(
            okta_selector.is_some() && entra_selector.is_none(),
            "the selector is the ONE field the dialects differ on, and it differs in exactly \
             this direction: Okta narrows in the path, Entra narrows in the operation value"
        );

        // And the difference stays confined to it when the path carries more. A consumer
        // reading `attribute` and `sub_attribute` gets the same answer either way, which is
        // the property that lets it not branch.
        let okta_sub_path =
            parse_patch_path(r#"members[value eq "usr_a"].display"#).expect("okta dialect");
        let entra_sub_path = parse_patch_path("members.display").expect("entra dialect");
        assert_eq!(okta_sub_path.attribute(), entra_sub_path.attribute());
        assert_eq!(
            okta_sub_path.sub_attribute(),
            entra_sub_path.sub_attribute()
        );
        assert_eq!(okta_sub_path.sub_attribute(), Some("display"));
    }

    #[test]
    fn a_selector_with_a_sub_attribute_parses_all_three_parts() {
        let parsed = parse_patch_path(r#"members[value eq "usr_a"].display"#).expect("valid");
        assert_eq!(parsed.attribute(), "members");
        assert_eq!(parsed.sub_attribute(), Some("display"));
        let Some(Filter::Compare { op, value, .. }) = parsed.selector().cloned() else {
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
            parsed.attribute(),
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber",
            "split on the LAST colon, so a URN containing colons survives"
        );
    }

    #[test]
    fn a_hostile_urn_prefix_is_refused_rather_than_carried() {
        // The blocker this file shipped with. Everything before the last colon went into
        // `attribute` untouched, so the type's promise that it holds nothing unparsed was
        // false for exactly the half an attacker controls most cheaply.
        for hostile in [
            "';DROP TABLE users--:userName", // query-audit-allow: parser input, not a query
            "<script>alert(1)</script>:userName",
            "../../../../etc/passwd:members[value eq \"a\"]",
            "a\rb\nc:active",
            "m\0:x",
            "m%00:x",
            "m/../:x",
            "m\":x",
            "!!!:userName",
            ":userName",
        ] {
            assert!(
                parse_patch_path(hostile).is_err(),
                "must refuse {hostile:?}"
            );
        }
    }

    #[test]
    fn a_selector_value_containing_a_colon_is_a_path_a_real_client_sends() {
        // `$ref` and `photos.value` are URIs in RFC 7643, so these are ordinary Okta traffic.
        // They were REFUSED, because the colon split ran before the bracket scan and a colon
        // inside the selector decided where the path was cut.
        for legitimate in [
            r#"photos[value eq "https://ex.com/p.png"].display"#,
            r#"members[$ref eq "https://ex.com/v2/Users/2819c223"]"#,
            r#"schemas[value eq "urn:ietf:params:scim:schemas:core:2.0:User"]"#,
            r#"members[value eq "a:b"]"#,
        ] {
            assert!(
                parse_patch_path(legitimate).is_ok(),
                "must accept {legitimate:?}"
            );
        }
    }

    #[test]
    fn a_colon_cannot_smuggle_an_unclosed_bracket_past_the_guard() {
        // `members[` was refused, and `members[:x` was ACCEPTED with the unbalanced bracket
        // sitting in `attribute` and the filter parser never invoked. The guard existed and
        // the colon split moved the input out from under it.
        for hostile in [
            "members[",
            "members[:x",
            r#"members[value eq "a" :x"#,
            "members]",
        ] {
            assert!(
                parse_patch_path(hostile).is_err(),
                "must refuse {hostile:?}"
            );
        }
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
