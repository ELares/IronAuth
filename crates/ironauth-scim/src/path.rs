// SPDX-License-Identifier: MIT OR Apache-2.0

//! SCIM resource path parsing (issue #135, criterion 5).
//!
//! # The failure this exists to prevent
//!
//! A SCIM server addresses resources by path: `/Users/{id}`, `/Groups/{id}`. The criterion
//! is that a valid token for organization A cannot reach any resource in organization B "via
//! any encoding, path traversal, filter, or bulk trick", and that URL-encoded bypasses fail
//! closed.
//!
//! Almost every published SCIM IDOR of this class has the same shape, and it is not a missing
//! authorization check. The check is there; the attacker arranges for the SERVER and the
//! CHECK to read the path differently. `/Users/%2e%2e/Groups/x` is one resource to a router
//! that decodes late and another to an authorization filter that decoded early, so the filter
//! approves what the router then fetches.
//!
//! # Why this refuses rather than normalizes
//!
//! The tempting design is to canonicalize: decode, resolve `..`, and compare. That puts this
//! module in the business of agreeing with every other decoder in the stack -- the proxy, the
//! web framework, the router -- and a disagreement with any of them is the bug back again.
//!
//! So a path segment containing a percent sign, a separator, a traversal element, a
//! backslash, or a control character is REFUSED, not repaired. No legitimate SCIM identifier
//! contains any of them: IronAuth ids are `[A-Za-z0-9_-]` after their prefix. Refusing costs
//! nothing real and removes the entire class, because there is no second interpretation left
//! for anything to disagree about.

use std::fmt;

/// The SCIM resource types this server addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceType {
    /// `/Users`
    User,
    /// `/Groups`
    Group,
}

impl ResourceType {
    /// The path segment, exactly as SCIM spells it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "Users",
            Self::Group => "Groups",
        }
    }
}

/// A parsed reference to one SCIM resource.
///
/// Like [`crate::Filter`], this type cannot hold text that was not understood: there is no
/// variant for a raw path and no public constructor. Obtaining one means [`parse_resource_path`]
/// accepted it, so a caller cannot reintroduce the ambiguity by passing the original string
/// alongside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRef {
    resource_type: ResourceType,
    id: Option<String>,
}

impl ResourceRef {
    /// Which collection this reference addresses.
    #[must_use]
    pub fn resource_type(&self) -> ResourceType {
        self.resource_type
    }

    /// The resource id, when the path addressed one rather than the collection.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }
}

/// Why a path was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    /// The path did not name a SCIM collection this server serves.
    UnknownResourceType,
    /// The path had more segments than `/{Type}/{id}`.
    TooManySegments,
    /// A segment carried a character that has no place in a SCIM identifier.
    ///
    /// Deliberately ONE variant for percent signs, separators, traversal, backslashes, and
    /// control characters. Naming which one a prober tripped tells them which encodings the
    /// server is watching for, and the answer is all of them.
    IllegalSegment,
    /// The path was empty or had no resource type.
    Empty,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownResourceType => write!(f, "unknown SCIM resource type"),
            Self::TooManySegments => write!(f, "the path names more than one resource"),
            Self::IllegalSegment => write!(f, "the path contains an illegal segment"),
            Self::Empty => write!(f, "the path names no resource"),
        }
    }
}

/// Characters a SCIM identifier segment may contain.
///
/// IronAuth ids are a prefix, an underscore, and base64url, so this is the whole legitimate
/// alphabet. Anything outside it is refused rather than escaped: an allowlist cannot be
/// bypassed by an encoding nobody thought of, and a denylist can.
fn is_legal_segment_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

/// Parse a SCIM resource path.
///
/// Takes the path EXACTLY as it arrived, before any decoding. A caller that decoded first has
/// already lost the property this provides: `%2e%2e` is refused here and becomes `..` there.
///
/// # Errors
///
/// [`PathError`], never naming which specific character or encoding was refused.
pub fn parse_resource_path(raw: &str) -> Result<ResourceRef, PathError> {
    // A single leading slash is expected and stripped; anything else (an empty path, a
    // scheme-relative `//host`, a backslash) is not a path this server addresses.
    // THE LEADING SLASH IS REQUIRED, not optional. RFC 7644 section 3.7.2 writes a bulk
    // operation's path as `/Users`, and `unwrap_or(raw)` accepted `Users` as well -- measured
    // over the real route: `{"method":"POST","path":"Users"}` created a user. Two spellings for
    // one collection is a second interpretation of a path, which is the one property this
    // module exists to remove; it sat against that claim while the trailing-slash case beside
    // it was being tightened for exactly the same reason.
    let Some(trimmed) = raw.strip_prefix('/') else {
        return Err(PathError::Empty);
    };
    if trimmed.is_empty() {
        return Err(PathError::Empty);
    }
    // A trailing slash names the COLLECTION, so `/Users/` is allowed and the slash dropped;
    // two trailing slashes are an empty segment and are not.
    //
    // ONLY ON THE COLLECTION FORM. It used to be dropped unconditionally, which made
    // `/Users/{id}/` an item path here while axum's router refuses it -- so an operation
    // inside a batch was routed by a laxer reading than the same request sent alone. A review
    // measured it: `GET /scim/v2/Users/{id}/` as a single request answers 404, and
    // `{"method":"PATCH","path":"/Users/{id}/"}` inside a batch APPLIED the patch. Not
    // exploitable across organizations -- the id was unchanged and the membership fence still
    // held -- but it is a surviving second interpretation of a path, which is the one property
    // this module claims to have eliminated.
    let trimmed = match trimmed.strip_suffix('/') {
        Some(without) if !without.contains('/') => without,
        // `/Users/{id}/` -- an ITEM path with a trailing slash, which axum's router refuses.
        Some(_) => return Err(PathError::IllegalSegment),
        None => trimmed,
    };

    let mut segments = trimmed.split('/');
    let Some(type_segment) = segments.next() else {
        return Err(PathError::Empty);
    };
    // The type is matched EXACTLY, case included. SCIM spells these `Users` and `Groups`, and
    // accepting `users` would mean two spellings address one collection, which is a second
    // interpretation for something else to disagree with.
    let resource_type = match type_segment {
        "Users" => ResourceType::User,
        "Groups" => ResourceType::Group,
        _ => return Err(PathError::UnknownResourceType),
    };

    let id = match segments.next() {
        None => None,
        Some(segment) => {
            if segment.is_empty() {
                return Err(PathError::IllegalSegment);
            }
            // The allowlist. A percent sign, a dot, a backslash, a control character, a space,
            // and every non-ASCII byte all fail here, so `%2e%2e`, `%252f`, `..`, `.`,
            // `\\`, a NUL, and a Unicode separator lookalike are one refusal with one reason.
            if !segment.bytes().all(is_legal_segment_byte) {
                return Err(PathError::IllegalSegment);
            }
            Some(segment.to_owned())
        }
    };
    if segments.next().is_some() {
        return Err(PathError::TooManySegments);
    }
    Ok(ResourceRef { resource_type, id })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_paths_a_provisioning_client_actually_sends_are_accepted() {
        assert_eq!(
            parse_resource_path("/Users").expect("collection"),
            ResourceRef {
                resource_type: ResourceType::User,
                id: None
            }
        );
        assert_eq!(
            parse_resource_path("/Users/usr_abc-123").expect("resource"),
            ResourceRef {
                resource_type: ResourceType::User,
                id: Some("usr_abc-123".to_owned()),
            }
        );
        assert_eq!(
            parse_resource_path("/Groups/").expect("trailing slash names the collection"),
            ResourceRef {
                resource_type: ResourceType::Group,
                id: None
            }
        );
    }

    #[test]
    fn every_encoding_and_traversal_trick_is_refused() {
        // The CVE-2026-32130 class. Each of these is a path that one decoder in a stack reads
        // differently from another, which is how an authorization filter approves what the
        // router then fetches. They are refused here as ONE rule with ONE reason, before any
        // decoding, so there is no second interpretation left to disagree about.
        for hostile in [
            "/Users/%2e%2e",          // encoded traversal
            "/Users/%2e%2e%2fGroups", // encoded traversal and separator
            "/Users/%252e%252e",      // DOUBLE encoded: survives one decode
            "/Users/..",              // plain traversal
            "/Users/.",               // current-directory element
            "/Users/../Groups/x",     // traversal into another collection
            "/Users/%2f",             // encoded separator
            "/Users/a%00b",           // NUL, which truncates a C-side comparison
            "/Users/a\\b",            // backslash, a separator on some stacks
            "/Users/a b",             // space
            "/Users/a\u{2044}b",      // fraction slash, a separator lookalike
            "/Users/a\u{ff0f}b",      // fullwidth solidus, another
            "/Users/a\nb",            // control character, header/log injection shaped
            "/Users//",               // empty segment
            "/Users/a/b",             // more segments than a resource has
        ] {
            assert!(
                parse_resource_path(hostile).is_err(),
                "must be refused: {hostile:?}"
            );
        }
    }

    #[test]
    fn a_refusal_never_says_which_trick_was_tried() {
        // Distinguishing them would tell a prober which encodings the server watches for, and
        // the useful answer is that it watches for none of them because it allowlists instead.
        let reasons: Vec<PathError> = ["/Users/%2e%2e", "/Users/..", "/Users/a\\b", "/Users//"]
            .into_iter()
            .map(|path| parse_resource_path(path).expect_err("refused"))
            .collect();
        assert!(
            reasons
                .iter()
                .all(|reason| *reason == PathError::IllegalSegment),
            "every encoding trick is one reason: {reasons:?}"
        );
    }

    #[test]
    fn an_unknown_collection_is_refused_rather_than_guessed() {
        for path in ["/users", "/USERS", "/Schemas", "/", "", "/Users2"] {
            assert!(parse_resource_path(path).is_err(), "{path:?}");
        }
    }

    #[test]
    fn a_legitimate_id_is_not_refused_by_the_allowlist() {
        // The control. Without it every test above passes on a parser that refuses
        // everything, which would be perfectly safe and completely useless.
        for id in [
            "usr_abc",
            "usr_YWJjZGVm-_123",
            "grp_0",
            "A",
            &"a".repeat(200),
        ] {
            let parsed = parse_resource_path(&format!("/Users/{id}"))
                .unwrap_or_else(|error| panic!("{id:?} must be accepted: {error}"));
            assert_eq!(parsed.id(), Some(id));
        }
    }

    #[test]
    fn a_resource_ref_cannot_be_built_from_an_unparsed_path() {
        // The structural claim, asserted as a fact about the type: there is no variant for
        // raw text, so a caller has nowhere to put the original string. If one is ever added
        // this stops compiling.
        let parsed = parse_resource_path("/Users/usr_a").expect("valid");
        let ResourceRef { resource_type, id } = parsed;
        assert_eq!(resource_type, ResourceType::User);
        assert!(id.is_some());
    }
}
