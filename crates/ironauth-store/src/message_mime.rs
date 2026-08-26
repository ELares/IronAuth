// SPDX-License-Identifier: MIT OR Apache-2.0

//! `Message-ID` and multipart assembly (issue #111).
//!
//! Issue #111 asks that "every outgoing email carries a valid Message-ID" and that "multipart
//! text plus HTML output is well-formed". Both are deliverability requirements rather than
//! cosmetics: a message with no `Message-ID`, or a malformed one, is scored as spam by every
//! major receiver, and a broken MIME boundary turns a formatted email into visible raw source.
//!
//! Pure and sans-IO. Uniqueness is the CALLER's to supply, which is why [`message_id`] takes
//! the local part rather than inventing one: this crate must not read a clock, and a function
//! that generated its own identifier would have to.
//!
//! # The boundary is the security-relevant part
//!
//! A multipart body is delimited by a boundary string. If that string also appears anywhere in
//! the content, the receiving parser splits on the wrong line and the structure the sender
//! intended is not the structure the recipient sees.
//!
//! That matters here because part of the content is USER DATA: a display name and an
//! organization name reach a verification email, and both are attacker-chosen at signup. An
//! attacker who can predict or discover the boundary can close the real part early and open one
//! of their own, with their own headers and their own body. So [`multipart_alternative`]
//! REFUSES to assemble a message whose boundary occurs in either part, rather than escaping,
//! truncating, or hoping.
//!
//! # Text first, HTML second, and that order is not stylistic
//!
//! RFC 2046 section 5.1.4 orders `multipart/alternative` parts least-rich FIRST, because a
//! client picks the last part it can render. Emitting HTML first means a client that
//! understands both shows the plain-text version, which is the opposite of the intent and looks
//! like the HTML template is broken.

use std::fmt::Write as _;

/// Why a message could not be assembled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MimeError {
    /// The `Message-ID` local part is empty or carries characters RFC 5322 forbids there.
    InvalidMessageIdLocalPart,
    /// The `Message-ID` domain is empty or malformed.
    InvalidMessageIdDomain,
    /// The boundary is empty, too long, or uses characters RFC 2046 does not permit.
    InvalidBoundary,
    /// The boundary occurs inside one of the parts, so the structure would be ambiguous.
    BoundaryCollidesWithContent,
}

impl MimeError {
    /// A stable, value-free description.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidMessageIdLocalPart => {
                "the Message-ID local part is empty or contains forbidden characters"
            }
            Self::InvalidMessageIdDomain => "the Message-ID domain is empty or malformed",
            Self::InvalidBoundary => "the multipart boundary is empty, too long, or malformed",
            Self::BoundaryCollidesWithContent => {
                "the multipart boundary occurs inside the content, so the structure is ambiguous"
            }
        }
    }
}

/// RFC 2046 caps a boundary at 70 characters.
const MAX_BOUNDARY: usize = 70;

/// Header and body lines are separated by CRLF, per RFC 5322. A bare LF is tolerated by many
/// agents and rejected by some, and "works with most receivers" is not deliverability.
const CRLF: &str = "\r\n";

/// Whether a character may appear in a `Message-ID` local part.
///
/// RFC 5322's `dot-atom-text` set, which is deliberately narrower than what the grammar's
/// quoted form would allow. A quoted local part is legal and is also the shape that trips
/// receiver heuristics, so it is simply not produced here.
fn local_part_char_is_allowed(character: char) -> bool {
    character.is_ascii_alphanumeric()
        || matches!(
            character,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '/'
                | '='
                | '?'
                | '^'
                | '_'
                | '`'
                | '{'
                | '|'
                | '}'
                | '~'
                | '.'
        )
}

/// Whether a character may appear in a `Message-ID` domain.
fn domain_char_is_allowed(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '-' | '.')
}

/// Build an RFC 5322 `Message-ID` header value, angle brackets included.
///
/// `local` must be unique per message and is the CALLER's responsibility: this crate holds no
/// clock and no randomness, so a function that invented one here would have to reach for both.
/// A caller typically passes an already-generated message identifier.
///
/// # Errors
///
/// [`MimeError`] when either half is empty or carries a character that would need quoting.
/// Rejecting rather than quoting is deliberate: a quoted local part is legal, is also what
/// receiver heuristics penalise, and there is no reason to generate one.
pub fn message_id(local: &str, domain: &str) -> Result<String, MimeError> {
    if local.is_empty()
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local.chars().all(local_part_char_is_allowed)
    {
        return Err(MimeError::InvalidMessageIdLocalPart);
    }
    if !is_usable_message_id_domain(domain) {
        return Err(MimeError::InvalidMessageIdDomain);
    }
    Ok(format!("<{local}@{domain}>"))
}

/// Whether `domain` may stand on the right of a `Message-ID`.
///
/// PUBLIC so a caller can ask BEFORE it becomes the deployment's sender domain. Refusing here is
/// the last possible moment: `prepare_message` maps the refusal to `PrepareError::Mime`, the
/// composer returns `mime_failed`, and the delivery consumer resolves the row `Failed` with no
/// provider contacted and no retry -- for every message the deployment ever sends. A host that
/// fails this is not a degraded configuration, it is a silent outage, and the only way to say so
/// in time is to let the boot path ask the same question.
///
/// The dot is the load-bearing clause. `localhost` and `op` are the two hosts this repository's
/// own deployment files configure, and neither has one.
#[must_use]
pub fn is_usable_message_id_domain(domain: &str) -> bool {
    !domain.is_empty()
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.starts_with('-')
        && !domain.contains("..")
        && domain.contains('.')
        && domain.chars().all(domain_char_is_allowed)
}

/// Whether a boundary is well formed per RFC 2046 section 5.1.1.
fn boundary_is_well_formed(boundary: &str) -> bool {
    !boundary.is_empty()
        && boundary.len() <= MAX_BOUNDARY
        && !boundary.ends_with(' ')
        && boundary.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(
                    character,
                    '\'' | '(' | ')' | '+' | '_' | ',' | '-' | '.' | '/' | ':' | '=' | '?' | ' '
                )
        })
}

/// Assemble a `multipart/alternative` body carrying a plain-text and an HTML alternative.
///
/// Returns the body only. The caller supplies the outer headers and must set
/// `Content-Type: multipart/alternative; boundary="<boundary>"` with the SAME boundary, which
/// is why it is a parameter here rather than generated: the two must agree, and a function that
/// invented a boundary would hand back a body the caller could not describe.
///
/// # Errors
///
/// - [`MimeError::InvalidBoundary`] when the boundary is empty, over 70 characters, or uses
///   characters RFC 2046 does not permit.
/// - [`MimeError::BoundaryCollidesWithContent`] when the boundary appears inside either part.
///   REFUSED rather than escaped or worked around: part of the content is attacker-chosen user
///   data, and a boundary an attacker can place in the body lets them close the real part and
///   open one of their own, with headers of their choosing.
pub fn multipart_alternative(text: &str, html: &str, boundary: &str) -> Result<String, MimeError> {
    if !boundary_is_well_formed(boundary) {
        return Err(MimeError::InvalidBoundary);
    }
    // Substring, not line-prefix. A delimiter is only significant at the start of a line, so a
    // line-anchored check would be the "correct" reading, and it would also be brittle: it
    // depends on the exact line splitting a receiving parser performs, and receivers disagree.
    // A plain substring test costs nothing and is not something an encoding trick gets past.
    if text.contains(boundary) || html.contains(boundary) {
        return Err(MimeError::BoundaryCollidesWithContent);
    }

    let mut body = String::with_capacity(text.len() + html.len() + 256);
    // Least-rich part FIRST (RFC 2046 5.1.4): a client renders the LAST part it understands, so
    // emitting HTML first shows plain text to everyone who can read both.
    let _ = write!(
        body,
        "--{boundary}{CRLF}\
         Content-Type: text/plain; charset=utf-8{CRLF}\
         Content-Transfer-Encoding: 8bit{CRLF}{CRLF}\
         {text}{CRLF}\
         --{boundary}{CRLF}\
         Content-Type: text/html; charset=utf-8{CRLF}\
         Content-Transfer-Encoding: 8bit{CRLF}{CRLF}\
         {html}{CRLF}\
         --{boundary}--{CRLF}"
    );
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::{MimeError, message_id, multipart_alternative};

    const BOUNDARY: &str = "ironauth-boundary-0001";

    #[test]
    fn a_message_id_is_wrapped_in_angle_brackets() {
        assert_eq!(
            message_id("msg_01ABC", "mail.example.test").expect("valid"),
            "<msg_01ABC@mail.example.test>"
        );
    }

    #[test]
    fn a_message_id_local_part_must_be_present_and_unquoted() {
        for local in [
            "",
            "has space",
            "has<bracket",
            "has@at",
            ".leading",
            "trailing.",
            "a..b",
            "quote\"here",
            "new\nline",
        ] {
            assert_eq!(
                message_id(local, "mail.example.test").unwrap_err(),
                MimeError::InvalidMessageIdLocalPart,
                "{local:?} must be refused"
            );
        }
    }

    #[test]
    fn a_message_id_domain_must_be_a_plausible_hostname() {
        for domain in [
            "",
            "nodot",
            ".leading.test",
            "trailing.test.",
            "a..b.test",
            "-leading.test",
            "has space.test",
            "under_score.test",
        ] {
            assert_eq!(
                message_id("msg_1", domain).unwrap_err(),
                MimeError::InvalidMessageIdDomain,
                "{domain:?} must be refused"
            );
        }
        // The control: a perfectly ordinary domain is accepted, so the refusals above are the
        // stated defects and not a function that rejects everything.
        assert!(message_id("msg_1", "mail.example.test").is_ok());
        assert!(message_id("msg_1", "a.b").is_ok());
    }

    /// An angle bracket in either half would let a caller close the header early.
    #[test]
    fn a_message_id_cannot_be_made_to_close_itself() {
        assert!(message_id("a>x<b", "mail.example.test").is_err());
        assert!(message_id("msg_1", "mail.example.test>evil").is_err());
    }

    #[test]
    fn a_multipart_body_puts_the_text_part_first() {
        let body = multipart_alternative("plain words", "<p>rich</p>", BOUNDARY).expect("valid");
        let text_at = body.find("text/plain").expect("a text part");
        let html_at = body.find("text/html").expect("an html part");
        assert!(
            text_at < html_at,
            "RFC 2046 5.1.4: a client renders the LAST part it understands, so HTML must come \
             second or everyone who can read both sees plain text"
        );
    }

    #[test]
    fn a_multipart_body_is_well_formed() {
        let body = multipart_alternative("plain", "<p>rich</p>", BOUNDARY).expect("valid");
        assert!(body.starts_with(&format!("--{BOUNDARY}\r\n")), "{body}");
        assert!(body.ends_with(&format!("--{BOUNDARY}--\r\n")), "{body}");
        assert_eq!(
            body.matches(&format!("--{BOUNDARY}")).count(),
            3,
            "two part delimiters and one closing delimiter"
        );
        assert!(body.contains("plain") && body.contains("<p>rich</p>"));
        // Every line ends CRLF. A bare LF is tolerated by many agents and rejected by some,
        // and "works with most receivers" is not deliverability.
        assert!(
            !body.replace("\r\n", "").contains('\n'),
            "a bare LF appears somewhere: {body:?}"
        );
    }

    /// THE structural attack: content that contains the boundary.
    ///
    /// Part of the content is user data (a display name, an organization name), so an attacker
    /// who can place the boundary in the body can close the real part and open one of their
    /// own, with headers of their choosing. Assembly is refused rather than escaped.
    #[test]
    fn content_containing_the_boundary_is_refused() {
        let injected = format!("hello\r\n--{BOUNDARY}\r\nContent-Type: text/html\r\n\r\n<evil>");
        assert_eq!(
            multipart_alternative(&injected, "<p>ok</p>", BOUNDARY).unwrap_err(),
            MimeError::BoundaryCollidesWithContent,
        );
        assert_eq!(
            multipart_alternative("ok", &injected, BOUNDARY).unwrap_err(),
            MimeError::BoundaryCollidesWithContent,
        );
        // A BARE mention, not at a line start and with no delimiter dashes, is refused too.
        // The check is a substring test on purpose: a line-anchored one depends on the exact
        // line splitting a receiving parser does, and receivers disagree.
        assert_eq!(
            multipart_alternative(&format!("see {BOUNDARY} here"), "ok", BOUNDARY).unwrap_err(),
            MimeError::BoundaryCollidesWithContent,
        );
        // The control: the same content with a different boundary assembles.
        assert!(multipart_alternative(&injected, "<p>ok</p>", "a-different-boundary").is_ok());
    }

    #[test]
    fn a_malformed_boundary_is_refused() {
        for boundary in ["", &"x".repeat(71), "has\"quote", "has\r\n", "trailing "] {
            assert_eq!(
                multipart_alternative("t", "h", boundary).unwrap_err(),
                MimeError::InvalidBoundary,
                "{boundary:?} must be refused"
            );
        }
        // Exactly at the RFC 2046 limit is allowed; one past it is not.
        assert!(multipart_alternative("t", "h", &"x".repeat(70)).is_ok());
    }

    /// Empty parts are legal. A message with no HTML alternative is a real thing to send, and
    /// refusing it would push callers into passing a placeholder that recipients would see.
    #[test]
    fn empty_parts_are_permitted() {
        let body = multipart_alternative("", "", BOUNDARY).expect("valid");
        assert!(body.contains("text/plain") && body.contains("text/html"));
    }

    #[test]
    fn every_mime_error_describes_itself_distinctly() {
        let all = [
            MimeError::InvalidMessageIdLocalPart,
            MimeError::InvalidMessageIdDomain,
            MimeError::InvalidBoundary,
            MimeError::BoundaryCollidesWithContent,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for error in &all {
            assert!(error.as_str().len() > 20, "{error:?} has no useful text");
            assert!(seen.insert(error.as_str()), "{error:?} shares its text");
        }
        assert_eq!(seen.len(), all.len());
    }
}
