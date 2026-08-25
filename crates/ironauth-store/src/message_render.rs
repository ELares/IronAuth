// SPDX-License-Identifier: MIT OR Apache-2.0

//! Safe message-template rendering (issue #111).
//!
//! Issue #111 asks for "safe templating only (data interpolation, no arbitrary code
//! execution)". This is that: `{{placeholder}}` substitution and nothing else. No expressions,
//! no conditionals, no loops, no includes, no partials. A template is a string with holes.
//!
//! The whole module exists because the values filling those holes are USER DATA. A display
//! name, an organization name and an email address all reach a verification email, all three
//! are attacker-chosen in a self-service signup, and each lands somewhere with different
//! rules about what characters mean something.
//!
//! # Three sinks, three escapes, one deliberate asymmetry
//!
//! - [`RenderMode::Html`] escapes, because a display name of `<img onerror=...>` in an HTML
//!   email body is script execution in whatever renders it.
//! - [`RenderMode::Text`] does NOT escape, deliberately. Escaping the plain-text alternative
//!   would show a recipient the literal `&amp;` in their own name, and there is no markup in a
//!   text part for anything to escape INTO. Escaping "just in case" is not free here: it is a
//!   visible defect in every message containing an ampersand.
//! - [`render_header`] refuses control characters entirely rather than escaping them, because
//!   a header has no escape syntax. A subject containing a bare newline does not render oddly,
//!   it TERMINATES the header and everything after becomes a new one: that is SMTP header
//!   injection, and it is how an attacker adds their own `Bcc`.
//!
//! # Interpolation is single-pass, and that is a security property
//!
//! A substituted value is never re-scanned. If a display name is literally `{{reset_token}}`,
//! it renders as those characters and does not expand. A second pass would let any user who
//! can set any string field read any value in the render context, which turns a display name
//! into an exfiltration primitive for a password-reset link.

use std::collections::BTreeMap;

/// Which sink a rendered string is destined for, and therefore how values are escaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderMode {
    /// A plain-text body. Values are inserted verbatim; there is no markup to escape into.
    Text,
    /// An HTML body. Values are escaped so markup in user data cannot become markup.
    Html,
}

/// Why rendering refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    /// The template names a placeholder the caller supplied no value for.
    ///
    /// An error rather than an empty string: a verification email whose link silently rendered
    /// as `Click here: ` is a broken message that still gets SENT, and the recipient is the one
    /// who discovers it.
    UnknownPlaceholder(String),
    /// A `{{` was opened and never closed.
    UnterminatedPlaceholder,
    /// A placeholder name is empty or carries characters outside `[a-z0-9_]`.
    ///
    /// The character set is deliberately narrow. A permissive name would let template authors
    /// write something that LOOKS like an expression (`{{user.name | upper}}`) and have it
    /// silently treated as one opaque key that is then reported missing, which reads as a bug
    /// in the renderer rather than as an unsupported feature.
    MalformedPlaceholderName(String),
    /// A header value contains a control character, which cannot be escaped, only refused.
    HeaderControlCharacter,
}

impl RenderError {
    /// A stable, value-free description for logs. Placeholder names are template author input
    /// rather than end-user input, so naming one is safe, but this stays value-free so a
    /// caller need not decide.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UnknownPlaceholder(_) => "the template names a placeholder with no value",
            Self::UnterminatedPlaceholder => "a placeholder was opened and never closed",
            Self::MalformedPlaceholderName(_) => "a placeholder name is empty or malformed",
            Self::HeaderControlCharacter => {
                "a header value contains a control character and cannot be sent"
            }
        }
    }
}

/// The values a template is rendered against.
pub type RenderContext = BTreeMap<String, String>;

/// Escape a value for an HTML sink.
///
/// The five characters are the ones that can leave a text position in HTML. Quotes are included
/// so a value is safe inside an attribute as well as in element text, since a template author
/// writing `href="{{link}}"` should not have to know which position we assumed.
///
/// Order is irrelevant HERE and that is worth stating, because it is not irrelevant in the
/// obvious alternative. A chain of `str::replace` calls must escape `&` first, or the `&` it
/// introduces for `<` gets escaped again into `&amp;lt;`. This walks the input once and appends
/// to a fresh buffer, so each input character is considered exactly once and no output is ever
/// re-examined. Reordering the arms provably changes nothing: a mutation that swapped them
/// survived the suite, which is the evidence for this paragraph rather than an argument for it.
fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            other => out.push(other),
        }
    }
    out
}

/// Whether a placeholder name is one this renderer accepts.
fn name_is_well_formed(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
}

/// Render `template`, substituting `{{name}}` from `context`.
///
/// Single pass: a substituted value is never re-scanned for placeholders, so a value that
/// happens to contain `{{other}}` renders as those literal characters.
///
/// # Errors
///
/// [`RenderError`] for an unknown placeholder, an unterminated one, or a malformed name.
pub fn render(
    template: &str,
    context: &RenderContext,
    mode: RenderMode,
) -> Result<String, RenderError> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after_open = &rest[open + 2..];
        let Some(close) = after_open.find("}}") else {
            return Err(RenderError::UnterminatedPlaceholder);
        };
        let name = after_open[..close].trim();
        if !name_is_well_formed(name) {
            return Err(RenderError::MalformedPlaceholderName(name.to_owned()));
        }
        let Some(value) = context.get(name) else {
            return Err(RenderError::UnknownPlaceholder(name.to_owned()));
        };
        // The ONLY place a value enters the output. Pushing the escaped value straight onto
        // `out`, rather than back onto the scan buffer, is what makes the pass single.
        match mode {
            RenderMode::Text => out.push_str(value),
            RenderMode::Html => out.push_str(&escape_html(value)),
        }
        rest = &after_open[close + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Check that a template is STRUCTURALLY well-formed, without rendering it.
///
/// A snapshot may carry a hand-authored template, and a promotion that accepted an unterminated
/// `{{` would store a body that fails at SEND time, when the recipient is the one who discovers
/// it. This is the template equivalent of the load-validity gate a journey artifact passes.
///
/// It answers syntax only: whether every placeholder closes and every name is well formed. It
/// deliberately does NOT answer whether the names are ones the sender will supply, because the
/// context depends on the message kind and a template for one kind is not wrong for naming a
/// placeholder another kind supplies.
///
/// Implemented by driving [`render`] rather than by walking the template again. A second walk
/// would be a second parser, and the two would drift: the one that decides what a placeholder
/// IS must be the one that decides whether a template is valid. Each round supplies the name
/// the last round reported missing, so it terminates in as many rounds as the template has
/// distinct placeholders.
///
/// # Errors
///
/// [`RenderError::UnterminatedPlaceholder`] or [`RenderError::MalformedPlaceholderName`].
pub fn validate_syntax(template: &str) -> Result<(), RenderError> {
    let mut context = RenderContext::new();
    loop {
        match render(template, &context, RenderMode::Text) {
            Ok(_) => return Ok(()),
            // Not a syntax fault: supply it and go round again, so the walk reaches the REST
            // of the template instead of stopping at the first placeholder.
            Err(RenderError::UnknownPlaceholder(name)) => {
                context.insert(name, String::new());
            }
            Err(structural) => return Err(structural),
        }
    }
}

/// Render a value destined for an email HEADER (a subject, a sender name).
///
/// Control characters are REFUSED, not escaped and not stripped. A header has no escape
/// syntax, so a bare `\r\n` does not render oddly, it ends the header: everything after it
/// becomes a new header of the attacker's choosing, which is how a `Bcc` gets added to a
/// verification email. Silently stripping would be safe for the message but would deliver a
/// subject the operator did not write and cannot see, so the send fails instead.
///
/// # Errors
///
/// [`RenderError::HeaderControlCharacter`] when the rendered value contains any control
/// character, and any error [`render`] can raise.
pub fn render_header(template: &str, context: &RenderContext) -> Result<String, RenderError> {
    // Text mode: a header is not HTML, and escaping would put `&amp;` in a subject line.
    let rendered = render(template, context, RenderMode::Text)?;
    // Every control character, not just CR and LF. A lone NUL or a vertical tab has no business
    // in a header either, and enumerating only the two that enable the classic attack is how
    // the next encoding trick gets through.
    if rendered.chars().any(char::is_control) {
        return Err(RenderError::HeaderControlCharacter);
    }
    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use super::{RenderContext, RenderError, RenderMode, render, render_header};

    fn context(pairs: &[(&str, &str)]) -> RenderContext {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn a_placeholder_is_substituted_and_surrounding_text_is_preserved() {
        let ctx = context(&[("name", "Ada"), ("link", "https://example.test/v")]);
        assert_eq!(
            render(
                "Hello {{name}}, visit {{link}} now.",
                &ctx,
                RenderMode::Text
            )
            .expect("render"),
            "Hello Ada, visit https://example.test/v now."
        );
    }

    #[test]
    fn a_template_with_no_placeholders_is_returned_unchanged() {
        let ctx = context(&[]);
        assert_eq!(
            render("nothing to see", &ctx, RenderMode::Text).expect("render"),
            "nothing to see"
        );
    }

    /// Whitespace inside the braces is tolerated, because template authors write it.
    #[test]
    fn placeholder_names_may_be_padded() {
        let ctx = context(&[("name", "Ada")]);
        for template in ["{{name}}", "{{ name }}", "{{  name  }}"] {
            assert_eq!(
                render(template, &ctx, RenderMode::Text).expect("render"),
                "Ada"
            );
        }
    }

    /// HTML mode escapes every character that can leave a text or attribute position.
    #[test]
    fn html_mode_escapes_markup_in_user_data() {
        let ctx = context(&[("name", r#"<img src=x onerror="steal()">&'"#)]);
        let rendered = render("<p>{{name}}</p>", &ctx, RenderMode::Html).expect("render");
        assert_eq!(
            rendered,
            "<p>&lt;img src=x onerror=&quot;steal()&quot;&gt;&amp;&#x27;</p>"
        );
        assert!(
            !rendered.contains("<img"),
            "markup must not survive: {rendered}"
        );
        // The template's OWN markup is untouched; only the substituted value is escaped.
        assert!(rendered.starts_with("<p>") && rendered.ends_with("</p>"));
    }

    /// The ampersand is escaped FIRST, or the escapes introduced by the other replacements
    /// would themselves be escaped and the output would show `&amp;lt;`.
    #[test]
    fn html_escaping_does_not_double_escape_its_own_output() {
        let ctx = context(&[("v", "<")]);
        assert_eq!(
            render("{{v}}", &ctx, RenderMode::Html).expect("render"),
            "&lt;"
        );
    }

    /// Text mode does NOT escape, and that is deliberate rather than an oversight.
    ///
    /// Escaping the plain-text alternative would show the recipient a literal `&amp;` in their
    /// own name, and a text part has no markup for anything to escape into.
    #[test]
    fn text_mode_leaves_values_verbatim() {
        let ctx = context(&[("name", "Ada & Lovelace <ada@example.test>")]);
        assert_eq!(
            render("Hi {{name}}", &ctx, RenderMode::Text).expect("render"),
            "Hi Ada & Lovelace <ada@example.test>"
        );
    }

    /// THE injection property: a substituted value is never re-scanned.
    ///
    /// Without this, any user who can set any string field could name another key in the render
    /// context and have it expanded, turning a display name into a way to read a password-reset
    /// link out of the same message.
    #[test]
    fn a_substituted_value_is_not_re_expanded() {
        let ctx = context(&[
            ("name", "{{reset_token}}"),
            ("reset_token", "s3cret-do-not-leak"),
        ]);
        let rendered = render("Hello {{name}}", &ctx, RenderMode::Text).expect("render");
        assert_eq!(rendered, "Hello {{reset_token}}");
        assert!(
            !rendered.contains("s3cret"),
            "a value must never be re-scanned for placeholders: {rendered}"
        );
    }

    /// The same property in HTML mode, where the braces are additionally escaped-neutral.
    #[test]
    fn a_substituted_value_is_not_re_expanded_in_html_mode() {
        let ctx = context(&[("name", "{{reset_token}}"), ("reset_token", "s3cret")]);
        let rendered = render("{{name}}", &ctx, RenderMode::Html).expect("render");
        assert!(!rendered.contains("s3cret"), "{rendered}");
    }

    /// An unknown placeholder fails the render rather than producing a hole.
    ///
    /// A verification email whose link rendered as `Click here: ` would still be SENT, and the
    /// recipient is the one who finds out.
    #[test]
    fn an_unknown_placeholder_is_an_error_not_an_empty_string() {
        let ctx = context(&[("name", "Ada")]);
        assert_eq!(
            render("Hi {{name}}, {{missing}}", &ctx, RenderMode::Text).unwrap_err(),
            RenderError::UnknownPlaceholder("missing".to_owned()),
        );
    }

    #[test]
    fn an_unterminated_placeholder_is_an_error() {
        let ctx = context(&[("name", "Ada")]);
        assert_eq!(
            render("Hi {{name", &ctx, RenderMode::Text).unwrap_err(),
            RenderError::UnterminatedPlaceholder,
        );
    }

    /// Anything resembling an expression is refused by name, not silently treated as a key.
    ///
    /// A template author who writes `{{user.name | upper}}` should learn that expressions are
    /// unsupported, not receive "unknown placeholder: user.name | upper", which reads as a
    /// renderer bug.
    #[test]
    fn expression_like_names_are_refused_as_malformed() {
        let ctx = context(&[("name", "Ada")]);
        for template in [
            "{{user.name}}",
            "{{name | upper}}",
            "{{ NAME }}",
            "{{na-me}}",
            "{{}}",
            "{{ }}",
            "{{include:/etc/passwd}}",
        ] {
            let error = render(template, &ctx, RenderMode::Text).unwrap_err();
            assert!(
                matches!(error, RenderError::MalformedPlaceholderName(_)),
                "{template} must be refused as malformed, got {error:?}"
            );
        }
    }

    /// THE header property: a control character terminates a header, so it is refused.
    #[test]
    fn a_header_value_with_a_newline_is_refused() {
        let ctx = context(&[("subject", "Welcome\r\nBcc: attacker@example.test")]);
        assert_eq!(
            render_header("{{subject}}", &ctx).unwrap_err(),
            RenderError::HeaderControlCharacter,
        );
    }

    /// Every control character, not only the two that enable the classic attack.
    #[test]
    fn a_header_refuses_any_control_character() {
        for injected in ["a\rb", "a\nb", "a\u{0}b", "a\u{b}b", "a\tb"] {
            let ctx = context(&[("v", injected)]);
            assert_eq!(
                render_header("{{v}}", &ctx).unwrap_err(),
                RenderError::HeaderControlCharacter,
                "{injected:?} must be refused"
            );
        }
    }

    /// The control-character check applies to the SUBSTITUTED value, not just the template.
    ///
    /// Checking only the template would miss the entire attack, since the attacker controls the
    /// value and not the template.
    #[test]
    fn a_clean_header_template_with_a_dirty_value_is_still_refused() {
        let ctx = context(&[("name", "Ada\r\nBcc: attacker@example.test")]);
        assert_eq!(
            render_header("Welcome, {{name}}", &ctx).unwrap_err(),
            RenderError::HeaderControlCharacter,
        );
        // The control that makes this meaningful: the same template with a clean value works.
        let clean = context(&[("name", "Ada")]);
        assert_eq!(
            render_header("Welcome, {{name}}", &clean).expect("render"),
            "Welcome, Ada"
        );
    }

    /// A header is not HTML: escaping would put `&amp;` in a subject line.
    #[test]
    fn a_header_does_not_html_escape() {
        let ctx = context(&[("org", "Ada & Co")]);
        assert_eq!(
            render_header("Invitation from {{org}}", &ctx).expect("render"),
            "Invitation from Ada & Co"
        );
    }

    /// Every error variant describes itself distinctly, so a log line diagnoses rather than
    /// merely reports.
    #[test]
    fn every_render_error_describes_itself_distinctly() {
        let all = [
            RenderError::UnknownPlaceholder("x".to_owned()),
            RenderError::UnterminatedPlaceholder,
            RenderError::MalformedPlaceholderName("x".to_owned()),
            RenderError::HeaderControlCharacter,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for error in &all {
            assert!(error.as_str().len() > 20, "{error:?} has no useful text");
            assert!(seen.insert(error.as_str()), "{error:?} shares its text");
        }
        assert_eq!(seen.len(), all.len());
    }
}
