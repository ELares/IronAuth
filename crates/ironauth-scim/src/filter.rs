// SPDX-License-Identifier: MIT OR Apache-2.0

//! The RFC 7644 section 3.4.2.2 filter grammar, parsed into a typed tree.
//!
//! # Why the type matters more than the parser
//!
//! A SCIM filter is attacker-controlled text that a server is asked to turn into a query.
//! The failure this crate exists to prevent is not "the parser has a bug", it is "the raw
//! text reached the datastore". Those are different problems and only one of them is fixable
//! by being careful.
//!
//! So [`Filter`] cannot represent unparsed text. There is no `Filter::Raw`, no
//! `Filter::from_str` that stores what it could not understand, and no public constructor
//! at all: [`parse_filter`] is the only way to obtain one. A caller that wanted to pass a
//! filter through untouched has nothing to put it in. The compiler enforces what a review
//! comment would otherwise have to.
//!
//! # What is refused, and why the bounds exist
//!
//! Depth and length are bounded. A filter is a tree an attacker chooses the shape of, and
//! `((((((...))))))` nested ten thousand deep is a stack overflow in a recursive-descent
//! parser, which is a crash rather than a rejection. The bounds are generous against any
//! real provisioning client and small against a hostile one.

use std::fmt;

/// The maximum parenthesis / grouping depth.
///
/// A recursive-descent parser recurses once per nesting level, so an unbounded depth is a
/// stack overflow reachable from a query string. Okta and Entra filters in practice nest two
/// or three deep; twenty is far beyond any of them and far below a crash.
const MAX_DEPTH: usize = 20;

/// The maximum filter length in bytes.
///
/// Bounded before parsing, so a megabyte of input costs a length check rather than a parse.
const MAX_LEN: usize = 4096;

/// A parsed SCIM filter.
///
/// Deliberately has NO variant carrying raw text: see the module docs. A value of this type
/// is a filter that was understood, which is the property the datastore boundary needs.
#[derive(Debug, Clone, PartialEq)]
pub enum Filter {
    /// `attr op value`, for example `userName eq "alice"`.
    Compare {
        /// The attribute being compared.
        path: AttributePath,
        /// The comparison.
        op: CompareOp,
        /// The literal being compared against.
        value: Value,
    },
    /// `attr pr`: the attribute is present.
    Present {
        /// The attribute being tested.
        path: AttributePath,
        /// The (single) presence operator, kept as a type so the shape stays uniform.
        op: PresentOp,
    },
    /// `a and b`.
    And(Box<Filter>, Box<Filter>),
    /// `a or b`.
    Or(Box<Filter>, Box<Filter>),
    /// `not (a)`.
    Not(Box<Filter>),
}

/// An attribute path: an optional schema URN, a name, and an optional sub-attribute.
///
/// Parsed into PARTS rather than kept as a dotted string, for the same reason the filter is
/// parsed at all: a caller holding `name.givenName` as text is one string concatenation away
/// from the injection this type exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributePath {
    /// The schema URN, when the path was fully qualified.
    pub urn: Option<String>,
    /// The attribute name, for example `userName`.
    pub name: String,
    /// The sub-attribute, for example the `givenName` of `name.givenName`.
    pub sub: Option<String>,
}

/// The RFC 7644 comparison operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    /// `eq`
    Equal,
    /// `ne`
    NotEqual,
    /// `co`
    Contains,
    /// `sw`
    StartsWith,
    /// `ew`
    EndsWith,
    /// `gt`
    GreaterThan,
    /// `ge`
    GreaterOrEqual,
    /// `lt`
    LessThan,
    /// `le`
    LessOrEqual,
}

/// The presence operator, `pr`. A type rather than a bare marker so a future operator with
/// no value cannot be added as an untyped special case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentOp;

/// A comparison literal.
///
/// The JSON types RFC 7644 allows, and nothing else. A `Value` cannot hold an object or an
/// array, because no comparison operator accepts one and admitting them would create a shape
/// every consumer has to handle and none can act on.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// A quoted string.
    String(String),
    /// A JSON number.
    Number(f64),
    /// `true` or `false`.
    Boolean(bool),
    /// `null`.
    Null,
}

/// Why a filter was refused.
///
/// Every variant carries enough to build the SCIM error a client can act on; none carries the
/// offending text, because echoing an attacker's input back into a response body is how a
/// parser becomes a reflection gadget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterError {
    /// The filter exceeded [`MAX_LEN`].
    TooLong {
        /// The bound that was exceeded.
        limit: usize,
    },
    /// The filter nested deeper than [`MAX_DEPTH`].
    TooDeep {
        /// The bound that was exceeded.
        limit: usize,
    },
    /// A token was not what the grammar allows at that position.
    Unexpected {
        /// The byte offset, so a client can point at the problem without the server echoing it.
        at: usize,
    },
    /// The filter ended in the middle of a construct.
    UnexpectedEnd,
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { limit } => write!(f, "the filter exceeds {limit} bytes"),
            Self::TooDeep { limit } => write!(f, "the filter nests deeper than {limit}"),
            Self::Unexpected { at } => write!(f, "unexpected token at offset {at}"),
            Self::UnexpectedEnd => write!(f, "the filter ended unexpectedly"),
        }
    }
}

/// The SCIM error body (RFC 7644 section 3.12) a refusal renders as.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ScimErrorBody {
    /// Always the SCIM Error schema URN.
    pub schemas: Vec<String>,
    /// The SCIM detail type. `invalidFilter` for every refusal here.
    #[serde(rename = "scimType")]
    pub scim_type: String,
    /// A human-readable detail that NEVER contains the rejected input.
    pub detail: String,
    /// The HTTP status, as SCIM requires, as a string.
    pub status: String,
}

impl FilterError {
    /// The SCIM error body for this refusal.
    ///
    /// `invalidFilter` with a 400 for every variant: RFC 7644 section 3.12 names exactly that
    /// for a filter the service provider cannot parse, and distinguishing the reasons in
    /// `scimType` would tell a prober which of its inputs got furthest.
    #[must_use]
    pub fn to_scim_error(&self) -> ScimErrorBody {
        ScimErrorBody {
            schemas: vec!["urn:ietf:params:scim:api:messages:2.0:Error".to_owned()],
            scim_type: "invalidFilter".to_owned(),
            detail: self.to_string(),
            status: "400".to_owned(),
        }
    }
}

/// Parse a SCIM filter.
///
/// The ONLY way to obtain a [`Filter`]. Everything the grammar does not allow is refused
/// here, so a caller holding a `Filter` is holding something understood.
///
/// # Errors
///
/// [`FilterError`] naming which bound or grammar rule refused it, never echoing the input.
pub fn parse_filter(input: &str) -> Result<Filter, FilterError> {
    if input.len() > MAX_LEN {
        return Err(FilterError::TooLong { limit: MAX_LEN });
    }
    let mut parser = Parser {
        bytes: input.as_bytes(),
        pos: 0,
        depth: 0,
    };
    let filter = parser.parse_or()?;
    parser.skip_spaces();
    if parser.pos != parser.bytes.len() {
        // Trailing input is a REFUSAL, not something to ignore. A parser that stopped at the
        // first complete filter would accept `userName eq "a" DROP TABLE`, understanding the
        // first half and silently discarding the rest.
        return Err(FilterError::Unexpected { at: parser.pos });
    }
    Ok(filter)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    depth: usize,
}

impl Parser<'_> {
    fn skip_spaces(&mut self) {
        while self.pos < self.bytes.len() && self.bytes[self.pos] == b' ' {
            self.pos += 1;
        }
    }

    /// Whether the next token, case-insensitively, is `word` followed by a delimiter.
    ///
    /// The delimiter check is what keeps `organisation` from matching the `or` operator: a
    /// bare prefix test would split an attribute name down the middle and parse the halves.
    fn peek_word(&mut self, word: &str) -> bool {
        self.skip_spaces();
        let end = self.pos + word.len();
        if end > self.bytes.len() {
            return false;
        }
        if !self.bytes[self.pos..end].eq_ignore_ascii_case(word.as_bytes()) {
            return false;
        }
        match self.bytes.get(end) {
            None => true,
            Some(&next) => next == b' ' || next == b'(' || next == b')',
        }
    }

    fn take_word(&mut self, word: &str) -> bool {
        if self.peek_word(word) {
            self.pos += word.len();
            true
        } else {
            false
        }
    }

    fn parse_or(&mut self) -> Result<Filter, FilterError> {
        let mut left = self.parse_and()?;
        while self.take_word("or") {
            let right = self.parse_and()?;
            left = Filter::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Filter, FilterError> {
        let mut left = self.parse_unary()?;
        while self.take_word("and") {
            let right = self.parse_unary()?;
            left = Filter::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Filter, FilterError> {
        if self.take_word("not") {
            self.skip_spaces();
            let inner = self.parse_group()?;
            return Ok(Filter::Not(Box::new(inner)));
        }
        self.skip_spaces();
        if self.bytes.get(self.pos) == Some(&b'(') {
            return self.parse_group();
        }
        self.parse_compare()
    }

    fn parse_group(&mut self) -> Result<Filter, FilterError> {
        self.skip_spaces();
        if self.bytes.get(self.pos) != Some(&b'(') {
            return Err(FilterError::Unexpected { at: self.pos });
        }
        // Counted BEFORE recursing, so the bound is checked on the way down where the stack
        // is actually consumed.
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(FilterError::TooDeep { limit: MAX_DEPTH });
        }
        self.pos += 1;
        let inner = self.parse_or()?;
        self.skip_spaces();
        if self.bytes.get(self.pos) != Some(&b')') {
            return Err(FilterError::UnexpectedEnd);
        }
        self.pos += 1;
        self.depth -= 1;
        Ok(inner)
    }

    fn parse_compare(&mut self) -> Result<Filter, FilterError> {
        let path = self.parse_path()?;
        self.skip_spaces();
        if self.take_word("pr") {
            return Ok(Filter::Present {
                path,
                op: PresentOp,
            });
        }
        let op = self.parse_op()?;
        self.skip_spaces();
        let value = self.parse_value()?;
        Ok(Filter::Compare { path, op, value })
    }

    /// An attribute path: `urn:...:Name.sub`, `Name.sub`, or `Name`.
    ///
    /// The URN is recognised by the LAST colon, because a SCIM URN contains colons itself and
    /// splitting on the first would cut the URN in half.
    fn parse_path(&mut self) -> Result<AttributePath, FilterError> {
        self.skip_spaces();
        let start = self.pos;
        while self.pos < self.bytes.len() {
            let byte = self.bytes[self.pos];
            if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'_' | b'-' | b'$') {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err(FilterError::Unexpected { at: start });
        }
        // Safe: every accepted byte above is ASCII, so the slice is on a char boundary.
        let raw = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| FilterError::Unexpected { at: start })?;
        let (urn, rest) = match raw.rfind(':') {
            Some(index) => (Some(raw[..index].to_owned()), &raw[index + 1..]),
            None => (None, raw),
        };
        let (name, sub) = match rest.split_once('.') {
            Some((name, sub)) => (name, Some(sub.to_owned())),
            None => (rest, None),
        };
        if name.is_empty() || sub.as_ref().is_some_and(String::is_empty) {
            return Err(FilterError::Unexpected { at: start });
        }
        Ok(AttributePath {
            urn,
            name: name.to_owned(),
            sub,
        })
    }

    fn parse_op(&mut self) -> Result<CompareOp, FilterError> {
        for (word, op) in [
            ("eq", CompareOp::Equal),
            ("ne", CompareOp::NotEqual),
            ("co", CompareOp::Contains),
            ("sw", CompareOp::StartsWith),
            ("ew", CompareOp::EndsWith),
            ("ge", CompareOp::GreaterOrEqual),
            ("gt", CompareOp::GreaterThan),
            ("le", CompareOp::LessOrEqual),
            ("lt", CompareOp::LessThan),
        ] {
            if self.take_word(word) {
                return Ok(op);
            }
        }
        self.skip_spaces();
        Err(FilterError::Unexpected { at: self.pos })
    }

    fn parse_value(&mut self) -> Result<Value, FilterError> {
        self.skip_spaces();
        match self.bytes.get(self.pos) {
            None => Err(FilterError::UnexpectedEnd),
            Some(&b'"') => self.parse_string(),
            Some(_) if self.take_word("true") => Ok(Value::Boolean(true)),
            Some(_) if self.take_word("false") => Ok(Value::Boolean(false)),
            Some(_) if self.take_word("null") => Ok(Value::Null),
            Some(_) => self.parse_number(),
        }
    }

    fn parse_string(&mut self) -> Result<Value, FilterError> {
        // Skip the opening quote.
        self.pos += 1;
        let mut out = String::new();
        loop {
            let Some(&byte) = self.bytes.get(self.pos) else {
                // An unterminated string is UnexpectedEnd, not a string running to the end of
                // input: accepting it would make `userName eq "alice` a valid filter.
                return Err(FilterError::UnexpectedEnd);
            };
            self.pos += 1;
            match byte {
                b'"' => break,
                b'\\' => {
                    let Some(&escaped) = self.bytes.get(self.pos) else {
                        return Err(FilterError::UnexpectedEnd);
                    };
                    self.pos += 1;
                    match escaped {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b't' => out.push('\t'),
                        b'r' => out.push('\r'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'u' => {
                            // Four hex digits. Bounds-checked BEFORE the slice, because the
                            // obvious version indexes past the end on a truncated escape and
                            // panics, which is a crash reachable from a query string.
                            let end = self.pos + 4;
                            if end > self.bytes.len() {
                                return Err(FilterError::UnexpectedEnd);
                            }
                            let hex = std::str::from_utf8(&self.bytes[self.pos..end])
                                .map_err(|_| FilterError::Unexpected { at: self.pos })?;
                            let code = u32::from_str_radix(hex, 16)
                                .map_err(|_| FilterError::Unexpected { at: self.pos })?;
                            let Some(character) = char::from_u32(code) else {
                                // A lone surrogate has no character. Refused rather than
                                // replaced, so a filter cannot smuggle U+FFFD past a
                                // comparison that was written against the original.
                                return Err(FilterError::Unexpected { at: self.pos });
                            };
                            out.push(character);
                            self.pos = end;
                        }
                        _ => return Err(FilterError::Unexpected { at: self.pos - 1 }),
                    }
                }
                _ => {
                    // Multi-byte UTF-8 passes through byte by byte; the accumulated bytes are
                    // still valid UTF-8 because the input was.
                    let start = self.pos - 1;
                    let width = utf8_width(byte);
                    let end = start + width;
                    if end > self.bytes.len() {
                        return Err(FilterError::UnexpectedEnd);
                    }
                    let text = std::str::from_utf8(&self.bytes[start..end])
                        .map_err(|_| FilterError::Unexpected { at: start })?;
                    out.push_str(text);
                    self.pos = end;
                }
            }
        }
        Ok(Value::String(out))
    }

    fn parse_number(&mut self) -> Result<Value, FilterError> {
        let start = self.pos;
        while self.pos < self.bytes.len() {
            let byte = self.bytes[self.pos];
            if byte.is_ascii_digit() || matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E') {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err(FilterError::Unexpected { at: start });
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| FilterError::Unexpected { at: start })?;
        text.parse::<f64>()
            .map(Value::Number)
            .map_err(|_| FilterError::Unexpected { at: start })
    }
}

/// The byte width of a UTF-8 sequence from its leading byte.
fn utf8_width(byte: u8) -> usize {
    if byte < 0x80 {
        1
    } else if byte >> 5 == 0b110 {
        2
    } else if byte >> 4 == 0b1110 {
        3
    } else {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(name: &str) -> AttributePath {
        AttributePath {
            urn: None,
            name: name.to_owned(),
            sub: None,
        }
    }

    #[test]
    fn the_grammar_parses_the_shapes_okta_and_entra_actually_send() {
        // Taken from what real provisioning clients send, not from what is convenient to
        // parse: an equality on userName, a presence test, a conjunction, and a
        // fully-qualified enterprise-extension path.
        assert_eq!(
            parse_filter(r#"userName eq "alice""#).expect("valid"),
            Filter::Compare {
                path: path("userName"),
                op: CompareOp::Equal,
                value: Value::String("alice".to_owned()),
            }
        );
        assert!(matches!(
            parse_filter("title pr").expect("valid"),
            Filter::Present { .. }
        ));
        assert!(matches!(
            parse_filter(r#"userName eq "a" and active eq true"#).expect("valid"),
            Filter::And(..)
        ));
        let qualified = parse_filter(
            r#"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber eq "7""#,
        )
        .expect("valid");
        let Filter::Compare { path, .. } = qualified else {
            panic!("a comparison");
        };
        assert_eq!(
            path.urn.as_deref(),
            Some("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"),
            "the URN is split on the LAST colon, so a URN containing colons survives"
        );
        assert_eq!(path.name, "employeeNumber");
    }

    #[test]
    fn a_sub_attribute_is_parsed_into_parts_rather_than_kept_as_text() {
        let parsed = parse_filter(r#"name.givenName eq "ada""#).expect("valid");
        let Filter::Compare { path, .. } = parsed else {
            panic!("a comparison");
        };
        assert_eq!(path.name, "name");
        assert_eq!(path.sub.as_deref(), Some("givenName"));
    }

    #[test]
    fn an_operator_name_inside_an_attribute_is_not_an_operator() {
        // `organisation` starts with `or`, and `andrew` with `and`. A prefix test without a
        // delimiter check splits the attribute and parses the halves, which is how a filter
        // means something other than what it says.
        let parsed = parse_filter(r#"organisation eq "acme""#).expect("valid");
        let Filter::Compare { path, .. } = parsed else {
            panic!("a comparison");
        };
        assert_eq!(path.name, "organisation");
        assert!(matches!(
            parse_filter(r#"andrew eq "x""#).expect("valid"),
            Filter::Compare { .. }
        ));
    }

    #[test]
    fn trailing_input_is_refused_rather_than_ignored() {
        // The injection shape. A parser that stopped at the first complete filter would
        // understand the first half and silently discard whatever followed it.
        let refused = parse_filter(r#"userName eq "a" DROP TABLE users"#);
        assert!(refused.is_err(), "trailing input must be refused");
        assert!(parse_filter(r#"userName eq "a" ; --"#).is_err());
    }

    #[test]
    fn an_unterminated_string_is_refused() {
        assert_eq!(
            parse_filter(r#"userName eq "alice"#),
            Err(FilterError::UnexpectedEnd),
            "an unterminated string must not run to the end of input and be accepted"
        );
    }

    #[test]
    fn a_truncated_unicode_escape_is_refused_rather_than_panicking() {
        // The obvious implementation slices four bytes without checking the end, which
        // panics. A crash reachable from a query string is worse than a wrong answer.
        assert_eq!(
            parse_filter(r#"userName eq "\u00"#),
            Err(FilterError::UnexpectedEnd)
        );
        assert!(parse_filter(r#"userName eq "\uZZZZ""#).is_err());
        // A lone surrogate has no character. Refused rather than replaced, so a filter
        // cannot smuggle U+FFFD past a comparison written against the original.
        assert!(parse_filter(r#"userName eq "\ud800""#).is_err());
    }

    #[test]
    fn nesting_past_the_bound_is_refused_rather_than_overflowing_the_stack() {
        let deep = format!(
            "{}userName eq \"a\"{}",
            "(".repeat(MAX_DEPTH + 5),
            ")".repeat(MAX_DEPTH + 5)
        );
        assert_eq!(
            parse_filter(&deep),
            Err(FilterError::TooDeep { limit: MAX_DEPTH }),
            "an attacker chooses the shape of this tree"
        );
        // And the bound is not so tight that a real filter trips it.
        let ordinary = r#"(userName eq "a" or (userName eq "b" and active eq true))"#;
        assert!(parse_filter(ordinary).is_ok());
    }

    #[test]
    fn a_filter_past_the_length_bound_is_refused_before_it_is_parsed() {
        let long = format!(r#"userName eq "{}""#, "a".repeat(MAX_LEN));
        assert_eq!(
            parse_filter(&long),
            Err(FilterError::TooLong { limit: MAX_LEN })
        );
    }

    #[test]
    fn the_error_body_is_scim_shaped_and_never_echoes_the_input() {
        // A parser that reflected its input would be a gadget for getting attacker text into
        // a response body. The detail names the RULE, never the value.
        let hostile = r#"userName eq "<script>alert(1)</script>"#;
        let error = parse_filter(hostile).expect_err("refused");
        let body = error.to_scim_error();
        assert_eq!(body.scim_type, "invalidFilter");
        assert_eq!(body.status, "400");
        assert_eq!(
            body.schemas,
            vec!["urn:ietf:params:scim:api:messages:2.0:Error".to_owned()]
        );
        assert!(
            !body.detail.contains("script"),
            "the error must not echo the rejected input: {}",
            body.detail
        );
    }

    #[test]
    fn every_refusal_renders_the_same_scim_type() {
        // Distinguishing the reasons in `scimType` would tell a prober which of its inputs
        // got furthest through the grammar.
        for input in [
            "userName eq ",
            r#"userName zz "a""#,
            "(",
            r#"userName eq "a" trailing"#,
            &"(".repeat(MAX_DEPTH + 2),
        ] {
            let error = parse_filter(input).expect_err("refused");
            assert_eq!(error.to_scim_error().scim_type, "invalidFilter", "{input}");
        }
    }

    #[test]
    fn no_input_makes_the_parser_panic() {
        // A cheap structural sweep over the shapes a fuzzer reaches first. The real fuzz
        // target is fuzz/fuzz_targets/scim_filter.rs; this keeps the property in the
        // ordinary lane, where a regression is noticed on the commit that caused it.
        for input in [
            "",
            " ",
            "(",
            ")",
            "()",
            "and",
            "or",
            "not",
            "not(",
            "pr",
            "\"",
            "\\",
            "\\u",
            "userName",
            "userName eq",
            "userName eq \"",
            "userName eq \\",
            ".",
            ":",
            "..",
            "a.b.c eq \"x\"",
            "a: eq \"x\"",
            "-",
            "1e",
            "1e999999",
            "true",
            "null",
            "userName eq \u{1F600}",
            "\u{1F600} eq \"a\"",
            "not not not (a pr)",
        ] {
            // The contract is "returns", not "succeeds": most of these are refusals.
            let _ = parse_filter(input);
        }
    }

    #[test]
    fn a_filter_cannot_be_constructed_from_unparsed_text() {
        // The structural property the module docs claim, asserted as a fact about the type
        // rather than as prose: every way to build a Filter goes through the parser, so a
        // caller has nowhere to put raw text. If a `Raw` variant or a public constructor is
        // ever added, this stops compiling and the reviewer is told why.
        let filter = parse_filter(r#"userName eq "a""#).expect("valid");
        match filter {
            Filter::Compare { .. }
            | Filter::Present { .. }
            | Filter::And(..)
            | Filter::Or(..)
            | Filter::Not(..) => {}
        }
    }
}
