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
//! So [`Filter`] cannot REPRESENT unparsed text. There is no `Filter::Raw` and no
//! `From<String>`: every variant is a construct the grammar produced, so a caller who wanted
//! to pass a filter through untouched has nothing to put it in.
//!
//! Being precise about the limit of that, because an earlier version of this paragraph
//! overstated it and a reviewer was right to say so: `Filter` is an enum a consumer has to
//! MATCH on, so its variants are public and a caller can hand-build a tree. What they cannot
//! do is build one that holds text nobody parsed, which is the property the datastore
//! boundary needs. [`crate::ResourceRef`] and [`crate::PatchPath`] carry `String`s rather
//! than a closed shape, so those two DO hide their fields and can only be produced by their
//! parsers; the difference is deliberate and follows from what each type has to let a
//! consumer do.
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
    /// `attr[subfilter]`: a filter over the values of ONE multi-valued attribute.
    ///
    /// RFC 7644 section 3.4.2.2 calls this a valuePath, and it is not a convenience: it is
    /// how a client says "the work email" rather than "some email is work and some email
    /// contains this". `emails[type eq "work" and value ew "@example.com"]` selects a single
    /// value satisfying both; `emails.type eq "work" and emails.value ew "@example.com"`
    /// matches a user with a work phone-less address and an unrelated personal one. Okta and
    /// Entra both send the bracketed form, so a server without it refuses real traffic.
    ValuePath {
        /// The multi-valued attribute whose values the sub-filter selects among.
        path: AttributePath,
        /// The filter applied to each value of that attribute.
        filter: Box<Filter>,
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
        in_value_path: false,
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
    /// Whether the parser is inside a valuePath's brackets.
    ///
    /// RFC 7644 section 3.4.2.2 defines the bracketed sub-filter over attribute expressions
    /// only, so `emails[a[b eq "x"]]` is not in the grammar. Tracked rather than assumed,
    /// because a parser that quietly accepted it would build a shape no consumer knows how
    /// to evaluate, and "we never generate that" is not a property of attacker input.
    in_value_path: bool,
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
            // `]` closes a valuePath, so `emails[value pr]` ends its operator on one. It is
            // safe to admit as a delimiter for the same reason the parentheses are: no
            // attribute name may contain it, so it cannot split one.
            Some(&next) => next == b' ' || next == b'(' || next == b')' || next == b']',
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
        // No `skip_spaces` first: the grammar writes `valuePath = attrPath "[" valFilter "]"`
        // with nothing between the name and the bracket, and `parse_path` stops exactly on a
        // `[` because it is not an attribute-name byte.
        if self.bytes.get(self.pos) == Some(&b'[') {
            return self.parse_value_path(path);
        }
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

    /// `attrPath "[" valFilter "]"`, positioned on the opening bracket.
    fn parse_value_path(&mut self, path: AttributePath) -> Result<Filter, FilterError> {
        if self.in_value_path {
            // Not in the grammar. Refused rather than parsed, because accepting it would
            // build a nested shape every consumer would have to handle and the spec gives
            // no meaning to.
            return Err(FilterError::Unexpected { at: self.pos });
        }
        // A bracket recurses exactly as a parenthesis does, so it consumes stack and is
        // counted against the SAME bound. Counted before recursing, on the way down.
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(FilterError::TooDeep { limit: MAX_DEPTH });
        }
        self.pos += 1;
        self.in_value_path = true;
        let inner = self.parse_or();
        // Cleared before the `?` below, so a refusal inside the brackets does not leave the
        // parser believing it is still inside them.
        self.in_value_path = false;
        let inner = inner?;
        self.skip_spaces();
        if self.bytes.get(self.pos) != Some(&b']') {
            return Err(FilterError::UnexpectedEnd);
        }
        self.pos += 1;
        self.depth -= 1;
        Ok(Filter::ValuePath {
            path,
            filter: Box::new(inner),
        })
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

/// Whether `resource` satisfies `filter` (RFC 7644 section 3.4.2.2).
///
/// # Why the evaluator lives beside the parser
///
/// Because the parser's guarantee is only half of one. [`Filter`] cannot hold raw filter text,
/// so no filter reaches a datastore unparsed -- but a filter that is parsed and then never
/// APPLIED is a filter the caller believes narrowed the answer and did not. Putting the
/// semantics in the same module as the grammar is what makes "every operator the parser
/// accepts is an operator something can act on" checkable in one place: a new [`CompareOp`]
/// breaks this match, rather than silently becoming an operator that parses and does nothing.
///
/// # Attribute names are matched case-insensitively
///
/// RFC 7643 section 2.1 says attribute names are case insensitive, and Okta sends `userName`
/// where Entra sends `username`. A case-sensitive lookup would answer "no such user" to one
/// vendor for a person the other can see.
///
/// A path that names no attribute of the resource does not match, for every operator except
/// `ne`: "not equal to a value that is not there" is true, and a resource missing the
/// attribute is genuinely not equal to it. That asymmetry is RFC 7644's, not this function's.
#[must_use]
pub fn matches(filter: &Filter, resource: &serde_json::Value) -> bool {
    match filter {
        Filter::Compare { path, op, value } => {
            let found = attribute_values(resource, path);
            if found.is_empty() {
                // "not equal to a value that is not there" is true; every other operator is
                // false against an attribute the resource does not carry. That asymmetry is
                // RFC 7644's, not this function's.
                return *op == CompareOp::NotEqual;
            }
            found.iter().any(|value_at| compare(value_at, *op, value))
        }
        Filter::Present {
            path,
            op: PresentOp,
        } => attribute_values(resource, path)
            .iter()
            .any(|found| !found.is_null()),
        Filter::ValuePath { path, filter } => {
            // The sub-filter applies to each VALUE of the multi-valued attribute, and the
            // whole path matches when ONE value satisfies the whole sub-filter. This reads
            // the attribute directly rather than through `attribute_values`, because that
            // helper flattens a sub-attribute across values, which is exactly the
            // across-values semantics a value path exists to refuse.
            match member(resource, &path.name) {
                Some(serde_json::Value::Array(values)) => {
                    values.iter().any(|value| matches(filter, value))
                }
                Some(single) => matches(filter, single),
                None => false,
            }
        }
        Filter::And(left, right) => matches(left, resource) && matches(right, resource),
        Filter::Or(left, right) => matches(left, resource) || matches(right, resource),
        Filter::Not(inner) => !matches(inner, resource),
    }
}

/// Every value an [`AttributePath`] names inside `resource`.
///
/// # A dotted path over a multi-valued attribute distributes across its values
///
/// `emails.type eq "work"` must match a user with several addresses one of which is a work
/// one, which means the path names a LIST of candidate values rather than a single one. A
/// lookup that returned the array itself and then asked it for a `type` member would find
/// nothing, and every dotted filter over `emails`, `phoneNumbers` or any other multi-valued
/// attribute would silently match nobody.
///
/// This distribution is also precisely what a value path does NOT do, and the difference is
/// the reason RFC 7644 section 3.4.2.2 has both spellings: `emails.type eq "work" and
/// emails.value ew "@example.com"` may be satisfied by two DIFFERENT addresses, while
/// `emails[type eq "work" and value ew "@example.com"]` requires one address to be both.
///
/// The schema URN half of a qualified path is IGNORED rather than matched. This surface
/// serves one schema per resource type, so `urn:...:core:2.0:User:userName` and `userName`
/// name the same thing; matching the URN would make a fully qualified filter (which Entra
/// sends) miss the attribute it correctly named.
fn attribute_values<'a>(
    resource: &'a serde_json::Value,
    path: &AttributePath,
) -> Vec<&'a serde_json::Value> {
    let Some(found) = member(resource, &path.name) else {
        return Vec::new();
    };
    match (path.sub.as_deref(), found) {
        (None, serde_json::Value::Array(values)) => values.iter().collect(),
        (None, single) => vec![single],
        (Some(sub), serde_json::Value::Array(values)) => values
            .iter()
            .filter_map(|value| member(value, sub))
            .collect(),
        (Some(sub), single) => member(single, sub).into_iter().collect(),
    }
}

/// One member of a JSON object, matched case-insensitively on the key.
fn member<'a>(value: &'a serde_json::Value, name: &str) -> Option<&'a serde_json::Value> {
    let object = value.as_object()?;
    object
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, found)| found)
}

/// Apply one comparison operator to a resource value and a filter literal.
///
/// Types that cannot be ordered do not compare: `gt` against a boolean is FALSE rather than an
/// error, because a filter is a selection and a value that cannot satisfy the test simply does
/// not. String comparison is case-insensitive, which RFC 7643 section 2.1 requires for the
/// `caseExact: false` attributes that make up the core user schema.
fn compare(found: &serde_json::Value, op: CompareOp, literal: &Value) -> bool {
    match (found, literal) {
        (serde_json::Value::String(left), Value::String(right)) => string_compare(left, op, right),
        (serde_json::Value::Bool(left), Value::Boolean(right)) => match op {
            CompareOp::Equal => left == right,
            CompareOp::NotEqual => left != right,
            _ => false,
        },
        (serde_json::Value::Number(left), Value::Number(right)) => {
            let Some(left) = left.as_f64() else {
                return false;
            };
            match op {
                // Bit-for-bit equality on the two f64s, which is what the JSON numbers
                // actually are; no epsilon, because a filter is a selection over stored
                // values rather than a measurement.
                CompareOp::Equal => (left - right).abs() == 0.0,
                CompareOp::NotEqual => (left - right).abs() != 0.0,
                CompareOp::GreaterThan => left > *right,
                CompareOp::GreaterOrEqual => left >= *right,
                CompareOp::LessThan => left < *right,
                CompareOp::LessOrEqual => left <= *right,
                CompareOp::Contains | CompareOp::StartsWith | CompareOp::EndsWith => false,
            }
        }
        (serde_json::Value::Null, Value::Null) => op == CompareOp::Equal,
        // Everything else is a TYPE MISMATCH: a null against a non-null, a string against a
        // number, an object against anything. None of them satisfies an equality and all of
        // them satisfy its negation, which is one arm rather than several saying the same.
        _ => op == CompareOp::NotEqual,
    }
}

/// The string half of [`compare`], case-insensitive per RFC 7643 section 2.1.
fn string_compare(left: &str, op: CompareOp, right: &str) -> bool {
    let left_folded = left.to_lowercase();
    let right_folded = right.to_lowercase();
    match op {
        CompareOp::Equal => left_folded == right_folded,
        CompareOp::NotEqual => left_folded != right_folded,
        CompareOp::Contains => left_folded.contains(&right_folded),
        CompareOp::StartsWith => left_folded.starts_with(&right_folded),
        CompareOp::EndsWith => left_folded.ends_with(&right_folded),
        CompareOp::GreaterThan => left_folded > right_folded,
        CompareOp::GreaterOrEqual => left_folded >= right_folded,
        CompareOp::LessThan => left_folded < right_folded,
        CompareOp::LessOrEqual => left_folded <= right_folded,
    }
}

#[cfg(test)]
mod evaluator_tests {
    use super::*;

    fn user() -> serde_json::Value {
        serde_json::json!({
            "id": "usr_1",
            "userName": "Alice@Example.com",
            "active": true,
            "externalId": "okta-77",
            "emails": [
                {"type": "work", "value": "alice@example.com"},
                {"type": "home", "value": "a@home.test"},
            ],
        })
    }

    fn holds(input: &str) -> bool {
        matches(&parse_filter(input).expect("a valid filter"), &user())
    }

    #[test]
    fn the_two_filters_a_provisioning_client_actually_sends_select_the_right_user() {
        // These are the ONLY filters Okta and Entra send during ordinary provisioning, so a
        // server that got either wrong would fail against real traffic on the first sync.
        assert!(holds(r#"userName eq "alice@example.com""#));
        assert!(holds(r#"externalId eq "okta-77""#));
        assert!(!holds(r#"userName eq "bob@example.com""#));
        assert!(!holds(r#"externalId eq "okta-78""#));
    }

    #[test]
    fn attribute_names_and_string_values_are_matched_case_insensitively() {
        // RFC 7643 section 2.1. Okta sends `userName`, Entra sends `username`, and the stored
        // handle here is mixed case: all three spellings name one person.
        assert!(holds(r#"username eq "ALICE@EXAMPLE.COM""#));
        assert!(holds(r#"USERNAME eq "alice@example.com""#));
        assert!(holds(r#"userName eq "Alice@Example.com""#));
    }

    #[test]
    fn a_value_path_selects_within_one_value_rather_than_across_all_of_them() {
        // The distinction the ValuePath doc comment names, asserted: the bracketed form
        // requires ONE email to be both work and at example.com, and the dotted form does
        // not. A user whose work address is elsewhere must not match the bracketed filter.
        assert!(holds(
            r#"emails[type eq "work" and value ew "@example.com"]"#
        ));
        assert!(!holds(
            r#"emails[type eq "home" and value ew "@example.com"]"#
        ));
        // The control: the dotted spelling matches, because the two conditions are satisfied
        // by DIFFERENT values. Without this the test above would pass on an evaluator that
        // simply never matched a value path.
        assert!(holds(
            r#"emails.type eq "home" and emails.value ew "@example.com""#
        ));
    }

    #[test]
    fn an_absent_attribute_matches_ne_and_nothing_else() {
        assert!(!holds(r#"nickName eq "alice""#));
        assert!(holds(r#"nickName ne "alice""#));
        assert!(!holds("nickName pr"));
        assert!(holds("userName pr"));
    }

    #[test]
    fn the_boolean_and_the_connectives_behave() {
        assert!(holds("active eq true"));
        assert!(!holds("active eq false"));
        assert!(holds(r#"active eq true and userName sw "alice""#));
        assert!(holds(r#"active eq false or userName co "example""#));
        assert!(holds(r#"not (userName eq "bob@example.com")"#));
        // The control for `not`: it has to be able to be false too, or every negation would
        // pass and the assertion above would say nothing.
        assert!(!holds(r#"not (userName eq "alice@example.com")"#));
    }

    #[test]
    fn a_fully_qualified_path_names_the_same_attribute_as_the_bare_one() {
        // Entra qualifies paths with the schema URN. Both spellings must select the user.
        assert!(holds(
            r#"urn:ietf:params:scim:schemas:core:2.0:User:userName eq "alice@example.com""#
        ));
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
        // A prefix test without a delimiter check splits an attribute name down the middle
        // and parses the halves, which is how a filter means something other than what it
        // says.
        //
        // The inputs below are chosen so that DELETING the delimiter check changes the
        // result. An earlier version of this test used `organisation eq "acme"`, which does
        // not: the attribute scan is greedy, so it swallows `organisation` whole before any
        // operator word is looked for, and the check never runs. The cases that matter are
        // the ones where an operator word is tested at a position an attribute also starts
        // at, which is every word tried BEFORE the attribute is read (`not`) and every word
        // tried where a value may begin (`true`, `false`, `null`).
        let parsed = parse_filter("notes pr").expect("`notes` is an attribute, not `not`");
        let Filter::Present { path, .. } = parsed else {
            panic!("a presence test");
        };
        assert_eq!(path.name, "notes");

        for (input, attribute) in [
            ("nothing eq \"x\"", "nothing"),
            ("notify eq \"x\"", "notify"),
        ] {
            let Filter::Compare { path, .. } = parse_filter(input).expect(input) else {
                panic!("a comparison for {input}");
            };
            assert_eq!(path.name, attribute, "{input}");
        }

        // The value side: `truename` is not `true` followed by junk. Without the delimiter
        // check the value parser takes the boolean and the remainder becomes trailing input.
        for literal_prefixed in [
            "userName eq truename",
            "userName eq falsehood",
            "userName eq nullable",
        ] {
            assert!(
                parse_filter(literal_prefixed).is_err(),
                "{literal_prefixed} is not a valid literal and must be refused outright"
            );
        }

        // And the operator itself still works when it IS the operator, so the check above is
        // not passing merely because everything is refused.
        assert!(matches!(
            parse_filter(r#"not (userName eq "a")"#).expect("valid"),
            Filter::Not(_)
        ));
        assert!(matches!(
            parse_filter("userName eq true").expect("valid"),
            Filter::Compare {
                value: Value::Boolean(true),
                ..
            }
        ));
        let parsed = parse_filter(r#"organisation eq "acme""#).expect("valid");
        let Filter::Compare { path, .. } = parsed else {
            panic!("a comparison");
        };
        assert_eq!(path.name, "organisation");
    }

    #[test]
    fn a_value_path_selects_within_one_multi_valued_attribute() {
        // The shape Okta and Entra both send. Criterion 1 asks for the RFC 7644 grammar, and
        // a server without this refuses real provisioning traffic outright.
        let parsed = parse_filter(r#"emails[type eq "work" and value ew "@example.com"]"#)
            .expect("a valuePath is in the grammar");
        let Filter::ValuePath { path, filter } = parsed else {
            panic!("a value path");
        };
        assert_eq!(path.name, "emails");
        assert_eq!(path.sub, None, "the bracket is not a sub-attribute");
        let Filter::And(left, right) = *filter else {
            panic!("the sub-filter is parsed, not held as text");
        };
        assert!(matches!(
            *left,
            Filter::Compare {
                op: CompareOp::Equal,
                ..
            }
        ));
        assert!(matches!(
            *right,
            Filter::Compare {
                op: CompareOp::EndsWith,
                ..
            }
        ));
    }

    #[test]
    fn a_value_path_is_not_the_same_filter_as_the_dotted_form() {
        // Why the variant exists at all. `emails[type eq "work" and value co "x"]` requires
        // ONE address to satisfy both; the dotted conjunction is satisfied by two different
        // addresses. A parser that folded the bracket into the dotted form would silently
        // widen every filter a connector sends.
        let bracketed = parse_filter(r#"emails[type eq "work" and value co "x"]"#).expect("valid");
        let dotted =
            parse_filter(r#"emails.type eq "work" and emails.value co "x""#).expect("valid");
        assert_ne!(bracketed, dotted);
    }

    #[test]
    fn a_value_path_still_obeys_every_bound_the_rest_of_the_grammar_does() {
        // A bracket recurses, so it is a stack-overflow lever unless it is counted. The
        // nesting refusal is separate: it is not in the grammar, and a shape no consumer can
        // evaluate must not become a value of this type.
        assert_eq!(
            parse_filter(&format!(
                "emails[{}value pr{}]",
                "(".repeat(MAX_DEPTH),
                ")".repeat(MAX_DEPTH)
            )),
            Err(FilterError::TooDeep { limit: MAX_DEPTH }),
            "the bracket counts against the same depth bound as a parenthesis"
        );
        assert!(
            parse_filter(r#"emails[members[value eq "x"]]"#).is_err(),
            "a nested valuePath is not in the grammar"
        );
        assert!(
            parse_filter(r#"emails[type eq "work""#).is_err(),
            "an unclosed bracket is refused rather than run to the end of input"
        );
        assert!(
            parse_filter("emails[]").is_err(),
            "an empty sub-filter is refused"
        );
        // The presence operator inside brackets: its delimiter is the `]`, which is the case
        // the delimiter set has to admit for real traffic to parse.
        assert!(matches!(
            parse_filter("emails[value pr]").expect("valid"),
            Filter::ValuePath { .. }
        ));
    }

    #[test]
    fn trailing_input_is_refused_rather_than_ignored() {
        // The injection shape. A parser that stopped at the first complete filter would
        // understand the first half and silently discard whatever followed it.
        // The marker on the next line is there because the audit scan matches per line:
        // this is hostile INPUT to the parser under test, not a query this crate runs.
        let refused = parse_filter(r#"userName eq "a" DROP TABLE users"#); // query-audit-allow: parser input, not a query
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
    fn no_filter_variant_can_hold_unparsed_text() {
        // The property, stated exactly. This is an EXHAUSTIVE match over every variant, so
        // adding a `Raw(String)` stops it compiling and the reviewer is told why. It does NOT
        // claim the enum is unconstructible: a consumer must match on it, so its variants are
        // public and a caller can hand-build a tree. What no variant offers is somewhere to
        // put text the grammar did not produce, and that is the property the boundary needs.
        let filter = parse_filter(r#"userName eq "a""#).expect("valid");
        match filter {
            Filter::Compare { path, op: _, value } => {
                // Every field of every variant is a parsed construct, not a passthrough:
                // `path` is split into parts and `value` is a typed literal.
                let _ = (path.urn, path.name, path.sub);
                match value {
                    Value::String(_) | Value::Number(_) | Value::Boolean(_) | Value::Null => {}
                }
            }
            Filter::Present {
                path,
                op: PresentOp,
            } => {
                let _ = (path.urn, path.name, path.sub);
            }
            Filter::ValuePath { path, filter } => {
                // The bracketed sub-filter is a `Filter`, not the text between the brackets,
                // so the property holds recursively rather than stopping at the bracket.
                let _ = (path.urn, path.name, path.sub, filter);
            }
            Filter::And(_, _) | Filter::Or(_, _) | Filter::Not(_) => {}
        }
    }
}
