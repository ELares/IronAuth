//! The `AuthnRequest` this deployment sends, and the HTTP-Redirect binding that carries it.
//!
//! # This is the only OUTBOUND direction in the crate
//!
//! Everything else here reads a document somebody else wrote and assumes it is hostile. This
//! module WRITES one, and the difference runs through it: there is no parser, no limit, and no
//! trust decision, because every value in the document came out of a connection row this
//! deployment controls. What it does have instead is escaping, because a row is not the same as
//! a safe string, and a bound on what it will emit at all.
//!
//! # Why an `AuthnRequest` at all, when the ACS already works
//!
//! Without one, the only reachable mode is IdP-initiated: a response arrives naming no request,
//! and the connection has to have opted into accepting those. #139 requires that mode be OFF by
//! default, and migration 0198 calls the assertion-id replay cache "the weaker defence" for a
//! reason -- it stops one assertion being used twice, and it does not stop somebody
//! auto-submitting a FRESH assertion for their own account into a victim's browser.
//!
//! THE OUTSTANDING REQUEST IS NECESSARY FOR THAT AND NOT YET SUFFICIENT, and an earlier version
//! of this paragraph said it "closes" it. What the row proves is that a response answers a
//! request THIS DEPLOYMENT issued and has not spent -- not that it answers one issued to the
//! browser now presenting it. The start endpoint is unauthenticated, so an attacker can mint
//! their own request, answer it at the identity provider as themselves, and auto-submit the
//! result into somebody else's browser; the row is spent exactly once either way.
//!
//! THE MISSING HALF IS A BROWSER BINDING: a cookie set at issue time carrying the request id or
//! its digest, checked at the assertion consumer service. It lands with sign-in, because that is
//! when a session first depends on it and this build's consumer mints nothing. One constraint is
//! worth writing down now rather than rediscovering: the response arrives on a CROSS-SITE POST,
//! so that cookie must be `SameSite=None; Secure` -- a `Lax` or `Strict` one is simply not sent,
//! and the binding would silently never match.

use ironauth_jose::SigningKey;
use std::fmt::Write as _;

/// The SAML 2.0 protocol namespace.
const PROTOCOL_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
/// The SAML 2.0 assertion namespace, for the `Issuer` element inside the request.
const ASSERTION_NS: &str = crate::ASSERTION_NS;
/// The binding the response comes back on: HTTP-POST, which is what the ACS serves.
pub const POST_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
/// The XML-Signature URI for RSA with SHA-256, which is what `SigAlg` carries.
pub const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

/// What the request asks for, all of it from the connection row.
pub struct Request<'a> {
    /// The `ID`, which is what a response's `InResponseTo` will carry. The caller generates it
    /// and records it, so this only writes it.
    pub id: &'a str,
    /// `IssueInstant`, as an `xsd:dateTime` in UTC.
    pub issue_instant: &'a str,
    /// Where it is sent: the connection's `idp_sso_url`. Written into `Destination` so the
    /// identity provider can refuse a request replayed at a different endpoint of its own.
    pub destination: &'a str,
    /// Who is asking: the connection's `sp_entity_id`.
    pub issuer: &'a str,
    /// Where the answer goes: the connection's `acs_url`.
    pub assertion_consumer_service_url: &'a str,
    /// The `NameIDPolicy` `Format` the connection is configured for.
    pub name_id_format: &'a str,
}

/// Why a request could not be built or encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    /// A field carried a character that cannot appear in XML at all.
    ///
    /// XML 1.0 has no escape for most C0 control characters, so a value holding one cannot be
    /// represented -- escaping it would produce a document no parser accepts. The connection
    /// columns are operator-supplied and bounded, so this is a misconfiguration rather than an
    /// attack, and it is refused rather than silently stripped: a `Destination` with a byte
    /// quietly removed is a URL pointing somewhere the operator did not choose.
    Unrepresentable {
        /// Which field, so the operator knows which column to fix.
        field: &'static str,
    },
    /// The signature primitive refused the key.
    Unsignable,
}

impl core::fmt::Display for RequestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unrepresentable { field } => {
                write!(
                    f,
                    "the connection's {field} contains a character XML cannot carry"
                )
            }
            Self::Unsignable => f.write_str("the connection's signing key could not sign"),
        }
    }
}

impl std::error::Error for RequestError {}

/// Build the `AuthnRequest` XML.
///
/// # What it does NOT ask for, and why each absence is deliberate
///
/// `ForceAuthn` is absent, so the identity provider may answer from an existing session. Setting
/// it would make every sign-in re-prompt, which is a policy an operator chooses, not a default.
///
/// `IsPassive` is absent for the mirror-image reason: a passive request must not prompt, and a
/// deployment that always sent one could never onboard a user who is not already signed in.
///
/// `AllowCreate` on the `NameIDPolicy` is absent rather than `true`. It asks the identity
/// provider to MINT a new identifier for somebody it has not issued one to, which is a decision
/// about their directory, not ours.
///
/// `AssertionConsumerServiceIndex` is not used; the URL is sent explicitly. An index refers into
/// metadata the identity provider fetched at some earlier time, so it is a claim about what they
/// have cached; the URL is a claim about now, and the ACS checks the `Recipient` against the
/// same column either way.
///
/// # Errors
///
/// [`RequestError::Unrepresentable`] if a field holds a character XML 1.0 cannot carry.
pub fn build(request: &Request<'_>) -> Result<String, RequestError> {
    let id = escape(request.id, "AuthnRequest ID")?;
    let issue_instant = escape(request.issue_instant, "IssueInstant")?;
    let destination = escape(request.destination, "idp_sso_url")?;
    let issuer = escape(request.issuer, "sp_entity_id")?;
    let acs_url = escape(request.assertion_consumer_service_url, "acs_url")?;
    let name_id_format = escape(request.name_id_format, "nameid_format")?;
    Ok(format!(
        "<samlp:AuthnRequest xmlns:samlp=\"{PROTOCOL_NS}\" xmlns:saml=\"{ASSERTION_NS}\" \
         ID=\"{id}\" Version=\"2.0\" IssueInstant=\"{issue_instant}\" \
         Destination=\"{destination}\" ProtocolBinding=\"{POST_BINDING}\" \
         AssertionConsumerServiceURL=\"{acs_url}\">\
         <saml:Issuer>{issuer}</saml:Issuer>\
         <samlp:NameIDPolicy Format=\"{name_id_format}\"/>\
         </samlp:AuthnRequest>"
    ))
}

/// Escape `raw` for an XML attribute value, refusing what cannot be carried.
///
/// # Five characters, three that must become numeric references, and a class with no escape
///
/// `&`, `<`, `>`, `"` and `'` become entities.
///
/// TAB, NEWLINE AND CARRIAGE RETURN BECOME `&#x9;`, `&#xA;` and `&#xD;`, and an earlier version
/// emitted them raw on the grounds that XML permits them. It does -- and XML 1.0 2.11/3.3.3 then
/// applies ATTRIBUTE-VALUE NORMALIZATION, which silently rewrites each of them to a SPACE before
/// any consumer sees the value. Every value this module writes lands in an attribute, so a
/// `Destination` or an `acs_url` holding one would reach the identity provider as a different
/// string than the row holds, and the ACS would then compare the `Recipient` it gets back
/// against the unmodified column and refuse. The numeric reference is what survives
/// normalization, and it is why this refuses nothing that XML can actually carry.
///
/// WHAT STILL HAS NO REPRESENTATION is the rest of C0, plus the two permanently unassigned
/// noncharacters `U+FFFE` and `U+FFFF`: no escape makes them legal -- `&#x1;` is as invalid as
/// the raw byte -- so a document containing one is rejected by a conforming parser. A reader
/// that stripped them would change the value; this refuses instead, and names the column.
fn escape(raw: &str, field: &'static str) -> Result<String, RequestError> {
    let mut out = String::with_capacity(raw.len());
    for character in raw.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            '\u{fffe}' | '\u{ffff}' => {
                return Err(RequestError::Unrepresentable { field });
            }
            other if (other as u32) < 0x20 => {
                return Err(RequestError::Unrepresentable { field });
            }
            other => out.push(other),
        }
    }
    Ok(out)
}

/// A signed HTTP-Redirect binding query string (OASIS Bindings 3.4.4.1).
pub struct Redirect {
    /// The query string to append to the identity provider's SSO URL, already percent-encoded.
    pub query: String,
}

/// Encode and sign `xml` for the HTTP-Redirect binding.
///
/// # The signature covers a query string, not the document
///
/// This is the part of SAML most often got wrong, and the shape is unusual: the redirect binding
/// does NOT sign the XML. It signs the octet string
/// `SAMLRequest=<v>&RelayState=<v>&SigAlg=<v>` -- the percent-encoded values, in that exact
/// order, with `RelayState` present only if it is being sent. The verifier reconstructs that
/// string from the query it received, so a signature over anything else verifies against
/// nothing.
///
/// TWO CONSEQUENCES WORTH STATING. The order is fixed by the spec and not by the order the
/// parameters happen to appear in the URL, so this builds the signing input explicitly rather
/// than reusing the query it emits. And the values signed are the ENCODED ones, so the encoding
/// is part of the signature: re-encoding a parameter differently on the way out breaks it.
///
/// # Errors
///
/// [`RequestError::Unsignable`] if the key cannot sign.
pub fn redirect(
    xml: &str,
    relay_state: Option<&str>,
    key: &SigningKey,
) -> Result<Redirect, RequestError> {
    // THE ALGORITHM COMES FROM THE KEY, not from a constant beside it. An earlier version
    // hardcoded the RSA URI while the connection's `algorithm` column was read by nothing -- so
    // the column configured nothing, and a key of another kind would have been ANNOUNCED as RSA
    // and refused by every verifier, with no clue as to why. `SigAlg` is now derived from what
    // the key actually signs with, which is the value that column constrains.
    let sig_alg_uri = match key.algorithm() {
        ironauth_jose::JwsAlgorithm::Rs256 => RSA_SHA256,
        // THE BINDING NAMES ONE ALGORITHM PER URI, and this build provisions one kind of key, so
        // anything else is a row the schema should not hold. Refusing beats announcing a URI the
        // signature does not match.
        _ => return Err(RequestError::Unsignable),
    };
    let deflated = deflate(xml.as_bytes());
    let encoded = urlencode(&base64_standard(&deflated));
    let sig_alg = urlencode(sig_alg_uri);

    let mut signing_input = format!("SAMLRequest={encoded}");
    let mut query = signing_input.clone();
    if let Some(relay) = relay_state {
        let relay = urlencode(relay);
        let _ = write!(signing_input, "&RelayState={relay}");
        let _ = write!(query, "&RelayState={relay}");
    }
    let _ = write!(signing_input, "&SigAlg={sig_alg}");
    let _ = write!(query, "&SigAlg={sig_alg}");

    let signature = ironauth_jose::sign_detached(key, signing_input.as_bytes())
        .map_err(|_| RequestError::Unsignable)?;
    let _ = write!(
        query,
        "&Signature={}",
        urlencode(&base64_standard(&signature))
    );
    Ok(Redirect { query })
}

/// DEFLATE `raw` as the redirect binding requires: a raw stream with no zlib or gzip wrapper.
///
/// # Stored blocks, and why that is not a shortcut
///
/// This emits DEFLATE's UNCOMPRESSED block type (RFC 1951 3.2.4), which every inflater accepts
/// and which needs no compression algorithm and no dependency. The binding requires the payload
/// to BE a DEFLATE stream; it does not require the stream to be small, and an `AuthnRequest` is
/// a few hundred bytes, so the difference between this and a compressed stream is tens of bytes
/// in a URL. Pulling a compression crate onto this path to save them would be the larger change.
///
/// A STORED BLOCK IS FIVE BYTES OF HEADER per 65535 bytes of payload: the final-block flag and
/// the type in the first byte, then the length and its ones-complement, little-endian. The loop
/// exists for payloads over 65535 bytes, which an `AuthnRequest` never reaches -- and writing it
/// anyway is cheaper than a comment claiming it cannot.
fn deflate(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + 8);
    let mut chunks = raw.chunks(0xFFFF).peekable();
    if raw.is_empty() {
        out.extend_from_slice(&[0x01, 0x00, 0x00, 0xFF, 0xFF]);
        return out;
    }
    while let Some(chunk) = chunks.next() {
        let last = u8::from(chunks.peek().is_none());
        let len = u16::try_from(chunk.len()).unwrap_or(u16::MAX);
        out.push(last);
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out
}

/// Standard base64 with padding, which is what the binding specifies.
fn base64_standard(raw: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(raw)
}

/// Percent-encode for a query-string VALUE.
///
/// EVERYTHING BUT THE UNRESERVED SET, which is deliberately more aggressive than a URL library's
/// default. The signature covers these exact bytes, so the encoding has to be one this code
/// controls and can reproduce; leaving a character unencoded because some table considers it
/// safe in a query is a byte the verifier may re-encode differently.
fn urlencode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            other => {
                out.push('%');
                out.push(
                    char::from_digit(u32::from(other >> 4), 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
                out.push(
                    char::from_digit(u32::from(other & 0x0F), 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    out
}
