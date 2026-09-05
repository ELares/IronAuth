//! The SP metadata document an operator uploads to their identity provider (issue #139).
//!
//! # What this closes
//!
//! `AuthnRequest` issuance signs with a key per connection, and until now nothing published the
//! public half -- so an identity provider that verified the signature had nothing to verify it
//! against, and one that did not verify was the only kind that worked. The signature was produced
//! correctly and could not be checked by the far side. This is the other end of that.
//!
//! It also carries the two facts an operator would otherwise type by hand and mistype: the entity
//! id this deployment presents to them, and the URL their responses go to. Both come out of the
//! connection row, so the document and the checks the assertion consumer performs cannot disagree
//! -- which is the failure mode of a metadata document maintained separately from the code.
//!
//! # A self-signed certificate, and why that is the right kind
//!
//! SAML metadata carries a key inside an `<ds:X509Certificate>`, and every identity provider
//! worth naming requires that form rather than a bare `<ds:KeyValue>`. The certificate here is
//! self-signed and carries no chain, which is not a weakness in this context: metadata trust in
//! SAML comes from HOW THE DOCUMENT WAS OBTAINED -- an operator downloads it over TLS and uploads
//! it into their own tenant -- and not from a certificate authority. Shibboleth's explicit-key
//! trust engine is built on exactly that reading, and it is the reason `anchors` on the inbound
//! side ignores certificate expiry too: what is pinned is key material, not a chain.

use ironauth_der::write::{
    bit_string, context, generalized_time, name_common, oid, seq, tlv, uint,
};
use ironauth_jose::SigningKey;

/// The SAML 2.0 metadata namespace.
const METADATA_NS: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
/// The XML Signature namespace, for the `KeyInfo` the metadata carries.
const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
/// The binding the assertion consumer service is served on.
const POST_BINDING: &str = crate::authn_request::POST_BINDING;

/// What the document describes, all of it from the connection row.
pub struct Descriptor<'a> {
    /// The entity id this deployment presents: the connection's `sp_entity_id`.
    pub entity_id: &'a str,
    /// Where responses are posted: the connection's `acs_url`.
    pub assertion_consumer_service_url: &'a str,
    /// The `NameID` format the connection is configured for.
    pub name_id_format: &'a str,
    /// The connection's signing key, whose public half the document publishes.
    pub key: &'a SigningKey,
    /// The certificate's `notBefore`, in seconds since the epoch.
    pub not_before_unix_secs: i64,
    /// The certificate's `notAfter`, in seconds since the epoch.
    pub not_after_unix_secs: i64,
}

/// Why a metadata document could not be produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataError {
    /// A field carried a character XML cannot represent.
    Unrepresentable {
        /// Which column, so the operator knows what to fix.
        field: &'static str,
    },
    /// The key is not one this build can put in a certificate.
    UnsupportedKey,
    /// The certificate could not be signed.
    Unsignable,
}

impl core::fmt::Display for MetadataError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unrepresentable { field } => {
                write!(
                    f,
                    "the connection's {field} contains a character XML cannot carry"
                )
            }
            Self::UnsupportedKey => {
                f.write_str("the connection's signing key is not one this server can publish")
            }
            Self::Unsignable => f.write_str("the metadata certificate could not be signed"),
        }
    }
}

impl std::error::Error for MetadataError {}

/// Build the `<md:EntityDescriptor>` document.
///
/// # What it does and does not advertise
///
/// `AuthnRequestsSigned="true"` is asserted, because this deployment always signs them and an
/// identity provider that reads the metadata should be configured to verify. `WantAssertionsSigned`
/// is asserted too: the assertion consumer refuses an unsigned assertion, so a provider that
/// honours the flag and one that ignores it reach the same outcome, and the flag is what turns a
/// refusal into a setup step rather than a mystery.
///
/// NO `<md:SingleLogoutService>`, because #139 puts Single Logout out of scope and advertising an
/// endpoint that does not exist is worse than advertising none: a provider will call it.
///
/// ONE `AssertionConsumerService`, at index 0, marked `isDefault`. A second would need a second
/// binding this build does not serve.
///
/// # Errors
///
/// [`MetadataError`] if a column cannot be represented in XML, or if the key cannot be published
/// or cannot sign.
pub fn entity_descriptor(descriptor: &Descriptor<'_>) -> Result<String, MetadataError> {
    let certificate = self_signed_certificate(descriptor)?;
    let entity_id = escape(descriptor.entity_id, "sp_entity_id")?;
    let acs_url = escape(descriptor.assertion_consumer_service_url, "acs_url")?;
    let name_id_format = escape(descriptor.name_id_format, "nameid_format")?;
    // BASE64 WITH NO LINE BREAKS. The schema permits them and most providers accept them, and a
    // conformant reader is entitled to apply `xs:base64Binary` whitespace rules either way -- so
    // emitting none is the reading every parser agrees on.
    let encoded = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(&certificate)
    };
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <md:EntityDescriptor xmlns:md=\"{METADATA_NS}\" xmlns:ds=\"{XMLDSIG_NS}\" \
         entityID=\"{entity_id}\">\
         <md:SPSSODescriptor protocolSupportEnumeration=\"{METADATA_NS_PROTOCOL}\" \
         AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\">\
         <md:KeyDescriptor use=\"signing\">\
         <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{encoded}</ds:X509Certificate>\
         </ds:X509Data></ds:KeyInfo></md:KeyDescriptor>\
         <md:NameIDFormat>{name_id_format}</md:NameIDFormat>\
         <md:AssertionConsumerService Binding=\"{POST_BINDING}\" Location=\"{acs_url}\" \
         index=\"0\" isDefault=\"true\"/>\
         </md:SPSSODescriptor></md:EntityDescriptor>"
    ))
}

/// The protocol an `SPSSODescriptor` must enumerate: SAML 2.0 itself.
const METADATA_NS_PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";

/// Build a self-signed X.509 certificate over the connection's signing key.
///
/// # The structure, spelled out because it is written by hand
///
/// `Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }`, and the
/// signature covers the DER of `tbsCertificate` exactly as encoded -- not a re-encoding of it,
/// which is why the bytes are built once and both used and signed.
///
/// THE SUBJECT AND ISSUER ARE THE SAME NAME, which is what self-signed means, and both are the
/// entity id. An identity provider displays this to an operator confirming they pasted the right
/// document, so it should be the string they recognise rather than a hostname.
fn self_signed_certificate(descriptor: &Descriptor<'_>) -> Result<Vec<u8>, MetadataError> {
    let public_key = descriptor
        .key
        .rsa_public_key_der()
        .ok_or(MetadataError::UnsupportedKey)?;

    // `AlgorithmIdentifier` for sha256WithRSAEncryption, and for rsaEncryption in the SPKI. Both
    // carry an explicit NULL parameter: RFC 4055 says RSA algorithm identifiers MUST, and a
    // certificate omitting it is one some verifiers reject.
    let signature_algorithm = seq(&[oid(&[1, 2, 840, 113_549, 1, 1, 11]), tlv(0x05, &[])]);
    let key_algorithm = seq(&[oid(&[1, 2, 840, 113_549, 1, 1, 1]), tlv(0x05, &[])]);
    let spki = seq(&[key_algorithm, bit_string(public_key)]);
    let name = name_common(descriptor.entity_id);

    let tbs = seq(&[
        // [0] EXPLICIT version, v3 (the value 2). Required because extensions are present.
        context(0, &uint(2)),
        // A SERIAL DERIVED FROM notBefore rather than random. It must be positive and unique per
        // issuer, and here the issuer is this key: a rotation mints a new key with a new
        // certificate, so the pair (issuer, serial) cannot repeat unless two certificates are
        // minted for one key in the same second, which the one-live-key index forbids.
        uint(u64::try_from(descriptor.not_before_unix_secs.max(1)).unwrap_or(1)),
        signature_algorithm.clone(),
        name.clone(),
        seq(&[
            generalized_time(descriptor.not_before_unix_secs),
            generalized_time(descriptor.not_after_unix_secs),
        ]),
        name,
        spki,
        // [3] EXPLICIT extensions: keyUsage, critical, digitalSignature only. A certificate that
        // asserts more than it needs invites a verifier to accept it for more than it should.
        context(3, &seq(&[key_usage_digital_signature()])),
    ]);

    let signature = ironauth_jose::sign_detached(descriptor.key, &tbs)
        .map_err(|_| MetadataError::Unsignable)?;
    Ok(seq(&[tbs, signature_algorithm, bit_string(&signature)]))
}

/// The `keyUsage` extension asserting `digitalSignature` and nothing else.
///
/// CRITICAL, which is what RFC 5280 recommends for `keyUsage` and what makes the restriction
/// meaningful: a verifier that does not understand the extension must refuse the certificate
/// rather than ignore the limit.
fn key_usage_digital_signature() -> Vec<u8> {
    // BIT STRING with 7 unused bits and bit 0 set: digitalSignature is the first bit, and the
    // encoding is the minimal one DER requires -- trailing zero bits are not written.
    let bits = tlv(0x03, &[0x07, 0x80]);
    seq(&[
        oid(&[2, 5, 29, 15]),
        tlv(0x01, &[0xFF]),
        ironauth_der::write::octet_string(&bits),
    ])
}

/// Escape `raw` for an XML attribute value or text node, refusing what cannot be carried.
///
/// THE SAME CONTRACT AS `authn_request::escape`, and deliberately a second copy rather than a
/// shared helper: these two modules write DIFFERENT documents for different readers, and a shared
/// escaper would be a single point whose contract has to serve both. The rules are XML's, not
/// this crate's, so the duplication cannot drift in a way a reader would not notice -- and the
/// alternative, a `pub(crate)` helper, is one refactor away from being applied to a third
/// document with a different node grammar.
fn escape(raw: &str, field: &'static str) -> Result<String, MetadataError> {
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
            '\u{fffe}' | '\u{ffff}' => return Err(MetadataError::Unrepresentable { field }),
            other if (other as u32) < 0x20 => {
                return Err(MetadataError::Unrepresentable { field });
            }
            other => out.push(other),
        }
    }
    Ok(out)
}
