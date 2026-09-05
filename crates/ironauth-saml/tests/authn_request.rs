//! The `AuthnRequest` this deployment sends, and its HTTP-Redirect encoding (issue #139).
//!
//! Everything else in this crate reads a hostile document. This is the one thing it writes, so
//! what is measured here is different: that the document says what the connection configured,
//! that a value which cannot be represented is refused rather than mangled, that the DEFLATE
//! stream is one a real inflater accepts, and that the signature covers the octet string OASIS
//! Bindings 3.4.4.1 names rather than one that merely looks similar.

use ironauth_jose::{JwsAlgorithm, SigningKey};
use ironauth_saml::authn_request::{self, RSA_SHA256, Request, RequestError};

const ISSUER: &str = "https://ironauth.example/saml/metadata";
const ACS: &str = "https://ironauth.example/t/acme/e/prod/saml/acs/smc_abc";
const SSO: &str = "https://idp.example/sso";
const FORMAT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

fn request() -> Request<'static> {
    Request {
        id: "_req_one",
        issue_instant: "2026-01-01T00:00:00Z",
        destination: SSO,
        issuer: ISSUER,
        assertion_consumer_service_url: ACS,
        name_id_format: FORMAT,
    }
}

/// An RSA signing key, generated once per test.
fn signing_key() -> SigningKey {
    let env = ironauth_env::Env::system();
    let der = ironauth_jose::generate_rsa_pkcs1_der(env.entropy()).expect("generate an RSA key");
    SigningKey::rsa_from_pkcs1_der(Some("sps_test".to_owned()), JwsAlgorithm::Rs256, &der)
        .expect("load the RSA key")
}

#[test]
fn the_document_carries_what_the_connection_configured() {
    let xml = authn_request::build(&request()).expect("build");

    // EVERY VALUE COMES FROM THE ROW, and each is asserted against the attribute that carries it
    // rather than against the document as a whole: a test comparing one long string passes for
    // whichever attribute happens to be wrong as readily as for none.
    assert!(xml.contains("ID=\"_req_one\""), "{xml}");
    assert!(xml.contains("Version=\"2.0\""), "{xml}");
    assert!(
        xml.contains("IssueInstant=\"2026-01-01T00:00:00Z\""),
        "{xml}"
    );
    assert!(xml.contains(&format!("Destination=\"{SSO}\"")), "{xml}");
    assert!(
        xml.contains(&format!("AssertionConsumerServiceURL=\"{ACS}\"")),
        "{xml}"
    );
    assert!(
        xml.contains(&format!("<saml:Issuer>{ISSUER}</saml:Issuer>")),
        "{xml}"
    );
    assert!(xml.contains(&format!("Format=\"{FORMAT}\"")), "{xml}");

    // THE RESPONSE COMES BACK ON THE BINDING THE ACS SERVES. A request asking for HTTP-Redirect
    // would be answered at an endpoint this deployment does not have.
    assert!(
        xml.contains("ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\""),
        "{xml}"
    );

    // AND WHAT IS DELIBERATELY ABSENT. Each of these changes what the identity provider does to
    // the person in front of it, and each absence is argued in the module doc -- so a future
    // edit that adds one has to come here and say why.
    for absent in [
        "ForceAuthn",
        "IsPassive",
        "AllowCreate",
        "AssertionConsumerServiceIndex",
    ] {
        assert!(
            !xml.contains(absent),
            "{absent} appeared in the request: {xml}"
        );
    }
}

#[test]
fn a_value_xml_cannot_carry_is_refused_and_names_its_column() {
    // NOT ESCAPED, REFUSED. XML 1.0 has no representation for most C0 controls -- `&#x1;` is as
    // invalid as the raw byte -- so a reader that stripped one would be changing the value. A
    // `Destination` silently shortened is a URL pointing somewhere the operator did not choose.
    let built = authn_request::build(&Request {
        destination: "https://idp.example/s\u{1}so",
        ..request()
    });
    assert_eq!(
        built,
        Err(RequestError::Unrepresentable {
            field: "idp_sso_url"
        })
    );

    // TAB, NEWLINE AND CARRIAGE RETURN ARE LEGAL XML and are kept, because refusing them would
    // refuse a value a schema-aware reader accepts.
    let kept = authn_request::build(&Request {
        issuer: "https://ironauth.example/\tmetadata",
        ..request()
    })
    .expect("a tab is representable");
    assert!(kept.contains("/\tmetadata"), "{kept}");

    // AND THE FIVE THAT DO HAVE ESCAPES ARE ESCAPED. An `sp_entity_id` holding a quote would
    // otherwise close the attribute it sits in and let the rest of the value become markup.
    let escaped = authn_request::build(&Request {
        issuer: "a&b<c>d\"e'f",
        ..request()
    })
    .expect("build");
    assert!(
        escaped.contains("<saml:Issuer>a&amp;b&lt;c&gt;d&quot;e&apos;f</saml:Issuer>"),
        "{escaped}"
    );
    assert!(
        !escaped.contains("d\"e"),
        "an unescaped quote reached the document: {escaped}"
    );
}

#[test]
fn the_redirect_query_is_deflated_base64_that_inflates_back() {
    let key = signing_key();
    let xml = authn_request::build(&request()).expect("build");
    let redirect = authn_request::redirect(&xml, None, &key).expect("encode");

    let encoded = param(&redirect.query, "SAMLRequest").expect("SAMLRequest is present");
    let deflated = base64_decode(&encoded);
    let inflated =
        inflate_stored(&deflated).expect("the payload is a DEFLATE stream of stored blocks");
    assert_eq!(
        String::from_utf8(inflated).expect("utf-8"),
        xml,
        "the payload did not round-trip"
    );
}

#[test]
fn the_signature_covers_the_octet_string_the_binding_names() {
    // THE SHAPE MOST OFTEN GOT WRONG. The redirect binding does not sign the XML; it signs
    // `SAMLRequest=<v>&RelayState=<v>&SigAlg=<v>` over the PERCENT-ENCODED values in that exact
    // order. A verifier reconstructs that string from what it received, so a signature over the
    // document, or over the parameters in the order they appear in the URL, verifies against
    // nothing -- and the failure looks like a bad key rather than a bad input.
    let key = signing_key();
    let xml = authn_request::build(&request()).expect("build");
    let redirect =
        authn_request::redirect(&xml, Some("/authorize?client_id=cli_x"), &key).expect("encode");

    let saml_request = param(&redirect.query, "SAMLRequest").expect("SAMLRequest");
    let relay_state = param(&redirect.query, "RelayState").expect("RelayState");
    let sig_alg = param(&redirect.query, "SigAlg").expect("SigAlg");
    let signature = param(&redirect.query, "Signature").expect("Signature");
    assert_eq!(percent_decode(&sig_alg), RSA_SHA256);

    let expected = format!("SAMLRequest={saml_request}&RelayState={relay_state}&SigAlg={sig_alg}");
    let verifying = key.verifying_key().expect("verifying key");
    ironauth_jose::verify_detached(
        &verifying,
        JwsAlgorithm::Rs256,
        expected.as_bytes(),
        &base64_decode(&signature),
    )
    .expect("the signature does not cover the octet string the binding names");

    // AND IT DOES NOT COVER A PLAUSIBLE NEIGHBOUR. Signing the parameters in the order they
    // appear in the URL is the same string here, so the discriminating case is the one where
    // `RelayState` is omitted from the input while being sent -- which is what a naive
    // "sign what I built" implementation produces.
    let without_relay = format!("SAMLRequest={saml_request}&SigAlg={sig_alg}");
    assert!(
        ironauth_jose::verify_detached(
            &verifying,
            JwsAlgorithm::Rs256,
            without_relay.as_bytes(),
            &base64_decode(&signature),
        )
        .is_err(),
        "the signature verifies over an input missing the RelayState it was sent with"
    );
}

#[test]
fn an_absent_relay_state_is_absent_from_both_the_query_and_the_signing_input() {
    // OASIS Bindings 3.4.4.1: `RelayState` appears in the signing input only if it is being
    // sent. Including an empty one would make the string this deployment signs differ from the
    // one a conformant verifier rebuilds, and every request would be refused.
    let key = signing_key();
    let xml = authn_request::build(&request()).expect("build");
    let redirect = authn_request::redirect(&xml, None, &key).expect("encode");
    assert!(
        param(&redirect.query, "RelayState").is_none(),
        "an absent RelayState was sent anyway: {}",
        redirect.query
    );

    let saml_request = param(&redirect.query, "SAMLRequest").expect("SAMLRequest");
    let sig_alg = param(&redirect.query, "SigAlg").expect("SigAlg");
    let signature = param(&redirect.query, "Signature").expect("Signature");
    let expected = format!("SAMLRequest={saml_request}&SigAlg={sig_alg}");
    ironauth_jose::verify_detached(
        &key.verifying_key().expect("verifying key"),
        JwsAlgorithm::Rs256,
        expected.as_bytes(),
        &base64_decode(&signature),
    )
    .expect("the signing input carried a RelayState that was not sent");
}

/// The value of `name` in a query string, still percent-encoded.
fn param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| value.to_owned())
    })
}

fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).expect("ascii");
            out.push(u8::from_str_radix(hex, 16).expect("hex"));
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).expect("utf-8")
}

fn base64_decode(raw: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(percent_decode(raw))
        .expect("standard base64")
}

/// Inflate a DEFLATE stream made entirely of STORED blocks (RFC 1951 3.2.4).
///
/// WRITTEN OUT RATHER THAN PULLED IN, for the reason the encoder gives: the tree has no
/// compression crate, and the stream this encoder emits has exactly one block type. It also
/// makes the test stricter than a library would -- a stream with a Huffman block would fail here
/// rather than being quietly inflated, so the encoder cannot start emitting one unnoticed.
fn inflate_stored(raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut index = 0;
    loop {
        let header = *raw.get(index)?;
        // Bit 0 is BFINAL; bits 1-2 are BTYPE, which must be 00 for a stored block.
        if header & 0b0000_0110 != 0 {
            return None;
        }
        let last = header & 1 == 1;
        let len = u16::from_le_bytes([*raw.get(index + 1)?, *raw.get(index + 2)?]);
        let nlen = u16::from_le_bytes([*raw.get(index + 3)?, *raw.get(index + 4)?]);
        if nlen != !len {
            return None;
        }
        let start = index + 5;
        let end = start + len as usize;
        out.extend_from_slice(raw.get(start..end)?);
        index = end;
        if last {
            return (index == raw.len()).then_some(out);
        }
    }
}
