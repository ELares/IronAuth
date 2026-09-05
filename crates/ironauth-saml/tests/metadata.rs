//! The SP metadata document, and the certificate inside it (issue #139).
//!
//! # The test that matters most
//!
//! `x509::pinned` is this crate's reader for a certificate an operator pins. The certificate this
//! module WRITES goes to an identity provider, and an operator commonly pastes the same bytes
//! back into a tool -- so the sharpest check available is that the writer's output is something
//! the reader beside it accepts, yielding the same key. An encoder that got a minimal length, an
//! integer sign byte or a bit string's unused-bit count wrong would pass a "does it contain the
//! right substring" test and fail here.

use ironauth_jose::{JwsAlgorithm, SigningKey};
use ironauth_saml::metadata::{self, Descriptor, MetadataError};
use ironauth_saml::x509;

const ENTITY_ID: &str = "https://ironauth.example/saml/smc_abc/metadata";
const ACS: &str = "https://ironauth.example/t/acme/e/prod/saml/acs/smc_abc";
const FORMAT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
const NOT_BEFORE: i64 = 1_767_225_600;
const NOT_AFTER: i64 = 1_798_761_600;

fn signing_key() -> SigningKey {
    let env = ironauth_env::Env::system();
    let der = ironauth_jose::generate_rsa_pkcs1_der(env.entropy()).expect("generate an RSA key");
    SigningKey::rsa_from_pkcs1_der(Some("sps_test".to_owned()), JwsAlgorithm::Rs256, &der)
        .expect("load the RSA key")
}

fn descriptor(key: &SigningKey) -> Descriptor<'_> {
    Descriptor {
        entity_id: ENTITY_ID,
        assertion_consumer_service_url: ACS,
        name_id_format: FORMAT,
        key,
        not_before_unix_secs: NOT_BEFORE,
        not_after_unix_secs: NOT_AFTER,
    }
}

/// The base64 inside the document's single `<ds:X509Certificate>`, decoded.
fn certificate_der(document: &str) -> Vec<u8> {
    use base64::Engine as _;
    let encoded = document
        .split("<ds:X509Certificate>")
        .nth(1)
        .and_then(|rest| rest.split("</ds:X509Certificate>").next())
        .expect("the document carries a certificate");
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .expect("standard base64 with no line breaks")
}

#[test]
fn the_certificate_this_writes_is_one_the_pinning_reader_accepts() {
    // THE ROUND TRIP, and the reason both directions of DER live in one crate. The document goes
    // out through the encoder and the certificate comes back through `x509::pinned` -- the same
    // function an operator's re-pinned certificate goes through -- so any disagreement about
    // minimal lengths, sign bytes or unused bits fails here rather than at an identity provider,
    // where it would present as "the signature did not verify".
    let key = signing_key();
    let document = metadata::entity_descriptor(&descriptor(&key)).expect("build");
    let der = certificate_der(&document);

    let pinned = x509::pinned(&der).expect("the reader beside the writer accepts what it wrote");
    assert_eq!(pinned.not_before_unix_secs, NOT_BEFORE);
    assert_eq!(pinned.not_after_unix_secs, NOT_AFTER);

    // AND IT IS THE SAME KEY. Reading a certificate proves the encoding; comparing the key
    // proves the certificate is about the key the connection signs with, which is the whole
    // point of publishing it. A document carrying a well-formed certificate for a DIFFERENT key
    // is the defect this catches and a structural check would not.
    let ironauth_jose::xmldsig::XmlSigKey::Rsa { modulus, exponent } = &pinned.key else {
        panic!("the certificate published a non-RSA key: {:?}", pinned.key);
    };
    // THE WRITER'S OWN SOURCE, decoded the same way: `rsa_public_key_der` hands back
    // `SEQUENCE { modulus, exponent }`, so both sides become the same two integers and the
    // comparison is exact rather than a substring search.
    let source = key.rsa_public_key_der().expect("an RSA key");
    let mut outer = ironauth_der::Der::new(source);
    let mut public = outer.take_sequence().expect("RSAPublicKey");
    let expected_modulus = public
        .take_tag(ironauth_der::tag::INTEGER)
        .expect("a modulus");
    let expected_exponent = public
        .take_tag(ironauth_der::tag::INTEGER)
        .expect("an exponent");
    // THE READER STRIPS THE SIGN BYTE the writer adds, which is the encoding rule both halves
    // have to agree on -- so the comparison is against the stripped form.
    assert_eq!(
        modulus.as_slice(),
        expected_modulus
            .strip_prefix(&[0x00])
            .unwrap_or(expected_modulus),
        "the certificate published a modulus other than the connection's"
    );
    assert_eq!(
        exponent.as_slice(),
        expected_exponent
            .strip_prefix(&[0x00])
            .unwrap_or(expected_exponent)
    );
}

#[test]
fn the_document_carries_the_connections_own_values() {
    let key = signing_key();
    let document = metadata::entity_descriptor(&descriptor(&key)).expect("build");

    // FROM THE ROW, each asserted against the attribute that carries it: a test comparing one
    // long string passes for whichever attribute is wrong as readily as for none.
    assert!(
        document.contains(&format!("entityID=\"{ENTITY_ID}\"")),
        "{document}"
    );
    assert!(
        document.contains(&format!("Location=\"{ACS}\"")),
        "{document}"
    );
    assert!(
        document.contains(&format!("<md:NameIDFormat>{FORMAT}</md:NameIDFormat>")),
        "{document}"
    );
    assert!(
        document.contains("Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\""),
        "{document}"
    );

    // WHAT IT ASSERTS ABOUT THIS DEPLOYMENT, both of which an identity provider acts on.
    assert!(
        document.contains("AuthnRequestsSigned=\"true\""),
        "{document}"
    );
    assert!(
        document.contains("WantAssertionsSigned=\"true\""),
        "{document}"
    );
    assert!(document.contains("use=\"signing\""), "{document}");

    // AND WHAT IT MUST NOT: an endpoint this build does not serve. A provider WILL call a
    // SingleLogoutService it is given, and #139 puts Single Logout out of scope.
    assert!(!document.contains("SingleLogoutService"), "{document}");
    assert!(!document.contains("use=\"encryption\""), "{document}");
}

#[test]
fn a_value_xml_cannot_carry_is_refused_and_names_its_column() {
    let key = signing_key();
    for (field, mutate) in [
        (
            "sp_entity_id",
            (|d: &mut Descriptor<'_>| d.entity_id = "https://a\u{1}b") as fn(&mut Descriptor<'_>),
        ),
        ("acs_url", |d: &mut Descriptor<'_>| {
            d.assertion_consumer_service_url = "https://a\u{1}b";
        }),
        ("nameid_format", |d: &mut Descriptor<'_>| {
            d.name_id_format = "urn:\u{1}";
        }),
    ] {
        let mut spec = descriptor(&key);
        mutate(&mut spec);
        assert_eq!(
            metadata::entity_descriptor(&spec),
            Err(MetadataError::Unrepresentable { field }),
            "the refusal named the wrong column for {field}"
        );
    }

    // AND THE FIVE WITH ESCAPES ARE ESCAPED, not refused: an entity id holding a quote would
    // otherwise close the attribute it sits in and let the rest become markup.
    let mut spec = descriptor(&key);
    spec.entity_id = "a&b<c>d\"e'f";
    let document = metadata::entity_descriptor(&spec).expect("build");
    assert!(
        document.contains("entityID=\"a&amp;b&lt;c&gt;d&quot;e&apos;f\""),
        "{document}"
    );
    assert!(
        !document.contains("d\"e"),
        "an unescaped quote reached the document: {document}"
    );
}

#[test]
fn a_key_this_build_cannot_publish_is_refused_rather_than_omitted() {
    // A DOCUMENT WITH NO KEY IS WORSE THAN NO DOCUMENT: an operator uploads it, their identity
    // provider accepts it, and every signed request is then refused for a reason the metadata
    // gave no hint of. `UnsupportedKey` names the situation instead.
    let env = ironauth_env::Env::system();
    let der = ironauth_jose::generate_ecdsa_p256_pkcs8_der(env.entropy()).expect("generate");
    let ec = SigningKey::ecdsa_p256_from_pkcs8(None, &der).expect("load");
    let mut spec = descriptor(&ec);
    spec.key = &ec;
    assert_eq!(
        metadata::entity_descriptor(&spec),
        Err(MetadataError::UnsupportedKey)
    );
}

#[test]
fn the_certificate_is_base64_with_no_line_breaks() {
    // THE SCHEMA PERMITS LINE BREAKS and most providers accept them, so this is a choice rather
    // than a rule -- but `xs:base64Binary` whitespace handling is one of the places readers
    // differ, and emitting none is the reading they all agree on.
    let key = signing_key();
    let document = metadata::entity_descriptor(&descriptor(&key)).expect("build");
    let encoded = document
        .split("<ds:X509Certificate>")
        .nth(1)
        .and_then(|rest| rest.split("</ds:X509Certificate>").next())
        .expect("a certificate");
    assert!(
        !encoded.contains('\n') && !encoded.contains('\r') && !encoded.contains(' '),
        "the certificate carried whitespace"
    );
    assert!(encoded.len() > 400, "the certificate is implausibly short");
}
