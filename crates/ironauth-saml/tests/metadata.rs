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

#[test]
fn the_certificate_verifies_under_its_own_published_key() {
    // THE CHECK THAT WOULD HAVE CAUGHT THE WORST DEFECT IN THIS MODULE. `x509::pinned`
    // deliberately never verifies a signature -- it reads a key out of a certificate an operator
    // pinned, and the trust decision is the pinning -- so the round-trip test above accepts a
    // certificate whose `signatureAlgorithm` says one thing and whose `signatureValue` is
    // another. An earlier version hardcoded sha256WithRSAEncryption while signing with whatever
    // the key declared, and five of the six RSA algorithms then produced a certificate every
    // real verifier refuses.
    let key = signing_key();
    let document = metadata::entity_descriptor(&descriptor(&key)).expect("build");
    let der = certificate_der(&document);

    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let mut outer = ironauth_der::Der::new(&der);
    let mut certificate = outer.take_sequence().expect("a certificate");
    let (_, tbs_bytes, _) = certificate.take_element().expect("the TBS");
    let _algorithm = certificate.take_element().expect("the algorithm");
    let signature = certificate
        .take_tag(ironauth_der::tag::BIT_STRING)
        .expect("the signature");

    // THE SIGNATURE COVERS THE TBS BYTES EXACTLY AS EMITTED, which is why they are taken from
    // the encoded certificate rather than rebuilt: a verifier re-encoding the TBS would be
    // checking a different question from the one a real one asks.
    ironauth_jose::verify_detached(
        &key.verifying_key().expect("verifying key"),
        ironauth_jose::JwsAlgorithm::Rs256,
        tbs_bytes,
        signature.strip_prefix(&[0x00]).expect("zero unused bits"),
    )
    .expect("the certificate does not verify under the key it publishes");
}

#[test]
fn a_key_whose_algorithm_has_no_oid_in_this_build_is_refused() {
    // AN RSA KEY IS NOT ENOUGH. The guard used to be "is it RSA", which admits Rs384, Rs512 and
    // the three PSS variants -- each of which signs with a different digest or padding than the
    // certificate announces. A certificate that lies about its own signature is refused by every
    // verifier that checks, and by nothing here, so the refusal has to be at the writer.
    let env = ironauth_env::Env::system();
    let der = ironauth_jose::generate_rsa_pkcs1_der(env.entropy()).expect("generate");
    for algorithm in [
        JwsAlgorithm::Rs384,
        JwsAlgorithm::Rs512,
        JwsAlgorithm::Ps256,
    ] {
        let other = SigningKey::rsa_from_pkcs1_der(None, algorithm, &der).expect("load");
        let mut spec = descriptor(&other);
        spec.key = &other;
        assert_eq!(
            metadata::entity_descriptor(&spec),
            Err(MetadataError::UnsupportedKey),
            "{algorithm:?} produced a certificate announcing a different algorithm"
        );
    }
}

#[test]
fn the_validity_uses_the_form_rfc_5280_requires_for_its_year() {
    // RFC 5280 4.1.2.5 IS A MUST: `UTCTime` through 2049, `GeneralizedTime` after. An earlier
    // version wrote `GeneralizedTime` always and justified it by what readers accept, which is
    // not what the rule is about -- every certificate this produced was non-conforming for the
    // next twenty-three years.
    let key = signing_key();

    // 2026: both bounds inside the UTCTime range.
    let document = metadata::entity_descriptor(&descriptor(&key)).expect("build");
    let der = certificate_der(&document);
    assert_eq!(validity_tags(&der), (0x17, 0x17), "a pre-2050 date was not UTCTime");

    // A WINDOW THAT CROSSES THE BOUNDARY takes one form each, which is the case a single-form
    // encoder cannot produce and the one the rule exists for.
    let mut spec = descriptor(&key);
    spec.not_before_unix_secs = 2_524_608_000; // 2050-01-01
    spec.not_after_unix_secs = 2_556_144_000; // 2051-01-01
    let der = certificate_der(&metadata::entity_descriptor(&spec).expect("build"));
    assert_eq!(
        validity_tags(&der),
        (0x18, 0x18),
        "a post-2049 date was not GeneralizedTime"
    );
}

/// The two tag bytes of a certificate's `Validity` pair.
#[test]
fn the_document_is_well_formed_xml() {
    // NOTHING HERE PARSED THE DOCUMENT AS XML. Every other test in this file reads it with
    // `split`, which is happy with a document no parser would accept: an unbalanced element, a
    // stray `&`, a duplicate attribute. An identity provider parses it, so this suite has to --
    // and with a parser the WRITER does not go through, which is why `quick-xml` is a dev
    // dependency here rather than the crate's own reader.
    let key = signing_key();
    let document = metadata::entity_descriptor(&descriptor(&key)).expect("a document");

    let mut reader = quick_xml::reader::Reader::from_str(&document);
    // THE RULE THAT MAKES A START TAG AND ITS END TAG ONE THING, without which an unbalanced
    // document parses cleanly and this test asserts nothing.
    reader.config_mut().check_end_names = true;
    let mut depth: i64 = 0;
    let mut elements = 0_u32;
    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(_)) => {
                depth += 1;
                elements += 1;
            }
            Ok(quick_xml::events::Event::Empty(_)) => elements += 1,
            Ok(quick_xml::events::Event::End(_)) => depth -= 1,
            Ok(quick_xml::events::Event::Eof) => break,
            Ok(_) => {}
            Err(error) => panic!("the metadata document is not well-formed XML: {error}"),
        }
    }
    assert_eq!(depth, 0, "the document closes at a depth other than zero");
    // AND IT IS NOT A DOCUMENT THAT PARSED BECAUSE IT WAS EMPTY, which is the degenerate input
    // every assertion above is satisfied by.
    assert!(elements >= 5, "only {elements} elements parsed");
}

#[test]
fn a_value_carrying_xml_syntax_does_not_escape_its_attribute() {
    // THE ESCAPING, MEASURED BY A PARSER RATHER THAN BY A SUBSTRING. An entity id closing its own
    // attribute and opening an element is the injection this writer's escaping exists to stop,
    // and a `contains` check cannot tell "escaped" from "absent".
    let key = signing_key();
    let hostile = r#"https://x/"><evil a="1"/><!--"#;
    let mut descriptor = descriptor(&key);
    descriptor.entity_id = hostile;
    let document = metadata::entity_descriptor(&descriptor).expect("a document");

    let mut reader = quick_xml::reader::Reader::from_str(&document);
    reader.config_mut().check_end_names = true;
    let mut names = Vec::new();
    let mut entity_ids = Vec::new();
    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(tag) | quick_xml::events::Event::Empty(tag)) => {
                names.push(String::from_utf8_lossy(tag.name().as_ref()).into_owned());
                for attribute in tag.attributes() {
                    let attribute = attribute.expect("a well-formed attribute");
                    if attribute.key.as_ref() == b"entityID" {
                        // `normalized_value` RATHER THAN THE DEPRECATED `unescape_value`, and
                        // it is also the righter one: XML 1.0 3.3.3 attribute-value
                        // normalization is what an identity provider's parser applies, so this
                        // compares against the string the far side actually sees.
                        entity_ids.push(
                            attribute
                                .normalized_value(quick_xml::XmlVersion::Explicit1_0)
                                .expect("escaped")
                                .into_owned(),
                        );
                    }
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Ok(_) => {}
            Err(error) => panic!("the document is not well-formed with a hostile value: {error}"),
        }
    }
    assert!(
        !names.iter().any(|name| name == "evil"),
        "a value opened an element: {names:?}"
    );
    // AND THE VALUE SURVIVES INTACT, which is the other half: escaping that mangles the entity id
    // produces a document an identity provider accepts and then cannot match.
    assert_eq!(entity_ids, vec![hostile.to_owned()]);
}

fn validity_tags(der: &[u8]) -> (u8, u8) {
    let mut outer = ironauth_der::Der::new(der);
    let mut certificate = outer.take_sequence().expect("a certificate");
    let mut tbs = certificate.take_sequence().expect("the TBS");
    // version [0], serial, signature, issuer, validity
    for _ in 0..4 {
        tbs.take_element().expect("a TBS field");
    }
    let mut validity = tbs.take_sequence().expect("the validity");
    let (before, _, _) = validity.take_element().expect("notBefore");
    let (after, _, _) = validity.take_element().expect("notAfter");
    (before, after)
}
