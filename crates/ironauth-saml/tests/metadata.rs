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
    let (_, algorithm_bytes, _) = certificate.take_element().expect("the algorithm");
    let signature = certificate
        .take_tag(ironauth_der::tag::BIT_STRING)
        .expect("the signature");

    // THE ANNOUNCED ALGORITHM, COMPARED TO SOMETHING. An earlier version of this test bound it
    // to `_algorithm` and threw it away, then verified with a literal `Rs256` -- so the OID the
    // certificate publishes was compared to nothing here or anywhere in the workspace, and
    // changing it to sha512WithRSAEncryption left the whole suite green while every identity
    // provider that checks a self-signature would refuse the document.
    let mut announced = ironauth_der::Der::new(algorithm_bytes);
    let mut announced = announced.take_sequence().expect("an AlgorithmIdentifier");
    assert_eq!(
        ironauth_der::oid_arcs(announced.take_tag(ironauth_der::tag::OID).expect("an oid"))
            .expect("arcs"),
        vec![1, 2, 840, 113_549, 1, 1, 11],
        "the certificate announces an algorithm other than the sha256WithRSAEncryption it is \
         signed with"
    );

    // AND ITS `parameters NULL`, which RFC 4055 2.1 makes a MUST for an RSA AlgorithmIdentifier
    // and which some verifiers reject a certificate for omitting. Reading only the OID and
    // walking away left that byte pair measured by nothing: deleting both NULLs from the writer
    // passed the entire workspace, because the signature is computed over the TBS as emitted, so
    // a shorter TBS is signed and checked in lockstep.
    assert_eq!(
        announced.take_tag(0x05).expect("the NULL parameter"),
        &[] as &[u8],
        "the AlgorithmIdentifier's parameters are not an explicit NULL"
    );
    assert!(
        announced.take_element().is_err(),
        "the AlgorithmIdentifier carries a third field"
    );

    // AND THE TBS SAYS THE SAME THING. RFC 5280 4.1.1.2 requires the outer `signatureAlgorithm`
    // to equal the TBS `signature` field, and a verifier that reads only one of them is the
    // reason the requirement exists.
    let mut tbs = ironauth_der::Der::new(tbs_bytes);
    let mut tbs = tbs.take_sequence().expect("the TBS");
    tbs.take_element().expect("version [0]");
    tbs.take_element().expect("serial");
    let (_, inner_algorithm, _) = tbs.take_element().expect("the TBS signature field");
    assert_eq!(
        inner_algorithm, algorithm_bytes,
        "the TBS signature field and the outer signatureAlgorithm disagree"
    );

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
    assert_eq!(
        validity_tags(&der),
        (0x17, 0x17),
        "a pre-2050 date was not UTCTime"
    );

    // BOTH BOUNDS PAST THE PIVOT. 2050-01-01 is the first instant the rule sends the other way,
    // so this also pins the boundary itself rather than a year safely beyond it.
    let mut spec = descriptor(&key);
    spec.not_before_unix_secs = 2_524_608_000; // 2050-01-01
    spec.not_after_unix_secs = 2_556_144_000; // 2051-01-01
    let der = certificate_der(&metadata::entity_descriptor(&spec).expect("build"));
    assert_eq!(
        validity_tags(&der),
        (0x18, 0x18),
        "a post-2049 date was not GeneralizedTime"
    );

    // AND A WINDOW THAT ACTUALLY CROSSES IT, taking one form each. An earlier version of this
    // test claimed the fixture above was the crossing case and it was not -- both its bounds
    // are post-2049. That left a whole class of encoder alive: one that decides the form ONCE,
    // from `not_before`, and applies it to both bounds. Every same-side fixture passes against
    // it, and a real five-year window spanning 2049 publishes a `notAfter` in the wrong form.
    let mut spec = descriptor(&key);
    spec.not_before_unix_secs = 2_493_072_000; // 2049-01-01, UTCTime
    spec.not_after_unix_secs = 2_556_144_000; // 2051-01-01, GeneralizedTime
    let der = certificate_der(&metadata::entity_descriptor(&spec).expect("build"));
    assert_eq!(
        validity_tags(&der),
        (0x17, 0x18),
        "a window spanning the 2049 pivot did not take one form on each side"
    );
}

#[test]
fn the_document_is_well_formed_xml() {
    // NOTHING HERE PARSED THE DOCUMENT AS XML. Every other test in this file reads it with
    // `split`, which is happy with a document no parser would accept: an unbalanced element, a
    // stray `&`, a duplicate attribute. An identity provider parses it, so this suite has to.
    //
    // `quick-xml` IS THIS CRATE'S OWN PARSER, NOT AN INDEPENDENT ONE, and an earlier version of
    // this comment claimed otherwise -- and added a redundant `[dev-dependencies]` entry to say
    // so, on the false premise that a package's regular dependencies are out of reach of its
    // integration tests. They are not; this file already reaches `ironauth-der` and `base64`
    // that way. What the check buys is still real and worth having: the WRITER in `metadata.rs`
    // and the reader in `parse.rs` share no code, so a document this emits and a parser rejects
    // fails here. It does not buy independence from quick-xml's own reading of the spec.
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

#[test]
fn the_key_usage_extension_is_critical_and_says_digital_signature_only() {
    // CLAIMED IN THREE PLACES AND READ BY NOBODY. The module says the extension is critical and
    // `digitalSignature` only, the helper's doc repeats it, and the TBS comment repeats it
    // again -- and every reader in the suite walks past it. `x509::pinned` reads the SPKI and
    // then requires the signatureAlgorithm and signatureValue after it, but it deliberately
    // does NOT call `end` on the TBS, so `[3] extensions` is never examined; `validity_tags`
    // stops inside `Validity`; and the self-verification test lifts the TBS as opaque bytes and
    // so agrees with whatever is inside it.
    //
    // AN EARLIER VERSION OF THIS COMMENT SAID `pinned` "stops after the SPKI and never calls
    // `end`", which describes the reader before it was fixed: it calls `end` twice, and
    // `certificates.rs::a_tbs_certificate_on_its_own_is_not_a_certificate` is the test that
    // holds it. The un-ended cursor is the TBS one, and that omission is deliberate -- the
    // optional `[1]`/`[2]` unique-id fields may follow -- which is exactly why the extension
    // needs a reader of its own rather than a stricter `pinned`.
    //
    // Widening the bits to `keyCertSign | cRLSign` keeps the encoded length identical, so
    // nothing downstream shifts and the whole workspace stays green while every operator
    // downloads a certificate asserting it may sign other certificates.
    let key = signing_key();
    let der = certificate_der(&metadata::entity_descriptor(&descriptor(&key)).expect("build"));

    let mut outer = ironauth_der::Der::new(&der);
    let mut certificate = outer.take_sequence().expect("a certificate");
    let mut tbs = certificate.take_sequence().expect("the TBS");
    // version [0], serial, signature, issuer, validity, subject, spki
    for _ in 0..7 {
        tbs.take_element().expect("a TBS field");
    }
    // [3] EXPLICIT extensions, context-constructed.
    let (tag, extensions_body, _) = tbs.take_element().expect("the extensions");
    assert_eq!(tag, 0xA3, "the extensions are not in the [3] EXPLICIT slot");

    // `take_element` hands back the WHOLE element, header included, so the [3] wrapper has to be
    // opened before the SEQUENCE OF inside it is reachable.
    let mut explicit = ironauth_der::Der::new(extensions_body);
    let inner = explicit.take_tag(0xA3).expect("the [3] wrapper");
    let mut list = ironauth_der::Der::new(inner);
    let mut extensions = list.take_sequence().expect("the extension sequence");
    let mut extension = extensions.take_sequence().expect("one extension");

    assert_eq!(
        ironauth_der::oid_arcs(extension.take_tag(ironauth_der::tag::OID).expect("an oid"))
            .expect("arcs"),
        vec![2, 5, 29, 15],
        "the only extension is not keyUsage"
    );

    // CRITICAL. DER encodes a BOOLEAN true as 0xFF and forbids any other non-zero byte, and an
    // extension a verifier is allowed to ignore is not a restriction.
    assert_eq!(
        extension.take_tag(0x01).expect("the critical flag"),
        &[0xFF],
        "keyUsage is not marked critical"
    );

    // AND THE BITS THEMSELVES: one unused-bit count of 7 and one byte 0x80, which is bit 0
    // (digitalSignature) and nothing else, minimally encoded as DER requires.
    let bits = extension
        .take_tag(ironauth_der::tag::OCTET_STRING)
        .expect("the extension value");
    let mut wrapped = ironauth_der::Der::new(bits);
    assert_eq!(
        wrapped
            .take_tag(ironauth_der::tag::BIT_STRING)
            .expect("a BIT STRING"),
        &[0x07, 0x80],
        "keyUsage asserts something other than digitalSignature alone"
    );

    // AND NOTHING ELSE IS ASSERTED: a second extension would be a second claim this document
    // makes about the key, and the sentence says there is one.
    assert!(
        extensions.take_element().is_err(),
        "the certificate carries an extension beyond keyUsage"
    );
}

/// The two tag bytes of a certificate's `Validity` pair.
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
