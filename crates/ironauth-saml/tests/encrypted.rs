// SPDX-License-Identifier: MIT OR Apache-2.0

//! Encrypted assertions (issue #138, criterion 5).
//!
//! # Every document here is one a real identity provider could send
//!
//! The corpus is built by ENCRYPTING a document that already verifies, so a refusal below is
//! always a refusal of the thing named and never of a document that was broken to begin with.
//! The control is first and the suite is worth nothing without it.
//!
//! # The attacks this encodes
//!
//! Encryption adds a second place for the wrapping family to live, and two published CVE classes
//! of its own. Keycloak CVE-2026-2092 and the Casdoor batch are the same mistake in different
//! codebases: treating "it decrypted" as evidence about WHO asserted something. Jager and
//! Somorovsky (CCS 2011) is the other: CBC modes turn the XML parser's own behaviour on the
//! decrypted bytes into a plaintext-recovery oracle, which is why no CBC URI is on the allowlist
//! and why `ring` offering none makes that structural.
//!
//! Needs no database.

use ironauth_jose::xmldsig::test_util::XmlTestKey;
use ironauth_saml::{
    DecryptError, KeyTransport, KeyTransportAlg, Limits, TrustAnchor, VerifyError,
    decrypt_and_verify,
};

/// A key-transport seam that just hands back the key it was given.
///
/// # Why the test seam is not RSA
///
/// The crate does no key unwrapping: it is a caller's seam, for the reasons the module doc gives.
/// So the property under test here is everything AROUND the unwrap -- the allowlist, the shape
/// refusals, the length check, the decrypt-then-revalidate ordering -- and a seam that performs
/// the unwrap faithfully is exactly what isolates those. A test that also implemented RSA-OAEP
/// would be testing RSA-OAEP.
struct Unwrapper {
    key: Vec<u8>,
    /// What the seam was ASKED for, so a test can assert the allowlist reached it correctly.
    seen: std::cell::RefCell<Vec<KeyTransportAlg>>,
}

impl KeyTransport for Unwrapper {
    fn unwrap_key(&self, algorithm: KeyTransportAlg, _wrapped: &[u8]) -> Option<Vec<u8>> {
        self.seen.borrow_mut().push(algorithm);
        Some(self.key.clone())
    }
}

/// A seam that refuses, which is what an HSM answers for a key that is not its own.
struct Refuses;

impl KeyTransport for Refuses {
    fn unwrap_key(&self, _algorithm: KeyTransportAlg, _wrapped: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

/// The key, the anchors, and a document that really decrypts and really verifies.
struct Fixture {
    anchors: Vec<TrustAnchor>,
    /// The signed assertion, in the clear.
    assertion: String,
    /// The data key the seam hands back.
    key: Vec<u8>,
}

/// A fixed IV, because a corpus entry that changes every run is not a regression test.
const IV: [u8; 12] = [7; 12];

impl Fixture {
    fn new() -> Self {
        let key = XmlTestKey::generate();
        let document = ironauth_saml::test_util::signed_response(&key, "_assertion");
        let start = document
            .find("<saml:Assertion")
            .expect("a signed assertion");
        let end = document
            .find("</saml:Assertion>")
            .expect("a signed assertion")
            + "</saml:Assertion>".len();
        // THE DECLARATION HAS TO COME WITH IT, and the first draft of this fixture forgot,
        // which is a real fact about encrypted assertions rather than a test bug. The plaintext
        // inside an `EncryptedData` is a STANDALONE document: the `xmlns:saml` the identity
        // provider wrote on the enclosing `Response` is not in scope any more, so a lifted
        // assertion has an unbound prefix and resolves to no candidate at all.
        //
        // Moving it onto the assertion does not disturb the signature, and that is worth saying
        // because it looks like it should. Exclusive canonicalization renders a visibly-used
        // declaration on the apex whichever ancestor declared it, so the canonical form -- and
        // therefore the digest -- is identical either way. `a_declaration_on_signed_info_is_in_
        // scope_for_its_children` in tests/wrapping.rs is the same property from the other side.
        let assertion = document[start..end].replacen(
            "<saml:Assertion ",
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" "#,
            1,
        );
        Self {
            anchors: vec![TrustAnchor::EcdsaP256(key.public_point())],
            assertion,
            key: vec![0x2a; 32],
        }
    }

    /// Wrap `plaintext` into an `EncryptedAssertion`, with every URI overridable.
    ///
    /// Overridable because half the corpus is about what happens when ONE of them is the wrong
    /// one: a builder that hard-coded them would need a hand-edited string per case, and a
    /// hand-edited string is where a test stops differing in exactly one dimension.
    fn wrap(&self, plaintext: &str, data_alg: &str, key_alg: &str) -> String {
        let cipher = ironauth_jose::xmlenc::test_util::encrypt(
            ironauth_jose::xmlenc::XmlEncAlg::Aes256Gcm,
            &self.key,
            &IV,
            plaintext.as_bytes(),
        );
        format!(
            concat!(
                r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" "#,
                r#"xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response">"#,
                r#"<saml:EncryptedAssertion>"#,
                r#"<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" "#,
                r#"Type="http://www.w3.org/2001/04/xmlenc#Element">"#,
                r#"<xenc:EncryptionMethod Algorithm="{}"/>"#,
                r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
                r#"<xenc:EncryptedKey>"#,
                r#"<xenc:EncryptionMethod Algorithm="{}"/>"#,
                r#"<xenc:CipherData><xenc:CipherValue>{}</xenc:CipherValue></xenc:CipherData>"#,
                r#"</xenc:EncryptedKey></ds:KeyInfo>"#,
                r#"<xenc:CipherData><xenc:CipherValue>{}</xenc:CipherValue></xenc:CipherData>"#,
                r#"</xenc:EncryptedData></saml:EncryptedAssertion></samlp:Response>"#
            ),
            data_alg,
            key_alg,
            ironauth_saml::test_util::base64(b"the wrapped key, which the seam ignores"),
            ironauth_saml::test_util::base64(&cipher),
        )
    }

    /// The ordinary document: AES-256-GCM data, RSA-OAEP key transport.
    fn document(&self) -> String {
        self.wrap(
            &self.assertion,
            "http://www.w3.org/2009/xmlenc11#aes256-gcm",
            "http://www.w3.org/2009/xmlenc11#rsa-oaep",
        )
    }

    fn unwrapper(&self) -> Unwrapper {
        Unwrapper {
            key: self.key.clone(),
            seen: std::cell::RefCell::new(Vec::new()),
        }
    }

    fn decrypt(
        &self,
        document: &str,
        transport: &dyn KeyTransport,
    ) -> Result<ironauth_saml::VerifiedAssertion, DecryptError> {
        decrypt_and_verify(
            document.as_bytes(),
            &Limits::default(),
            &self.anchors,
            transport,
        )
    }
}

/// THE CONTROL, and the suite is worth nothing without it.
#[test]
fn an_encrypted_assertion_decrypts_and_verifies() {
    let fixture = Fixture::new();
    let unwrapper = fixture.unwrapper();
    let assertion = fixture
        .decrypt(&fixture.document(), &unwrapper)
        .expect("the unmodified encrypted document must decrypt and verify");
    assert_eq!(
        assertion
            .text_of(ironauth_saml::ASSERTION_NS, "NameID")
            .as_deref(),
        Some("victim@example.test")
    );
    // AND THE ALLOWLIST REACHED THE SEAM CORRECTLY. Without this the crate could be passing the
    // wrong algorithm to a caller's unwrapper and nothing would notice, because this seam ignores
    // the argument.
    assert_eq!(
        unwrapper.seen.borrow().as_slice(),
        &[KeyTransportAlg::RsaOaep]
    );
}

/// AN ASSERTION THAT DECRYPTS BUT IS NOT SIGNED BY A PINNED KEY IS REFUSED.
///
/// # This is the CVE class, and it is one line of code away in every implementation
///
/// Keycloak CVE-2026-2092 and the Casdoor batch are both this: "it decrypted" taken as evidence
/// about who asserted something. Decryption says the sender knew a key. It says nothing about
/// whose identity is in the document, and an attacker who obtains the encryption key -- which is
/// a PUBLIC key, published in the service provider's own metadata -- can encrypt anything.
///
/// The three arms vary one thing each: the signature is by a stranger, the signature is absent,
/// and the signed content was edited after signing.
#[test]
fn decryption_is_not_verification() {
    let fixture = Fixture::new();
    let stranger = XmlTestKey::generate();
    let stranger_document = ironauth_saml::test_util::signed_response(&stranger, "_assertion");
    let start = stranger_document
        .find("<saml:Assertion")
        .expect("an assertion");
    let end = stranger_document
        .find("</saml:Assertion>")
        .expect("an assertion")
        + "</saml:Assertion>".len();

    for (what, plaintext) in [
        (
            "signed by a key nobody pinned",
            stranger_document[start..end].to_owned(),
        ),
        (
            "not signed at all",
            r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assertion"><saml:Subject><saml:NameID>attacker@evil.test</saml:NameID></saml:Subject></saml:Assertion>"#.to_owned(),
        ),
        (
            "edited after it was signed",
            fixture
                .assertion
                .replace("victim@example.test", "attacker@evil.test"),
        ),
    ] {
        let document = fixture.wrap(
            &plaintext,
            "http://www.w3.org/2009/xmlenc11#aes256-gcm",
            "http://www.w3.org/2009/xmlenc11#rsa-oaep",
        );
        let unwrapper = fixture.unwrapper();
        let outcome = fixture.decrypt(&document, &unwrapper);
        assert!(
            matches!(outcome, Err(DecryptError::Unverified(_))),
            "{what} must be refused by the verifier, got {outcome:?}"
        );
        // AND IT REALLY DECRYPTED. Without this the refusal could be a decryption failure wearing
        // a verification error, and the test would pass against an implementation that could not
        // decrypt at all.
        assert_eq!(unwrapper.seen.borrow().len(), 1, "{what} must have decrypted");
    }
}

/// Every CBC mode is refused, and so is RSA-1.5 key transport.
///
/// # Two published breaks, and neither is a theoretical one
///
/// Jager and Somorovsky (CCS 2011) recovered plaintext from a conforming XML Encryption
/// implementation using CBC: the oracle is what the XML parser does with the decrypted bytes, so
/// an implementation cannot defend itself by being careful with error messages. The follow-up
/// work broke the backwards-compatibility defences too.
///
/// RSA-1.5 key transport is Bleichenbacher, and Keycloak shipped CVE-2026-2092 for it.
///
/// THE REFUSAL COMES BEFORE THE SEAM, which the assertion on `seen` is what pins: a caller's
/// unwrapper must never be asked to perform RSA-1.5, or the unwrapper becomes the oracle no
/// matter how carefully it is written.
#[test]
fn the_broken_algorithms_are_refused_before_the_seam() {
    let fixture = Fixture::new();
    let ok_key = "http://www.w3.org/2009/xmlenc11#rsa-oaep";
    let ok_data = "http://www.w3.org/2009/xmlenc11#aes256-gcm";

    for (what, data_alg, key_alg) in [
        (
            "AES-128-CBC",
            "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
            ok_key,
        ),
        (
            "AES-256-CBC",
            "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
            ok_key,
        ),
        (
            "Triple DES CBC",
            "http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
            ok_key,
        ),
        (
            "RSA-1.5 key transport",
            ok_data,
            "http://www.w3.org/2001/04/xmlenc#rsa-1_5",
        ),
        ("an unknown data algorithm", "urn:evil", ok_key),
        ("an unknown key transport", ok_data, "urn:evil"),
    ] {
        let document = fixture.wrap(&fixture.assertion, data_alg, key_alg);
        let unwrapper = fixture.unwrapper();
        assert_eq!(
            fixture.decrypt(&document, &unwrapper),
            Err(DecryptError::AlgorithmRefused),
            "{what}"
        );
        assert!(
            unwrapper.seen.borrow().is_empty(),
            "{what}: the seam must never be asked to perform a refused algorithm"
        );
    }

    // CONTROL: the same builder with both URIs on the allowlist produces a document that works.
    assert!(
        fixture
            .decrypt(&fixture.document(), &fixture.unwrapper())
            .is_ok()
    );
}

/// A document that asks this crate to go and FETCH something is refused.
///
/// # A reference is an outbound request an unauthenticated party chose
///
/// `RetrievalMethod` and `CipherReference` are both URIs. Honouring either would let a document
/// posted by anyone drive a request from the service provider, which is the SSRF half of the XXE
/// family arriving through a different door. This crate performs no I/O at all, so the answer is
/// a refusal rather than a fetch that fails.
#[test]
fn a_reference_to_somewhere_else_is_refused() {
    let fixture = Fixture::new();
    for (what, from, to) in [
        (
            "a RetrievalMethod instead of the key",
            "<xenc:EncryptedKey>",
            r#"<ds:RetrievalMethod URI="http://attacker.test/key"/><xenc:EncryptedKey>"#,
        ),
        (
            "a CipherReference instead of the data",
            "<xenc:CipherData><xenc:CipherValue>",
            r#"<xenc:CipherData><xenc:CipherReference URI="http://attacker.test/data"/><xenc:CipherValue>"#,
        ),
    ] {
        let document = fixture.document().replacen(from, to, 1);
        assert_eq!(
            fixture.decrypt(&document, &fixture.unwrapper()),
            Err(DecryptError::Shape),
            "{what}"
        );
    }
}

/// Two of anything is a refusal, for the reason every other "exactly one" here exists.
#[test]
fn two_of_anything_is_refused() {
    let fixture = Fixture::new();
    let document = fixture.document();
    for (what, open, close) in [
        (
            "two EncryptedAssertion",
            "<saml:EncryptedAssertion>",
            "</saml:EncryptedAssertion>",
        ),
        (
            "two EncryptedData",
            "<xenc:EncryptedData ",
            "</xenc:EncryptedData>",
        ),
        (
            "two EncryptedKey",
            "<xenc:EncryptedKey>",
            "</xenc:EncryptedKey>",
        ),
    ] {
        let start = document.find(open).expect("the element is present");
        let end = document.find(close).expect("the element is present") + close.len();
        let duplicated = [&document[..end], &document[start..end], &document[end..]].concat();
        assert_ne!(duplicated, document, "{what} must change the document");
        assert_eq!(
            fixture.decrypt(&duplicated, &fixture.unwrapper()),
            Err(DecryptError::Shape),
            "{what}"
        );
    }
}

/// A ciphertext that does not authenticate fails closed, and says nothing about why.
///
/// # The error is one word on purpose
///
/// A bad tag and a wrong key answer identically, and the seam refusing answers identically too.
/// Distinguishing them is the padding oracle in a different costume: an attacker who can tell
/// "the key unwrapped but the data did not authenticate" from "the key did not unwrap" has the
/// exact bit Bleichenbacher's attack iterates on.
#[test]
fn a_tampered_ciphertext_fails_closed_and_indistinguishably() {
    let fixture = Fixture::new();
    let document = fixture.document();
    let start =
        document.rfind("<xenc:CipherValue>").expect("cipher data") + "<xenc:CipherValue>".len();
    let flipped = {
        let mut bytes = document.clone().into_bytes();
        // Flip a character INSIDE the base64 run, so the ciphertext still decodes and the change
        // is in the plaintext-and-tag rather than in the framing.
        bytes[start + 4] = if bytes[start + 4] == b'A' { b'B' } else { b'A' };
        String::from_utf8(bytes).expect("still UTF-8")
    };
    assert_ne!(flipped, document, "the test must actually tamper");

    let outcomes = [
        fixture.decrypt(&flipped, &fixture.unwrapper()),
        fixture.decrypt(&document, &Refuses),
        fixture.decrypt(
            &document,
            &Unwrapper {
                key: vec![0x99; 32],
                seen: std::cell::RefCell::new(Vec::new()),
            },
        ),
    ];
    for outcome in &outcomes {
        assert_eq!(*outcome, Err(DecryptError::DecryptFailed));
    }
    // CONTROL: the untampered document under the right key still works, so the sameness above is
    // not "everything fails".
    assert!(fixture.decrypt(&document, &fixture.unwrapper()).is_ok());
}

/// A key of the wrong LENGTH is a refusal, not a truncation.
///
/// A seam is a caller's code and can answer with anything. Silently adjusting what it returned --
/// truncating, padding, hashing to length -- is how an implementation ends up decrypting under a
/// key neither party chose.
#[test]
fn a_data_key_of_the_wrong_length_is_refused() {
    let fixture = Fixture::new();
    for length in [0_usize, 16, 31, 33, 64] {
        let unwrapper = Unwrapper {
            key: vec![0x2a; length],
            seen: std::cell::RefCell::new(Vec::new()),
        };
        assert_eq!(
            fixture.decrypt(&fixture.document(), &unwrapper),
            Err(DecryptError::DecryptFailed),
            "a {length} byte key for AES-256-GCM"
        );
    }
}

/// The `Type` attribute must say ELEMENT, because that is what this crate treats it as.
///
/// # A fragment is not an element, and reading one as the other is a shape confusion
///
/// XML Encryption's `Type` distinguishes `#Element` (the ciphertext is a whole element) from
/// `#Content` (it is the CHILDREN of an element, without the element itself). This crate parses
/// the plaintext as a document, which is only correct for `#Element`. A `#Content` ciphertext
/// decrypting to a well-formed-looking fragment would be read as a document it is not.
///
/// Refusing is the honest answer: this crate does not implement `#Content`, and guessing which
/// one a document meant is how two implementations end up disagreeing about what was encrypted.
#[test]
fn an_encrypted_content_ciphertext_is_refused() {
    let fixture = Fixture::new();
    for (what, value) in [
        ("#Content", "http://www.w3.org/2001/04/xmlenc#Content"),
        ("an unknown type", "urn:evil"),
    ] {
        let document = fixture.document().replacen(
            r#"Type="http://www.w3.org/2001/04/xmlenc#Element""#,
            &format!(r#"Type="{value}""#),
            1,
        );
        assert_eq!(
            fixture.decrypt(&document, &fixture.unwrapper()),
            Err(DecryptError::Shape),
            "{what}"
        );
    }
    // AND AN ABSENT Type IS ACCEPTED, because the attribute is OPTIONAL in the schema and a great
    // deal of deployed SAML omits it. Refusing it would refuse conforming documents; the shape is
    // then whatever the plaintext turns out to parse as, which the verifier still has to accept.
    let absent =
        fixture
            .document()
            .replacen(r#" Type="http://www.w3.org/2001/04/xmlenc#Element""#, "", 1);
    assert!(fixture.decrypt(&absent, &fixture.unwrapper()).is_ok());
}

/// The bounds apply to the DECRYPTED document, not only to the one that arrived.
///
/// # Which bound, and why it is not the obvious one
///
/// The obvious test is a small ciphertext decrypting to an oversized document, and it CANNOT BE
/// WRITTEN: base64 expands by four thirds, so the outer document is always larger in bytes than
/// the plaintext inside it. If the outer one passed `max_bytes`, the inner one does too. The
/// first draft of this test asserted the opposite and failed, which is the better outcome than
/// the version that would have passed by picking numbers until it did.
///
/// THE AMPLIFICATION IS IN THE SHAPE, NOT THE SIZE. A `Response` wrapping an `EncryptedData` is
/// about ten elements whatever the payload, so a plaintext with hundreds of elements, or nested
/// hundreds deep, arrives inside a document that is trivially within every structural bound. The
/// element count and the depth are therefore the bounds an attacker can step around by
/// encrypting, and they are what this pins.
///
/// (The compression bomb that DOES apply to SAML lands earlier: the HTTP-Redirect binding
/// delivers base64 of a DEFLATE stream, and `Limits::max_bytes` measures the buffer after
/// something else produced it. The crate documentation says whatever performs that decode must
/// carry its own output bound, and it is not written yet.)
#[test]
fn the_limits_apply_to_the_decrypted_document() {
    let fixture = Fixture::new();
    let limits = Limits {
        max_elements: 24,
        max_depth: 12,
        ..Limits::default()
    };

    for (what, payload) in [
        (
            "more elements than the bound",
            "<saml:Advice>".to_owned() + &"<saml:X/>".repeat(64) + "</saml:Advice>",
        ),
        (
            "deeper than the bound",
            "<saml:Advice>".to_owned()
                + &"<saml:X>".repeat(32)
                + &"</saml:X>".repeat(32)
                + "</saml:Advice>",
        ),
    ] {
        let padded = fixture.assertion.replace(
            "<saml:Issuer>urn:idp</saml:Issuer>",
            &format!("<saml:Issuer>urn:idp</saml:Issuer>{payload}"),
        );
        let document = fixture.wrap(
            &padded,
            "http://www.w3.org/2009/xmlenc11#aes256-gcm",
            "http://www.w3.org/2009/xmlenc11#rsa-oaep",
        );
        // THE OUTER DOCUMENT IS WITHIN EVERY BOUND, which is what makes this an amplification
        // rather than a document that was always going to be refused. Asserted by parsing it
        // under the same limits rather than by counting by eye.
        assert!(
            ironauth_saml::parse(document.as_bytes(), &limits).is_ok(),
            "{what}: the OUTER document must parse, or this tests the wrong thing"
        );
        assert!(
            ironauth_saml::parse(padded.as_bytes(), &limits).is_err(),
            "{what}: the DECRYPTED document must not parse, or there is nothing to refuse"
        );
        assert!(
            matches!(
                decrypt_and_verify(
                    document.as_bytes(),
                    &limits,
                    &fixture.anchors,
                    &fixture.unwrapper(),
                ),
                Err(DecryptError::Unverified(VerifyError::Malformed(_)))
            ),
            "{what}: a ciphertext inside the bounds that decrypts past them must be refused"
        );
    }

    // CONTROL: the same builder at the default limits produces a document that works, so the
    // refusals above are about the bounds and not about the payload being malformed.
    let padded = fixture.assertion.replace(
        "<saml:Issuer>urn:idp</saml:Issuer>",
        "<saml:Issuer>urn:idp</saml:Issuer><saml:Advice><saml:X/></saml:Advice>",
    );
    let document = fixture.wrap(
        &padded,
        "http://www.w3.org/2009/xmlenc11#aes256-gcm",
        "http://www.w3.org/2009/xmlenc11#rsa-oaep",
    );
    assert!(
        matches!(
            decrypt_and_verify(
                document.as_bytes(),
                &Limits::default(),
                &fixture.anchors,
                &fixture.unwrapper(),
            ),
            Err(DecryptError::Unverified(VerifyError::SignatureInvalid))
        ),
        "the padded assertion is well formed; it fails on the DIGEST, which the padding changed"
    );
}

/// The ciphertext must be INSIDE the `EncryptedAssertion`, not merely somewhere in the document.
///
/// # The wrapping shape, one layer down
///
/// A first draft of `decrypt_and_verify` searched the whole document for an `EncryptedData` while
/// counting only the `EncryptedAssertion`, with a comment claiming a containment it did not
/// check. One of each, with the ciphertext a SIBLING of the assertion rather than its child, was
/// decrypted and returned -- "the element I found is not the element that matters", which is XML
/// Signature Wrapping arriving through the encryption door.
///
/// Both arms move the SAME ciphertext, so the only thing varying is where it sits.
#[test]
fn the_ciphertext_must_be_inside_the_encrypted_assertion() {
    let fixture = Fixture::new();
    let document = fixture.document();
    let start = document
        .find("<xenc:EncryptedData")
        .expect("the fixture has an EncryptedData");
    let end = document
        .find("</xenc:EncryptedData>")
        .expect("the fixture has an EncryptedData")
        + "</xenc:EncryptedData>".len();
    let ciphertext = &document[start..end];
    let hollow = [&document[..start], &document[end..]].concat();

    for (what, moved) in [
        (
            "a sibling of the EncryptedAssertion",
            hollow.replacen(
                "</saml:EncryptedAssertion>",
                &format!("</saml:EncryptedAssertion>{ciphertext}"),
                1,
            ),
        ),
        (
            "outside it entirely, before it",
            hollow.replacen(
                "<saml:EncryptedAssertion>",
                &format!("{ciphertext}<saml:EncryptedAssertion>"),
                1,
            ),
        ),
    ] {
        assert_eq!(
            fixture.decrypt(&moved, &fixture.unwrapper()),
            Err(DecryptError::Shape),
            "{what}"
        );
    }

    // CONTROL: the same ciphertext put back where it belongs decrypts and verifies, so the
    // refusals above are about POSITION and not about the surgery having broken it.
    let restored = hollow.replacen(
        "<saml:EncryptedAssertion>",
        &format!("<saml:EncryptedAssertion>{ciphertext}"),
        1,
    );
    assert_eq!(restored, document, "the surgery must be reversible");
    assert!(fixture.decrypt(&restored, &fixture.unwrapper()).is_ok());
}
