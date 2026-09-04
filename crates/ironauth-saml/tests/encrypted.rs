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
    DecryptError, KeyTransport, KeyTransportAlg, Limits, OaepDigest, OaepMgf, OaepParameters,
    TrustAnchor, VerifyError, decrypt_and_verify,
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
    /// What the seam was ASKED for, so a test can assert the allowlist reached it correctly and
    /// that the OAEP parameters the document named actually arrived.
    seen: std::cell::RefCell<Vec<(KeyTransportAlg, OaepParameters)>>,
}

impl KeyTransport for Unwrapper {
    fn unwrap_key(
        &self,
        algorithm: KeyTransportAlg,
        parameters: &OaepParameters,
        _wrapped: &[u8],
    ) -> Option<Vec<u8>> {
        self.seen.borrow_mut().push((algorithm, parameters.clone()));
        Some(self.key.clone())
    }
}

/// A seam that refuses, which is what an HSM answers for a key that is not its own.
struct Refuses;

impl KeyTransport for Refuses {
    fn unwrap_key(
        &self,
        _algorithm: KeyTransportAlg,
        _parameters: &OaepParameters,
        _wrapped: &[u8],
    ) -> Option<Vec<u8>> {
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
        self.wrap_with(plaintext, data_alg, key_alg, 32)
    }

    /// The same, with the data-encryption key length chosen explicitly.
    ///
    /// AES-128-GCM takes a 16 byte key, and the whole 128 path was reachable and unexercised
    /// until a reviewer pointed out that `wrap` hard-coded the 256 variant: the allowlist arm,
    /// the enum variant and its key length were all killed by no test.
    fn wrap_with(&self, plaintext: &str, data_alg: &str, key_alg: &str, bits: usize) -> String {
        let cipher = ironauth_jose::xmlenc::test_util::encrypt(
            if bits == 16 {
                ironauth_jose::xmlenc::XmlEncAlg::Aes128Gcm
            } else {
                ironauth_jose::xmlenc::XmlEncAlg::Aes256Gcm
            },
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
        unwrapper
            .seen
            .borrow()
            .iter()
            .map(|(algorithm, _)| *algorithm)
            .collect::<Vec<_>>(),
        vec![KeyTransportAlg::RsaOaep]
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
            // WITH THE DECLARATION, and this arm is why the fixture's comment about it matters.
            // Lifted without it, the `saml:` prefix is unbound, `verify` finds ZERO candidates,
            // and the document is refused as `ReferenceRefused` for having no assertion at all --
            // the stranger's key is never reached. A reviewer showed that pinning the stranger
            // did not change the outcome, so the arm demonstrated nothing about trust anchors,
            // while the checklist row rested its whole rationale on it.
            stranger_document[start..end].replacen(
                "<saml:Assertion ",
                r#"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" "#,
                1,
            ),
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
        // THE SPECIFIC REFUSAL, not `Unverified(_)`. The wildcard accepted a refusal for the
        // wrong reason, which is how the first arm passed while proving nothing: a document
        // refused for having no readable assertion looks the same through it as one refused for
        // being signed by a stranger.
        let outcome = fixture.decrypt(&document, &unwrapper);
        let expected = match what {
            "not signed at all" => VerifyError::SignatureMissing,
            _ => VerifyError::SignatureInvalid,
        };
        assert_eq!(
            outcome,
            Err(DecryptError::Unverified(expected)),
            "{what} must be refused by the verifier"
        );
        // AND IT REALLY DECRYPTED. Asking the seam is not evidence of that -- the seam is asked
        // before the ciphertext is opened -- so what is checked is that the refusal came from the
        // VERIFIER, which only runs on a plaintext. The `assert_eq!` above carries that: a
        // decryption failure answers `DecryptFailed`, not `Unverified`.
        assert_eq!(
            unwrapper.seen.borrow().len(),
            1,
            "{what}: the seam must be asked exactly once"
        );
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
/// RSA-1.5 key transport is Bleichenbacher (1998), which needs no CVE. NOT CVE-2026-2092: this
/// file cites that one correctly twice above, for a DIFFERENT vulnerability -- encrypted-assertion
/// injection under an unsigned Response -- and using one identifier for two things 300 lines
/// apart is how a reader checking a refusal finds the wrong justification.
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
    // The element bound is generous enough that the DEPTH arm crosses only the depth bound: a
    // payload that trips both is pinned by whichever is checked first, which is how the wildcard
    // hid the fact that the depth half was unmeasured.
    let limits = Limits {
        max_elements: 64,
        max_depth: 12,
        ..Limits::default()
    };

    // THE SPECIFIC VARIANT, not `Malformed(_)`. The depth payload is also 34 elements, so under
    // the wildcard the depth arm was satisfied by the ELEMENT bound: raising the depth guard left
    // it green on `TooManyElements` while its doc claimed to pin depth. The element bound is now
    // generous enough that only the depth arm crosses it.
    for (what, payload, expected) in [
        (
            "more elements than the bound",
            "<saml:Advice>".to_owned() + &"<saml:X/>".repeat(128) + "</saml:Advice>",
            ironauth_saml::SamlError::TooManyElements,
        ),
        (
            "deeper than the bound",
            "<saml:Advice>".to_owned()
                + &"<saml:X>".repeat(32)
                + &"</saml:X>".repeat(32)
                + "</saml:Advice>",
            ironauth_saml::SamlError::TooDeep,
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
        assert_eq!(
            decrypt_and_verify(
                document.as_bytes(),
                &limits,
                &fixture.anchors,
                &fixture.unwrapper(),
            ),
            Err(DecryptError::Unverified(VerifyError::Malformed(expected))),
            "{what}: a ciphertext inside the bounds that decrypts past them must be refused, \
             and for the named reason"
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

/// The accept-arms the documentation argues hardest for are DRIVEN, not merely written.
///
/// # Two allowlist entries that no test named
///
/// `#rsa-oaep-mgf1p` and `#aes128-gcm` were both reachable and both unexercised: deleting either
/// match arm turned it into `AlgorithmRefused` with the whole suite still green. The first is the
/// one the module doc argues at length must be accepted despite its SHA-1, on the ground that
/// refusing it would refuse most deployed identity providers -- so it was the arm with the
/// longest justification and no test at all.
///
/// The OAEP PARAMETERS are asserted too, because reaching the seam is not the same as reaching
/// it correctly: an unwrapper told SHA-1 when the document said SHA-256 decrypts under the wrong
/// parameters and fails indistinguishably from a wrong key.
#[test]
fn every_accepted_algorithm_is_driven_end_to_end() {
    for (what, data_alg, key_alg, expected) in [
        (
            "AES-256-GCM with RSA-OAEP",
            "http://www.w3.org/2009/xmlenc11#aes256-gcm",
            "http://www.w3.org/2009/xmlenc11#rsa-oaep",
            KeyTransportAlg::RsaOaep,
        ),
        (
            "AES-128-GCM with RSA-OAEP",
            "http://www.w3.org/2009/xmlenc11#aes128-gcm",
            "http://www.w3.org/2009/xmlenc11#rsa-oaep",
            KeyTransportAlg::RsaOaep,
        ),
        (
            "AES-256-GCM with RSA-OAEP-MGF1P",
            "http://www.w3.org/2009/xmlenc11#aes256-gcm",
            "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
            KeyTransportAlg::RsaOaepMgf1Sha1,
        ),
    ] {
        let bits = if data_alg.ends_with("aes128-gcm") {
            16
        } else {
            32
        };
        let fixture = Fixture {
            key: vec![0x2a; bits],
            ..Fixture::new()
        };
        let document = fixture.wrap_with(&fixture.assertion, data_alg, key_alg, bits);
        let unwrapper = fixture.unwrapper();
        let assertion = fixture
            .decrypt(&document, &unwrapper)
            .unwrap_or_else(|error| panic!("{what} must decrypt and verify: {error:?}"));
        assert_eq!(
            assertion
                .text_of(ironauth_saml::ASSERTION_NS, "NameID")
                .as_deref(),
            Some("victim@example.test"),
            "{what}"
        );
        // AND THE SEAM WAS TOLD THE RIGHT THING. Without this the crate could pass any algorithm
        // it liked to a caller's unwrapper, because this one ignores the argument.
        let seen = unwrapper.seen.borrow();
        let [(algorithm, parameters)] = seen.as_slice() else {
            panic!("{what}: the seam must be asked exactly once");
        };
        assert_eq!(*algorithm, expected, "{what}");
        // The defaults, since none of these documents names OAEP parameters.
        assert_eq!(parameters.digest, OaepDigest::Sha1, "{what}");
        assert_eq!(parameters.mgf, OaepMgf::Mgf1Sha1, "{what}");
        assert_eq!(parameters.label, None, "{what}");
    }
}

/// The OAEP parameters a document names REACH the seam, and a contradiction is refused.
///
/// # An unwrapper cannot guess
///
/// XML Encryption 1.1 section 5.5.2 parameterises RSA-OAEP with `ds:DigestMethod`, `xenc11:MGF`
/// and `xenc:OAEPparams`, and the specification's own worked example uses SHA-256 with
/// MGF1-SHA256. An earlier version read only the `Algorithm` attribute and discarded all three,
/// so a conforming SHA-256 document and one using the SHA-1 defaults arrived at the caller
/// looking identical -- and a caller that guessed wrong would fail indistinguishably from a wrong
/// key.
#[test]
fn the_oaep_parameters_reach_the_seam() {
    let fixture = Fixture::new();
    let parameterised = fixture.document().replacen(
        r#"<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/>"#,
        concat!(
            r#"<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep">"#,
            r#"<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>"#,
            r#"<xenc11:MGF xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" "#,
            r#"Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256"/>"#,
            r#"<xenc:OAEPparams>QUJD</xenc:OAEPparams>"#,
            "</xenc:EncryptionMethod>"
        ),
        1,
    );
    assert_ne!(parameterised, fixture.document(), "the edit must apply");
    let unwrapper = fixture.unwrapper();
    fixture
        .decrypt(&parameterised, &unwrapper)
        .expect("a parameterised OAEP document decrypts and verifies");
    let seen = unwrapper.seen.borrow();
    let [(_, parameters)] = seen.as_slice() else {
        panic!("the seam must be asked exactly once");
    };
    assert_eq!(parameters.digest, OaepDigest::Sha256);
    assert_eq!(parameters.mgf, OaepMgf::Mgf1Sha256);
    assert_eq!(parameters.label.as_deref(), Some(&b"ABC"[..]));

    // AND `#rsa-oaep-mgf1p` FIXES THE MASK GENERATION FUNCTION ONLY.
    //
    // XML Encryption 1.0 section 5.4.2, which defines that URI, says the MGF "is always MGF1 with
    // SHA1" and makes the DIGEST an explicit parameter. So mgf1p with a SHA-256 DigestMethod is
    // conforming and is what xmlsec and OpenSAML emit; an earlier version of this crate refused
    // it, and a reviewer found the shape in another SAML library's own test corpus.
    let with_digest = fixture
        .wrap_with(
            &fixture.assertion,
            "http://www.w3.org/2009/xmlenc11#aes256-gcm",
            "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
            32,
        )
        .replacen(
            r#"<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>"#,
            concat!(
                r#"<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p">"#,
                r#"<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>"#,
                "</xenc:EncryptionMethod>"
            ),
            1,
        );
    let unwrapper = fixture.unwrapper();
    fixture
        .decrypt(&with_digest, &unwrapper)
        .expect("mgf1p with an explicit digest is conforming");
    {
        let seen = unwrapper.seen.borrow();
        let [(algorithm, parameters)] = seen.as_slice() else {
            panic!("the seam must be asked exactly once");
        };
        assert_eq!(*algorithm, KeyTransportAlg::RsaOaepMgf1Sha1);
        assert_eq!(parameters.digest, OaepDigest::Sha256);
        // The URI decided this one, so it is the fixed value whatever the digest says.
        assert_eq!(parameters.mgf, OaepMgf::Mgf1Sha1);
    }

    // WHAT IT MAY NOT CARRY is an explicit MGF, because the URI already decided that. Refusing
    // the digest and accepting the MGF was the previous rule, which had the specification exactly
    // backwards on both halves.
    let with_mgf = fixture
        .wrap_with(
            &fixture.assertion,
            "http://www.w3.org/2009/xmlenc11#aes256-gcm",
            "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
            32,
        )
        .replacen(
            r#"<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>"#,
            concat!(
                r#"<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p">"#,
                r#"<xenc11:MGF xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" "#,
                r#"Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha1"/>"#,
                "</xenc:EncryptionMethod>"
            ),
            1,
        );
    let unwrapper = fixture.unwrapper();
    assert_eq!(
        fixture.decrypt(&with_mgf, &unwrapper),
        Err(DecryptError::AlgorithmRefused)
    );
    assert!(
        unwrapper.seen.borrow().is_empty(),
        "a contradictory document must be refused before the seam is asked"
    );
}

/// The `EncryptedKey` may be a SIBLING of the `EncryptedData`, which is what `OpenSAML` emits.
///
/// # The schema says so, and refusing it refused a large share of the field
///
/// `saml-schema-assertion-2.0.xsd` defines `EncryptedElementType` as an `EncryptedData` followed
/// by zero or more `EncryptedKey` SIBLINGS. `OpenSAML` and Shibboleth emit that shape, pointing at
/// the key with a `ds:RetrievalMethod` whose URI is a same-document fragment.
///
/// A first version accepted only the nested placement and refused any `RetrievalMethod` outright,
/// justified as "honouring one would let an unauthenticated document drive an outbound request".
/// That is true of an absolute URI and FALSE of `#_ek`, which resolves inside the tree already
/// parsed. So the refusal was refusing conforming documents on a reason that did not apply to
/// them, and every such identity provider failed with `Shape` -- indistinguishable from malformed.
#[test]
fn the_key_may_sit_beside_the_ciphertext() {
    let fixture = Fixture::new();
    let document = fixture.document();
    let start = document
        .find("<xenc:EncryptedKey>")
        .expect("the fixture has an EncryptedKey");
    let end = document
        .find("</xenc:EncryptedKey>")
        .expect("the fixture has an EncryptedKey")
        + "</xenc:EncryptedKey>".len();
    // THE DECLARATION COMES WITH IT. `xmlns:xenc` is on the `EncryptedData` element itself, so a
    // sibling is outside the scope that declared it -- the same class of mistake as lifting an
    // assertion out of the Response that declared `xmlns:saml`. A real identity provider declares
    // the prefix higher up; this test carries it on the element it moves.
    let key = document[start..end].replacen(
        "<xenc:EncryptedKey>",
        concat!(
            r#"<xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" "#,
            r#"Id="_ek">"#
        ),
        1,
    );
    // Lift it out of the KeyInfo and put it beside the EncryptedData, with the fragment reference
    // the schema shape uses.
    let moved = [&document[..start], &document[end..]]
        .concat()
        .replacen(
            "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"></ds:KeyInfo>",
            concat!(
                r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
                "<ds:RetrievalMethod URI=\"#_ek\" ",
                "Type=\"http://www.w3.org/2001/04/xmlenc#EncryptedKey\"/>",
                "</ds:KeyInfo>"
            ),
            1,
        )
        .replacen(
            "</xenc:EncryptedData>",
            &format!("</xenc:EncryptedData>{key}"),
            1,
        );
    assert_ne!(moved, document, "the surgery must move something");

    let unwrapper = fixture.unwrapper();
    let assertion = fixture
        .decrypt(&moved, &unwrapper)
        .expect("the schema's own EncryptedKey placement must work");
    assert_eq!(
        assertion
            .text_of(ironauth_saml::ASSERTION_NS, "NameID")
            .as_deref(),
        Some("victim@example.test")
    );

    // AND AN ABSOLUTE URI IS STILL REFUSED, because that one really would be a request. This is
    // the arm that keeps the loosening honest: the refusal moved from "any RetrievalMethod" to
    // "one that names somewhere else", and without this the fix would just be a removal.
    let outbound = moved.replacen("URI=\"#_ek\"", "URI=\"http://attacker.test/key\"", 1);
    let unwrapper = fixture.unwrapper();
    assert_eq!(
        fixture.decrypt(&outbound, &unwrapper),
        Err(DecryptError::Shape)
    );
    assert!(
        unwrapper.seen.borrow().is_empty(),
        "a document naming somewhere else must be refused before the seam is asked"
    );
}

/// A cleartext assertion beside an encrypted one is refused.
///
/// # Two entry points, one document, two identities
///
/// Encryption uses the service provider's PUBLIC key, out of its own published metadata, so
/// anyone can mint an `EncryptedAssertion`. A `Response` carrying the identity provider's
/// genuinely signed CLEARTEXT assertion plus an attacker's encrypted one was accepted, and
/// `decrypt_and_verify` returned the encrypted subject while `verify` on the identical bytes
/// returned the cleartext one. Which identity the caller gets then depends on which function it
/// happened to call, which is the disagreement this crate exists to make impossible.
#[test]
fn a_cleartext_assertion_beside_an_encrypted_one_is_refused() {
    let fixture = Fixture::new();
    let cleartext = fixture.assertion.clone();
    let both = fixture.document().replacen(
        "</samlp:Response>",
        &format!("{cleartext}</samlp:Response>"),
        1,
    );
    assert_ne!(both, fixture.document(), "the edit must apply");
    let unwrapper = fixture.unwrapper();
    assert_eq!(
        fixture.decrypt(&both, &unwrapper),
        Err(DecryptError::Shape),
        "a document carrying both forms must be refused rather than resolved to one"
    );
    assert!(
        unwrapper.seen.borrow().is_empty(),
        "it must be refused before the seam is asked"
    );
}

/// The error does not reveal whether the key transport succeeded.
///
/// # Bleichenbacher's bit, handed over by an argument evaluation order
///
/// An earlier version evaluated `cipher_value(&data)` as an ARGUMENT to the decrypt call, so it
/// ran AFTER the caller's unwrapper. A document with a deliberately malformed `CipherData` then
/// answered `Shape` when the unwrap succeeded and `DecryptFailed` when it did not -- and an
/// unauthenticated party varying only the `EncryptedKey`, holding the broken `CipherData` fixed,
/// read one bit per request: did the private-key unwrap work. That is the whole of an adaptive
/// chosen-ciphertext attack's oracle, handed over by the error taxonomy built to withhold it.
///
/// The two documents below differ ONLY in whether the seam answers, and they must be
/// indistinguishable.
#[test]
fn the_error_does_not_reveal_whether_the_unwrap_succeeded() {
    let fixture = Fixture::new();
    let broken = fixture.document().replacen(
        "</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>",
        "!!!not base64!!!</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>",
        1,
    );
    assert_ne!(broken, fixture.document(), "the edit must apply");

    let succeeds = fixture.decrypt(&broken, &fixture.unwrapper());
    let refuses = fixture.decrypt(&broken, &Refuses);
    assert_eq!(
        succeeds, refuses,
        "the answer must not depend on whether the seam unwrapped the key"
    );

    // AND THE SAME FOR A WRONG-LENGTH KEY, which is the other way a seam can "succeed" and still
    // be wrong. All three are one answer.
    let wrong_length = fixture.decrypt(
        &broken,
        &Unwrapper {
            key: vec![0x2a; 7],
            seen: std::cell::RefCell::new(Vec::new()),
        },
    );
    assert_eq!(succeeds, wrong_length);

    // CONTROL: the unbroken document still tells the two apart in the only place it may -- by
    // succeeding for one and failing for the other. Without this the sameness above would be
    // satisfied by a crate that always returns the same error.
    assert!(
        fixture
            .decrypt(&fixture.document(), &fixture.unwrapper())
            .is_ok()
    );
    assert_eq!(
        fixture.decrypt(&fixture.document(), &Refuses),
        Err(DecryptError::DecryptFailed)
    );
}

/// A refusal written for one element refuses two of it.
///
/// # "Is it present" and "is there exactly one" are different questions
///
/// Both guards were `Scoped::child(..).is_some()`, and `child` answers `None` for zero matches
/// AND for two or more. So a document carrying the element TWICE walked straight past a refusal
/// written to reject it once -- inverting this crate's own doctrine that two is a contradiction,
/// for exactly the two elements whose whole purpose is to be refused.
#[test]
fn writing_a_refused_element_twice_does_not_evade_the_refusal() {
    let fixture = Fixture::new();
    let reference = r#"<xenc:CipherReference URI="http://attacker.test/data"/>"#;
    for (what, count) in [("once", 1), ("twice", 2), ("three times", 3)] {
        let document = fixture.document().replacen(
            "<xenc:CipherData><xenc:CipherValue>",
            &format!(
                "<xenc:CipherData>{}<xenc:CipherValue>",
                reference.repeat(count)
            ),
            1,
        );
        assert_ne!(document, fixture.document(), "{what}: the edit must apply");
        let unwrapper = fixture.unwrapper();
        assert_eq!(
            fixture.decrypt(&document, &unwrapper),
            Err(DecryptError::Shape),
            "{what}"
        );
    }
}

/// A duplicated OAEP parameter is REFUSED, not silently downgraded to the default.
///
/// # Duplication selecting a weaker parameter set is worse than duplication evading a refusal
///
/// `Scoped::child` answers `None` for zero matches AND for two or more, and in `oaep_parameters`
/// `None` means "use the specification's default". So writing a `DigestMethod` twice did not
/// evade a refusal, it CHOSE SHA-1: the crate told a caller's HSM SHA-1 for a document that named
/// SHA-512, which is precisely the "decrypts under the wrong parameters and fails
/// indistinguishably from a wrong key" failure the parameters exist to prevent. Two
/// `OAEPparams` silently dropped the label.
///
/// This is the same class the previous round fixed for `CipherReference`, reappearing in the code
/// that fixed it.
#[test]
fn a_duplicated_oaep_parameter_is_refused() {
    let fixture = Fixture::new();
    for (what, doubled) in [
        (
            "two DigestMethod",
            concat!(
                r#"<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>"#,
                r#"<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>"#
            ),
        ),
        (
            "two MGF",
            concat!(
                r#"<xenc11:MGF xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" "#,
                r#"Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha512"/>"#,
                r#"<xenc11:MGF xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" "#,
                r#"Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha512"/>"#
            ),
        ),
        (
            "two OAEPparams",
            "<xenc:OAEPparams>QUJD</xenc:OAEPparams><xenc:OAEPparams>QUJD</xenc:OAEPparams>",
        ),
    ] {
        let document = fixture.document().replacen(
            r#"<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/>"#,
            &format!(
                concat!(
                    r#"<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep">"#,
                    "{}</xenc:EncryptionMethod>"
                ),
                doubled
            ),
            1,
        );
        assert_ne!(document, fixture.document(), "{what}: the edit must apply");
        let unwrapper = fixture.unwrapper();
        assert_eq!(
            fixture.decrypt(&document, &unwrapper),
            Err(DecryptError::Shape),
            "{what}"
        );
        assert!(
            unwrapper.seen.borrow().is_empty(),
            "{what}: refused before the seam is asked"
        );
    }
}

/// A second `ds:KeyInfo` is refused, and does not make a key invisible or skip the URI check.
///
/// # What the round-1 fix relaxed by accident
///
/// The lookup used to be `child(..).ok_or(Shape)?`, which refused two `KeyInfo` children. The fix
/// relaxed it to `.map(..).unwrap_or_default()` so an absent `KeyInfo` could fall through to the
/// sibling placement -- and `child` still answers `None` for TWO. So two `KeyInfo` children
/// produced an EMPTY nested list rather than a refusal: a document holding three `EncryptedKey`
/// elements was accepted, and because the same call gated the `RetrievalMethod` loop, the
/// absolute-URI refusal was skipped entirely. That refusal is the arm that keeps the sibling
/// placement honest, so relaxing it removed the only thing standing between a document and an
/// outbound request.
#[test]
fn a_second_key_info_is_refused() {
    let fixture = Fixture::new();
    let empty_info = r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>"#;
    let document = fixture.document();
    let start = document
        .find("<xenc:EncryptedKey>")
        .expect("the fixture has an EncryptedKey");
    let end = document
        .find("</xenc:EncryptedKey>")
        .expect("the fixture has an EncryptedKey")
        + "</xenc:EncryptedKey>".len();
    let key = document[start..end].replacen(
        "<xenc:EncryptedKey>",
        r#"<xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">"#,
        1,
    );

    // THE SHAPE THAT MATTERS: two KeyInfo children AND a sibling key. With `child` answering
    // `None` for two, the nested list came back EMPTY and the sibling was used, so a document
    // carrying two EncryptedKey elements decrypted. A test that only doubles the KeyInfo without
    // a sibling refuses either way and proves nothing -- which is how the first version of this
    // test passed against the mutation.
    let doubled = document
        .replacen("<ds:KeyInfo", &format!("{empty_info}<ds:KeyInfo"), 1)
        .replacen(
            "</xenc:EncryptedData>",
            &format!("</xenc:EncryptedData>{key}"),
            1,
        );
    assert_ne!(doubled, document, "the edit must apply");
    let unwrapper = fixture.unwrapper();
    assert_eq!(
        fixture.decrypt(&doubled, &unwrapper),
        Err(DecryptError::Shape),
        "two KeyInfo children must be refused, not resolved to neither"
    );
    assert!(unwrapper.seen.borrow().is_empty());

    // AND THE SAME DOCUMENT WITH ONE KeyInfo IS THE CONTROL: it is refused too, but for the
    // reason the crate means -- two keys -- so the arm above is not passing on a coincidence.
    let single = document.replacen(
        "</xenc:EncryptedData>",
        &format!("</xenc:EncryptedData>{key}"),
        1,
    );
    assert_eq!(
        fixture.decrypt(&single, &fixture.unwrapper()),
        Err(DecryptError::Shape)
    );
}

/// A `RetrievalMethod` must name the key that is actually used.
///
/// # A reference that names nothing is a reference to nothing
///
/// Checking only the leading `#` made the reference decorative: a document could point at
/// `#somewhere_else` and still be decrypted under whichever key happened to be found. The
/// fragment now has to match the `Id` of the key the crate uses, which is what makes the sibling
/// placement a REFERENCE rather than a coincidence.
#[test]
fn a_retrieval_method_must_name_the_key_it_uses() {
    let fixture = Fixture::new();
    let document = fixture.document();
    let start = document
        .find("<xenc:EncryptedKey>")
        .expect("the fixture has an EncryptedKey");
    let end = document
        .find("</xenc:EncryptedKey>")
        .expect("the fixture has an EncryptedKey")
        + "</xenc:EncryptedKey>".len();
    let key = document[start..end].replacen(
        "<xenc:EncryptedKey>",
        concat!(
            r#"<xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" "#,
            r#"Id="_ek">"#
        ),
        1,
    );
    let with_reference = |uri: &str| {
        [&document[..start], &document[end..]]
            .concat()
            .replacen(
                "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"></ds:KeyInfo>",
                &format!(
                    concat!(
                        r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
                        "<ds:RetrievalMethod URI=\"{}\"/></ds:KeyInfo>"
                    ),
                    uri
                ),
                1,
            )
            .replacen(
                "</xenc:EncryptedData>",
                &format!("</xenc:EncryptedData>{key}"),
                1,
            )
    };

    // CONTROL: naming the key that is there works.
    assert!(
        fixture
            .decrypt(&with_reference("#_ek"), &fixture.unwrapper())
            .is_ok(),
        "a reference naming the key must work"
    );

    for (what, uri) in [
        ("a fragment naming something else", "#somewhere_else"),
        ("an absolute URI", "http://attacker.test/key"),
        ("an empty fragment", "#"),
    ] {
        let unwrapper = fixture.unwrapper();
        assert_eq!(
            fixture.decrypt(&with_reference(uri), &unwrapper),
            Err(DecryptError::Shape),
            "{what}"
        );
        assert!(
            unwrapper.seen.borrow().is_empty(),
            "{what}: refused before the seam is asked"
        );
    }
}

/// One key in EACH placement is two keys.
///
/// # The rule the code states and no test drove
///
/// `wrapped_key` merges the nested and sibling lists and demands exactly one, with a comment
/// saying "ONE KEY, wherever it sits. Two is the contradiction, and one in each place is two."
/// No test put one in each place, so replacing the merge with "prefer the nested one and ignore
/// the sibling" left the whole suite green.
#[test]
fn one_key_in_each_placement_is_two_keys() {
    let fixture = Fixture::new();
    let document = fixture.document();
    let start = document
        .find("<xenc:EncryptedKey>")
        .expect("the fixture has an EncryptedKey");
    let end = document
        .find("</xenc:EncryptedKey>")
        .expect("the fixture has an EncryptedKey")
        + "</xenc:EncryptedKey>".len();
    let key = document[start..end].replacen(
        "<xenc:EncryptedKey>",
        r#"<xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">"#,
        1,
    );
    // The nested key stays where it is; a copy goes beside the EncryptedData.
    let both = document.replacen(
        "</xenc:EncryptedData>",
        &format!("</xenc:EncryptedData>{key}"),
        1,
    );
    assert_ne!(both, document, "the edit must apply");
    let unwrapper = fixture.unwrapper();
    assert_eq!(
        fixture.decrypt(&both, &unwrapper),
        Err(DecryptError::Shape),
        "one key in each placement is two keys"
    );
    assert!(unwrapper.seen.borrow().is_empty());
}

/// EVERY OAEP digest and mask-generation URI on the allowlist reaches the seam as itself.
///
/// # A table, because one named parameter tested one arm
///
/// `the_oaep_parameters_reach_the_seam` drives SHA-256 and MGF1-SHA256, so it killed those two
/// arms and no others: the SHA-1, SHA-384 and SHA-512 digests and the MGF1-SHA384/512 arms could
/// each be deleted with the suite green. The SHA-384 row matters most, because the crate has
/// already been wrong about which registry owns that URI once -- `verify.rs` records a research
/// pass producing `xmlenc#sha384` for a signature digest where RFC 4051 says `xmldsig-more`, and
/// XML Encryption 1.1 section 5.8.3 assigns the OTHER one for OAEP. Both are accepted here and
/// both are driven.
#[test]
fn every_oaep_parameter_uri_reaches_the_seam_as_itself() {
    let fixture = Fixture::new();
    let drive = |children: &str| {
        let document = fixture.document().replacen(
            r#"<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/>"#,
            &format!(
                concat!(
                    r#"<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep">"#,
                    "{}</xenc:EncryptionMethod>"
                ),
                children
            ),
            1,
        );
        let unwrapper = fixture.unwrapper();
        let outcome = fixture.decrypt(&document, &unwrapper);
        let seen = unwrapper.seen.borrow().clone();
        (outcome.is_ok(), seen)
    };

    for (uri, expected) in [
        ("http://www.w3.org/2000/09/xmldsig#sha1", OaepDigest::Sha1),
        (
            "http://www.w3.org/2001/04/xmlenc#sha256",
            OaepDigest::Sha256,
        ),
        // RFC 4051 2.1.3, the XMLDSIG registry.
        (
            "http://www.w3.org/2001/04/xmldsig-more#sha384",
            OaepDigest::Sha384,
        ),
        // XML Encryption 1.1 5.8.3, which is the one that specification assigns for OAEP.
        (
            "http://www.w3.org/2001/04/xmlenc#sha384",
            OaepDigest::Sha384,
        ),
        (
            "http://www.w3.org/2001/04/xmlenc#sha512",
            OaepDigest::Sha512,
        ),
    ] {
        let (ok, seen) = drive(&format!(r#"<ds:DigestMethod Algorithm="{uri}"/>"#));
        assert!(ok, "{uri} must be accepted");
        let [(_, parameters)] = seen.as_slice() else {
            panic!("{uri}: the seam must be asked exactly once");
        };
        assert_eq!(parameters.digest, expected, "{uri}");
    }

    for (uri, expected) in [
        (
            "http://www.w3.org/2009/xmlenc11#mgf1sha1",
            OaepMgf::Mgf1Sha1,
        ),
        (
            "http://www.w3.org/2009/xmlenc11#mgf1sha256",
            OaepMgf::Mgf1Sha256,
        ),
        (
            "http://www.w3.org/2009/xmlenc11#mgf1sha384",
            OaepMgf::Mgf1Sha384,
        ),
        (
            "http://www.w3.org/2009/xmlenc11#mgf1sha512",
            OaepMgf::Mgf1Sha512,
        ),
    ] {
        let (ok, seen) = drive(&format!(
            concat!(
                r#"<xenc11:MGF xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" "#,
                r#"Algorithm="{}"/>"#
            ),
            uri
        ));
        assert!(ok, "{uri} must be accepted");
        let [(_, parameters)] = seen.as_slice() else {
            panic!("{uri}: the seam must be asked exactly once");
        };
        assert_eq!(parameters.mgf, expected, "{uri}");
    }

    // AND ANYTHING ELSE IS REFUSED, so the rows above are not passing because everything is.
    for children in [
        r#"<ds:DigestMethod Algorithm="urn:evil"/>"#,
        r#"<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#ripemd160"/>"#,
        concat!(
            r#"<xenc11:MGF xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" "#,
            r#"Algorithm="urn:evil"/>"#
        ),
    ] {
        let (ok, seen) = drive(children);
        assert!(!ok, "{children} must be refused");
        assert!(
            seen.is_empty(),
            "{children}: refused before the seam is asked"
        );
    }
}

/// A `RetrievalMethod` URI must be a FRAGMENT, not merely match the key's `Id`.
///
/// # The `Id` is attacker-chosen, so matching it proves nothing on its own
///
/// The round-2 fix added an `Id`-equality check, and it killed every arm of the test written for
/// the `#` rule: each of them fed an absolute URI beside a key whose `Id` did not match, so the
/// equality refused them and the `#` guard was never the thing under test. Replacing the `#`
/// requirement with `strip_prefix('#').unwrap_or(uri)` left the whole suite green.
///
/// The document that separates them pairs an absolute URI with a key whose `Id` IS that string --
/// which the crate never validates as an `NCName`, so nothing else stops it. Under the mutation it
/// decrypts.
#[test]
fn a_retrieval_method_uri_must_be_a_fragment() {
    let fixture = Fixture::new();
    let document = fixture.document();
    let start = document
        .find("<xenc:EncryptedKey>")
        .expect("the fixture has an EncryptedKey");
    let end = document
        .find("</xenc:EncryptedKey>")
        .expect("the fixture has an EncryptedKey")
        + "</xenc:EncryptedKey>".len();

    let build = |id: &str, uri: &str| {
        let key = document[start..end].replacen(
            "<xenc:EncryptedKey>",
            &format!(
                concat!(
                    r#"<xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" "#,
                    "Id=\"{}\">"
                ),
                id
            ),
            1,
        );
        [&document[..start], &document[end..]]
            .concat()
            .replacen(
                "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"></ds:KeyInfo>",
                &format!(
                    concat!(
                        r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
                        "<ds:RetrievalMethod URI=\"{}\"/></ds:KeyInfo>"
                    ),
                    uri
                ),
                1,
            )
            .replacen(
                "</xenc:EncryptedData>",
                &format!("</xenc:EncryptedData>{key}"),
                1,
            )
    };

    // CONTROL: a fragment naming the key works.
    assert!(
        fixture
            .decrypt(&build("_ek", "#_ek"), &fixture.unwrapper())
            .is_ok()
    );

    for (what, id, uri) in [
        (
            "an absolute URI that MATCHES the key's Id",
            "http://attacker.test/key",
            "http://attacker.test/key",
        ),
        ("a bare relative reference that matches", "_ek", "_ek"),
    ] {
        let unwrapper = fixture.unwrapper();
        assert_eq!(
            fixture.decrypt(&build(id, uri), &unwrapper),
            Err(DecryptError::Shape),
            "{what}"
        );
        assert!(unwrapper.seen.borrow().is_empty(), "{what}");
    }
}

/// The decrypted plaintext must BE an assertion, not merely contain one.
///
/// # What the `#Content` refusal rested on
///
/// `verify` searches by descendant, so a ciphertext decrypting to a whole `samlp:Response`
/// wrapping an assertion was accepted and the assertion inside it returned. The SAML schema makes
/// an `EncryptedAssertion`'s plaintext an `Assertion` and `OpenSAML` refuses anything else, so this
/// was an accept-more divergence -- and it undercut `check_type`'s own argument, which refuses
/// `#Content` on the ground that a fragment must not be read as a document while accepting a
/// document that was not the element it claimed.
#[test]
fn the_plaintext_must_be_an_assertion_rather_than_wrap_one() {
    let fixture = Fixture::new();
    let wrapped = format!(
        concat!(
            r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" "#,
            r#"ID="_inner">{}</samlp:Response>"#
        ),
        fixture.assertion
    );
    let document = fixture.wrap(
        &wrapped,
        "http://www.w3.org/2009/xmlenc11#aes256-gcm",
        "http://www.w3.org/2009/xmlenc11#rsa-oaep",
    );
    assert_eq!(
        fixture.decrypt(&document, &fixture.unwrapper()),
        Err(DecryptError::Shape),
        "a plaintext that WRAPS an assertion is not an assertion"
    );
    // CONTROL: the same assertion, unwrapped, still works.
    assert!(
        fixture
            .decrypt(&fixture.document(), &fixture.unwrapper())
            .is_ok()
    );
}
