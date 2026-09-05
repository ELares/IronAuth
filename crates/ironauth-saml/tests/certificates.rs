// SPDX-License-Identifier: MIT OR Apache-2.0

//! The public key inside a certificate, against certificates a DIFFERENT tool produced.
//!
//! # Why the fixtures are files and not built here
//!
//! A test that builds its own DER and hands it to the reader is one implementation checked
//! against itself: every assumption the writer made, the reader makes too, so the pair agrees
//! about a document no real encoder would produce and disagrees with every real one.
//!
//! So the four certificates in `tests/certificates/` were produced by `openssl req -x509`, and
//! the EXPECTED KEY BYTES beside them were extracted by `openssl x509 -text` -- neither this
//! crate nor anything in this repository. If the walk in `x509.rs` and OpenSSL disagree about
//! where the key is, these tests say so.
//!
//! The DER BUILDER further down exists for the negative cases only, where the point is to
//! produce something no real encoder emits: an indefinite length, a non-minimal integer, a
//! compressed point. Nothing it builds is asserted to be ACCEPTED except as a control.
//!
//! Needs no database.

use ironauth_jose::xmldsig::XmlSigKey;
use ironauth_saml::x509::{MAX_CERTIFICATE_BYTES, X509Error, public_key, public_key_from_spki};

/// A fixture certificate, as bytes.
fn certificate(name: &str) -> Vec<u8> {
    std::fs::read(format!("tests/certificates/{name}.der"))
        .unwrap_or_else(|error| panic!("the {name} fixture is missing: {error}"))
}

/// A hex fixture OpenSSL wrote, as bytes.
fn expected(name: &str) -> Vec<u8> {
    let text = std::fs::read_to_string(format!("tests/certificates/{name}.hex"))
        .unwrap_or_else(|error| panic!("the {name} expectation is missing: {error}"));
    let text = text.trim();
    assert!(text.len() % 2 == 0 && !text.is_empty(), "not hex");
    (0..text.len() / 2)
        .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hex digits"))
        .collect()
}

#[test]
fn the_key_read_from_a_real_certificate_is_the_key_openssl_says_is_in_it() {
    // THE WHOLE POINT OF THIS FILE. Both sides of each assertion came from OpenSSL: the
    // certificate, and the key bytes. This crate's walk is the only thing being measured.
    let XmlSigKey::Rsa { modulus, exponent } =
        public_key(&certificate("rsa2048")).expect("a real RSA certificate")
    else {
        panic!("an rsaEncryption certificate did not read as an RSA key");
    };
    assert_eq!(
        modulus,
        expected("rsa2048.modulus"),
        "the modulus is not the one OpenSSL prints"
    );
    assert_eq!(
        modulus.len(),
        256,
        "a 2048-bit modulus is 256 bytes; a different length means the DER sign byte was kept \
         or a byte was lost"
    );
    assert_eq!(
        exponent,
        expected("rsa2048.exponent"),
        "the exponent is not the one OpenSSL prints"
    );

    let XmlSigKey::EcdsaP256(point) =
        public_key(&certificate("ecdsa-p256")).expect("a real P-256 certificate")
    else {
        panic!("a prime256v1 certificate did not read as a P-256 key");
    };
    assert_eq!(point, expected("ecdsa-p256.point"));
    assert_eq!(point.len(), 65, "an uncompressed P-256 point is 65 bytes");

    let XmlSigKey::EcdsaP384(point) =
        public_key(&certificate("ecdsa-p384")).expect("a real P-384 certificate")
    else {
        panic!("a secp384r1 certificate did not read as a P-384 key");
    };
    assert_eq!(point, expected("ecdsa-p384.point"));
    assert_eq!(point.len(), 97, "an uncompressed P-384 point is 97 bytes");
}

#[test]
fn the_curve_comes_from_the_algorithm_parameter_and_not_from_the_point_length() {
    // P-256 AND P-384 POINTS ARE DIFFERENT LENGTHS, so a reader could guess the curve from the
    // length and be right on every real certificate. It would then be wrong on the one that
    // matters: a certificate whose parameter says P-384 while its point is 65 bytes is not a
    // P-256 key, it is a malformed P-384 one, and pinning it as P-256 pins a key the identity
    // provider does not have.
    //
    // The two fixtures above already distinguish the curves. What this adds is the CROSS: the
    // P-256 parameter with a P-384-length point, which a length-guessing reader accepts as
    // P-384 and a parameter-reading one refuses.
    let spki = spki_ec(P256_OID, &[0x04; 97]);
    assert_eq!(
        public_key_from_spki(&spki),
        Err(X509Error::Malformed),
        "a P-256 key with a 97-byte point was read as P-384"
    );
    let spki = spki_ec(P384_OID, &[0x04; 65]);
    assert_eq!(
        public_key_from_spki(&spki),
        Err(X509Error::Malformed),
        "a P-384 key with a 65-byte point was read as P-256"
    );

    // AND THE CONTROLS, so the refusals above are about the pairing and not about the builder
    // producing something unreadable.
    assert!(matches!(
        public_key_from_spki(&spki_ec(P256_OID, &[0x04; 65])),
        Ok(XmlSigKey::EcdsaP256(_))
    ));
    assert!(matches!(
        public_key_from_spki(&spki_ec(P384_OID, &[0x04; 97])),
        Ok(XmlSigKey::EcdsaP384(_))
    ));
}

#[test]
fn a_compressed_point_is_refused_rather_than_decompressed() {
    // A COMPRESSED POINT IS `0x02`/`0x03 || x`, and recovering `y` from it is a modular square
    // root -- arithmetic this crate has no business doing, on a value an attacker supplied.
    // No identity provider emits one, so refusing costs nothing.
    for prefix in [0x02_u8, 0x03] {
        let mut point = vec![prefix];
        point.extend_from_slice(&[0x11; 32]);
        assert_eq!(
            public_key_from_spki(&spki_ec(P256_OID, &point)),
            Err(X509Error::Malformed),
            "a compressed point with prefix {prefix:#04x} was not refused"
        );
    }
    // AND THE POINT AT INFINITY, the single byte `0x00`, which is a valid encoding of a value
    // that is not a public key at all.
    assert_eq!(
        public_key_from_spki(&spki_ec(P256_OID, &[0x00])),
        Err(X509Error::Malformed)
    );
}

#[test]
fn a_key_the_signature_backend_cannot_verify_with_is_refused_at_upload() {
    // THE ONLY MOMENT AN OPERATOR CAN ACT. `ring` verifies RSA between 2048 and 8192 bits, so a
    // 1024-bit key pinned here fails EVERY assertion later, with an error about a signature --
    // which sends somebody to look at the identity provider's signing configuration rather than
    // at the certificate they uploaded.
    //
    // The fixture is a real 1024-bit certificate, not a truncated one.
    assert_eq!(
        public_key(&certificate("rsa1024")),
        Err(X509Error::RsaKeySize),
        "a 1024-bit RSA certificate was pinned"
    );

    // AND THE BOUNDS THEMSELVES, one byte either side. 2048 bits is 256 bytes and 8192 is 1024;
    // a fixture well inside the range cannot tell `<` from `<=`.
    for (bytes, accepted) in [(255, false), (256, true), (1024, true), (1025, false)] {
        let mut modulus = vec![0xff_u8; bytes];
        modulus[0] = 0xd0; // high bit set, so DER writes a sign byte: the padding must be stripped
        let result = public_key_from_spki(&spki_rsa(&modulus, &[0x01, 0x00, 0x01]));
        assert_eq!(
            result.is_ok(),
            accepted,
            "a {}-byte modulus was {}",
            bytes,
            if accepted { "refused" } else { "accepted" }
        );
        if !accepted {
            assert_eq!(
                result,
                Err(X509Error::RsaKeySize),
                "refused for the wrong reason"
            );
        }
    }
}

#[test]
fn an_algorithm_this_server_cannot_verify_with_is_named_as_such() {
    // ED25519 AND DSA ARE REAL CERTIFICATES and no XML Signature algorithm this crate accepts
    // uses them. The refusal is separate from `Malformed` because the operator's fix is
    // different and possible: their identity provider can issue a key this deployment supports,
    // which is not something they can do about a corrupt file.
    //
    // `1.3.101.112` is id-Ed25519.
    let ed25519: &[u8] = &[0x2b, 0x65, 0x70];
    assert_eq!(
        public_key_from_spki(&spki(ed25519, None, &[0x11; 32])),
        Err(X509Error::UnsupportedAlgorithm)
    );
    // `1.2.840.10045.3.1.1` is prime192v1: an EC curve, and one nothing here verifies with.
    let p192: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x01];
    assert_eq!(
        public_key_from_spki(&spki(EC_OID, Some(p192), &[0x04; 49])),
        Err(X509Error::UnsupportedAlgorithm),
        "an unsupported CURVE was not distinguished from a corrupt document"
    );
}

#[test]
fn a_der_encoding_no_conforming_encoder_produces_is_refused() {
    // THE SHAPES THAT MAKE TWO READERS DISAGREE. Each of these is accepted by some BER reader
    // and forbidden by DER, and every one of them means "the same document read two ways" --
    // which is the entire subject of this crate one layer up.
    let good = spki_rsa(&[0xd0; 256], &[0x01, 0x00, 0x01]);
    assert!(
        public_key_from_spki(&good).is_ok(),
        "the control does not parse"
    );

    // AN INDEFINITE LENGTH (`0x80`), whose end is wherever the reader decides it is.
    let mut indefinite = good.clone();
    indefinite[1] = 0x80;
    assert_eq!(public_key_from_spki(&indefinite), Err(X509Error::Malformed));

    // A NON-MINIMAL LENGTH: the long form used for a length that fits the short one.
    assert_eq!(
        public_key_from_spki(&[0x30, 0x81, 0x02, 0x05, 0x00]),
        Err(X509Error::Malformed),
        "a two-byte length written in the long form was accepted"
    );
    // And the long form with a leading zero, which is the same number written longer.
    assert_eq!(
        public_key_from_spki(&[0x30, 0x82, 0x00, 0x81, 0x05, 0x00]),
        Err(X509Error::Malformed)
    );

    // A LENGTH THAT RUNS PAST THE BUFFER, which is the oldest bug in every TLV reader.
    assert_eq!(
        public_key_from_spki(&[0x30, 0x7f, 0x05, 0x00]),
        Err(X509Error::Malformed)
    );

    // TRAILING BYTES INSIDE A SEQUENCE somebody chose the length of. A second reader might
    // interpret them; this one refuses to be the reader that did not notice.
    let mut trailing = good.clone();
    let inner_start = trailing.len();
    trailing.extend_from_slice(&[0x05, 0x00]);
    // Grow the outer SEQUENCE's length so the trailing bytes are INSIDE it, which is the shape
    // that matters: bytes after the outer length are a different test.
    let _ = inner_start;
    let mut with_junk = spki_rsa_with_trailing(&[0xd0; 256], &[0x01, 0x00, 0x01]);
    assert_eq!(
        public_key_from_spki(&with_junk),
        Err(X509Error::Malformed),
        "an element after the RSA exponent was ignored"
    );
    with_junk.clear();
}

#[test]
fn an_integer_der_calls_negative_or_non_minimal_is_not_a_modulus() {
    // DER INTEGERS ARE SIGNED. A modulus whose top bit is set carries a leading `0x00` to keep
    // it positive, and that byte is PADDING, not magnitude: keeping it makes a 2048-bit modulus
    // 257 bytes and fails a size check that is correct. Dropping it unconditionally is the
    // opposite error -- it eats a real leading zero.
    let padded = spki_rsa(&[0xd0; 256], &[0x01, 0x00, 0x01]);
    let XmlSigKey::Rsa { modulus, .. } = public_key_from_spki(&padded).expect("a control key")
    else {
        panic!("not RSA");
    };
    assert_eq!(
        modulus.len(),
        256,
        "the DER sign byte was kept in the modulus"
    );
    assert_eq!(
        modulus[0], 0xd0,
        "the sign byte was stripped from the wrong end"
    );

    // A NEGATIVE INTEGER -- top bit set with no sign byte -- is not a modulus, and reading one
    // as though the sign were decoration is how a length check gets fooled.
    assert_eq!(
        public_key_from_spki(&spki_rsa_raw_modulus(&[0xd0; 256], &[0x01, 0x00, 0x01])),
        Err(X509Error::Malformed),
        "a negative INTEGER was read as a modulus"
    );

    // AND A NON-MINIMAL POSITIVE: `00 7f` is 127 written longer, which DER forbids.
    assert_eq!(
        public_key_from_spki(&spki_rsa_raw_modulus(&[0x00, 0x7f], &[0x01, 0x00, 0x01])),
        Err(X509Error::Malformed)
    );
}

#[test]
fn a_bit_string_with_unused_bits_is_not_a_key() {
    // A KEY IS A WHOLE NUMBER OF BYTES. A non-zero unused-bit count means the bytes after it are
    // not the key this reader thinks they are -- either a different kind of object, or an
    // encoder inventing one.
    let mut spki = spki_ec(P256_OID, &[0x04; 65]);
    // The BIT STRING's first content byte is the unused-bit count; find it by its length.
    let position = spki
        .windows(2)
        .position(|pair| pair == [0x03, 0x42])
        .expect("the BIT STRING header is there")
        + 2;
    assert_eq!(
        spki[position], 0,
        "the control is not a whole-byte BIT STRING"
    );
    spki[position] = 1;
    assert_eq!(public_key_from_spki(&spki), Err(X509Error::Malformed));
}

#[test]
fn a_certificate_with_no_version_field_still_reads() {
    // A V1 CERTIFICATE OMITS THE `[0] version` FIELD ENTIRELY. A reader that required it refuses
    // every v1 certificate; one that unconditionally skipped a field would read the serial
    // number as the version and be one element out for the rest of the structure -- and would
    // then find something that is not an SPKI where the SPKI belongs, or worse, something that
    // parses as one.
    //
    // Both shapes are built here because no fixture generator emits v1 any more.
    let key = spki_rsa(&[0xd0; 256], &[0x01, 0x00, 0x01]);
    let v1 = certificate_around(&key, false);
    let v3 = certificate_around(&key, true);
    assert!(public_key(&v1).is_ok(), "a v1 certificate was refused");
    assert_eq!(
        public_key(&v1),
        public_key(&v3),
        "the version field changed which key was read"
    );
}

#[test]
fn the_size_bound_is_checked_before_anything_is_walked() {
    assert_eq!(public_key(&[]), Err(X509Error::Size));
    assert_eq!(public_key_from_spki(&[]), Err(X509Error::Size));
    assert_eq!(
        public_key(&vec![0x30; MAX_CERTIFICATE_BYTES + 1]),
        Err(X509Error::Size),
        "a certificate past the bound was walked rather than refused"
    );
    // AND ONE BYTE UNDER THE BOUND IS NOT REFUSED FOR ITS SIZE. It is refused for being
    // nonsense, which is a different answer and the one that shows the bound is where it says.
    assert_eq!(
        public_key(&vec![0x30; MAX_CERTIFICATE_BYTES]),
        Err(X509Error::Malformed)
    );
}

#[test]
fn every_fixture_certificate_reads_as_a_key_and_none_of_them_panics() {
    // A SWEEP OVER THE WHOLE FIXTURE DIRECTORY, so a certificate added later without a test of
    // its own is still walked -- and so that this file cannot be trimmed to the cases that pass.
    let mut seen = 0;
    for entry in std::fs::read_dir("tests/certificates").expect("the fixture directory") {
        let path = entry.expect("a directory entry").path();
        if path.extension().is_none_or(|extension| extension != "der") {
            continue;
        }
        seen += 1;
        let der = std::fs::read(&path).expect("a fixture");
        let name = path
            .file_stem()
            .expect("a name")
            .to_string_lossy()
            .to_string();
        let result = public_key(&der);
        if name == "rsa1024" {
            assert_eq!(result, Err(X509Error::RsaKeySize), "{name}");
        } else {
            assert!(result.is_ok(), "{name} did not read as a key: {result:?}");
        }

        // AND EVERY SINGLE-BYTE TRUNCATION OF IT, which is the cheap way to reach a length field
        // that runs past the end from every position in a real document.
        for cut in 1..der.len() {
            let _ = public_key(&der[..cut]);
        }
    }
    assert_eq!(
        seen, 4,
        "a fixture was added or removed without updating this sweep"
    );
}

// ---------------------------------------------------------------------------------------------
// The DER builder, for the shapes no real encoder produces.
// ---------------------------------------------------------------------------------------------

const EC_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const RSA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const P256_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const P384_OID: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];

/// A tag, a DER length, and contents.
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 0x80 {
        out.push(u8::try_from(value.len()).expect("checked"));
    } else {
        let bytes = value.len().to_be_bytes();
        let significant: Vec<u8> = bytes
            .iter()
            .copied()
            .skip_while(|byte| *byte == 0)
            .collect();
        out.push(0x80 | u8::try_from(significant.len()).expect("at most eight"));
        out.extend_from_slice(&significant);
    }
    out.extend_from_slice(value);
    out
}

/// A DER INTEGER holding a non-negative number, with the sign byte a real encoder would add.
fn integer(magnitude: &[u8]) -> Vec<u8> {
    let mut value = Vec::new();
    if magnitude.first().is_some_and(|byte| byte & 0x80 != 0) {
        value.push(0);
    }
    value.extend_from_slice(magnitude);
    tlv(0x02, &value)
}

/// A `SubjectPublicKeyInfo` with this algorithm, optional parameter, and key bytes.
fn spki(algorithm: &[u8], parameter: Option<&[u8]>, key: &[u8]) -> Vec<u8> {
    let mut identifier = tlv(0x06, algorithm);
    if let Some(parameter) = parameter {
        identifier.extend_from_slice(&tlv(0x06, parameter));
    }
    let mut bits = vec![0];
    bits.extend_from_slice(key);
    let mut body = tlv(0x30, &identifier);
    body.extend_from_slice(&tlv(0x03, &bits));
    tlv(0x30, &body)
}

fn spki_ec(curve: &[u8], point: &[u8]) -> Vec<u8> {
    spki(EC_OID, Some(curve), point)
}

fn spki_rsa(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let mut inner = integer(modulus);
    inner.extend_from_slice(&integer(exponent));
    spki(RSA_OID, None, &tlv(0x30, &inner))
}

/// An RSA key whose modulus INTEGER is written verbatim, sign byte and all left to the caller.
fn spki_rsa_raw_modulus(modulus_der_value: &[u8], exponent: &[u8]) -> Vec<u8> {
    let mut inner = tlv(0x02, modulus_der_value);
    inner.extend_from_slice(&integer(exponent));
    spki(RSA_OID, None, &tlv(0x30, &inner))
}

/// An RSA key with a third element after the exponent, inside the same SEQUENCE.
fn spki_rsa_with_trailing(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let mut inner = integer(modulus);
    inner.extend_from_slice(&integer(exponent));
    inner.extend_from_slice(&tlv(0x05, &[])); // NULL
    spki(RSA_OID, None, &tlv(0x30, &inner))
}

/// A certificate whose `subjectPublicKeyInfo` is `key`, with or without the `[0] version` field.
///
/// Everything else is filler the walk steps over without interpreting, which is the property
/// being relied on: if the walk ever started reading the serial number or the validity dates,
/// this filler would stop being acceptable and the test would say so.
fn certificate_around(key: &[u8], versioned: bool) -> Vec<u8> {
    let mut tbs = Vec::new();
    if versioned {
        tbs.extend_from_slice(&tlv(0xa0, &integer(&[2]))); // [0] EXPLICIT v3
    }
    tbs.extend_from_slice(&integer(&[0x01])); // serialNumber
    tbs.extend_from_slice(&tlv(0x30, &tlv(0x06, RSA_OID))); // signature
    tbs.extend_from_slice(&tlv(0x30, &[])); // issuer
    tbs.extend_from_slice(&tlv(0x30, &[])); // validity
    tbs.extend_from_slice(&tlv(0x30, &[])); // subject
    tbs.extend_from_slice(key);
    let mut certificate = tlv(0x30, &tbs);
    certificate.extend_from_slice(&tlv(0x30, &tlv(0x06, RSA_OID))); // signatureAlgorithm
    certificate.extend_from_slice(&tlv(0x03, &[0, 0x11, 0x22])); // signatureValue
    tlv(0x30, &certificate)
}
