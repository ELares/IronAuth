// SPDX-License-Identifier: MIT OR Apache-2.0

//! The key and validity inside a certificate, against certificates a DIFFERENT tool produced.
//!
//! # Why the fixtures are files, and why the expectations came from OpenSSL
//!
//! A test that builds its own DER and hands it to the reader is one implementation checked
//! against itself: every assumption the writer made, the reader makes too, so the pair agrees
//! about a document no real encoder would produce and disagrees with every real one.
//!
//! So the five certificates in `tests/certificates/` came from `openssl req -x509`, and the
//! expected key bytes and validity dates beside them from `openssl x509` -- neither this crate
//! nor anything in this repository. If the walk in `x509.rs` and OpenSSL disagree about what a
//! certificate says, these tests say so.
//!
//! # The second-reader cases are the point of the file
//!
//! Several cases below are shapes this walk USED to accept and OpenSSL refuses. That direction
//! matters more than the reverse: a server that pins a key from a blob no other tool calls a
//! public key is the permissive reader in a disagreement, which is the hazard this whole crate
//! exists to close one layer up.
//!
//! The DER BUILDER at the bottom exists only for shapes no real encoder emits. Nothing it builds
//! is asserted to be ACCEPTED except as a control beside a refusal.
//!
//! Needs no database.

use ironauth_jose::xmldsig::XmlSigKey;
use ironauth_saml::x509::{MAX_CERTIFICATE_BYTES, X509Error, pinned, public_key_from_spki};

/// A fixture certificate, as bytes.
fn certificate(name: &str) -> Vec<u8> {
    std::fs::read(format!("tests/certificates/{name}.der"))
        .unwrap_or_else(|error| panic!("the {name} fixture is missing: {error}"))
}

/// A hex expectation OpenSSL wrote, as bytes.
fn expected(name: &str) -> Vec<u8> {
    let text = std::fs::read_to_string(format!("tests/certificates/{name}.hex"))
        .unwrap_or_else(|error| panic!("the {name} expectation is missing: {error}"));
    let text = text.trim();
    assert!(text.len() % 2 == 0 && !text.is_empty(), "not hex");
    (0..text.len() / 2)
        .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hex digits"))
        .collect()
}

/// The `(not_before, not_after)` OpenSSL printed for a fixture, in epoch seconds.
fn expected_validity(name: &str) -> (i64, i64) {
    let table = std::fs::read_to_string("tests/certificates/validity.txt")
        .expect("the validity expectations are missing");
    for line in table.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some(name) {
            let before = parts.next().expect("a notBefore").parse().expect("seconds");
            let after = parts.next().expect("a notAfter").parse().expect("seconds");
            return (before, after);
        }
    }
    panic!("no validity expectation for {name}");
}

#[test]
fn what_is_read_from_a_real_certificate_is_what_openssl_says_is_in_it() {
    // THE WHOLE POINT OF THIS FILE. Both sides of each assertion came from OpenSSL: the
    // certificate, and what it contains. This crate's walk is the only thing being measured.
    let read = pinned(&certificate("rsa2048")).expect("a real RSA certificate");
    let XmlSigKey::Rsa { modulus, exponent } = &read.key else {
        panic!("an rsaEncryption certificate did not read as an RSA key");
    };
    assert_eq!(
        *modulus,
        expected("rsa2048.modulus"),
        "the modulus is not the one OpenSSL prints"
    );
    assert_eq!(
        modulus.len(),
        256,
        "a 2048-bit modulus is 256 bytes; another length means the DER sign byte was kept or a \
         byte was lost"
    );
    assert_eq!(*exponent, expected("rsa2048.exponent"));
    assert_eq!(
        (read.not_before_unix_secs, read.not_after_unix_secs),
        expected_validity("rsa2048"),
        "the validity is not the interval OpenSSL prints"
    );

    let read = pinned(&certificate("ecdsa-p256")).expect("a real P-256 certificate");
    let XmlSigKey::EcdsaP256(point) = &read.key else {
        panic!("a prime256v1 certificate did not read as a P-256 key");
    };
    assert_eq!(*point, expected("ecdsa-p256.point"));
    assert_eq!(point.len(), 65, "an uncompressed P-256 point is 65 bytes");
    assert_eq!(
        (read.not_before_unix_secs, read.not_after_unix_secs),
        expected_validity("ecdsa-p256")
    );

    let read = pinned(&certificate("ecdsa-p384")).expect("a real P-384 certificate");
    let XmlSigKey::EcdsaP384(point) = &read.key else {
        panic!("a secp384r1 certificate did not read as a P-384 key");
    };
    assert_eq!(*point, expected("ecdsa-p384.point"));
    assert_eq!(point.len(), 97, "an uncompressed P-384 point is 97 bytes");
    assert_eq!(
        (read.not_before_unix_secs, read.not_after_unix_secs),
        expected_validity("ecdsa-p384")
    );
}

#[test]
fn a_v3_certificate_with_extensions_reads_the_same_as_a_v1_one() {
    // EVERY REAL UPLOAD IS V3 WITH EXTENSIONS. The other four fixtures are v1, which LibreSSL's
    // `req -x509` emits without an extension config -- so before this fixture existed, the
    // `[0] version` skip and the trailing `[3] extensions` were proved only by the builder at
    // the bottom of this file, which is this file agreeing with itself.
    //
    // This one carries basicConstraints, keyUsage and subjectKeyIdentifier, so the TBSCertificate
    // is NOT exhausted after the SPKI. A walk that required it to be would refuse every
    // certificate an identity provider actually issues.
    let read = pinned(&certificate("rsa2048-v3-extensions")).expect("a v3 certificate");
    let XmlSigKey::Rsa { modulus, exponent } = &read.key else {
        panic!("not RSA");
    };
    assert_eq!(
        *modulus,
        expected("rsa2048-v3-extensions.modulus"),
        "the extensions moved which bytes were read as the key"
    );
    assert_eq!(*exponent, vec![0x01, 0x00, 0x01]);
    assert_eq!(
        (read.not_before_unix_secs, read.not_after_unix_secs),
        expected_validity("rsa2048-v3-extensions")
    );
}

#[test]
fn nothing_may_follow_the_certificate_or_the_key() {
    // AN OPERATOR WHO APPENDS A ROTATION CERTIFICATE TO THE OLD ONE would otherwise silently pin
    // the OLD key and then watch every assertion fail with an error about a signature -- the
    // exact misdirection `RsaKeySize` exists to prevent. Two certificates in one upload is what
    // somebody produces by concatenating two PEM blocks.
    let mut two = certificate("rsa2048");
    two.extend_from_slice(&certificate("ecdsa-p256"));
    assert_eq!(
        pinned(&two),
        Err(X509Error::Malformed),
        "a blob holding two certificates was pinned as the first"
    );

    // AND A SINGLE TRAILING ELEMENT, the same fault smaller.
    let mut tail = certificate("rsa2048");
    tail.extend_from_slice(&[0x05, 0x00]); // NULL
    assert_eq!(pinned(&tail), Err(X509Error::Malformed));

    // THE SAME RULE INSIDE THE SPKI. THIS IS THE ONE OPENSSL REFUSES while an earlier version of
    // this walk accepted it, so the server was the permissive reader of a blob no other tool
    // calls a public key.
    assert_eq!(
        public_key_from_spki(&spki_rsa_with_extra_element(
            &[0xd0; 256],
            &[0x01, 0x00, 0x01]
        )),
        Err(X509Error::Malformed),
        "a third element inside a SubjectPublicKeyInfo was ignored"
    );

    // AND INSIDE THE BIT STRING, after RSAPublicKey.
    assert_eq!(
        public_key_from_spki(&spki_rsa_junk_after_key(&[0xd0; 256], &[0x01, 0x00, 0x01])),
        Err(X509Error::Malformed),
        "an element after RSAPublicKey inside the key BIT STRING was ignored"
    );

    // AND INSIDE RSAPublicKey, after the exponent.
    assert_eq!(
        public_key_from_spki(&spki_rsa_third_integer(&[0xd0; 256], &[0x01, 0x00, 0x01])),
        Err(X509Error::Malformed)
    );

    // AND AFTER A BARE SPKI.
    let mut spki = spki_rsa(&[0xd0; 256], &[0x01, 0x00, 0x01]);
    assert!(
        public_key_from_spki(&spki).is_ok(),
        "the control does not parse"
    );
    spki.extend_from_slice(&[0x05, 0x00]);
    assert_eq!(public_key_from_spki(&spki), Err(X509Error::Malformed));
}

#[test]
fn the_rsa_algorithm_parameters_are_checked_and_not_stepped_over() {
    // `AlgorithmIdentifier { rsaEncryption, P-384 OID, NULL }` is not an RSA key description, and
    // an earlier version never looked past the OID, so it read as RSA. OpenSSL refuses it.
    let p384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
    assert_eq!(
        public_key_from_spki(&spki_rsa_with_parameter(
            &[0xd0; 256],
            &[0x01, 0x00, 0x01],
            Some(p384)
        )),
        Err(X509Error::Malformed),
        "an rsaEncryption AlgorithmIdentifier carrying a curve was read as RSA"
    );

    // BOTH CONFORMING SHAPES ARE ACCEPTED: RFC 4055 requires the explicit NULL, and some
    // encoders omit the parameters entirely. Refusing the second would reject certificates that
    // verify everywhere else, over a field that carries no information either way.
    assert!(
        public_key_from_spki(&spki_rsa(&[0xd0; 256], &[0x01, 0x00, 0x01])).is_ok(),
        "the explicit NULL was refused"
    );
    assert!(
        public_key_from_spki(&spki_rsa_with_parameter(
            &[0xd0; 256],
            &[0x01, 0x00, 0x01],
            None
        ))
        .is_ok(),
        "absent RSA parameters were refused"
    );
}

#[test]
fn the_curve_comes_from_the_algorithm_parameter_and_not_from_the_point_length() {
    // P-256 AND P-384 POINTS ARE DIFFERENT LENGTHS, so a reader could guess the curve from the
    // length and be right on every real certificate -- then wrong on the one that matters. A
    // certificate whose parameter says P-384 while its point is 65 bytes is not a P-256 key, it
    // is a malformed P-384 one, and pinning it as P-256 pins a key the provider does not have.
    assert_eq!(
        public_key_from_spki(&spki_ec(P256_OID, &point(0x04, 96))),
        Err(X509Error::Malformed),
        "a P-256 key with a 97-byte point was read as P-384"
    );
    assert_eq!(
        public_key_from_spki(&spki_ec(P384_OID, &point(0x04, 64))),
        Err(X509Error::Malformed),
        "a P-384 key with a 65-byte point was read as P-256"
    );

    // AND THE CONTROLS, so the refusals above are about the pairing and not about the builder.
    assert!(matches!(
        public_key_from_spki(&spki_ec(P256_OID, &point(0x04, 64))),
        Ok(XmlSigKey::EcdsaP256(_))
    ));
    assert!(matches!(
        public_key_from_spki(&spki_ec(P384_OID, &point(0x04, 96))),
        Ok(XmlSigKey::EcdsaP384(_))
    ));
}

#[test]
fn a_compressed_point_is_refused_for_being_compressed_and_not_for_its_length() {
    // AN EARLIER VERSION CHECKED THE LENGTH FIRST, so every compressed fixture was 33 bytes and
    // the `0x04` guard was never reached: deleting it left the whole suite green. The prefix is
    // checked FIRST now, and these points are the RIGHT TOTAL LENGTH for their curve, so a
    // length-only reader accepts every one of them.
    for prefix in [0x02_u8, 0x03] {
        assert_eq!(
            public_key_from_spki(&spki_ec(P256_OID, &point(prefix, 64))),
            Err(X509Error::Malformed),
            "a 65-byte point with prefix {prefix:#04x} passed the length test and was accepted"
        );
        assert_eq!(
            public_key_from_spki(&spki_ec(P384_OID, &point(prefix, 96))),
            Err(X509Error::Malformed),
            "a 97-byte point with prefix {prefix:#04x} was accepted"
        );
    }
    // A HYBRID POINT (`0x06`/`0x07`) carries both coordinates AND the sign, so it is the right
    // length and still not the uncompressed encoding.
    assert_eq!(
        public_key_from_spki(&spki_ec(P256_OID, &point(0x06, 64))),
        Err(X509Error::Malformed)
    );
    // THE POINT AT INFINITY, the single byte `0x00`: a valid encoding of something that is not a
    // public key.
    assert_eq!(
        public_key_from_spki(&spki_ec(P256_OID, &[0x00])),
        Err(X509Error::Malformed)
    );
}

#[test]
fn both_halves_of_an_rsa_key_are_bounded_by_what_the_backend_will_verify_with() {
    // THE ONLY MOMENT AN OPERATOR CAN ACT. `ring` verifies RSA between 2048 and 8192 bits, so a
    // key outside that fails EVERY assertion later with an error about a signature -- which
    // sends somebody to look at their identity provider's signing configuration rather than at
    // the certificate they uploaded.
    assert_eq!(
        pinned(&certificate("rsa1024")),
        Err(X509Error::RsaKeySize),
        "a real 1024-bit RSA certificate was pinned"
    );

    // THE MODULUS BOUNDS, one byte either side: a fixture well inside the range cannot tell `<`
    // from `<=`.
    for (bytes, accepted) in [(255, false), (256, true), (1024, true), (1025, false)] {
        let mut modulus = vec![0xff_u8; bytes];
        modulus[0] = 0xd0; // high bit set, so DER writes a sign byte the walk must strip
        let result = public_key_from_spki(&spki_rsa(&modulus, &[0x01, 0x00, 0x01]));
        assert_eq!(result.is_ok(), accepted, "a {bytes}-byte modulus");
        if !accepted {
            assert_eq!(
                result,
                Err(X509Error::RsaKeySize),
                "refused for the wrong reason"
            );
        }
    }

    // THE EXPONENT, WHICH AN EARLIER VERSION DID NOT CHECK AT ALL -- so `RsaKeySize`'s promise
    // held for one of the two numbers a key is made of. `ring` requires an odd exponent below
    // 2^33, so a 40-byte one is a key this deployment could pin and never verify with.
    for (exponent, accepted) in [
        (vec![0x03], true),
        (vec![0x01, 0x00, 0x01], true),
        (vec![0x01_u8; 5], true),
        (vec![0x01_u8; 6], false),
        (vec![0x01_u8; 40], false),
        // AN EVEN EXPONENT IS NOT A PUBLIC EXPONENT: it shares a factor with phi(n), so it is not
        // invertible and no signature ever verifies against it.
        (vec![0x01, 0x00, 0x02], false),
        (vec![0x02], false),
    ] {
        let result = public_key_from_spki(&spki_rsa(&[0xd0; 256], &exponent));
        assert_eq!(
            result.is_ok(),
            accepted,
            "a {}-byte exponent ending {:#04x}",
            exponent.len(),
            exponent.last().copied().unwrap_or_default()
        );
        if !accepted {
            assert_eq!(result, Err(X509Error::RsaKeySize));
        }
    }
}

#[test]
fn an_algorithm_this_server_cannot_verify_with_is_named_as_such() {
    // ED25519 AND AN UNSUPPORTED CURVE ARE REAL CERTIFICATES, and no XML Signature algorithm this
    // crate accepts uses them. The refusal is separate from `Malformed` because the operator's
    // fix is different and possible: their provider can issue a key this deployment supports,
    // which is not something they can do about a corrupt file.
    let ed25519: &[u8] = &[0x2b, 0x65, 0x70]; // 1.3.101.112
    assert_eq!(
        public_key_from_spki(&spki(ed25519, None, &[0x11; 32])),
        Err(X509Error::UnsupportedAlgorithm)
    );
    let p521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23]; // 1.3.132.0.35
    assert_eq!(
        public_key_from_spki(&spki(EC_OID, Some(p521), &point(0x04, 132))),
        Err(X509Error::UnsupportedAlgorithm),
        "an unsupported CURVE was not distinguished from a corrupt document"
    );
}

#[test]
fn a_der_encoding_no_conforming_encoder_produces_is_refused() {
    // THE SHAPES THAT MAKE TWO READERS DISAGREE. Each is accepted by some BER reader and
    // forbidden by DER, and every one means "the same bytes read two ways".
    //
    // EACH FIXTURE IS OTHERWISE COMPLETE, so only the rule named can refuse it. An earlier
    // version's minimality cases were answered by the buffer-overrun check instead, which meant
    // deleting both minimality rules left the suite green.
    let good = spki_rsa(&[0xd0; 256], &[0x01, 0x00, 0x01]);
    assert!(
        public_key_from_spki(&good).is_ok(),
        "the control does not parse"
    );

    // AN INDEFINITE LENGTH (`0x80`), whose end is wherever the reader decides it is.
    let mut indefinite = good.clone();
    indefinite[1] = 0x80;
    assert_eq!(public_key_from_spki(&indefinite), Err(X509Error::Malformed));

    // A NON-MINIMAL LENGTH: the long form for a length that fits the short one. The contents are
    // present and complete, so nothing but minimality can refuse it -- and the SHORT-FORM twin
    // beside it is refused for a DIFFERENT reason (it is not an SPKI), which is what shows this
    // pair is measuring the length encoding and not the contents.
    let long_form = [0x30_u8, 0x81, 0x02, 0x05, 0x00];
    assert_eq!(public_key_from_spki(&long_form), Err(X509Error::Malformed));
    // The long form with a leading zero, which is the same number written longer still.
    assert_eq!(
        public_key_from_spki(&[0x30, 0x82, 0x00, 0x81, 0x05, 0x00]),
        Err(X509Error::Malformed)
    );

    // A LENGTH THAT RUNS PAST THE BUFFER.
    assert_eq!(
        public_key_from_spki(&[0x30, 0x7f, 0x05, 0x00]),
        Err(X509Error::Malformed)
    );
}

#[test]
fn an_integer_der_calls_negative_or_non_minimal_is_not_a_modulus() {
    // DER INTEGERS ARE SIGNED. A modulus whose top bit is set carries a leading `0x00` to keep it
    // positive, and that byte is PADDING: keeping it makes a 2048-bit modulus 257 bytes and fails
    // a size check that is right. Dropping it unconditionally is the opposite error.
    let XmlSigKey::Rsa { modulus, .. } =
        public_key_from_spki(&spki_rsa(&[0xd0; 256], &[0x01, 0x00, 0x01])).expect("a control key")
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

    // A NEGATIVE INTEGER -- top bit set with no sign byte -- is not a modulus.
    assert_eq!(
        public_key_from_spki(&spki_rsa_raw_modulus(&[0xd0; 256], &[0x01, 0x00, 0x01])),
        Err(X509Error::Malformed),
        "a negative INTEGER was read as a modulus"
    );
    // AND A NON-MINIMAL POSITIVE: `00 7f` is 127 written longer.
    assert_eq!(
        public_key_from_spki(&spki_rsa_raw_modulus(&[0x00, 0x7f], &[0x01, 0x00, 0x01])),
        Err(X509Error::Malformed)
    );
}

#[test]
fn a_bit_string_with_unused_bits_is_not_a_key() {
    // A KEY IS A WHOLE NUMBER OF BYTES. A non-zero unused-bit count means the bytes after it are
    // not the key this reader thinks they are.
    let mut spki = spki_ec(P256_OID, &point(0x04, 64));
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
fn an_interval_that_ends_before_it_starts_is_not_a_validity() {
    // THE STORE AGREES: 0197 carries `CHECK (not_before < not_after)`. Refusing here means an
    // operator is told about their certificate rather than about a constraint violation, and it
    // means the two answers cannot drift apart.
    let key = spki_rsa(&[0xd0; 256], &[0x01, 0x00, 0x01]);
    let forward = certificate_around(&key, true, "260101000000Z", "270101000000Z");
    assert!(pinned(&forward).is_ok(), "the control does not parse");

    let backward = certificate_around(&key, true, "270101000000Z", "260101000000Z");
    assert_eq!(pinned(&backward), Err(X509Error::Malformed));

    // AND A ZERO-LENGTH INTERVAL, the degenerate input a `<` catches and a `<=` does not: a
    // certificate valid for no time at all.
    let instant = certificate_around(&key, true, "260101000000Z", "260101000000Z");
    assert_eq!(pinned(&instant), Err(X509Error::Malformed));
}

#[test]
fn a_certificate_with_no_version_field_still_reads() {
    // A V1 CERTIFICATE OMITS `[0] version` ENTIRELY. A reader that required it refuses every v1
    // certificate; one that skipped a field unconditionally would read the serial number as the
    // version and be one element out for everything after it -- and would then find something
    // that is not an SPKI where the SPKI belongs, or worse, something that parses as one.
    //
    // The fixtures corroborate this with certificates a different tool built: four v1 and one v3,
    // all read above.
    let key = spki_rsa(&[0xd0; 256], &[0x01, 0x00, 0x01]);
    let v1 = certificate_around(&key, false, "260101000000Z", "270101000000Z");
    let v3 = certificate_around(&key, true, "260101000000Z", "270101000000Z");
    assert!(pinned(&v1).is_ok(), "a v1 certificate was refused");
    assert_eq!(
        pinned(&v1),
        pinned(&v3),
        "the version field changed what was read"
    );
}

#[test]
fn the_size_bound_is_checked_at_both_entry_points_before_anything_is_walked() {
    // AN EARLIER VERSION CHECKED THE UPPER BOUND ON ONLY ONE OF THE TWO, so the other would walk
    // a blob of any size.
    assert_eq!(pinned(&[]), Err(X509Error::Size));
    assert_eq!(public_key_from_spki(&[]), Err(X509Error::Size));
    assert_eq!(
        pinned(&vec![0x30; MAX_CERTIFICATE_BYTES + 1]),
        Err(X509Error::Size)
    );
    assert_eq!(
        public_key_from_spki(&vec![0x30; MAX_CERTIFICATE_BYTES + 1]),
        Err(X509Error::Size),
        "public_key_from_spki walked a blob past the bound"
    );
    // ONE BYTE UNDER THE BOUND IS NOT REFUSED FOR ITS SIZE. It is refused for being nonsense,
    // which is a different answer and the one that shows the bound is where it says it is.
    assert_eq!(
        pinned(&vec![0x30; MAX_CERTIFICATE_BYTES]),
        Err(X509Error::Malformed)
    );
    assert_eq!(
        public_key_from_spki(&vec![0x30; MAX_CERTIFICATE_BYTES]),
        Err(X509Error::Malformed)
    );

    // AND THE BOUND MATCHES THE COLUMN THAT HAS TO HOLD THE SAME BYTES. A larger bound here
    // accepts a certificate the very next statement refuses, and the operator is then told about
    // a database constraint rather than about their certificate. Read out of the migration so
    // the two cannot drift apart silently.
    let migration = std::fs::read_to_string(
        "../ironauth-store/migrations/0197_saml_connection_certificates.sql",
    )
    .expect("the migration is there");
    assert!(
        migration.contains(&format!("BETWEEN 1 AND {MAX_CERTIFICATE_BYTES}")),
        "the reader's bound and the column's CHECK have drifted apart"
    );
}

#[test]
fn every_fixture_reads_and_no_truncation_of_one_is_read_as_a_certificate() {
    // A SWEEP OVER THE WHOLE FIXTURE DIRECTORY, so a certificate added later without a test of
    // its own is still walked, and so this file cannot be trimmed to the cases that pass.
    let mut seen = 0;
    let mut truncations = 0;
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
        let result = pinned(&der);
        if name == "rsa1024" {
            assert_eq!(result, Err(X509Error::RsaKeySize), "{name}");
        } else {
            assert!(result.is_ok(), "{name} did not read: {result:?}");
        }

        // EVERY SINGLE-BYTE TRUNCATION, which reaches a length that runs past the end from every
        // position in a REAL document rather than a built one. Each must REFUSE rather than
        // merely not panic: a prefix of a certificate is not a certificate, and a walk that
        // answered Ok for one would be reading a key out of bytes that were cut in half. An
        // earlier version of this sweep asserted nothing at all.
        for cut in 1..der.len() {
            assert!(
                pinned(&der[..cut]).is_err(),
                "{name} truncated to {cut} bytes was read as a certificate"
            );
            truncations += 1;
        }
    }
    assert_eq!(
        seen, 5,
        "a fixture was added or removed without updating this sweep"
    );
    assert!(
        truncations > 2000,
        "the sweep covered {truncations} truncations, far fewer than the fixtures hold"
    );
}

// ---------------------------------------------------------------------------------------------
// The DER builder, for the shapes no real encoder produces.
// ---------------------------------------------------------------------------------------------

const EC_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const RSA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const P256_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const P384_OID: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];

/// An EC point with this prefix byte and this many coordinate bytes after it.
fn point(prefix: u8, coordinate_bytes: usize) -> Vec<u8> {
    let mut out = vec![prefix];
    out.extend(std::iter::repeat_n(0x11_u8, coordinate_bytes));
    out
}

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

/// A `SubjectPublicKeyInfo` around an `AlgorithmIdentifier` body and key bytes.
fn spki_around(identifier: &[u8], key: &[u8]) -> Vec<u8> {
    let mut bits = vec![0];
    bits.extend_from_slice(key);
    let mut body = tlv(0x30, identifier);
    body.extend_from_slice(&tlv(0x03, &bits));
    tlv(0x30, &body)
}

/// A `SubjectPublicKeyInfo` with this algorithm, optional parameter, and key bytes.
fn spki(algorithm: &[u8], parameter: Option<&[u8]>, key: &[u8]) -> Vec<u8> {
    let mut identifier = tlv(0x06, algorithm);
    if let Some(parameter) = parameter {
        identifier.extend_from_slice(&tlv(0x06, parameter));
    }
    spki_around(&identifier, key)
}

fn spki_ec(curve: &[u8], point: &[u8]) -> Vec<u8> {
    spki(EC_OID, Some(curve), point)
}

/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`.
fn rsa_public_key(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let mut inner = integer(modulus);
    inner.extend_from_slice(&integer(exponent));
    tlv(0x30, &inner)
}

/// The `AlgorithmIdentifier` body a conforming rsaEncryption encoder writes: OID then NULL.
fn rsa_identifier() -> Vec<u8> {
    let mut identifier = tlv(0x06, RSA_OID);
    identifier.extend_from_slice(&tlv(0x05, &[]));
    identifier
}

/// An RSA key with the `parameters NULL` a conforming encoder writes.
fn spki_rsa(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    spki_around(&rsa_identifier(), &rsa_public_key(modulus, exponent))
}

/// An RSA key whose `AlgorithmIdentifier` carries this parameter before the NULL, or no
/// parameters at all.
fn spki_rsa_with_parameter(modulus: &[u8], exponent: &[u8], parameter: Option<&[u8]>) -> Vec<u8> {
    let mut identifier = tlv(0x06, RSA_OID);
    if let Some(parameter) = parameter {
        identifier.extend_from_slice(&tlv(0x06, parameter));
        identifier.extend_from_slice(&tlv(0x05, &[]));
    }
    spki_around(&identifier, &rsa_public_key(modulus, exponent))
}

/// An RSA key with a third element inside the `SubjectPublicKeyInfo` SEQUENCE.
fn spki_rsa_with_extra_element(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let mut bits = vec![0];
    bits.extend_from_slice(&rsa_public_key(modulus, exponent));
    let mut body = tlv(0x30, &rsa_identifier());
    body.extend_from_slice(&tlv(0x03, &bits));
    body.extend_from_slice(&tlv(0x05, &[])); // the third element
    tlv(0x30, &body)
}

/// An RSA key with an element after `RSAPublicKey` inside the key BIT STRING.
fn spki_rsa_junk_after_key(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let mut key = rsa_public_key(modulus, exponent);
    key.extend_from_slice(&tlv(0x05, &[]));
    spki_around(&rsa_identifier(), &key)
}

/// An RSA key with a third INTEGER inside `RSAPublicKey`.
fn spki_rsa_third_integer(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let mut inner = integer(modulus);
    inner.extend_from_slice(&integer(exponent));
    inner.extend_from_slice(&integer(&[0x07]));
    spki_around(&rsa_identifier(), &tlv(0x30, &inner))
}

/// An RSA key whose modulus INTEGER is written verbatim, sign byte and all left to the caller.
fn spki_rsa_raw_modulus(modulus_der_value: &[u8], exponent: &[u8]) -> Vec<u8> {
    let mut inner = tlv(0x02, modulus_der_value);
    inner.extend_from_slice(&integer(exponent));
    spki_around(&rsa_identifier(), &tlv(0x30, &inner))
}

/// A certificate whose `subjectPublicKeyInfo` is `key`, with or without `[0] version`, and with
/// these two `UTCTime` values.
///
/// Everything else is filler the walk steps over, which is the property being relied on: if the
/// walk ever started reading the serial number or the issuer, this filler would stop being
/// acceptable and the tests would say so.
fn certificate_around(key: &[u8], versioned: bool, not_before: &str, not_after: &str) -> Vec<u8> {
    let mut tbs = Vec::new();
    if versioned {
        tbs.extend_from_slice(&tlv(0xa0, &integer(&[2]))); // [0] EXPLICIT v3
    }
    tbs.extend_from_slice(&integer(&[0x01])); // serialNumber
    tbs.extend_from_slice(&tlv(0x30, &tlv(0x06, RSA_OID))); // signature
    tbs.extend_from_slice(&tlv(0x30, &[])); // issuer
    let mut validity = tlv(0x17, not_before.as_bytes()); // UTCTime
    validity.extend_from_slice(&tlv(0x17, not_after.as_bytes()));
    tbs.extend_from_slice(&tlv(0x30, &validity));
    tbs.extend_from_slice(&tlv(0x30, &[])); // subject
    tbs.extend_from_slice(key);
    let mut certificate = tlv(0x30, &tbs);
    certificate.extend_from_slice(&tlv(0x30, &tlv(0x06, RSA_OID))); // signatureAlgorithm
    certificate.extend_from_slice(&tlv(0x03, &[0, 0x11, 0x22])); // signatureValue
    tlv(0x30, &certificate)
}
