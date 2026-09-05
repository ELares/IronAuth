//! The DER ENCODER, and the reason it lives beside the reader (issue #139).
//!
//! # One crate, both directions
//!
//! The crate doc argues that a second READER would be a defect, because two readers are two
//! answers to "what does this certificate say" and the interesting inputs are the ones they
//! disagree about. A writer is not a second reader, so that argument does not reach it -- but a
//! different one does.
//!
//! WHAT THIS ENCODES GETS READ BACK BY THE READER NEXT DOOR. A SAML service provider publishes a
//! self-signed certificate in its metadata; an operator commonly pastes that same certificate
//! into a tool that hands it back, and `x509::pinned` is what reads one. Encoder and decoder
//! disagreements are exactly the class the crate doc names -- a non-minimal length, an integer
//! with a spare sign byte, a bit string's unused-bit count -- and keeping both here means the two
//! are written against one another rather than against two readings of X.690.
//!
//! IT WAS ALREADY WRITTEN ONCE, in `ironauth-webauthn`'s test-only PKI builder, which synthesises
//! a FIDO chain. That code is the origin of everything here and now calls this instead, so the
//! encoder a test exercises heavily is the encoder production uses.
//!
//! # What it is not
//!
//! Not a general ASN.1 encoder. It writes definite-length DER for the handful of structures an
//! X.509 certificate and an SPKI need, and every function takes already-encoded bytes rather than
//! a schema, so the caller composes the grammar explicitly and a reader can see the shape.

use crate::tag;

/// Encode a DER length.
///
/// MINIMAL FORM ONLY, which is what DER requires and what the reader beside this enforces: a
/// length under 128 is one byte, and anything else is the long form with no leading zero. An
/// encoder that emitted a padded length would produce certificates its own reader rejects.
fn len(value: usize) -> Vec<u8> {
    if value < 0x80 {
        return vec![u8::try_from(value).unwrap_or(0x7F)];
    }
    let mut bytes = Vec::new();
    let mut remaining = value;
    while remaining > 0 {
        bytes.push(u8::try_from(remaining & 0xFF).unwrap_or(0));
        remaining >>= 8;
    }
    bytes.reverse();
    let mut out = vec![0x80 | u8::try_from(bytes.len()).unwrap_or(0)];
    out.extend_from_slice(&bytes);
    out
}

/// Encode one tag-length-value triple.
#[must_use]
pub fn tlv(tag_byte: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag_byte];
    out.extend_from_slice(&len(contents.len()));
    out.extend_from_slice(contents);
    out
}

/// Encode a `SEQUENCE` from already-encoded elements.
#[must_use]
pub fn seq(elements: &[Vec<u8>]) -> Vec<u8> {
    tlv(tag::SEQUENCE, &elements.concat())
}

/// Encode a `SET` from already-encoded elements.
#[must_use]
pub fn set(elements: &[Vec<u8>]) -> Vec<u8> {
    tlv(tag::SET, &elements.concat())
}

/// Encode an `OBJECT IDENTIFIER` from its dotted arcs.
///
/// THE FIRST TWO ARCS SHARE A BYTE, which is X.690's rule and the one place OID encoding
/// surprises people: `1.2.840...` begins `0x2A` because 1 * 40 + 2 = 42. Arcs of 128 or more are
/// base-128 with the continuation bit set on every byte but the last.
///
/// # Panics
///
/// If `arcs` has fewer than two elements, which is not an OID.
#[must_use]
pub fn oid(arcs: &[u64]) -> Vec<u8> {
    assert!(arcs.len() >= 2, "an OID has at least two arcs");
    let mut body = vec![u8::try_from(arcs[0] * 40 + arcs[1]).unwrap_or(0)];
    for &arc in &arcs[2..] {
        let mut stack = Vec::new();
        let mut remaining = arc;
        stack.push(u8::try_from(remaining & 0x7F).unwrap_or(0));
        remaining >>= 7;
        while remaining > 0 {
            stack.push(u8::try_from(remaining & 0x7F).unwrap_or(0) | 0x80);
            remaining >>= 7;
        }
        stack.reverse();
        body.extend_from_slice(&stack);
    }
    tlv(tag::OID, &body)
}

/// Encode an `INTEGER` from an unsigned value.
#[must_use]
pub fn uint(value: u64) -> Vec<u8> {
    uint_bytes(&value.to_be_bytes())
}

/// Encode an `INTEGER` from a big-endian unsigned magnitude of any width.
///
/// TWO RULES, AND BOTH MATTER TO THE READER. Leading zero bytes are stripped, because DER
/// requires the minimal encoding; and a zero byte is then prepended if the top bit is set,
/// because ASN.1 integers are SIGNED and a modulus whose first bit is 1 would otherwise encode a
/// negative number. An RSA modulus almost always has that bit set, so the second rule fires on
/// nearly every certificate this writes.
#[must_use]
pub fn uint_bytes(magnitude: &[u8]) -> Vec<u8> {
    let mut bytes: Vec<u8> = magnitude.to_vec();
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    if bytes.first().is_some_and(|first| first & 0x80 != 0) {
        bytes.insert(0, 0);
    }
    if bytes.is_empty() {
        bytes.push(0);
    }
    tlv(tag::INTEGER, &bytes)
}

/// Encode a `BIT STRING` with zero unused bits.
#[must_use]
pub fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut body = vec![0x00];
    body.extend_from_slice(bytes);
    tlv(tag::BIT_STRING, &body)
}

/// Encode an `OCTET STRING`.
#[must_use]
pub fn octet_string(bytes: &[u8]) -> Vec<u8> {
    tlv(tag::OCTET_STRING, bytes)
}

/// Encode a `UTF8String`.
#[must_use]
pub fn utf8_string(text: &str) -> Vec<u8> {
    tlv(tag::UTF8_STRING, text.as_bytes())
}

/// Encode a `GeneralizedTime` from a Unix timestamp, at second precision in UTC.
///
/// GENERALIZED RATHER THAN UTCTIME, deliberately. RFC 5280 says a certificate MUST use `UTCTime`
/// for dates through 2049 and `GeneralizedTime` after -- and `UTCTime`'s two-digit year is the
/// reason that rule exists. Every reader accepts `GeneralizedTime` in both ranges, the reader
/// beside this one included, so writing it always costs two bytes and removes a boundary.
#[must_use]
pub fn generalized_time(unix_seconds: i64) -> Vec<u8> {
    let (year, month, day, hour, minute, second) = civil_from_unix(unix_seconds);
    let text = format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z");
    tlv(tag::GENERALIZED_TIME, text.as_bytes())
}

/// Encode a context-specific constructed field, as X.509's `[0] EXPLICIT` tags are.
#[must_use]
pub fn context(number: u8, contents: &[u8]) -> Vec<u8> {
    tlv(0xA0 | (number & 0x1F), contents)
}

/// A `Name` carrying a single common-name attribute.
#[must_use]
pub fn name_common(common_name: &str) -> Vec<u8> {
    let attribute = seq(&[oid(&[2, 5, 4, 3]), utf8_string(common_name)]);
    seq(&[set(&[attribute])])
}

/// The civil date and time of a Unix timestamp, in UTC.
fn civil_from_unix(unix: i64) -> (i64, i64, i64, i64, i64, i64) {
    let days = unix.div_euclid(86_400);
    let seconds = unix.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year_of_era = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 {
        year_of_era + 1
    } else {
        year_of_era
    };
    (
        year,
        month,
        day,
        seconds / 3_600,
        (seconds % 3_600) / 60,
        seconds % 60,
    )
}

#[cfg(test)]
mod tests {
    use super::{bit_string, generalized_time, len, oid, uint, uint_bytes};
    use crate::{Der, tag};

    #[test]
    fn a_length_is_the_minimal_form_the_reader_requires() {
        // THE READER NEXT DOOR REJECTS A NON-MINIMAL LENGTH, so an encoder that padded would
        // produce certificates this crate cannot read back. 127 is the last single byte; 128 is
        // the first long form.
        assert_eq!(len(0), vec![0x00]);
        assert_eq!(len(127), vec![0x7F]);
        assert_eq!(len(128), vec![0x81, 0x80]);
        assert_eq!(len(255), vec![0x81, 0xFF]);
        assert_eq!(len(256), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn an_oid_shares_its_first_two_arcs_in_one_byte() {
        // rsaEncryption, 1.2.840.113549.1.1.1: 1*40+2 = 42 = 0x2A, then base-128 for 840.
        assert_eq!(
            oid(&[1, 2, 840, 113_549, 1, 1, 1]),
            vec![
                0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01
            ]
        );
        // sha256WithRSAEncryption, the same prefix with a different tail.
        assert_eq!(
            oid(&[1, 2, 840, 113_549, 1, 1, 11]),
            vec![
                0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B
            ]
        );
        // commonName, 2.5.4.3: 2*40+5 = 85 = 0x55.
        assert_eq!(oid(&[2, 5, 4, 3]), vec![0x06, 0x03, 0x55, 0x04, 0x03]);
    }

    #[test]
    fn an_integer_is_minimal_and_never_accidentally_negative() {
        // ASN.1 INTEGERs are SIGNED. An RSA modulus almost always has its top bit set, so
        // omitting the pad byte would encode a negative modulus -- a certificate every verifier
        // refuses, and one this crate's own reader would read as a different number.
        assert_eq!(uint(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(uint(127), vec![0x02, 0x01, 0x7F]);
        assert_eq!(uint(128), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(uint_bytes(&[0x00, 0x00, 0x01]), vec![0x02, 0x01, 0x01]);
        assert_eq!(
            uint_bytes(&[0xFF, 0x01]),
            vec![0x02, 0x03, 0x00, 0xFF, 0x01]
        );
    }

    #[test]
    fn what_this_writes_the_reader_beside_it_reads_back() {
        // THE WHOLE REASON BOTH DIRECTIONS LIVE IN ONE CRATE. Each value goes out through the
        // encoder and comes back through the decoder, so a disagreement about minimal lengths,
        // sign bytes or unused bits fails here rather than at an identity provider.
        let encoded = super::seq(&[
            uint(1),
            oid(&[1, 2, 840, 113_549, 1, 1, 11]),
            bit_string(&[0xDE, 0xAD]),
            generalized_time(1_767_225_600),
        ]);
        let mut outer = Der::new(&encoded);
        let mut inner = outer.take_sequence().expect("a sequence");
        assert_eq!(inner.take_tag(tag::INTEGER).expect("an integer"), &[0x01]);
        assert_eq!(
            crate::oid_arcs(inner.take_tag(tag::OID).expect("an oid")).expect("arcs"),
            vec![1, 2, 840, 113_549, 1, 1, 11]
        );
        // THE UNUSED-BIT COUNT IS THE FIRST BYTE, and the encoder writes zero: reading it back
        // here is what pins the two halves to the same convention.
        assert_eq!(
            inner.take_tag(tag::BIT_STRING).expect("a bit string"),
            &[0x00, 0xDE, 0xAD]
        );
        let (tag_byte, contents) = inner.take_any().expect("a time");
        assert_eq!(
            crate::parse_time(tag_byte, contents).expect("a timestamp"),
            1_767_225_600
        );
    }
}
