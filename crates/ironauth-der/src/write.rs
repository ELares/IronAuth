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
/// THE FIRST TWO ARCS SHARE A SUBIDENTIFIER, which is X.690's rule and the one place OID encoding
/// surprises people: `1.2.840...` begins `0x2A` because 1 * 40 + 2 = 42. It is a SUBIDENTIFIER
/// and not a byte -- an earlier version wrote `40 * a + b` as a single `u8`, and `2.100.3` has a
/// first subidentifier of 180, which does not fit and silently encoded a DIFFERENT OID. The
/// combined value goes through the same base-128 encoding every other arc does, which is what
/// makes that impossible rather than merely unlikely.
///
/// # Panics
///
/// If `arcs` has fewer than two elements, which is not an OID.
#[must_use]
pub fn oid(arcs: &[u64]) -> Vec<u8> {
    assert!(arcs.len() >= 2, "an OID has at least two arcs");
    let mut body = base128(arcs[0] * 40 + arcs[1]);
    for &arc in &arcs[2..] {
        body.extend_from_slice(&base128(arc));
    }
    tlv(tag::OID, &body)
}

/// One OID subidentifier: base-128, most significant group first, continuation bit set on every
/// byte but the last.
fn base128(value: u64) -> Vec<u8> {
    let mut stack = vec![u8::try_from(value & 0x7F).unwrap_or(0)];
    let mut remaining = value >> 7;
    while remaining > 0 {
        stack.push(u8::try_from(remaining & 0x7F).unwrap_or(0) | 0x80);
        remaining >>= 7;
    }
    stack.reverse();
    stack
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
/// because ASN.1 integers are SIGNED and a magnitude whose first bit is 1 would otherwise encode
/// a negative number.
///
/// THE SIGN RULE IS NOT EXERCISED BY THE CERTIFICATE WRITER TODAY, and an earlier version of this
/// doc claimed the opposite -- that an RSA modulus "almost always has that bit set, so the second
/// rule fires on nearly every certificate". It does not: a modulus reaches the SPKI as DER that
/// ring already encoded, so it never passes through here at all, and the only integers this
/// crate's own callers write are a version and a serial, both small and both positive. The rule
/// is right and the unit test below is what holds it, not a certificate.
#[must_use]
fn uint_bytes(magnitude: &[u8]) -> Vec<u8> {
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
fn utf8_string(text: &str) -> Vec<u8> {
    tlv(tag::UTF8_STRING, text.as_bytes())
}

/// Encode a `GeneralizedTime` from a Unix timestamp, at second precision in UTC.
///
#[must_use]
pub fn generalized_time(unix_seconds: i64) -> Vec<u8> {
    let (year, month, day, hour, minute, second) = civil_from_unix(unix_seconds);
    let text = format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z");
    tlv(tag::GENERALIZED_TIME, text.as_bytes())
}

/// Encode an X.509 `Time` from a Unix timestamp, choosing the form RFC 5280 requires.
///
/// THE RULE IS A MUST AND IT IS NOT ABOUT WHAT READERS ACCEPT. RFC 5280 4.1.2.5 says a conforming
/// certificate MUST encode a date through 2049 as `UTCTime` and 2050 onwards as
/// `GeneralizedTime` -- so a certificate writing `GeneralizedTime` for 2026 is non-conforming
/// whatever a lenient parser does with it. An earlier version of this crate wrote
/// `GeneralizedTime` always and argued that every reader accepts it, which answered a question
/// the specification was not asking.
///
/// `UTCTime`'S TWO-DIGIT YEAR is read by RFC 5280 as 1950-2049, which is why the boundary sits
/// where it does and why the choice is a year comparison rather than a preference.
#[must_use]
pub fn x509_time(unix_seconds: i64) -> Vec<u8> {
    let (year, month, day, hour, minute, second) = civil_from_unix(unix_seconds);
    if (1950..=2049).contains(&year) {
        let text = format!(
            "{:02}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z",
            year % 100
        );
        return tlv(tag::UTC_TIME, text.as_bytes());
    }
    generalized_time(unix_seconds)
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
    fn an_oid_combines_its_first_two_arcs_into_one_subidentifier() {
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

        // A FIRST SUBIDENTIFIER OVER 127, which is the case that distinguishes a subidentifier
        // from a byte and the one every OID this workspace writes today happens to avoid --
        // which is why an encoder that wrote it as a single `u8` passed every test. `2.100.3`
        // combines to 180, and X.690 8.19.2 spreads that over two base-128 bytes; writing one
        // emits a DIFFERENT OID, silently.
        assert_eq!(oid(&[2, 100, 3]), vec![0x06, 0x03, 0x81, 0x34, 0x03]);

        // AND IT DECODES BACK to the arcs it was built from, through the reader beside it. The
        // reader had the same defect, in the same place, and this round trip is what found it.
        assert_eq!(
            crate::oid_arcs(&oid(&[2, 100, 3])[2..]).expect("arcs"),
            vec![2, 100, 3]
        );
    }

    #[test]
    fn an_integer_is_minimal_and_never_accidentally_negative() {
        // ASN.1 INTEGERs are SIGNED, so a magnitude whose top bit is set needs a pad byte or it
        // encodes a negative number. THIS COMMENT USED TO SAY THAT AN RSA MODULUS IS THE VALUE
        // AT RISK, which is the same false sentence `uint_bytes`'s own doc retracts 150 lines
        // above and then points the reader down here to see held. No modulus reaches this
        // function: it arrives at the SPKI as DER ring already encoded. What omitting the pad
        // byte actually breaks is a version or a serial, and that is what these cases pin.
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
