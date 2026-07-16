// SPDX-License-Identifier: MIT OR Apache-2.0

//! A minimal, allocation-light ASN.1 DER reader (issue #66 PR B).
//!
//! The FIDO Metadata Service BLOB is a JWS whose `x5c` header carries an X.509
//! certificate chain, and a packed attestation statement carries the same. To
//! verify those chains without pulling in `openssl`, `webpki`, or a `RustCrypto`
//! `der`/`x509-cert` tree (the workspace `cargo deny` and the in-tree bespoke
//! bias, mirroring the #65 ceremony-over-ciborium decision), this module reads
//! exactly the DER structures a certificate and an SPKI need: nested TLV triples,
//! tagged fields, integers, OIDs, bit/octet strings, and the two X.509 time
//! forms. It is a READER only: it never allocates a parse tree, it borrows from
//! the input, and every malformed length or truncation is a clean
//! [`DerError`], never a panic.
//!
//! It is deliberately NOT a general ASN.1 library. It supports definite-length
//! DER (the only form a conformant certificate uses), single-byte and multi-byte
//! lengths, and the handful of universal tags X.509 needs. An indefinite length,
//! a constructed primitive, or an unknown high-tag-number form is rejected rather
//! than guessed.

/// A DER parse failure. One opaque reason set: the caller collapses every X.509
/// or MDS3 failure to a single non-enumerating outcome, so this carries no wire
/// oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerError {
    /// The input ended before a complete TLV could be read.
    Truncated,
    /// A length used the reserved indefinite form or overflowed `usize`.
    BadLength,
    /// The tag did not match what the grammar expected at this position.
    UnexpectedTag,
    /// A value was structurally invalid for its tag (a bad integer, OID, or time).
    BadValue,
}

/// DER universal tag numbers (class 0, the only class this reader needs beyond
/// context-specific constructed fields, handled explicitly by [`Der::take_tag`]).
pub mod tag {
    /// `BOOLEAN`.
    pub const BOOLEAN: u8 = 0x01;
    /// `INTEGER`.
    pub const INTEGER: u8 = 0x02;
    /// `BIT STRING`.
    pub const BIT_STRING: u8 = 0x03;
    /// `OCTET STRING`.
    pub const OCTET_STRING: u8 = 0x04;
    /// `OBJECT IDENTIFIER`.
    pub const OID: u8 = 0x06;
    /// `UTF8String`.
    pub const UTF8_STRING: u8 = 0x0C;
    /// `PrintableString`.
    pub const PRINTABLE_STRING: u8 = 0x13;
    /// `IA5String`.
    pub const IA5_STRING: u8 = 0x16;
    /// `UTCTime`.
    pub const UTC_TIME: u8 = 0x17;
    /// `GeneralizedTime`.
    pub const GENERALIZED_TIME: u8 = 0x18;
    /// `SEQUENCE` (constructed).
    pub const SEQUENCE: u8 = 0x30;
    /// `SET` (constructed).
    pub const SET: u8 = 0x31;
    /// The constructed context-specific class bits (`0b1010_0000`), OR'd with the
    /// field number, as X.509 uses for `[0] version`, `[3] extensions`, etc.
    pub const CONTEXT_CONSTRUCTED: u8 = 0xA0;
}

/// A borrowing DER cursor over a byte slice.
#[derive(Debug, Clone, Copy)]
pub struct Der<'a> {
    bytes: &'a [u8],
}

impl<'a> Der<'a> {
    /// A cursor over `bytes`.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Whether the cursor is exhausted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Read one TLV of exactly `expected` tag and return its raw contents,
    /// advancing past it.
    ///
    /// # Errors
    ///
    /// [`DerError::UnexpectedTag`] if the next tag is not `expected`,
    /// [`DerError::Truncated`] / [`DerError::BadLength`] on a malformed header.
    pub fn take_tag(&mut self, expected: u8) -> Result<&'a [u8], DerError> {
        let (tag, contents, rest) = read_tlv(self.bytes)?;
        if tag != expected {
            return Err(DerError::UnexpectedTag);
        }
        self.bytes = rest;
        Ok(contents)
    }

    /// Read one TLV of any tag, returning `(tag, contents)` and advancing.
    ///
    /// # Errors
    ///
    /// [`DerError::Truncated`] / [`DerError::BadLength`] on a malformed header.
    pub fn take_any(&mut self) -> Result<(u8, &'a [u8]), DerError> {
        let (tag, contents, rest) = read_tlv(self.bytes)?;
        self.bytes = rest;
        Ok((tag, contents))
    }

    /// Peek the next tag byte without consuming, or `None` at end of input.
    #[must_use]
    pub fn peek_tag(&self) -> Option<u8> {
        self.bytes.first().copied()
    }

    /// Read one TLV of any tag, returning `(tag, full_element, contents)` where
    /// `full_element` is the COMPLETE encoded triple (tag + length + contents),
    /// advancing past it. Needed for a certificate signature, which is computed
    /// over the raw DER of the `tbsCertificate` element (its header included), not
    /// over the contents alone.
    ///
    /// # Errors
    ///
    /// [`DerError::Truncated`] / [`DerError::BadLength`] on a malformed header.
    pub fn take_element(&mut self) -> Result<(u8, &'a [u8], &'a [u8]), DerError> {
        let start = self.bytes;
        let (tag, contents, rest) = read_tlv(self.bytes)?;
        let consumed = start.len() - rest.len();
        let full = &start[..consumed];
        self.bytes = rest;
        Ok((tag, full, contents))
    }

    /// Read a `SEQUENCE` and return a sub-cursor over its contents.
    ///
    /// # Errors
    ///
    /// As [`Der::take_tag`] for the `SEQUENCE` tag.
    pub fn take_sequence(&mut self) -> Result<Der<'a>, DerError> {
        Ok(Der::new(self.take_tag(tag::SEQUENCE)?))
    }
}

/// Split one DER TLV off the front of `bytes`, returning `(tag, contents, rest)`.
///
/// Handles single-byte and multi-byte definite lengths; rejects the indefinite
/// length form (`0x80`) and any length that overflows `usize` or runs past the
/// buffer.
fn read_tlv(bytes: &[u8]) -> Result<(u8, &[u8], &[u8]), DerError> {
    let (&tag, after_tag) = bytes.split_first().ok_or(DerError::Truncated)?;
    // Reject the high-tag-number form (bottom 5 bits all set): no X.509 field this
    // reader consumes uses it, so it is a malformed input, not a value to skip.
    if tag & 0x1F == 0x1F {
        return Err(DerError::UnexpectedTag);
    }
    let (&len_byte, after_len_byte) = after_tag.split_first().ok_or(DerError::Truncated)?;
    let (length, after_length) = if len_byte & 0x80 == 0 {
        // Short form: the byte IS the length.
        (usize::from(len_byte), after_len_byte)
    } else {
        let num_bytes = usize::from(len_byte & 0x7F);
        // 0x80 is the indefinite form (not valid DER); a run longer than 8 bytes
        // cannot fit a usize on any supported target.
        if num_bytes == 0 || num_bytes > core::mem::size_of::<usize>() {
            return Err(DerError::BadLength);
        }
        let (len_bytes, after) = split_at_checked(after_len_byte, num_bytes)?;
        // DER requires the minimal encoding; a leading zero here would be non-minimal.
        if len_bytes[0] == 0 {
            return Err(DerError::BadLength);
        }
        let mut length = 0usize;
        for &b in len_bytes {
            length = length
                .checked_shl(8)
                .and_then(|shifted| shifted.checked_add(usize::from(b)))
                .ok_or(DerError::BadLength)?;
        }
        (length, after)
    };
    let (contents, rest) = split_at_checked(after_length, length)?;
    Ok((tag, contents, rest))
}

/// `slice.split_at` that returns [`DerError::Truncated`] instead of panicking when
/// `mid` runs past the end.
fn split_at_checked(slice: &[u8], mid: usize) -> Result<(&[u8], &[u8]), DerError> {
    if mid > slice.len() {
        return Err(DerError::Truncated);
    }
    Ok(slice.split_at(mid))
}

/// Read a DER `OBJECT IDENTIFIER`'s contents into its dotted arc components.
///
/// The first byte encodes the first two arcs as `40*a + b`; the rest are
/// base-128 with the high bit as a continuation flag. Returns the arcs so a
/// caller can compare against a known OID without a string round-trip.
///
/// # Errors
///
/// [`DerError::BadValue`] on an empty OID or a truncated final arc.
pub fn oid_arcs(contents: &[u8]) -> Result<Vec<u64>, DerError> {
    let (&first, rest) = contents.split_first().ok_or(DerError::BadValue)?;
    let mut arcs = Vec::new();
    arcs.push(u64::from(first / 40));
    arcs.push(u64::from(first % 40));
    let mut value: u64 = 0;
    let mut pending = false;
    for &b in rest {
        pending = true;
        value = value
            .checked_shl(7)
            .and_then(|shifted| shifted.checked_add(u64::from(b & 0x7F)))
            .ok_or(DerError::BadValue)?;
        if b & 0x80 == 0 {
            arcs.push(value);
            value = 0;
            pending = false;
        }
    }
    if pending {
        // A final arc whose last byte still had the continuation bit set.
        return Err(DerError::BadValue);
    }
    Ok(arcs)
}

/// Parse a DER `UTCTime` or `GeneralizedTime`'s contents into a Unix timestamp
/// (seconds).
///
/// Only the `Z` (UTC) forms a conformant certificate uses are accepted:
/// `YYMMDDHHMMSSZ` (`UTCTime`, with the RFC 5280 pivot: `YY < 50` is 20YY, else
/// 19YY) and `YYYYMMDDHHMMSSZ` (`GeneralizedTime`). A local-time or fractional
/// form is [`DerError::BadValue`].
///
/// # Errors
///
/// [`DerError::BadValue`] on any non-`Z`, non-second-precision, or out-of-range
/// value.
pub fn parse_time(tag_byte: u8, contents: &[u8]) -> Result<i64, DerError> {
    let text = core::str::from_utf8(contents).map_err(|_| DerError::BadValue)?;
    let text = text.strip_suffix('Z').ok_or(DerError::BadValue)?;
    let (year, rest) = match tag_byte {
        tag::UTC_TIME => {
            if text.len() != 12 {
                return Err(DerError::BadValue);
            }
            let yy: i64 = parse_2(&text[0..2])?;
            let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
            (year, &text[2..])
        }
        tag::GENERALIZED_TIME => {
            if text.len() != 14 {
                return Err(DerError::BadValue);
            }
            let yyyy: i64 = text[0..4].parse().map_err(|_| DerError::BadValue)?;
            (yyyy, &text[4..])
        }
        _ => return Err(DerError::BadValue),
    };
    let month = parse_2(&rest[0..2])?;
    let day = parse_2(&rest[2..4])?;
    let hour = parse_2(&rest[4..6])?;
    let minute = parse_2(&rest[6..8])?;
    let second = parse_2(&rest[8..10])?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(DerError::BadValue);
    }
    Ok(civil_to_unix(year, month, day, hour, minute, second))
}

/// Parse a two-digit ASCII field.
fn parse_2(s: &str) -> Result<i64, DerError> {
    if s.len() != 2 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(DerError::BadValue);
    }
    s.parse().map_err(|_| DerError::BadValue)
}

/// Convert a proleptic-Gregorian civil date-time (UTC) to a Unix timestamp using
/// Howard Hinnant's `days_from_civil` algorithm. Pure integer arithmetic, no
/// dependency on any calendar crate or the clock seam (this is data conversion,
/// not a time source).
fn civil_to_unix(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + hour * 3_600 + minute * 60 + second
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_nested_sequence_and_integer() {
        // SEQUENCE { INTEGER 1, OCTET STRING [0xAA, 0xBB] }
        let der = [0x30, 0x07, 0x02, 0x01, 0x01, 0x04, 0x02, 0xAA, 0xBB];
        let mut top = Der::new(&der);
        let mut seq = top.take_sequence().unwrap();
        assert_eq!(seq.take_tag(tag::INTEGER).unwrap(), &[0x01]);
        assert_eq!(seq.take_tag(tag::OCTET_STRING).unwrap(), &[0xAA, 0xBB]);
        assert!(seq.is_empty());
    }

    #[test]
    fn rejects_indefinite_length() {
        let der = [0x30, 0x80, 0x00, 0x00];
        assert_eq!(
            Der::new(&der).take_sequence().err(),
            Some(DerError::BadLength)
        );
    }

    #[test]
    fn rejects_truncated_length() {
        let der = [0x04, 0x05, 0x01, 0x02];
        let mut d = Der::new(&der);
        assert_eq!(
            d.take_tag(tag::OCTET_STRING).err(),
            Some(DerError::Truncated)
        );
    }

    #[test]
    fn multi_byte_length_is_read() {
        // OCTET STRING of 200 bytes: 0x04 0x81 0xC8 <200 bytes>.
        let mut der = vec![0x04, 0x81, 0xC8];
        der.extend(std::iter::repeat_n(0x2A, 200));
        let mut d = Der::new(&der);
        assert_eq!(d.take_tag(tag::OCTET_STRING).unwrap().len(), 200);
    }

    #[test]
    fn oid_arcs_decode_known_oids() {
        // 1.2.840.10045.4.3.2 (ecdsa-with-SHA256): 2a 86 48 ce 3d 04 03 02.
        let contents = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
        assert_eq!(
            oid_arcs(&contents).unwrap(),
            vec![1, 2, 840, 10045, 4, 3, 2]
        );
    }

    #[test]
    fn utc_time_pivot_and_epoch() {
        // 700101000000Z (UTCTime) is the Unix epoch (1970, since 70 >= 50 -> 1970).
        assert_eq!(parse_time(tag::UTC_TIME, b"700101000000Z").unwrap(), 0);
        // 000101000000Z -> 2000-01-01 (00 < 50 -> 2000).
        assert_eq!(
            parse_time(tag::UTC_TIME, b"000101000000Z").unwrap(),
            946_684_800
        );
        // GeneralizedTime 20240101000000Z.
        assert_eq!(
            parse_time(tag::GENERALIZED_TIME, b"20240101000000Z").unwrap(),
            1_704_067_200
        );
    }

    #[test]
    fn non_z_time_is_rejected() {
        assert_eq!(
            parse_time(tag::UTC_TIME, b"700101000000").err(),
            Some(DerError::BadValue)
        );
    }
}
