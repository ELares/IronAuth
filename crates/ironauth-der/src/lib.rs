// SPDX-License-Identifier: MIT OR Apache-2.0

//! IronAuth's ONE ASN.1 DER reader, and the encoder that writes what it reads.
//!
//! # Why it is a crate and not a module
//!
//! It began as a module inside `ironauth-webauthn` (issue #66), where the FIDO Metadata Service
//! BLOB's `x5c` chain and a packed attestation statement both needed it. SAML certificate
//! pinning (issue #139) needs the same thing: an operator uploads the certificate their identity
//! provider gave them, and the key inside it gets pinned.
//!
//! A SECOND READER WOULD BE THE DEFECT. Two DER readers in one codebase is two answers to "what
//! does this certificate say", and the interesting inputs are exactly the ones they disagree
//! about -- a non-minimal length, a trailing element, an integer with a spare sign byte. One of
//! the two would then be the permissive reader, and which one an attacker reaches decides what
//! gets accepted. So this moved out rather than being written twice, and both callers read DER
//! the same way by construction.
//!
//! WHAT EACH CALLER KEEPS is its own POLICY, which genuinely differs: WebAuthn verifies
//! attestation chains and accepts Ed25519 and P-256; SAML pins a key with no chain to verify
//! and accepts P-256, P-384 and RSA in the range its signature backend can use. Policy belongs
//! with the caller. Reading bytes does not.
//!
//! # What it is
//!
//! THE READER is the larger half and the one with the security argument: it never allocates a
//! parse tree, it borrows from the input, and every
//! malformed length or truncation is a clean [`DerError`], never a panic. It reads exactly the
//! DER structures a certificate and an SPKI need -- nested TLV triples, tagged fields, integers,
//! OIDs, bit and octet strings, and the two X.509 time forms.
//!
//! It is deliberately NOT a general ASN.1 library, and deliberately not `der`/`x509-cert`: the
//! workspace's bias is a bespoke reader for the subset actually used, the same decision #65 made
//! about ceremony parsing over `ciborium`. It supports definite-length DER, single- and
//! multi-byte lengths, and the universal tags X.509 needs. An indefinite length, a constructed
//! primitive, or an unknown high-tag-number form is rejected rather than guessed.

pub mod write;

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
        // AND A LENGTH THAT FITS THE SHORT FORM MUST USE IT. DER admits exactly one encoding
        // of each length; `81 02` is `02` written longer, and a reader that accepts both agrees
        // with a stricter one about every conforming document and disagrees about that one.
        //
        // `checked_mul` for the same reason as in `oid_arcs`: `checked_shl(8)` reports success
        // after dropping the high bits. Unreachable here, because `num_bytes` is bounded to the
        // width of a `usize` -- but a guard that cannot guard is worse than none, because the
        // next person to widen the bound will believe it.
        let mut length = 0usize;
        for &b in len_bytes {
            length = length
                .checked_mul(256)
                .and_then(|shifted| shifted.checked_add(usize::from(b)))
                .ok_or(DerError::BadLength)?;
        }
        if length < 0x80 {
            return Err(DerError::BadLength);
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
/// Every component is a base-128 SUBIDENTIFIER with the high bit as a continuation flag, and the
/// FIRST subidentifier carries the first TWO arcs packed as `40*a + b` (X.690 8.19.4). Returns the
/// arcs so a caller can compare against a known OID without a string round-trip.
///
/// THE FIRST SUBIDENTIFIER IS BASE-128 LIKE THE REST, which an earlier version of this function
/// did not do: it read one byte and answered `first / 40, first % 40`. Two things were wrong with
/// that. A first subidentifier of 128 or more is spread over several bytes, and reading one of
/// them decoded a DIFFERENT OID than every conformant parser -- `81 34 03` is `2.100.3`, and the
/// old reader answered `3.9.52.3`. And `first / 40` can answer 3 through 6, which is not a legal
/// first arc at all: X.690 8.19.4 fixes the first arc at 0, 1 or 2, and the last of those absorbs
/// everything from 80 upward, so the split is a three-way test rather than a division.
///
/// # Errors
///
/// [`DerError::BadValue`] on an empty OID, a truncated final subidentifier, a non-minimal
/// subidentifier, or one that does not fit a `u64`.
pub fn oid_arcs(contents: &[u8]) -> Result<Vec<u64>, DerError> {
    let mut subidentifiers = Vec::new();
    let mut value: u64 = 0;
    let mut pending = false;
    for &b in contents {
        // A LEADING CONTINUATION BYTE OF 0x80 IS A NON-MINIMAL ARC: seven zero bits in front of
        // the number, which X.690 8.19.2 forbids and which is a SECOND encoding of one value.
        // OpenSSL compares an OBJECT IDENTIFIER by its ENCODED BYTES, so it reads such an OID as
        // a different one entirely and refuses the certificate -- leaving this the permissive
        // reader in a disagreement, which is the hazard this crate's own doc claims to close.
        if !pending && b == 0x80 {
            return Err(DerError::BadValue);
        }
        pending = true;
        // `checked_mul(128)` RATHER THAN `checked_shl(7)`, WHICH GUARDS NOTHING HERE.
        // `checked_shl` answers `None` only when the SHIFT AMOUNT is at least the bit width; a
        // shift of 7 is always in range, so `u64::MAX.checked_shl(7)` is `Some(..488)` -- the
        // high bits are gone and the call reports success. An OID arc is unbounded in DER, so
        // this loop is reachable with as many bytes as an attacker likes, and a wrapped arc can
        // be made to equal any value at all: `1.2.840.113549.1.1.1` included, which is the OID
        // that decides a key is RSA.
        value = value
            .checked_mul(128)
            .and_then(|shifted| shifted.checked_add(u64::from(b & 0x7F)))
            .ok_or(DerError::BadValue)?;
        if b & 0x80 == 0 {
            subidentifiers.push(value);
            value = 0;
            pending = false;
        }
    }
    if pending {
        // A final subidentifier whose last byte still had the continuation bit set.
        return Err(DerError::BadValue);
    }
    // X.690 8.19.4: THE FIRST SUBIDENTIFIER IS 40*arc1 + arc2, and arc1 is 0, 1 or 2. The top
    // range is open -- arc1 of 2 admits any arc2, so everything from 80 upward belongs to it --
    // which is why this is a three-way test and not a division by 40.
    let (&first, rest) = subidentifiers.split_first().ok_or(DerError::BadValue)?;
    let mut arcs = match first {
        0..=39 => vec![0, first],
        40..=79 => vec![1, first - 40],
        _ => vec![2, first - 80],
    };
    arcs.extend_from_slice(rest);
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
    // Every field below is cut at a CONSTANT byte offset, and the ASCII-digit checks
    // live INSIDE `parse_2`, which runs AFTER the slice. The `text.len()` checks prove
    // only that the bytes exist, never that an offset is a character boundary, so a
    // multi-byte character straddling one made `&text[0..2]` (and each sibling offset)
    // PANIC on a certificate whose bytes the caller does not control. Rejecting a
    // non-ASCII value here makes every offset below a boundary. It moves no verdict:
    // the length is exact and every byte of an accepted value already had to satisfy
    // an ASCII-only field parse, so nothing that parses today was non-ASCII.
    if !text.is_ascii() {
        return Err(DerError::BadValue);
    }
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
            // `i64::from_str` ACCEPTS A LEADING SIGN, so `-226` and `+226` both parse -- and a
            // negative year becomes a negative epoch, which a caller then writes into a column
            // as a real instant. X.690 gives GeneralizedTime four DIGITS and no sign.
            if !text[0..4].bytes().all(|byte| byte.is_ascii_digit()) {
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
    fn the_first_subidentifier_is_base_128_and_splits_three_ways() {
        // THE THREE-WAY SPLIT, at each boundary. 39 is the last arc2 under arc1 0; 40 and 79
        // bracket arc1 1; 80 opens arc1 2, which is then unbounded.
        assert_eq!(oid_arcs(&[39]).unwrap(), vec![0, 39]);
        assert_eq!(oid_arcs(&[40]).unwrap(), vec![1, 0]);
        assert_eq!(oid_arcs(&[79]).unwrap(), vec![1, 39]);
        assert_eq!(oid_arcs(&[80]).unwrap(), vec![2, 0]);

        // A FIRST SUBIDENTIFIER OVER 127, spread over two bytes. `81 34` is 180, which is
        // 2.100 -- and the reader this replaced answered 3.9 for it, an arc1 that X.690 does not
        // allow to exist. Every conformant parser reads these bytes as 2.100.3.
        assert_eq!(oid_arcs(&[0x81, 0x34, 0x03]).unwrap(), vec![2, 100, 3]);

        // AND A NON-MINIMAL FIRST SUBIDENTIFIER IS REFUSED, which the old reader could not do
        // either: it consumed the first byte before the minimality check could see it, so
        // `80 15` was read as an OID instead of rejected as a second encoding of one.
        assert!(oid_arcs(&[0x80, 0x15]).is_err());
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

    #[test]
    fn a_multibyte_character_in_a_time_is_rejected_not_a_panic() {
        // Issue #419, the char-boundary panic class. The length checks are BYTE checks,
        // so a value of the right byte length whose characters are not all one byte
        // used to be sliced through the middle of one: "end byte index 2 is not a char
        // boundary". Each of these is exactly 12 (UTCTime) or 14 (GeneralizedTime)
        // bytes before the `Z`, straddling a different field offset, and every one is
        // now the ordinary rejection the digit checks always intended.
        for contents in [
            // UTCTime: the euro straddles the year, month, and day cuts in turn.
            &b"\xe2\x82\xac123456789Z"[..],
            &b"99\xe2\x82\xac1234567Z"[..],
            &b"9901\xe2\x82\xac12345Z"[..],
            // A 2-byte and a 4-byte character, at other offsets.
            &b"9\xc3\xa90102030405Z"[..],
            &b"99010203\xf0\x9f\x98\x8005Z"[..],
        ] {
            assert_eq!(
                parse_time(tag::UTC_TIME, contents).err(),
                Some(DerError::BadValue),
                "UTCTime {contents:?}"
            );
        }
        for contents in [
            &b"12\xe2\x82\xac123456789Z"[..],
            &b"\xe2\x82\xac12345678901Z"[..],
            &b"2024010203\xf0\x9f\x98\x80Z"[..],
        ] {
            assert_eq!(
                parse_time(tag::GENERALIZED_TIME, contents).err(),
                Some(DerError::BadValue),
                "GeneralizedTime {contents:?}"
            );
        }
        // The ASCII gate moves no accepted value: the conformant times still parse.
        assert_eq!(parse_time(tag::UTC_TIME, b"700101000000Z").unwrap(), 0);
        assert_eq!(
            parse_time(tag::GENERALIZED_TIME, b"20240101000000Z").unwrap(),
            1_704_067_200
        );
    }
}
