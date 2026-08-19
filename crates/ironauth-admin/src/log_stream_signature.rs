// SPDX-License-Identifier: MIT OR Apache-2.0

//! The signed security-event stream (issue #110 criterion 5).
//!
//! The published verifier is `packages/ironauth-sdk/snippets/verify-log-stream.mjs`, kept in
//! step with this module by the corpus at `packages/ironauth-sdk/vectors/log-stream-vectors.json`,
//! which `scripts/log-stream-vectors.sh` regenerates from the shipped signer and fails on any
//! diff. Consumer-facing documentation is `docs/log-stream-verification.md`.
//!
//! A SIEM receiving shipped batches has to answer three questions that TLS cannot answer for
//! it, because TLS protects the hop and says nothing about the payload once it has landed in
//! an object store, a forwarder, or a log index:
//!
//! 1. **Authenticity.** Did this batch come from this deployment, or from anyone who could
//!    write to the bucket the S3 sink writes into?
//! 2. **Replay.** Have I already applied this batch under a different name?
//!
//! Ordering is the third question a SIEM asks and this does NOT answer it. See below.
//!
//! The AWS `SigV4` signing already in [`crate::log_shipper`] answers none of these. It
//! authenticates the *request to S3* -- it is transport authentication to one sink, discarded
//! the moment the object is written, and absent entirely for the HTTP, Datadog and Splunk
//! sinks.
//!
//! # What is signed, and why each part is in there
//!
//! The signature covers a canonical string, not the raw body, so a consumer can reconstruct
//! exactly what was signed without depending on how any particular sink framed the request:
//!
//! ```text
//! ironauth-log-stream-v1
//! <stream id>
//! <cursor sequence>
//! <cursor id>
//! <event count>
//! <SHA-256 of the serialized events, lowercase hex>
//! ```
//!
//! **The stream id** binds the signature to one stream, so a batch cannot be lifted from a
//! low-value stream and replayed into a high-value one that happens to share a key.
//!
//! **The cursor position** is what makes ORDERING part of the signature rather than a
//! property a consumer has to trust the transport for. The shipper advances the cursor only
//! on success and only to what was accepted, so positions are monotonic per stream: a
//! consumer that records the last position it verified detects a REPLAY (a position it has
//! already seen) without any server-side state.
//!
//! IT DOES NOT DETECT A GAP, and an earlier version of this paragraph claimed it did. The
//! position is `occurred_micros`, a wall-clock microsecond timestamp of the batch's last row,
//! not a counter, so there is no "expected next one" to compare against. A consumer can prove
//! it has not seen a position before; it cannot prove it has missed nothing in between.
//! Closing that would mean signing the batch's START position too, so positions chain, and
//! that is a wire change rather than a documentation one. That is the whole reason the
//! position is signed rather than merely
//! sent.
//!
//! **The count and the digest of the events** are separate on purpose. The digest alone would
//! detect any change to the payload, so the count is redundant for integrity -- but it is not
//! redundant for DIAGNOSIS: a consumer that fails verification can say whether it received a
//! different number of events or the same number with different content, and those point at
//! very different faults.
//!
//! # Why HMAC rather than a public-key signature
//!
//! A SIEM integration is a shared-secret relationship already: the stream carries a
//! credential the operator provisioned for the sink. Asymmetric signing would mean publishing
//! and rotating a key pair for a consumer that is, by construction, one party the operator
//! configured. HMAC-SHA256 keeps the verification a consumer must implement to something
//! every runtime has natively -- which is exactly what makes the sample consumer in
//! `packages/ironauth-sdk/snippets` short enough to be read rather than trusted.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// The canonical-form version, first line of every signed string.
///
/// Versioned in the SIGNED material rather than beside it, so a consumer that understands
/// only v1 cannot be talked into verifying a v2 string by an attacker who strips a header:
/// the version is part of what the MAC commits to.
pub const CANONICAL_VERSION: &str = "ironauth-log-stream-v1";

/// The canonical string a batch signature covers.
///
/// `events_json` is the serialized events exactly as the sink will send them. It is hashed
/// rather than embedded so the canonical string stays a fixed size regardless of batch size,
/// and so a consumer verifying a large batch does not have to hold two copies of it.
#[must_use]
pub fn canonical_string(
    stream_id: &str,
    cursor_sequence: i64,
    cursor_id: &str,
    event_count: usize,
    events_json: &str,
) -> String {
    let digest = hex(&Sha256::digest(events_json.as_bytes()));
    format!(
        "{CANONICAL_VERSION}\n{stream_id}\n{cursor_sequence}\n{cursor_id}\n{event_count}\n{digest}"
    )
}

/// Lowercase hex, in one place so the digest and the signature can never disagree about
/// their encoding -- which a consumer reimplementing this in another language would have no
/// way to discover except by a verification that fails for no visible reason.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, byte| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{byte:02x}");
        acc
    })
}

/// Sign a batch, returning the signature as lowercase hex.
///
/// # Panics
///
/// Never: HMAC-SHA256 accepts a key of any length.
#[must_use]
pub fn sign(key: &[u8], canonical: &str) -> String {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(canonical.as_bytes());
    hex(&mac.finalize().into_bytes())
}

/// Whether `signature` is the signature of `canonical` under `key`.
///
/// Compared through the MAC's own verifier rather than by string equality, so the comparison
/// is constant time. A byte-by-byte `==` on the hex would leak the position of the first
/// difference to anyone who can submit candidate signatures and time the answer, which is the
/// standard way a naive verifier is turned into an oracle.
///
/// # Panics
///
/// Never: HMAC-SHA256 accepts a key of any length, and a signature that is not hex is
/// REFUSED rather than unwrapped -- a verifier that panicked on malformed input would hand
/// anyone who can reach it a denial of service in place of a `false`.
#[must_use]
pub fn verify(key: &[u8], canonical: &str, signature: &str) -> bool {
    let Ok(expected) = decode_hex(signature) else {
        return false;
    };
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(canonical.as_bytes());
    mac.verify_slice(&expected).is_ok()
}

/// Decode lowercase or uppercase hex, refusing anything else.
fn decode_hex(input: &str) -> Result<Vec<u8>, ()> {
    if input.len() % 2 != 0 {
        return Err(());
    }
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"a-stream-signing-secret";
    const EVENTS: &str = r#"[{"class_uid":3002,"activity_id":1}]"#;

    fn canonical() -> String {
        canonical_string("lst_abc", 42, "out_xyz", 1, EVENTS)
    }

    #[test]
    fn a_signature_verifies_against_the_string_it_covers() {
        let signature = sign(KEY, &canonical());
        assert!(verify(KEY, &canonical(), &signature));
    }

    #[test]
    fn a_signature_from_a_different_key_does_not_verify() {
        let signature = sign(b"another-secret", &canonical());
        assert!(
            !verify(KEY, &canonical(), &signature),
            "a batch signed by anyone else must not verify, or the signature answers no \
             question a consumer asked"
        );
    }

    /// Each field of the canonical string is LOAD-BEARING.
    ///
    /// Asserted field by field rather than as one happy path, because a canonical form that
    /// silently ignores one of its inputs is the classic way a signature scheme ends up
    /// covering less than its documentation claims. Every case below is a real substitution
    /// an attacker or a bug could make.
    #[test]
    fn every_field_of_the_canonical_string_changes_the_signature() {
        let base = sign(KEY, &canonical());

        // A batch lifted into a DIFFERENT stream that shares a key.
        let other_stream = sign(
            KEY,
            &canonical_string("lst_other", 42, "out_xyz", 1, EVENTS),
        );
        assert_ne!(base, other_stream, "the stream id must be covered");

        // The same batch presented at a different position: a REPLAY.
        let replayed = sign(KEY, &canonical_string("lst_abc", 41, "out_xyz", 1, EVENTS));
        assert_ne!(base, replayed, "the cursor sequence must be covered");

        let other_id = sign(
            KEY,
            &canonical_string("lst_abc", 42, "out_other", 1, EVENTS),
        );
        assert_ne!(base, other_id, "the cursor id must be covered");

        // The same content, a different claimed count: the diagnosis case.
        let miscounted = sign(KEY, &canonical_string("lst_abc", 42, "out_xyz", 2, EVENTS));
        assert_ne!(base, miscounted, "the event count must be covered");

        // The same count, different content: the integrity case.
        let tampered = sign(
            KEY,
            &canonical_string(
                "lst_abc",
                42,
                "out_xyz",
                1,
                r#"[{"class_uid":3002,"activity_id":2}]"#,
            ),
        );
        assert_ne!(base, tampered, "the events digest must be covered");
    }

    /// The VERSION is inside the MAC, not beside it.
    ///
    /// If a consumer could be handed a v2 string and verify it as v1, the version would be
    /// advisory rather than binding, and a future format change would be a downgrade vector
    /// rather than a clean break.
    #[test]
    fn the_canonical_version_is_part_of_what_is_signed() {
        let canonical = canonical();
        assert!(
            canonical.starts_with(CANONICAL_VERSION),
            "the version leads the signed string"
        );
        let downgraded = canonical.replacen(CANONICAL_VERSION, "ironauth-log-stream-v2", 1);
        assert!(
            !verify(KEY, &downgraded, &sign(KEY, &canonical)),
            "a v1 signature must not verify a v2 string"
        );
    }

    #[test]
    fn a_malformed_signature_is_refused_rather_than_panicking() {
        for bad in ["", "zz", "abc", "not-hex-at-all"] {
            assert!(
                !verify(KEY, &canonical(), bad),
                "{bad:?} must be refused, not accepted and not a panic"
            );
        }
    }
}
