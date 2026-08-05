// SPDX-License-Identifier: MIT OR Apache-2.0

//! Standard Webhooks signing and verification (issue #105, spec v1.0).
//!
//! This is the SIGNING CONTRACT half of #105. Endpoint registration, secret storage,
//! delivery through the outbox and the retry/DLQ behaviour are separate slices; nothing
//! here touches the store or the network.
//!
//! Adopting the specification wholesale is the point: every existing Standard Webhooks
//! verifier works against a conforming producer with no bespoke code, which is the
//! difference between "we have webhooks" and "your existing library verifies them".
//!
//! ## What the signature covers, and why replay fails
//!
//! The signing input is `{id}.{timestamp}.{payload}`, concatenated with literal dots.
//! Binding all three means a captured delivery cannot be replayed with a fresh timestamp
//! (the signature no longer matches) nor with a different body under the same id. The
//! verifier additionally refuses a timestamp outside a tolerance window, so a delivery
//! captured and held is refused even before the comparison.
//!
//! ## Rotation without downtime
//!
//! `webhook-signature` carries a SPACE-DELIMITED list of `v1,<base64>` entries. During a
//! rotation overlap window a delivery is signed under both the old and the new secret, so
//! a consumer that has either one verifies. That is what makes rotation a configuration
//! change rather than a coordinated deploy, and it is why signing takes a SLICE of
//! secrets rather than one.
//!
//! This module implements the DEFAULT symmetric scheme (`v1`, HMAC-SHA256). The optional
//! asymmetric `v1a` (Ed25519) scheme is a later slice of the same issue; the header
//! parser here already ignores entries whose version prefix it does not recognise, which
//! is what lets `v1a` be added without changing any consumer of this code.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

use crate::crypto::verify_signature;
use crate::mint::MacAlgorithm;
use crate::policy::JwsAlgorithm;
use crate::policy::KeyMaterial;
use crate::sign::{sign_asymmetric, sign_hmac};
use crate::signing_key::SigningKey;

/// The prefix every Standard Webhooks symmetric secret carries.
const SECRET_PREFIX: &str = "whsec_";

/// The version tag of the symmetric (HMAC-SHA256) scheme.
const SYMMETRIC_VERSION: &str = "v1";

/// The version tag of the asymmetric (Ed25519) scheme.
///
/// A consumer of the asymmetric scheme verifies with a PUBLIC key, so the producer's
/// signing key never leaves this process. That is the difference that matters: with the
/// symmetric scheme a leaked consumer secret lets an attacker FORGE deliveries, and with
/// this one it lets them verify, which is what they could already do.
const ASYMMETRIC_VERSION: &str = "v1a";

/// Why a webhook signature was refused.
///
/// Deliberately coarse for the caller that reports outward, and precise enough for an
/// operator reading logs. A verifier must never tell a caller WHICH secret matched or
/// how close a comparison came.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookError {
    /// The secret was not in the `whsec_<base64>` format.
    MalformedSecret,
    /// The `webhook-timestamp` header was not an integer number of seconds.
    MalformedTimestamp,
    /// The timestamp fell outside the tolerance window, in either direction.
    TimestampOutOfTolerance,
    /// No signature in the header verified under any supplied secret.
    NoMatchingSignature,
    /// An Ed25519 key could not produce a signature.
    SigningFailed,
}

/// A parsed Standard Webhooks symmetric secret.
///
/// Held as raw bytes: the `whsec_` prefix and base64 are a TRANSPORT format for
/// operators and config files, not the key. Parsing once at the edge means the signing
/// path cannot accidentally MAC over the printable form, which would still produce a
/// stable-looking signature that no conforming verifier could reproduce.
#[derive(Clone)]
pub struct WebhookSecret(Vec<u8>);

impl WebhookSecret {
    /// Parse a `whsec_<base64>` secret.
    ///
    /// # Errors
    ///
    /// [`WebhookError::MalformedSecret`] if the prefix is absent or the remainder is not
    /// standard base64.
    pub fn parse(raw: &str) -> Result<Self, WebhookError> {
        let encoded = raw
            .strip_prefix(SECRET_PREFIX)
            .ok_or(WebhookError::MalformedSecret)?;
        let bytes = BASE64_STANDARD
            .decode(encoded)
            .map_err(|_| WebhookError::MalformedSecret)?;
        if bytes.is_empty() {
            return Err(WebhookError::MalformedSecret);
        }
        Ok(Self(bytes))
    }

    /// Wrap raw secret bytes (the form a generator produces before encoding).
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The `whsec_`-prefixed printable form, for handing to an operator once.
    #[must_use]
    pub fn to_transport_string(&self) -> String {
        format!("{SECRET_PREFIX}{}", BASE64_STANDARD.encode(&self.0))
    }
}

impl core::fmt::Debug for WebhookSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("WebhookSecret(<redacted>)")
    }
}

impl Drop for WebhookSecret {
    fn drop(&mut self) {
        crate::redact::wipe(&mut self.0);
    }
}

/// Parse and range-check the `webhook-timestamp` header, shared by both verifiers so the
/// tolerance rule cannot drift between schemes.
///
/// BOTH directions. A delivery held and replayed later is the obvious case; a future-dated
/// one is refused too, because accepting it would let a captured delivery stay valid for
/// as long as the sender's clock skew allowed.
fn parse_timestamp(
    timestamp_header: &str,
    tolerance_secs: i64,
    now_secs: i64,
) -> Result<i64, WebhookError> {
    let timestamp: i64 = timestamp_header
        .trim()
        .parse()
        .map_err(|_| WebhookError::MalformedTimestamp)?;
    if (now_secs - timestamp).abs() > tolerance_secs {
        return Err(WebhookError::TimestampOutOfTolerance);
    }
    Ok(timestamp)
}

/// The exact bytes a signature is computed over: `{id}.{timestamp}.{payload}`.
///
/// One function so the signer and the verifier can never disagree about the
/// construction, which is the single most likely way two implementations of this spec
/// fail to interoperate.
fn signing_input(id: &str, timestamp_secs: i64, payload: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(id.len() + payload.len() + 24);
    input.extend_from_slice(id.as_bytes());
    input.push(b'.');
    input.extend_from_slice(timestamp_secs.to_string().as_bytes());
    input.push(b'.');
    input.extend_from_slice(payload);
    input
}

/// Build the `webhook-signature` header value for one delivery.
///
/// `secrets` is a slice so a rotation overlap window can sign under the old and the new
/// secret at once; a consumer holding either verifies. An empty slice yields an empty
/// header, which no verifier accepts.
#[must_use]
pub fn sign_delivery(
    secrets: &[WebhookSecret],
    id: &str,
    timestamp_secs: i64,
    payload: &[u8],
) -> String {
    let input = signing_input(id, timestamp_secs, payload);
    secrets
        .iter()
        .map(|secret| {
            let mac = sign_hmac(MacAlgorithm::Hs256, &secret.0, &input);
            format!("{SYMMETRIC_VERSION},{}", BASE64_STANDARD.encode(mac))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Verify a `webhook-signature` header against every supplied secret.
///
/// Returns `Ok(())` when at least one `v1` entry verifies under at least one secret and
/// the timestamp is inside `tolerance_secs`. Entries whose version prefix is not
/// recognised are SKIPPED rather than refused, which is what lets a future `v1a`
/// signature ride alongside `v1` without breaking a verifier written today.
///
/// # Errors
///
/// [`WebhookError::MalformedTimestamp`] if the header is not an integer;
/// [`WebhookError::TimestampOutOfTolerance`] if it is too old or too far in the future;
/// [`WebhookError::NoMatchingSignature`] if nothing verified.
pub fn verify_delivery(
    secrets: &[WebhookSecret],
    id: &str,
    timestamp_header: &str,
    payload: &[u8],
    signature_header: &str,
    tolerance_secs: i64,
    now_secs: i64,
) -> Result<(), WebhookError> {
    let timestamp = parse_timestamp(timestamp_header, tolerance_secs, now_secs)?;
    let input = signing_input(id, timestamp, payload);
    let mut matched = false;
    for entry in signature_header.split(' ').filter(|e| !e.is_empty()) {
        let Some((version, encoded)) = entry.split_once(',') else {
            continue;
        };
        if version != SYMMETRIC_VERSION {
            continue;
        }
        let Ok(presented) = BASE64_STANDARD.decode(encoded) else {
            continue;
        };
        for secret in secrets {
            let expected = sign_hmac(MacAlgorithm::Hs256, &secret.0, &input);
            // Constant time, and deliberately WITHOUT an early exit from the loops: a
            // verifier that returned on the first match would leak, through timing, which
            // secret in a rotation pair matched and how far down the header it was.
            matched |= constant_time_eq(&expected, &presented);
        }
    }
    if matched {
        Ok(())
    } else {
        Err(WebhookError::NoMatchingSignature)
    }
}

/// Build the `webhook-signature` header value under the ASYMMETRIC scheme.
///
/// Signs the same `{id}.{timestamp}.{payload}` input the symmetric scheme does, so the
/// replay properties are identical and a verifier's construction does not change with the
/// scheme. `keys` is a slice for the same rotation reason `sign_delivery` takes one.
///
/// # Errors
///
/// [`WebhookError::SigningFailed`] if a key cannot sign, which does not happen for an
/// Ed25519 key `ring` has already accepted.
pub fn sign_delivery_ed25519(
    keys: &[SigningKey],
    id: &str,
    timestamp_secs: i64,
    payload: &[u8],
) -> Result<String, WebhookError> {
    let input = signing_input(id, timestamp_secs, payload);
    let mut entries = Vec::with_capacity(keys.len());
    for key in keys {
        let signature = sign_asymmetric(key, &input).map_err(|()| WebhookError::SigningFailed)?;
        entries.push(format!(
            "{ASYMMETRIC_VERSION},{}",
            BASE64_STANDARD.encode(signature)
        ));
    }
    Ok(entries.join(" "))
}

/// Verify a `webhook-signature` header under the ASYMMETRIC scheme.
///
/// `public_keys` are raw Ed25519 public keys, the form a per-endpoint published key takes.
/// Entries whose version prefix is not `v1a` are SKIPPED, exactly as the symmetric
/// verifier skips what it does not know, so a header carrying both schemes verifies under
/// either verifier.
///
/// # Errors
///
/// The same three as [`verify_delivery`], for the same reasons.
pub fn verify_delivery_ed25519(
    public_keys: &[Vec<u8>],
    id: &str,
    timestamp_header: &str,
    payload: &[u8],
    signature_header: &str,
    tolerance_secs: i64,
    now_secs: i64,
) -> Result<(), WebhookError> {
    let timestamp = parse_timestamp(timestamp_header, tolerance_secs, now_secs)?;
    let input = signing_input(id, timestamp, payload);
    let mut matched = false;
    for entry in signature_header.split(' ').filter(|e| !e.is_empty()) {
        let Some((version, encoded)) = entry.split_once(',') else {
            continue;
        };
        // NOT load bearing for safety, and measured rather than assumed: with this check
        // removed, a `v1` entry still fails because Ed25519 verification refuses HMAC
        // bytes, and no test changes. It stays because it keeps the two verifiers
        // symmetric and skips pointless signature work, not because it is the thing
        // refusing the other scheme.
        if version != ASYMMETRIC_VERSION {
            continue;
        }
        let Ok(presented) = BASE64_STANDARD.decode(encoded) else {
            continue;
        };
        for public_key in public_keys {
            // `verify_signature` is the ONE ring-backed primitive this crate exposes, so
            // the asymmetric webhook check and every JWS check share a verifier rather
            // than this path growing its own.
            let key = KeyMaterial::Ed25519(public_key.clone());
            matched |= verify_signature(JwsAlgorithm::EdDsa, &key, &input, &presented).is_ok();
        }
    }
    if matched {
        Ok(())
    } else {
        Err(WebhookError::NoMatchingSignature)
    }
}

/// Compare two byte strings without a length-dependent early exit.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "msg_2Xq8kZ1s";
    const TS: i64 = 1_700_000_000;
    const PAYLOAD: &[u8] = br#"{"type":"user.created","data":{"id":"usr_1"}}"#;

    fn secret(byte: u8) -> WebhookSecret {
        WebhookSecret::from_bytes(vec![byte; 32])
    }

    #[test]
    fn the_signing_input_is_id_dot_timestamp_dot_payload() {
        // THE interoperability property. Everything else in this module is
        // self-consistent by construction: a signer and verifier that agreed on a WRONG
        // input would round-trip happily and fail against every conforming library. So
        // the exact bytes are asserted literally rather than through a round trip.
        let input = signing_input(ID, TS, PAYLOAD);
        let expected = format!("{ID}.{TS}.{}", String::from_utf8_lossy(PAYLOAD));
        assert_eq!(String::from_utf8(input).unwrap(), expected);
    }

    #[test]
    fn the_header_is_version_prefixed_and_round_trips() {
        let secrets = [secret(0x11)];
        let header = sign_delivery(&secrets, ID, TS, PAYLOAD);
        assert!(header.starts_with("v1,"), "version prefixed: {header}");
        assert_eq!(header.split(' ').count(), 1, "one secret, one signature");
        verify_delivery(&secrets, ID, &TS.to_string(), PAYLOAD, &header, 300, TS)
            .expect("a fresh delivery verifies");
    }

    #[test]
    fn rotation_signs_under_both_and_either_secret_verifies() {
        // The whole reason rotation is a config change rather than a coordinated deploy.
        let old = secret(0x11);
        let new = secret(0x22);
        let header = sign_delivery(&[old.clone(), new.clone()], ID, TS, PAYLOAD);
        assert_eq!(header.split(' ').count(), 2, "one signature per secret");

        for (label, held) in [("old", old), ("new", new)] {
            verify_delivery(&[held], ID, &TS.to_string(), PAYLOAD, &header, 300, TS)
                .unwrap_or_else(|error| {
                    panic!("a consumer holding the {label} secret verifies: {error:?}")
                });
        }
        // And a consumer holding NEITHER is refused, so the overlap window widens who can
        // verify without widening it to everyone.
        assert_eq!(
            verify_delivery(
                &[secret(0x33)],
                ID,
                &TS.to_string(),
                PAYLOAD,
                &header,
                300,
                TS
            ),
            Err(WebhookError::NoMatchingSignature)
        );
    }

    #[test]
    fn a_captured_delivery_cannot_be_replayed_with_a_new_timestamp_or_body() {
        // Binding id, timestamp and payload together is what makes this fail. Each half
        // is driven separately so neither can pass on the other's strength.
        let secrets = [secret(0x11)];
        let header = sign_delivery(&secrets, ID, TS, PAYLOAD);

        // A fresh timestamp on the captured signature: the signature no longer matches,
        // and it is refused for that reason rather than by tolerance (the clock moves too).
        assert_eq!(
            verify_delivery(
                &secrets,
                ID,
                &(TS + 10).to_string(),
                PAYLOAD,
                &header,
                300,
                TS + 10
            ),
            Err(WebhookError::NoMatchingSignature)
        );
        // A different body under the same id and timestamp.
        assert_eq!(
            verify_delivery(
                &secrets,
                ID,
                &TS.to_string(),
                br#"{"type":"user.deleted"}"#,
                &header,
                300,
                TS
            ),
            Err(WebhookError::NoMatchingSignature)
        );
        // A different id, same everything else.
        assert_eq!(
            verify_delivery(
                &secrets,
                "msg_other",
                &TS.to_string(),
                PAYLOAD,
                &header,
                300,
                TS
            ),
            Err(WebhookError::NoMatchingSignature)
        );
    }

    #[test]
    fn the_tolerance_window_refuses_stale_and_future_dated_deliveries() {
        let secrets = [secret(0x11)];
        let header = sign_delivery(&secrets, ID, TS, PAYLOAD);
        let stamp = TS.to_string();

        // Inside, both directions.
        verify_delivery(&secrets, ID, &stamp, PAYLOAD, &header, 300, TS + 299)
            .expect("just inside");
        verify_delivery(&secrets, ID, &stamp, PAYLOAD, &header, 300, TS - 299)
            .expect("just inside, early");
        // Outside, both directions. The future-dated case matters: accepting it would let
        // a captured delivery stay valid for as long as a sender's clock skew allowed.
        assert_eq!(
            verify_delivery(&secrets, ID, &stamp, PAYLOAD, &header, 300, TS + 301),
            Err(WebhookError::TimestampOutOfTolerance)
        );
        assert_eq!(
            verify_delivery(&secrets, ID, &stamp, PAYLOAD, &header, 300, TS - 301),
            Err(WebhookError::TimestampOutOfTolerance)
        );
        assert_eq!(
            verify_delivery(&secrets, ID, "not-a-number", PAYLOAD, &header, 300, TS),
            Err(WebhookError::MalformedTimestamp)
        );
    }

    #[test]
    fn an_unknown_version_prefix_is_skipped_rather_than_refused() {
        // What lets the asymmetric `v1a` scheme be added later without breaking a
        // verifier written today: it must ignore what it does not know, not reject it.
        let secrets = [secret(0x11)];
        let v1 = sign_delivery(&secrets, ID, TS, PAYLOAD);
        let mixed = format!("v1a,ZmFrZQ== {v1}");
        verify_delivery(&secrets, ID, &TS.to_string(), PAYLOAD, &mixed, 300, TS)
            .expect("the recognised entry still verifies alongside an unknown one");

        // But an unknown entry ALONE is not a pass.
        assert_eq!(
            verify_delivery(
                &secrets,
                ID,
                &TS.to_string(),
                PAYLOAD,
                "v1a,ZmFrZQ==",
                300,
                TS
            ),
            Err(WebhookError::NoMatchingSignature)
        );
    }

    #[test]
    fn the_transport_format_round_trips_and_refuses_malformed_input() {
        let raw = WebhookSecret::from_bytes(vec![0x11; 32]);
        let printed = raw.to_transport_string();
        assert!(printed.starts_with("whsec_"), "{printed}");
        let parsed = WebhookSecret::parse(&printed).expect("round trips");
        // Signing under the parsed secret matches signing under the original, which is
        // what proves the MAC is over the RAW bytes rather than the printable form.
        assert_eq!(
            sign_delivery(&[parsed], ID, TS, PAYLOAD),
            sign_delivery(&[raw], ID, TS, PAYLOAD)
        );

        assert_eq!(
            WebhookSecret::parse("nope_abc").unwrap_err(),
            WebhookError::MalformedSecret
        );
        assert_eq!(
            WebhookSecret::parse("whsec_!!!").unwrap_err(),
            WebhookError::MalformedSecret
        );
        assert_eq!(
            WebhookSecret::parse("whsec_").unwrap_err(),
            WebhookError::MalformedSecret
        );
    }

    #[test]
    fn an_empty_secret_set_signs_nothing_and_verifies_nothing() {
        // The fail-closed edge: a misconfigured endpoint with no secret must not produce
        // a header a permissive verifier might wave through.
        assert_eq!(sign_delivery(&[], ID, TS, PAYLOAD), "");
        assert_eq!(
            verify_delivery(&[], ID, &TS.to_string(), PAYLOAD, "", 300, TS),
            Err(WebhookError::NoMatchingSignature)
        );
    }

    fn ed25519(seed: u8) -> (SigningKey, Vec<u8>) {
        let key = SigningKey::ed25519_from_seed(None, &[seed; 32]).expect("ed25519 key");
        // The RAW public key, which is the form a per-endpoint published key takes.
        let crate::signing_key::PublicComponents::Okp { x: bytes } =
            key.public_components().expect("public components")
        else {
            panic!("an Ed25519 key has OKP public components")
        };
        (key, bytes)
    }

    #[test]
    fn the_asymmetric_scheme_signs_the_same_input_and_round_trips() {
        // The construction MUST match the symmetric scheme byte for byte: a verifier that
        // had to build a different input per scheme is a verifier that will get one wrong.
        let (key, public) = ed25519(0x41);
        let header = sign_delivery_ed25519(&[key], ID, TS, PAYLOAD).expect("signs");
        assert!(header.starts_with("v1a,"), "version prefixed: {header}");
        verify_delivery_ed25519(&[public], ID, &TS.to_string(), PAYLOAD, &header, 300, TS)
            .expect("a fresh delivery verifies");
    }

    #[test]
    fn an_asymmetric_signature_is_refused_under_a_different_public_key() {
        let (key, _) = ed25519(0x41);
        let (_, other_public) = ed25519(0x42);
        let header = sign_delivery_ed25519(&[key], ID, TS, PAYLOAD).expect("signs");
        assert_eq!(
            verify_delivery_ed25519(
                &[other_public],
                ID,
                &TS.to_string(),
                PAYLOAD,
                &header,
                300,
                TS
            ),
            Err(WebhookError::NoMatchingSignature)
        );
    }

    #[test]
    fn the_asymmetric_scheme_binds_id_timestamp_and_body_too() {
        // Same replay properties as v1, driven separately rather than assumed to follow
        // from sharing a helper.
        let (key, public) = ed25519(0x41);
        let header = sign_delivery_ed25519(&[key], ID, TS, PAYLOAD).expect("signs");
        for (label, id, ts, payload) in [
            ("a fresh timestamp", ID, TS + 10, PAYLOAD),
            (
                "a different body",
                ID,
                TS,
                br#"{"type":"user.deleted"}"#.as_slice(),
            ),
            ("a different id", "msg_other", TS, PAYLOAD),
        ] {
            assert_eq!(
                verify_delivery_ed25519(
                    std::slice::from_ref(&public),
                    id,
                    &ts.to_string(),
                    payload,
                    &header,
                    300,
                    ts
                ),
                Err(WebhookError::NoMatchingSignature),
                "{label} must not verify"
            );
        }
    }

    #[test]
    fn a_header_carrying_both_schemes_verifies_under_either_verifier() {
        // THE forward-compatibility payoff of skipping unknown prefixes, now that a
        // second scheme actually exists. A producer may emit both during a migration
        // between schemes, and neither verifier may choke on the other's entry.
        let symmetric = [secret(0x11)];
        let (key, public) = ed25519(0x41);
        let v1 = sign_delivery(&symmetric, ID, TS, PAYLOAD);
        let v1a = sign_delivery_ed25519(&[key], ID, TS, PAYLOAD).expect("signs");
        let both = format!("{v1} {v1a}");

        verify_delivery(&symmetric, ID, &TS.to_string(), PAYLOAD, &both, 300, TS)
            .expect("the symmetric verifier finds its entry");
        verify_delivery_ed25519(&[public], ID, &TS.to_string(), PAYLOAD, &both, 300, TS)
            .expect("the asymmetric verifier finds its entry");

        // And neither accepts the OTHER scheme's entry on its own, in BOTH directions,
        // which is what stops "skip what you do not know" from becoming "accept anything".
        assert_eq!(
            verify_delivery(&symmetric, ID, &TS.to_string(), PAYLOAD, &v1a, 300, TS),
            Err(WebhookError::NoMatchingSignature)
        );
        let (_, public2) = ed25519(0x41);
        assert_eq!(
            verify_delivery_ed25519(&[public2], ID, &TS.to_string(), PAYLOAD, &v1, 300, TS),
            Err(WebhookError::NoMatchingSignature)
        );
    }

    #[test]
    fn the_asymmetric_verifier_applies_the_same_timestamp_tolerance() {
        let (key, public) = ed25519(0x41);
        let header = sign_delivery_ed25519(&[key], ID, TS, PAYLOAD).expect("signs");
        let stamp = TS.to_string();
        assert_eq!(
            verify_delivery_ed25519(
                std::slice::from_ref(&public),
                ID,
                &stamp,
                PAYLOAD,
                &header,
                300,
                TS + 301
            ),
            Err(WebhookError::TimestampOutOfTolerance)
        );
        assert_eq!(
            verify_delivery_ed25519(&[public], ID, "nope", PAYLOAD, &header, 300, TS),
            Err(WebhookError::MalformedTimestamp)
        );
    }
}
