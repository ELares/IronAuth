// SPDX-License-Identifier: MIT OR Apache-2.0

//! The FIDO Metadata Service (MDS3) BLOB sync job (issue #66 PR B).
//!
//! A deployment running `direct` attestation must hold a fresh, cryptographically
//! verified snapshot of the FIDO metadata so a registration can chain a packed
//! attestation to the authenticator model's root. This module is that sync: it
//! FETCHES the MDS3 BLOB through the one SSRF-hardened [`ironauth_fetch::Fetcher`]
//! (declaring [`ironauth_fetch::FetchPurpose::Mds3Sync`]), VERIFIES it against the
//! compiled-in FIDO Alliance Root CA (never a value taken from the blob) with the
//! pure [`ironauth_webauthn::mds3`] verifier at the `env.clock()` instant, and
//! UPSERTS the verified entries into the per-scope `mds3_blob_cache`.
//!
//! Trust is pinned OUT OF BAND: [`pinned_fido_root_der`] returns the compiled-in
//! root, and a test injects a fake root through the `pinned_root_der` parameter so
//! the real root is exercised only in production. Revocation is deferred for v1;
//! the admin health surface reports the cached blob's `nextUpdate` staleness so an
//! operator sees a stale snapshot.
//!
//! The refresh CADENCE (a periodic worker, mirroring the back-channel logout
//! worker) is an operational wiring left to the binary; this module provides the
//! verify-and-cache step it calls.

use ironauth_env::Env;
use ironauth_fetch::{FetchPurpose, FetchRequest, Fetcher};
use ironauth_store::{ActorRef, CorrelationId, Scope, ServiceId, Store};
use ironauth_webauthn::mds3::{self, Mds3Error};

/// The pinned FIDO Alliance Root CA certificate, DER-encoded.
///
/// This MUST be populated with the real FIDO Alliance Root CA certificate bytes
/// before enabling `direct` attestation in production; it is the single trust
/// anchor for the MDS3 BLOB and is deliberately COMPILED IN and never fetched, so
/// a compromised metadata endpoint cannot introduce its own root. It ships empty
/// here (the certificate distribution is an operator/release step): with an empty
/// root, [`sync`] refuses to run (a fail-closed no-op) rather than trusting an
/// unpinned chain.
pub const FIDO_ALLIANCE_ROOT_CA_DER: &[u8] = &[];

/// The compiled-in pinned FIDO root for production use.
#[must_use]
pub fn pinned_fido_root_der() -> &'static [u8] {
    FIDO_ALLIANCE_ROOT_CA_DER
}

/// Why an MDS3 sync failed.
#[derive(Debug)]
pub enum SyncError {
    /// No pinned FIDO root is compiled in, so the chain cannot be anchored: the sync
    /// refuses to run rather than trust an unpinned blob.
    NoPinnedRoot,
    /// The BLOB fetch failed (blocked destination, timeout, or transport error).
    Fetch,
    /// The fetched body was not valid UTF-8 (a compact JWS is ASCII).
    NotText,
    /// The BLOB did not verify against the pinned root.
    Verify(Mds3Error),
    /// The verified snapshot could not be cached.
    Store,
}

/// Fetch, verify, and cache the MDS3 BLOB for one scope.
///
/// Returns the verified blob sequence number on success. The `base_url` is the
/// deployment's MDS3 endpoint (defaulting to [`mds3::MDS3_BASE_URL`], overridable
/// through `webauthn.mds3_base_url`); `pinned_root_der` is the trust anchor
/// (production passes [`pinned_fido_root_der`]; a test passes its fake root).
///
/// # Errors
///
/// A [`SyncError`] for a missing pinned root, a fetch failure, a verification
/// failure, or a store failure.
pub async fn sync(
    fetcher: &Fetcher,
    env: &Env,
    store: &Store,
    scope: Scope,
    base_url: &str,
    pinned_root_der: &[u8],
) -> Result<i64, SyncError> {
    if pinned_root_der.is_empty() {
        return Err(SyncError::NoPinnedRoot);
    }

    let response = fetcher
        .fetch(FetchRequest::get(FetchPurpose::Mds3Sync, base_url))
        .await
        .map_err(|_| SyncError::Fetch)?;
    if !response.status().is_success() {
        return Err(SyncError::Fetch);
    }
    let blob = core::str::from_utf8(response.body()).map_err(|_| SyncError::NotText)?;

    let now_micros = crate::util::epoch_micros(env.clock().now_utc());
    let now_unix = now_micros / 1_000_000;
    let payload = mds3::verify_blob(blob, pinned_root_der, now_unix).map_err(SyncError::Verify)?;

    let payload_json = serde_json::to_value(&payload).map_err(|_| SyncError::Store)?;
    let digest = digest_blob(response.body());
    let next_update_micros = payload.next_update.saturating_mul(1_000_000);
    let blob_no = payload.no;

    // A stable service actor for the MDS3 sync job's audit trail (a fixed 16-byte
    // seed, so the actor is identical across requests and nodes without storing one).
    let actor = ActorRef::service(ServiceId::from_seed_bytes(*b"ironauth-mds3syn"));
    store
        .scoped(scope)
        .acting(actor, CorrelationId::generate(env))
        .mds3_blob_cache()
        .upsert(
            env,
            blob_no,
            next_update_micros,
            &payload_json,
            &digest,
            now_micros,
            now_micros,
        )
        .await
        .map_err(|_| SyncError::Store)?;
    Ok(blob_no)
}

/// The SHA-256 digest of the raw BLOB bytes, for byte-identical-refetch detection.
#[must_use]
pub fn digest_blob(raw: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(raw).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_sha256() {
        // A stable known-answer: SHA-256 of the empty input.
        let d = digest_blob(b"");
        assert_eq!(d.len(), 32);
        assert_eq!(d[0], 0xe3);
        assert_eq!(d[31], 0x55);
    }

    #[test]
    fn an_empty_pinned_root_is_a_fail_closed_no_op_marker() {
        // The compiled-in default is empty until the real FIDO root is shipped; the
        // sync refuses to anchor an unpinned chain.
        assert!(pinned_fido_root_der().is_empty());
    }
}
