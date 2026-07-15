// SPDX-License-Identifier: MIT OR Apache-2.0

//! The external customer-KMS seam over the real SSRF-hardened fetcher (issue #49).
//!
//! Proves the one security-critical guarantee this build makes about BYOK's
//! external path: a customer KMS endpoint is outbound and rides the single
//! SSRF-hardened dispatcher, so a KMS URL that points at a loopback or otherwise
//! internal address is refused and the driver fails closed. There is no policy
//! exception for a KMS URL. The live per-cloud marshaling is owner/infra-gated and
//! is out of scope here (see the crate docs).

use std::sync::Arc;

use ironauth_env::FixedEntropy;
use ironauth_fetch::{FetchLimits, Fetcher};
use ironauth_jose::{Aad, Kek, Sealed};
use ironauth_kms::{HttpKmsProvider, KmsError, KmsProvider, KmsProviderKind};

fn fetcher() -> Arc<Fetcher> {
    Arc::new(Fetcher::new(FetchLimits::default()).expect("build the SSRF-hardened fetcher"))
}

fn kek_aad() -> Aad {
    Aad::builder()
        .text("kek-wrap")
        .text("ten_a")
        .text("env_a")
        .version(1)
        .build()
}

/// A loopback KMS endpoint is refused before any request is marshaled: the driver
/// fails closed with the uniform unreachable error, exactly as the SSRF policy
/// blocks any loopback destination.
#[tokio::test]
async fn loopback_kms_endpoint_is_refused_fail_closed() {
    let provider = HttpKmsProvider::new(
        KmsProviderKind::Aws,
        "https://127.0.0.1/kms/unwrap",
        "arn:aws:kms:example:key/opaque-handle",
        fetcher(),
    );
    let entropy = FixedEntropy::new(1);
    let kek = Kek::generate(&entropy);

    // Neither wrap nor unwrap reaches the (internal) endpoint: both fail closed.
    assert_eq!(
        provider.wrap_kek(&entropy, &kek_aad(), &kek).await.err(),
        Some(KmsError::Unreachable)
    );
    let wrapped = Sealed::from_bytes(vec![0_u8; 64]).expect("min-length blob");
    assert_eq!(
        provider.unwrap_kek(&kek_aad(), &wrapped).await.err(),
        Some(KmsError::Unreachable)
    );
}

/// A private (RFC 1918) KMS endpoint is refused the same way: the driver never
/// reaches an internal service, and the error carries no oracle for which range
/// it was.
#[tokio::test]
async fn private_range_kms_endpoint_is_refused_fail_closed() {
    let provider = HttpKmsProvider::new(
        KmsProviderKind::Vault,
        "https://10.0.0.1/v1/transit/decrypt/tenant",
        "transit/tenant-root",
        fetcher(),
    );
    let entropy = FixedEntropy::new(2);
    let kek = Kek::generate(&entropy);
    assert_eq!(
        provider.wrap_kek(&entropy, &kek_aad(), &kek).await.err(),
        Some(KmsError::Unreachable)
    );
}

/// The plaintext-http default is refused too (KMS traffic must be TLS): the
/// fetcher rejects a plaintext scheme, and the driver fails closed.
#[tokio::test]
async fn plaintext_http_kms_endpoint_is_refused() {
    let provider = HttpKmsProvider::new(
        KmsProviderKind::Azure,
        "http://kms.example.test/keys/tenant",
        "https://vault.example.test/keys/tenant",
        fetcher(),
    );
    let entropy = FixedEntropy::new(3);
    let kek = Kek::generate(&entropy);
    assert_eq!(
        provider.wrap_kek(&entropy, &kek_aad(), &kek).await.err(),
        Some(KmsError::Unreachable)
    );
}
