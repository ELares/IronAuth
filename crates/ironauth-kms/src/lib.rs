// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exploratory bring-your-own-key (BYOK) KMS seam for IronAuth (issue #49).
//!
//! # What this is, and what it is not
//!
//! This crate is the PLUGGABLE key-management-service driver interface the BYOK
//! rung of the isolation ladder needs, plus two drivers behind it. It EXTENDS the
//! per-tenant envelope substrate (issue #48, `ironauth_jose::envelope`): that
//! substrate seals payloads under a per-tenant data-encryption key (DEK), wrapped
//! under a per-tenant key-encryption key (KEK), wrapped under a root. In the
//! platform-key deployment the root is the platform master key held in process.
//! BYOK swaps WHO holds that root: a CUSTOMER-MANAGED root key (in the customer's
//! KMS/HSM, or a customer-supplied key) wraps the tenant KEK, so the customer
//! controls the root of their tenant's encryption and can revoke it.
//!
//! Two consequences follow, and they are the whole point of the rung:
//!
//! - **No platform-key fallback.** For a BYOK tenant the KEK is recoverable ONLY
//!   through the customer root. If the root is unreachable or access is revoked,
//!   the tenant's crypto operations FAIL CLOSED with a structured [`KmsError`];
//!   nothing silently re-wraps under a platform key.
//! - **Revocation is crypto-shredding.** Because the KEK is wrapped only under the
//!   customer root, revoking or destroying that root makes every one of the
//!   tenant's [`ironauth_jose`] ciphertexts permanently unreadable. That is
//!   exactly the erasure primitive the offboarding pipeline (issue #46) reaches at
//!   its terminal stage (NIST SP 800-57 Part 1 key destruction; GDPR Article 17).
//!
//! # Maturity: default-off and honest about the gate
//!
//! BYOK is exploratory and ships DEFAULT-OFF (`[byok] enabled = false`). This
//! crate deliberately builds the MECHANISM and the SEAM, not four live cloud
//! integrations:
//!
//! - [`LocalKmsProvider`] is a fully working driver: it holds a customer root key
//!   in process and really wraps and unwraps a [`Kek`], so the entire BYOK
//!   property (root wraps KEK, revoke root => undecryptable, pluggable behind the
//!   trait) is provable deterministically with no external service.
//! - [`HttpKmsProvider`] is the EXTERNAL seam: it proves that an external KMS call
//!   is outbound and rides the single SSRF-hardened dispatcher ([`ironauth_fetch`]),
//!   so a loopback or internal KMS endpoint is refused and the driver fails closed.
//!   The live per-cloud request marshaling (AWS KMS, GCP KMS, Azure Key Vault,
//!   `HashiCorp` Vault) is OWNER/INFRA-GATED: it needs a live external endpoint and
//!   credentials that do not exist in this build, so after the outbound reachability
//!   call the driver returns [`KmsError::NotProvisioned`] rather than pretend to
//!   marshal a request it cannot complete. This is the honest boundary between the
//!   shipped seam and the gated live driver.
//!
//! # Key material never leaks
//!
//! A driver holds a root or a reference to one; it never surfaces raw key bytes.
//! [`KmsProviderKind`] and the opaque key reference an [`HttpKmsProvider`] carries
//! are non-secret handles. [`LocalKmsProvider`] wraps its root in
//! [`ironauth_jose::MasterKey`], whose `Debug` is already redacted and whose bytes
//! zero on drop. [`KmsError`] carries no key material, ciphertext, or endpoint, so
//! it is safe to log.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ironauth_env::Entropy;
use ironauth_fetch::{FetchPurpose, FetchRequest, Fetcher};
use ironauth_jose::{Aad, EnvelopeError, Kek, MasterKey, Sealed};

/// A boxed, `Send` future returned by an object-safe async driver method.
///
/// The trait is object-safe (`dyn KmsProvider`) so a deployment can select a
/// driver at runtime; native `async fn` in a trait is not yet object-safe, so the
/// methods return this boxed future instead. No extra dependency is pulled in for
/// it.
pub type KmsFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, KmsError>> + Send + 'a>>;

/// Which KMS driver backs a BYOK binding. A closed, non-secret set: it names the
/// driver, never key material, and is the value persisted as the binding's
/// provider label and matched by the store's provider CHECK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KmsProviderKind {
    /// The in-process local/test driver ([`LocalKmsProvider`]): a customer root
    /// key held by the platform (a customer-supplied key), no external service.
    Local,
    /// AWS Key Management Service (external, owner/infra-gated).
    Aws,
    /// Google Cloud KMS (external, owner/infra-gated).
    Gcp,
    /// Azure Key Vault (external, owner/infra-gated).
    Azure,
    /// `HashiCorp` Vault transit (external, owner/infra-gated).
    Vault,
}

impl KmsProviderKind {
    /// The stable wire label for this driver (the value persisted as a BYOK
    /// binding's `provider` and matched by the store CHECK).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            KmsProviderKind::Local => "local",
            KmsProviderKind::Aws => "aws",
            KmsProviderKind::Gcp => "gcp",
            KmsProviderKind::Azure => "azure",
            KmsProviderKind::Vault => "vault",
        }
    }

    /// Whether this driver reaches an external service (so its live use is
    /// owner/infra-gated and its calls are outbound through [`ironauth_fetch`]).
    #[must_use]
    pub const fn is_external(self) -> bool {
        !matches!(self, KmsProviderKind::Local)
    }
}

impl core::fmt::Display for KmsProviderKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a BYOK key operation failed. Every variant is FAIL-CLOSED: a BYOK tenant
/// whose root is unreachable, revoked, or whose live driver is not provisioned
/// gets a structured error, never a silent platform-key fallback. The variants
/// carry NO key material, ciphertext, or endpoint, so a `KmsError` is safe to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KmsError {
    /// The customer KMS endpoint could not be reached, or the outbound request
    /// was refused by the SSRF policy (a loopback or otherwise internal endpoint).
    /// Uniform by design, mirroring [`ironauth_fetch::FetchError::Blocked`]: it
    /// leaks no oracle for internal topology. Fail closed.
    Unreachable,
    /// The customer revoked access to the root key, or removed it. The tenant's
    /// KEK can no longer be unwrapped and nothing falls back to a platform key:
    /// this IS the crypto-shred (revocation as erasure).
    AccessRevoked,
    /// The wrapped KEK did not authenticate under the root key: a wrong root, a
    /// tampered or shredded blob, or a mismatched associated-data context. Never
    /// distinguishes which, so it is not an oracle.
    Unwrap,
    /// The external driver reached its seam but the live per-cloud request
    /// marshaling is owner/infra-gated and not provisioned in this build. Fail
    /// closed rather than fabricate a wrap the driver cannot complete.
    NotProvisioned,
}

impl core::fmt::Display for KmsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KmsError::Unreachable => f.write_str("customer KMS endpoint unreachable or refused"),
            KmsError::AccessRevoked => f.write_str("customer KMS access revoked"),
            KmsError::Unwrap => f.write_str("wrapped key failed authentication under the root key"),
            KmsError::NotProvisioned => {
                f.write_str("external KMS driver is not provisioned in this build")
            }
        }
    }
}

impl std::error::Error for KmsError {}

impl From<EnvelopeError> for KmsError {
    fn from(_: EnvelopeError) -> Self {
        // An envelope decrypt/format failure at the root layer is a wrap failure.
        // The distinction (wrong key vs malformed) never crosses this boundary, so
        // the driver stays free of a decryption oracle.
        KmsError::Unwrap
    }
}

/// The pluggable BYOK driver interface: wrap and unwrap a per-tenant [`Kek`] under
/// a customer-managed root key. Object-safe, so a deployment selects a driver at
/// runtime; every method fails closed.
///
/// A driver NEVER holds or returns raw key bytes: it wraps a [`Kek`] (whose bytes
/// stay inside [`ironauth_jose`]) into a [`Sealed`] blob and unwraps a [`Sealed`]
/// blob back into a [`Kek`]. The associated-data [`Aad`] binds the wrap to its
/// scope and version, so a wrapped KEK cannot be lifted to another tenant,
/// environment, or key generation.
pub trait KmsProvider: Send + Sync {
    /// Which driver this is.
    fn kind(&self) -> KmsProviderKind;

    /// Wrap `kek` under the customer root, binding `aad`. The result is stored as
    /// the tenant's wrapped KEK.
    ///
    /// # Errors
    ///
    /// [`KmsError::AccessRevoked`] if the root is revoked; [`KmsError::Unreachable`]
    /// if an external endpoint is unreachable or refused; [`KmsError::NotProvisioned`]
    /// if an external driver's live marshaling is owner/infra-gated.
    fn wrap_kek<'a>(
        &'a self,
        entropy: &'a dyn Entropy,
        aad: &'a Aad,
        kek: &'a Kek,
    ) -> KmsFuture<'a, Sealed>;

    /// Unwrap the tenant KEK from `wrapped` under the customer root, binding `aad`.
    ///
    /// # Errors
    ///
    /// [`KmsError::AccessRevoked`] if the root is revoked (the crypto-shred);
    /// [`KmsError::Unreachable`] if an external endpoint is unreachable or refused;
    /// [`KmsError::Unwrap`] if the blob does not authenticate;
    /// [`KmsError::NotProvisioned`] if an external driver's live marshaling is gated.
    fn unwrap_kek<'a>(&'a self, aad: &'a Aad, wrapped: &'a Sealed) -> KmsFuture<'a, Kek>;
}

/// The in-process local/test BYOK driver: a customer root key held by the
/// platform (a customer-SUPPLIED key, the simplest BYOK form), backed by an
/// [`ironauth_jose::MasterKey`]. It really wraps and unwraps a [`Kek`], so the
/// full BYOK property is provable with no external service.
///
/// [`LocalKmsProvider::revoke`] models the customer withdrawing the root: after
/// it, every wrap and unwrap fails closed with [`KmsError::AccessRevoked`], so a
/// KEK wrapped before revocation can never be unwrapped again. That is the
/// crypto-shred (revocation as erasure), demonstrated deterministically.
#[derive(Debug)]
pub struct LocalKmsProvider {
    root: MasterKey,
    revoked: AtomicBool,
}

impl LocalKmsProvider {
    /// A driver over an existing customer root key.
    #[must_use]
    pub fn new(root: MasterKey) -> Self {
        Self {
            root,
            revoked: AtomicBool::new(false),
        }
    }

    /// A driver over a fresh random root drawn from the entropy seam (test and
    /// bootstrap use). A production customer root is supplied out of band.
    #[must_use]
    pub fn generate(id: impl Into<String>, entropy: &dyn Entropy) -> Self {
        Self::new(MasterKey::generate(id, entropy))
    }

    /// Revoke access to the root: model the customer withdrawing or destroying it.
    /// Every subsequent wrap and unwrap fails closed, so the tenant's data becomes
    /// permanently undecryptable (the crypto-shred).
    pub fn revoke(&self) {
        self.revoked.store(true, Ordering::SeqCst);
    }

    /// Whether the root has been revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::SeqCst)
    }
}

impl KmsProvider for LocalKmsProvider {
    fn kind(&self) -> KmsProviderKind {
        KmsProviderKind::Local
    }

    fn wrap_kek<'a>(
        &'a self,
        entropy: &'a dyn Entropy,
        aad: &'a Aad,
        kek: &'a Kek,
    ) -> KmsFuture<'a, Sealed> {
        Box::pin(async move {
            if self.is_revoked() {
                return Err(KmsError::AccessRevoked);
            }
            Ok(self.root.wrap_kek(entropy, aad, kek))
        })
    }

    fn unwrap_kek<'a>(&'a self, aad: &'a Aad, wrapped: &'a Sealed) -> KmsFuture<'a, Kek> {
        Box::pin(async move {
            if self.is_revoked() {
                return Err(KmsError::AccessRevoked);
            }
            Ok(self.root.unwrap_kek(aad, wrapped)?)
        })
    }
}

/// The external customer-KMS/HSM seam: the driver that reaches AWS KMS, GCP KMS,
/// Azure Key Vault, or `HashiCorp` Vault over the network.
///
/// Its ONE guarantee that this build proves is the security-critical one: the
/// call is outbound and rides the single SSRF-hardened dispatcher
/// ([`ironauth_fetch`]), so a KMS `endpoint` that resolves to a loopback or
/// otherwise internal address is refused and the driver fails closed with
/// [`KmsError::Unreachable`], exactly like any other blocked destination. There is
/// no policy exception for a KMS URL.
///
/// The live per-cloud request marshaling is OWNER/INFRA-GATED: it needs a real
/// external endpoint and credentials that do not exist in this build. So after the
/// outbound reachability call the driver returns [`KmsError::NotProvisioned`]
/// rather than fabricate a wrap it cannot complete. `key_ref` is the opaque
/// external key handle (an ARN, a resource name, a key URI); it is a non-secret
/// reference, never key material.
pub struct HttpKmsProvider {
    kind: KmsProviderKind,
    endpoint: String,
    key_ref: String,
    fetcher: Arc<Fetcher>,
}

impl HttpKmsProvider {
    /// A driver for `kind` reaching `endpoint` (an https KMS URL), operating on
    /// the key identified by the opaque `key_ref`, calling out through the shared
    /// SSRF-hardened `fetcher`.
    #[must_use]
    pub fn new(
        kind: KmsProviderKind,
        endpoint: impl Into<String>,
        key_ref: impl Into<String>,
        fetcher: Arc<Fetcher>,
    ) -> Self {
        Self {
            kind,
            endpoint: endpoint.into(),
            key_ref: key_ref.into(),
            fetcher,
        }
    }

    /// The opaque external key reference (a non-secret handle).
    #[must_use]
    pub fn key_ref(&self) -> &str {
        &self.key_ref
    }

    /// Route a reachability call to the configured KMS endpoint through the
    /// SSRF-hardened dispatcher. Any refusal or transport failure collapses to
    /// [`KmsError::Unreachable`] (fail closed, no oracle). On success the endpoint
    /// is a reachable public destination and the live driver would marshal its
    /// request here; that marshaling is owner/infra-gated.
    async fn reach_endpoint(&self) -> Result<(), KmsError> {
        let request = FetchRequest::get(FetchPurpose::KmsRequest, self.endpoint.clone());
        match self.fetcher.fetch(request).await {
            Ok(_) => Ok(()),
            Err(_) => Err(KmsError::Unreachable),
        }
    }
}

impl core::fmt::Debug for HttpKmsProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The endpoint and key reference are non-secret, but keep Debug terse and
        // free of the (attacker-influenceable) endpoint string.
        f.debug_struct("HttpKmsProvider")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl KmsProvider for HttpKmsProvider {
    fn kind(&self) -> KmsProviderKind {
        self.kind
    }

    fn wrap_kek<'a>(
        &'a self,
        _entropy: &'a dyn Entropy,
        _aad: &'a Aad,
        _kek: &'a Kek,
    ) -> KmsFuture<'a, Sealed> {
        Box::pin(async move {
            self.reach_endpoint().await?;
            Err(KmsError::NotProvisioned)
        })
    }

    fn unwrap_kek<'a>(&'a self, _aad: &'a Aad, _wrapped: &'a Sealed) -> KmsFuture<'a, Kek> {
        Box::pin(async move {
            self.reach_endpoint().await?;
            Err(KmsError::NotProvisioned)
        })
    }
}

#[cfg(test)]
// The KEK/DEK envelope vocabulary is deliberately close (wrapped_kek/wrapped_dek,
// kek/dek): the paired names mirror the two envelope tiers and read clearer
// together than artificially spread apart.
#[allow(clippy::similar_names)]
mod tests {
    use super::*;
    use ironauth_env::FixedEntropy;
    use ironauth_jose::Dek;

    fn kek_aad() -> Aad {
        Aad::builder()
            .text("kek-wrap")
            .text("ten_a")
            .text("env_a")
            .version(1)
            .build()
    }

    fn dek_aad() -> Aad {
        Aad::builder()
            .text("dek-wrap")
            .text("ten_a")
            .version(1)
            .build()
    }

    fn payload_aad() -> Aad {
        Aad::builder()
            .text("email")
            .text("ten_a")
            .version(1)
            .build()
    }

    #[tokio::test]
    async fn local_root_wraps_and_unwraps_the_tenant_kek() {
        let entropy = FixedEntropy::new(1);
        let provider = LocalKmsProvider::generate("byok-root-1", &entropy);
        let kek = Kek::generate(&entropy);

        // A DEK wrapped under the KEK, and a payload sealed under the DEK: the full
        // envelope the tenant's data really uses.
        let dek = Dek::generate(&entropy);
        let wrapped_dek = kek.wrap_dek(&entropy, &dek_aad(), &dek);
        let sealed = dek.seal(&entropy, &payload_aad(), b"ada@example.test");

        // BYOK: the customer root wraps the KEK, and unwrapping it recovers a KEK
        // that opens the whole chain back to the plaintext.
        let wrapped_kek = provider
            .wrap_kek(&entropy, &kek_aad(), &kek)
            .await
            .expect("wrap kek");
        let recovered_kek = provider
            .unwrap_kek(&kek_aad(), &wrapped_kek)
            .await
            .expect("unwrap kek");
        let recovered_dek = recovered_kek
            .unwrap_dek(&dek_aad(), &wrapped_dek)
            .expect("unwrap dek");
        assert_eq!(
            recovered_dek.open(&payload_aad(), &sealed).expect("open"),
            b"ada@example.test"
        );
    }

    #[tokio::test]
    async fn revoking_the_root_fails_closed_and_crypto_shreds() {
        let entropy = FixedEntropy::new(2);
        let provider = LocalKmsProvider::generate("byok-root-1", &entropy);
        let kek = Kek::generate(&entropy);
        let wrapped_kek = provider
            .wrap_kek(&entropy, &kek_aad(), &kek)
            .await
            .expect("wrap kek");

        // The customer withdraws the root.
        assert!(!provider.is_revoked());
        provider.revoke();
        assert!(provider.is_revoked());

        // With the root gone, the KEK wrapped before revocation can never be
        // unwrapped again: the tenant's data is permanently undecryptable. Nothing
        // falls back to a platform key; the failure is the structured revoke error.
        assert_eq!(
            provider.unwrap_kek(&kek_aad(), &wrapped_kek).await.err(),
            Some(KmsError::AccessRevoked)
        );
        assert_eq!(
            provider.wrap_kek(&entropy, &kek_aad(), &kek).await.err(),
            Some(KmsError::AccessRevoked)
        );
    }

    #[tokio::test]
    async fn a_different_root_or_context_cannot_unwrap() {
        let entropy = FixedEntropy::new(3);
        let root_a = LocalKmsProvider::generate("byok-root-a", &entropy);
        let root_b = LocalKmsProvider::generate("byok-root-b", &entropy);
        let kek = Kek::generate(&entropy);
        let wrapped = root_a
            .wrap_kek(&entropy, &kek_aad(), &kek)
            .await
            .expect("wrap");

        // Another customer's root cannot unwrap this KEK (no cross-tenant lift).
        // Kek carries no PartialEq (it never leaks its bytes), so assert on the err.
        assert_eq!(
            root_b.unwrap_kek(&kek_aad(), &wrapped).await.err(),
            Some(KmsError::Unwrap)
        );
        // A different associated-data context fails too.
        let other = Aad::builder()
            .text("kek-wrap")
            .text("ten_b")
            .version(1)
            .build();
        assert_eq!(
            root_a.unwrap_kek(&other, &wrapped).await.err(),
            Some(KmsError::Unwrap)
        );
    }

    #[tokio::test]
    async fn pluggable_behind_a_trait_object() {
        // A deployment holds a driver as a trait object and dispatches through it,
        // proving the seam is pluggable (a new driver is a new implementation).
        let entropy = FixedEntropy::new(4);
        let provider: Arc<dyn KmsProvider> =
            Arc::new(LocalKmsProvider::generate("byok-root-1", &entropy));
        assert_eq!(provider.kind(), KmsProviderKind::Local);
        let kek = Kek::generate(&entropy);
        let wrapped = provider
            .wrap_kek(&entropy, &kek_aad(), &kek)
            .await
            .expect("wrap");
        assert!(provider.unwrap_kek(&kek_aad(), &wrapped).await.is_ok());
    }

    #[test]
    fn provider_kind_labels_are_stable_and_external_flagged() {
        assert_eq!(KmsProviderKind::Local.as_str(), "local");
        assert_eq!(KmsProviderKind::Aws.as_str(), "aws");
        assert_eq!(KmsProviderKind::Gcp.as_str(), "gcp");
        assert_eq!(KmsProviderKind::Azure.as_str(), "azure");
        assert_eq!(KmsProviderKind::Vault.as_str(), "vault");
        assert!(!KmsProviderKind::Local.is_external());
        for external in [
            KmsProviderKind::Aws,
            KmsProviderKind::Gcp,
            KmsProviderKind::Azure,
            KmsProviderKind::Vault,
        ] {
            assert!(external.is_external());
        }
    }

    #[test]
    fn debug_never_reveals_key_material() {
        let provider = LocalKmsProvider::generate("byok-root-1", &FixedEntropy::new(5));
        let rendered = format!("{provider:?}");
        assert!(rendered.contains("redacted"), "got: {rendered}");
    }

    #[test]
    fn kms_error_is_key_free_and_displays() {
        for err in [
            KmsError::Unreachable,
            KmsError::AccessRevoked,
            KmsError::Unwrap,
            KmsError::NotProvisioned,
        ] {
            let rendered = format!("{err}");
            assert!(!rendered.is_empty());
            assert!(!rendered.contains('['), "no raw bytes: {rendered}");
        }
    }
}
