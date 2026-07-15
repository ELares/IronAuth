# ironauth-kms changelog

All notable changes to the `ironauth-kms` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- Initial exploratory BYOK (bring-your-own-key) KMS seam (issue #49), default-off
  and experimental. Extends the per-tenant envelope substrate (issue #48): a
  customer-managed root key wraps the per-tenant key-encryption key (KEK), so the
  customer controls the root of their tenant's encryption and revoking it
  crypto-shreds the tenant.
  - **Pluggable driver interface.** `KmsProvider` is an object-safe async trait
    that wraps and unwraps a `Kek` under a customer root, so a deployment selects
    a driver at runtime and a new driver is a new implementation.
  - **Working local/test driver.** `LocalKmsProvider` holds a customer-supplied
    root (an `ironauth_jose::MasterKey`) in process and really wraps and unwraps
    the KEK, so the whole BYOK property is provable deterministically with no
    external service. `revoke()` models the customer withdrawing the root: every
    subsequent operation fails closed with `KmsError::AccessRevoked`, so a KEK
    wrapped before revocation is unrecoverable (revocation as crypto-shred).
  - **No platform-key fallback.** Every failure path (`KmsError::Unreachable`,
    `AccessRevoked`, `Unwrap`, `NotProvisioned`) is fail-closed and structured;
    nothing silently re-wraps under a platform key.
  - **SSRF-hardened external seam.** `HttpKmsProvider` reaches an external KMS
    only through `ironauth-fetch` (the new `FetchPurpose::KmsRequest`), so a
    loopback or otherwise internal KMS endpoint is refused exactly like any other
    blocked destination and the driver fails closed. The live per-cloud request
    marshaling (AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault) is
    owner/infra-gated: after the outbound reachability call the driver returns
    `KmsError::NotProvisioned` rather than fabricate a wrap it cannot complete.
  - **Key material never leaks.** A driver holds a root or a non-secret reference;
    `KmsError` and every `Debug` are free of key bytes, ciphertext, and the
    endpoint string.
