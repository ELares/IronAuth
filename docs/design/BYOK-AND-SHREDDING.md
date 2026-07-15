# Advanced isolation, BYOK, and crypto-shredding offboarding (issue #49)

Status: EXPLORATORY, default-off. This note is the graduation assessment for the
rungs issue #49 prototypes on the seams issue #48 (per-tenant envelope encryption)
and issue #46 (tenant lifecycle offboarding) deliberately left. It is honest about
what ships as a working mechanism, what is a seam, and what is owner/infra-gated.

The isolation ladder has three rungs in scope. Pooled shared-schema rows (with
forced row-level security, see `TENANCY.md`) remain the default and are unchanged.

## Rung 1: BYOK (bring your own key)

**What ships (a working mechanism + a pluggable seam).**

- `ironauth-kms` is a pluggable KMS driver interface (`KmsProvider`, an object-safe
  async trait) that wraps and unwraps a per-tenant key-encryption key (KEK) under a
  customer-managed root key. It extends the #48 envelope: the platform master key is
  replaced, for a BYOK tenant, by a customer root.
- `LocalKmsProvider` is a fully working driver over a customer-SUPPLIED in-process
  root (the simplest BYOK form). It really wraps and unwraps a KEK, and `revoke()`
  models the customer withdrawing the root, after which every operation fails closed.
  This proves the whole property deterministically with no external service:
  - the customer root wraps the KEK (no platform-key fallback: every failure is a
    structured `KmsError`, nothing re-wraps under a platform key);
  - revoking or destroying the root makes the tenant's data permanently
    undecryptable (revocation as crypto-shred);
  - the seam is pluggable (a new driver is a new implementation; a deployment holds
    one as `Arc<dyn KmsProvider>`).
- `HttpKmsProvider` is the external-KMS seam. Its one security-critical guarantee is
  proven: an external KMS call is outbound and rides the single SSRF-hardened
  dispatcher (`ironauth-fetch`, the new `FetchPurpose::KmsRequest`), so a loopback or
  otherwise internal KMS endpoint is refused exactly like any other blocked
  destination and the driver fails closed. There is no policy exception for a KMS URL.
- Persistence: migration 0031 adds `tenant_byok_bindings`, a tenant-scoped table
  (forced row-level security, column-scoped grants) recording per scope the driver,
  an OPAQUE external key reference (an ARN, a resource name, a key URI), and the
  binding's lifecycle status. It never stores a customer root key or key material of
  any kind: only a non-secret reference. `ActingEnvelopeRepo::enroll_byok` records a
  binding (audited `envelope.byok.enroll`); `EnvelopeRepo::byok_binding` reads it.
- Config: `[byok]` is EXPERIMENTAL and DEFAULT-OFF (`enabled = false`), with a
  `provider` selector and an external `endpoint`.

**What is owner/infra-gated (NOT shipped, and honestly so).**

- The live per-cloud request marshaling for AWS KMS, GCP KMS, Azure Key Vault, and
  HashiCorp Vault. Each needs a live external endpoint and credentials that do not
  exist in this build, so `HttpKmsProvider`, after the outbound reachability call,
  returns `KmsError::NotProvisioned` rather than fabricate a wrap it cannot complete.
- Routing the store's per-read KEK unwrap through a live external KMS (with the
  caching rules that respect a revocation window). Today the store persists the
  binding and severs it at offboarding; wiring the read path to call the external KMS
  on every unwrap, with a revocation-window cache, is the next graduation step.
- The LocalStack-class integration suite across all four drivers, and the chaos test
  (KMS unreachable during live traffic degrades only the affected tenant).

**Graduation criteria (to leave exploratory).** A live driver for at least one cloud
KMS wired through the read path with the revocation-window cache; the four-driver
LocalStack integration suite green including the revocation fail-closed path; the
chaos test; an operator runbook for key rotation and revocation.

## Rung 2: Crypto-shredding offboarding

**What ships (wired into #46's terminal stage, provable).**

- The terminal hard-delete (purge) stage crypto-shreds the platform KEK (this landed
  with #46/#48) AND now severs any BYOK binding in the SAME audited transaction: the
  binding flips to `destroyed`, its external key reference is cleared, and the sever
  instant is stamped. For a BYOK tenant the customer root is what wrapped the KEK, so
  destroying the platform KEK and severing the binding leaves no recoverable key by
  either path.
- Proven at the persistence layer (`tests/byok_offboarding.rs`): a purged tenant's
  sealed PII is permanently undecryptable (a distinct `Encryption` failure, never a
  plaintext or a bare not-found), its KEK and binding rows are retained as erasure
  evidence, and a sibling tenant's PII and binding are entirely untouched.
- The audited `tenant.purge` action plus the retained, `destroyed`-stamped KEK and
  binding rows are the erasure evidence trail.

**What is deferred (documented, not built).**

- Asynchronous physical byte deletion jobs after the shred, and byte-level storage
  inspection that the deletion completed. Crypto-shredding already makes the data
  unrecoverable at the terminal stage; the async physical purge is a follow-on.
- A formal, separately queryable erasure ATTESTATION record (beyond the audited purge
  and the evidence rows), and pseudonymized audit (subjects referenced by stable
  pseudonyms with PII in a separately erasable store, so per-user erasure destroys the
  PII while the audit skeleton survives).

**Graduation criteria.** The async physical-deletion worker with a storage-level
completion assertion; the pseudonymized-audit split with a per-user erasure path; a
formal erasure-attestation artifact.

## Rung 3: Dedicated per-tenant database

Not built in this slice (out of scope per the issue's staging). The M1 storage seam
(`Store`) is the intended integration point: an opt-in per-tenant connection string
routed through it, with the IDOR and lifecycle harnesses run identically against a
dedicated-database tenant. Schema-per-tenant remains a documented seam only.
Dedicated per-tenant IronCache/IronBus instances stay a deferred natural extension;
first-party infrastructure stays optional per the covenants.
