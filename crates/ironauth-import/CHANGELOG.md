# ironauth-import changelog

All notable changes to the `ironauth-import` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- Second-factor restore on import (issue #58/#69, review): `ImportRecord` gains an
  optional `totp` list (`ImportTotp`: the Base32 seed, parameters, friendly name,
  status, and single-use step) and a `recovery_codes` list (`ImportRecoveryCode`: the
  one-way hash and consumed state), which `to_record_line` / `parse_record_line`
  round-trip. The engine decodes and bounds-checks each factor (Base32 seed, digits
  6..=8, period 15..=60, known algorithm/status, 1..=200 char name) and restores it
  through the store's `totp_credentials` / `recovery_codes` re-seal path, so a
  re-imported TOTP factor verifies against the original authenticator and a re-imported
  recovery code redeems. Adds an internal dependency on `ironauth-jose` for the Base32
  decode; no new external crate.
- Migration state-machine wrap (issue #59, exploratory): `import_into_run` drives
  `import_stream` and ingests every per-record outcome (`Created` / `Skipped` /
  `Failed`) into an `ironauth-store` migration run's accounting ledger, so a bulk import
  is wrapped in the invariant-checked state machine. The run's COUNT invariant then
  measures the ingested accounting against the caller's declared `source_total`, so an
  import that does not reconcile with its source cannot be declared complete, and the
  per-record failures stay visible in the operator view. Purely additive (a new `run`
  module); no change to the streaming engine or the record format.
- Credential-registry round-trip (issue #58, review): `ImportRecord` gains an optional
  `credentials` list (a new `ImportCredential`: factor kind, friendly name, optional
  last-used instant), so the full identity export carries every passkey / TOTP /
  recovery-code enrollment and the engine restores each one under the imported user
  (validated to the closed credential-type set and the 1-to-200-character name bound,
  per-record failure isolation preserved; a re-imported duplicate skips without
  re-enrolling). The record shape is additive, so the M7 credential-secret material
  rides the same list.
- Export side of the record format (issue #58): `ImportRecord` now also derives
  `Serialize`, and `to_record_line` writes exactly what `parse_record_line` reads, so
  the full identity export (in `ironauth-admin`) produces the same line-delimited
  format the import consumes and a round-trip is lossless by construction. The record
  gains optional `traits` and `traits_schema_version` fields; the engine restores
  traits VERBATIM through the extended `admin_create`, so an export re-import carries
  a user's identity traits, not only the credential.

- New crate: streaming bulk user import with foreign password-hash support (issue
  #55). IronAuth's migration on-ramp, published as its own semver-versioned crate
  (the passwap pattern): the hash-scheme layer earns outside review of exactly the
  code that most needs it, and the server consumes it as a normal dependency.
  - **`scheme`: the algorithm-tagged foreign-hash layer.** Parse, tag, bounds-check,
    and verify a foreign hash by dispatching on its scheme: bcrypt (all four
    `$2a$`/`$2b$`/`$2x$`/`$2y$` variants), scrypt (RFC 7914 PHC), PBKDF2 (RFC 8018
    PHC over HMAC-SHA256/512), the Argon2 family (RFC 9106 PHC), and Firebase's
    modified scrypt (scrypt key derivation + AES-256-CTR over the account signer
    key) in a canonical `$fbscrypt$` serialization. Known-answer tests per scheme,
    including the published Firebase cross-implementation vector.
  - **Denial-of-service bounds.** Documented maximum cost parameters per scheme
    (bcrypt cost, scrypt log2(N)/r/p, PBKDF2 iterations, Argon2 memory/passes/
    parallelism, Firebase mem_cost/rounds). An out-of-bounds hash is rejected AT
    IMPORT with a per-parameter error, never stored (the Kratos lesson: an
    attacker-supplied cost cannot turn a later login verification into a DoS).
  - **`engine`: the streaming import engine.** Consumes an iterator of
    newline-delimited JSON records ONE AT A TIME (bounded memory, never collecting
    the input) and creates each user through the audited, isolation-scoped
    `ActingUserRepo::admin_create` (issue #52), so imported users get lifecycle,
    tenant isolation, and PII encryption (issue #48) for free. Per-record failure
    isolation (a bad record is reported and skipped, the batch continues; nothing
    silently dropped), idempotent re-import (a duplicate id / external id / login
    handle is a skip, not a second row), and scope confinement (a cross-scope id is
    rejected, so an import into one tenant cannot touch another). Progress-observable
    through a per-record callback and an aggregate `ImportReport`.
  - **Verify-then-rehash.** The stored foreign hash is a one-way verifier; the login
    path (ironauth-oidc) verifies it and, on first success, rehashes the password to
    the native Argon2id verifier and retires the foreign hash, so migration is
    lossless and no plaintext password is ever stored.
  - **Determinism seam.** `created_at` reads from `env.clock()` and the rehash salt
    from `env.entropy()`; no raw `SystemTime` or RNG.
