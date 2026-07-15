# ironauth-import changelog

All notable changes to the `ironauth-import` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

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
