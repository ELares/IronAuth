# ironauth-store changelog

All notable changes to the `ironauth-store` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- Registered redirect URIs and the exact-string redirect comparator (issue #13).
  - **The redirect-matching policy** lives here as two pure functions,
    `redirect_uri_matches` and `redirect_uri_is_registrable` (`src/redirect.rs`),
    since the store owns the client registry and thus the registered set matched
    against. Matching is EXACT byte string, with the single RFC 8252 section 7.3
    loopback deviation (a variable port on an `http` loopback IP literal:
    `127.0.0.1` or `[::1]`, never `localhost`). Registrability accepts exactly the
    three RFC 8252 redirect shapes (claimed `https`, `http` loopback IP literal, a
    reverse-domain private-use scheme) and rejects everything else. A permanent CVE
    regression corpus (wildcard, substring, case-fold, normalization, encoding, and
    homograph classes) and a cargo-fuzz target (`fuzz/`, `redirect_match`) guard
    against any accepted bypass. The loopback port exception range-checks the port
    (`1..=65535`, so `:0`/`:99999` are not port variants), and a registrable `https`
    redirect carrying userinfo (`https://good@evil/cb`, a host-confusion vector) is
    refused rather than stored and later matched byte-for-byte.
  - **The eighth production migration** adds the additive `clients.redirect_uris`
    (`text[]`) column, the registered set; `ClientRecord` now carries
    `redirect_uris` and `auth_method`, and `ActingClientRepo::register_redirect_uris`
    validates each URI as a registrable redirect target BEFORE storing it (a
    malformed scheme is `StoreError::InvalidRedirectUri`, rejected at registration).
    New audit action `client.redirect_uris.register`.
- OIDC authorization-code grant persistence (issue #12). Adds the fourth
  production migration and the scoped `authorization` repository, all under the
  existing tenant-isolation model (RLS enabled and forced, nonempty-scope CHECK).
  - **Three tenant-scoped tables:** `grants` (the revocation spine linking a code
    to its session, consent, and issued tokens), `authorization_codes` (single
    use, binding the `client_id`, `redirect_uri`, `nonce`, and PKCE
    `code_challenge`), and `issued_tokens` (the `jti` of each token, so
    grant-chain revocation is observable). Registered in
    `scripts/query-audit.sh`; granted to the data-plane `ironauth_app` role.
  - **Atomic single use.** `ActingAuthorizationRepo::redeem` consumes a code in
    one `UPDATE ... WHERE consumed_at IS NULL RETURNING ...`; zero rows is a
    replay, classified so the caller can revoke the grant chain. The consume
    audits `authorization_code.redeem` in the same transaction. No in-memory
    marker, so single use holds across N stateless nodes.
  - **New scoped identifiers** (`ac_`, `grt_`, `tok_`), audit actions
    (`authorization_code.issue`/`.redeem`/`.reuse`, `token.issue`), and the
    `authorization_codes.redeem` / `issued_tokens.token_status` IDOR probes.
- Management-plane control substrate (issue #11). Adds the control-plane role,
  the management repositories, and the third production migration; the #6 and #7
  isolation and audit tests stay green.
  - **A distinct control-plane role, `ironauth_control`.** Migration 3 GRANTs it
    the operator, tenant, and environment LEVEL tables that the data-plane
    `ironauth_app` cannot see, plus append-only audit and the two new management
    tables, and nothing on `clients`/`organizations`. Like `ironauth_app` it is a
    peer, never a superset (never a superuser or owner, so forced row-level
    security applies), and the migration GRANTs but never creates it or ships a
    password. The test harness (`test_support`) provisions it race-safely and
    exposes a separate `control_store()`; the two pools are kept distinct.
  - **Management repositories reusing `write_audited`.** `Store::management()`
    reaches `TenantRepo`/`EnvironmentRepo` (operator plane, level tables) and the
    tenant-scoped `ManagementCredentialRepo`, plus the credential-scoped
    `IdempotencyRepo`. Every mutation routes through the same single audited-write
    primitive, so a management mutation without its same-transaction audit row is
    as impossible as a data-plane one. The primitive is now generic over an
    `AuditTarget` so a level-id target (a tenant, an environment) audits through
    the same path as a scoped-id target. New `Action` variants: `tenant.create`,
    `tenant.delete`, `environment.create`, `environment.delete`,
    `management_key.create`, `management_key.delete`.
  - **Operator-plane audit scoping.** Creating a tenant creates its first
    environment in the same transaction and audits scoped to that fresh
    `(tenant, environment)`; environment CRUD scopes to `(tenant, environment)`;
    tenant deactivation scopes to the tenant's retained oldest environment. See
    `docs/adr/0005-management-api.md`.
  - **New scoped tables.** `management_credentials` (environment-scoped `mak_`
    keys: forced row-level security, nonempty-scope CHECK, the same foreign keys
    as `clients`; only the key hash is stored) and `idempotency_keys` (the
    Idempotency-Key replay store, deliberately CREDENTIAL-scoped rather than
    tenant-RLS-scoped, because an operator-plane POST is looked up before any
    tenant exists). Both are added to `scripts/query-audit.sh`'s scoped-table
    list. `tenants` and `environments` gain a `deleted_at` soft-delete column, so
    a DELETE is a deactivation that keeps the row and the append-only audit
    foreign keys satisfiable.
  - New id types and helpers: `ManagementKeyId` (`mak_`, scoped),
    `ScopedId::parse_declared_scope` (recovers a credential token's declared scope
    without a caller scope, for self-authenticating tokens only),
    `LevelId::from_seed_bytes`/`ScopedId::unique_bytes` (well-known and derived
    identities: the bootstrap operator and a management key's service actor).
  - No new dependency; still runtime sqlx only and musl/MSRV-1.85 clean.

- Relational primary store with a same-transaction audit log and an
  expand-contract migration framework (issue #7). Builds directly on the #6
  isolation substrate.
  - **Postgres relations are the sole source of truth** (normalized tables,
    foreign keys enforced, explicitly not event sourced). The decision and the
    zitadel#9599 evidence are recorded in
    `docs/adr/0002-relational-primary-store.md`.
  - **Same-transaction audit log, structurally enforced.** A new tenant-scoped
    `audit_log` table (scoped, forced row-level security, nonempty-scope CHECK,
    same foreign keys as `clients`). Every repository mutation routes through a
    single private audited-write primitive (`write_audited`) that performs the
    data change and writes exactly one audit row in one transaction and is the
    only committing write path; the public mutators cannot commit without it, so
    "a mutation without an audit row" is unrepresentable and a failed mutation
    leaves no trace. The envelope carries a typed `ActorRef`
    (`Human`/`Service`/`Agent`, each with a typed actor id), an `Action`, the
    typed scoped target, `(tenant, environment)`, `occurred_at` (from the
    `ironauth-env` clock seam, never the database clock), and a `CorrelationId`.
    It is the substrate for later OCSF mapping and stream separation (M11); no
    streams or OCSF are built here.
  - **Acting context for writes.** Reads (`ScopedStore::clients`,
    `ScopedStore::audit`) need no actor; writes are reachable only through
    `ScopedStore::acting(actor, correlation)`, so an actor and correlation id are
    required at the type level for every mutation. This changed the
    `create`/`delete` signatures; all #6 call sites and the IDOR delete probe
    were updated and every #6 isolation test stays green.
  - **Append-only enforcement.** The application role is granted SELECT and
    INSERT on `audit_log` and neither UPDATE nor DELETE; a privilege test as
    `ironauth_app` proves UPDATE and DELETE are refused while INSERT/SELECT in
    scope work. Retention is a later, explicit operation.
  - **Expand-contract migration runner** (`MigrationRunner`), replacing the
    single-file raw apply. Tracks applied migrations in a `_schema_migrations`
    ledger (version, name, SHA-256 checksum, phase, applied_at), applies pending
    migrations in order each inside its own transaction, and refuses out-of-order
    application, checksum drift on an already-applied migration, and a ledger
    version unknown to the running build (the N/N-1 downgrade guard), all as
    typed `MigrationError`s. Concurrent runners (several replicas booting during
    a rolling upgrade) serialize through a session-level Postgres advisory lock,
    so the losers wait and find the chain applied instead of racing to create the
    same objects. The production chain is exactly two migrations: the #6 schema
    (version 1) and the audit log (version 2); it ships no throwaway objects. The
    worked expand-contract example (add a nullable column, backfill, drop the old
    column) exercises all three phases in the migration test only, never in a
    real schema. Migration safety: any migration adding a tenant-scoped table
    must set up forced row-level security, the isolation policy, and the
    nonempty-scope CHECK (extended to `scripts/query-audit.sh`'s scoped-table
    list, now including `audit_log`).
  - Minimum PostgreSQL 14: the audit `occurred_at` is read back exactly (its
    integer microseconds) only where `EXTRACT(EPOCH FROM timestamptz)` returns
    numeric, which is PostgreSQL 14+; older versions return double precision and
    can round the read-back by +/- 1 us. The stored value is exact regardless.
  - Adds `sha2` (migration checksums): pure Rust, permissive (MIT OR
    Apache-2.0), already present transitively via sqlx, so no new crate enters
    the dependency graph; MSRV 1.85 and the musl static lane are unaffected.
  - New integration tests against a real database: transactional atomicity
    (injected mid-transaction failure leaves no orphan data or audit row, and a
    data-insert failure writes no audit row), every-mutation-audits with the full
    envelope, append-only privilege (UPDATE, DELETE, and TRUNCATE all denied to
    the application role; INSERT/SELECT in scope allowed), and the migration
    framework (in-order/idempotent, out-of-order rejection, checksum-mismatch
    rejection, NotSorted for descending and duplicate versions, the N/N-1
    downgrade guard, per-migration rollback of a failed DDL, concurrent-runner
    serialization via the advisory lock, the production chain being exactly two
    migrations with no demo object, and the test-only expand-contract example end
    to end).

- Initial persistence and tenant isolation layer (issue #6). Isolation is
  enforced below the application in three independent layers:
  - **Typed scoped identifiers** (`TenantId`, `EnvironmentId`, `OperatorId`,
    and the scoped `ScopedId<K>` with `ClientId`/`OrganizationId`): non-guessable
    (128-bit, entropy from `ironauth-env`), non-recyclable (random, never
    serial), typed-prefixed and URL-safe. Scoped identifiers embed their tenant
    and environment; `parse_in_scope` fails cross-scope as a uniform not-found
    with no existence or error-shape oracle.
  - **Scope-only repositories** (`Store::scoped(scope)` -> `ScopedStore` ->
    `ClientRepo`): constructible only from a `Scope`, which is applied to every
    query; the pool and scoped tables are crate-private. Compile-fail tests
    prove a repository cannot be built without a scope and a scoped handle
    cannot query another tenant.
  - **Postgres row-level security**: every tenant-scoped table has RLS ENABLED
    and FORCED with policies keyed on the transaction-local `ironauth.tenant_id`
    and `ironauth.environment_id`. Deny-by-default is an enforced invariant: a
    CHECK constraint forbids any scoped row from carrying an empty scope, so an
    unset session denies whether its scope variable is NULL (pristine connection)
    or the empty string (pooled connection that reverted a scope). The shipped
    migration never creates the low-privilege role or a password; the role is
    provisioned out of band (production) or by the test harness (race-safely),
    so no credential for the isolation-boundary role is committed.
  - The reusable cross-tenant `idor_harness` (feature `testing`) that every
    future surface registers with, plus the `test_support` real-database
    harness.
  - Four-level resource model schema (operator, tenant, environment,
    organization) with a minimal `Store::migrate()`. The full migration
    framework and the same-transaction audit log are issue #7.
  - Uses the runtime sqlx query API only (never the compile-time `query!`
    macros), rustls + ring with the OS trust store (no native-tls/openssl, no
    webpki-roots, no aws-lc), so every database-free lane stays database-free and
    the musl static and MSRV-1.85 lanes hold.
