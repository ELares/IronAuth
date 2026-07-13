# ironauth-store changelog

All notable changes to the `ironauth-store` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

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
    application and checksum drift on an already-applied migration, both as typed
    `MigrationError`s. The #6 schema is migration 1, the audit log is migration
    2, and migrations 3 to 5 are a checked expand-contract example (add a
    nullable column, backfill, drop the old column) on a throwaway demo object.
    Migration safety: any migration adding a tenant-scoped table must set up
    forced row-level security, the isolation policy, and the nonempty-scope CHECK
    (extended to `scripts/query-audit.sh`'s scoped-table list, now including
    `audit_log`).
  - Adds `sha2` (migration checksums): pure Rust, permissive (MIT OR
    Apache-2.0), already present transitively via sqlx, so no new crate enters
    the dependency graph; MSRV 1.85 and the musl static lane are unaffected.
  - New integration tests against a real database: transactional atomicity
    (injected mid-transaction failure leaves no orphan data or audit row, and a
    data-insert failure writes no audit row), every-mutation-audits with the full
    envelope, append-only privilege, and the migration framework
    (in-order/idempotent, out-of-order rejection, checksum-mismatch rejection,
    and the expand-contract example end to end).

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
