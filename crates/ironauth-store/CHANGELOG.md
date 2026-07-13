# ironauth-store changelog

All notable changes to the `ironauth-store` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

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
    and `ironauth.environment_id`; deny-by-default when unset.
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
