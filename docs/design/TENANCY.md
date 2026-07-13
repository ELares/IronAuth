<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Tenant and environment isolation

Status: accepted (M1, tenant-substrate issue #6)

This document records the root schema decision for multi-tenancy: the four-level
resource model, the pooled shared-schema storage choice, and the reasons
isolation is enforced below the application layer rather than by per-handler
checks. Every later surface plugs into the harness built here.

## Why this is the highest-risk decision

Cross-tenant access is the top CVE class for a multi-tenant identity provider,
and the record shows a consistent root cause: authorization checked per
controller instead of enforced below the application. The recurring families
are:

- **IDOR (insecure direct object reference).** An endpoint resolves a
  caller-supplied resource identifier without confirming it belongs to the
  caller's tenant, so one tenant reads or mutates another's object.
- **Recycled-identifier leakage.** Serial or reused identifiers let a caller
  reach a resource that was reassigned after deletion, or enumerate resources
  that were never theirs.
- **Cross-organization escalation.** URL or path concatenation lets an
  organization administrator act on a sibling organization.
- **Unauthenticated administrative surfaces.** A management or provisioning
  endpoint ships without the isolation the rest of the system assumes.

The common lesson is that isolation by convention fails: any handler that
forgets the tenant filter is a breach. IronAuth ships isolation by construction
instead, so a forgotten check cannot exist.

## The four-level resource model

IronAuth models four distinct, typed levels. No surveyed product, commercial or
open source, ships all four cleanly: some conflate tenant with environment,
others conflate environment with the server instance.

1. **Operator.** The platform deployment itself: whoever runs this IronAuth. The
   top of the tree; not tenant-scoped.
2. **Tenant.** A customer of the operator. The unit of isolation and billing.
3. **Environment.** A promotable context within a tenant, for example
   production and staging. Kept distinct from the tenant so that configuration
   can be promoted between environments without crossing a tenant boundary.
4. **Organization.** A grouping within an environment for business-to-business
   scenarios (end-customer companies within a tenant's application).

`(tenant, environment)` is the mandatory isolation scope. Every scoped resource
carries both columns from day one.

### Organization is a schema slot only in M1

This issue lands only the organization table and its foreign key. Organizations
become a public API resource in M5, gain lifecycle operations in M5, and the
full business-to-business surface (membership, invitations, policies) arrives in
M10. The slot exists now so scoped tables and the isolation harness cover the
table from the first migration, never as a retrofit.

## Storage model: pooled shared schema

IronAuth stores all tenants in shared tables keyed by `(tenant, environment)`,
not one schema or one database per tenant.

- **Realm-per-tenant does not scale.** Cache-per-realm memory and per-realm
  cluster operations degrade a realm-per-tenant design past a few hundred
  tenants. The target here is 100k+ tenants with per-tenant marginal cost being
  ordinary rows.
- **Pooled shared schema is proven at scale.** Systems that key their event
  store and their per-object rows on a tenant (and application) identifier reach
  very large tenant counts because a new tenant is just more rows.
- **Graduated isolation stays open.** Opt-in per-tenant database isolation for
  tenants that require physical separation is deliberately deferred (M5). The
  shared-schema model does not preclude it.

## Isolation is enforced below the application, in three layers

Isolation must not depend on a handler remembering to filter. It is enforced in
three independent layers, each of which would stop a cross-tenant access on its
own.

### 1. Typed scoped identifiers

Every identifier is a non-guessable, non-recyclable, typed-prefixed token
(`ten_`, `env_`, `op_`, `cli_`, `org_`). Randomness comes only from the
`ironauth-env` entropy seam.

- **Non-guessable.** 128 bits of entropy per component, rendered URL-safe. Not
  enumerable, not predictable.
- **Non-recyclable.** Random, never serial; a value is never reissued after
  deletion. The primary keys are the random identifiers themselves, so the
  database cannot recycle one either.
- **Scope embedded.** A scoped resource identifier encodes its tenant and its
  environment alongside its unique component. Parsing one under the wrong scope
  fails as a uniform not-found, identical to a resource that never existed:
  there is no existence oracle and no error-shape oracle. A handler that holds a
  scoped identifier cannot even express a cross-tenant query.

The design chooses to embed the scope in the identifier so the parse boundary
itself rejects cross-scope references, rather than deferring the whole check to
the database round-trip. The identifier is opaque; because every component is
random, embedding the tenant leaks nothing enumerable.

### 2. Scope-only repositories

A repository can only be constructed from a `Scope`, via `Store::scoped(scope)`.
It applies that scope to every query itself; a handler never passes a tenant or
environment per call. The connection pool and the scoped tables are private to
the store crate, so no other crate can issue an unscoped query. Two guarantees
are enforced at compile time (proven by trybuild compile-fail tests):

- a repository cannot be constructed without a scope, and
- a scoped handle exposes no API to reach another tenant.

A CI lint (`scripts/query-audit.sh`) fails the build if scoped-table SQL appears
anywhere but the repository module, closing the raw-pool bypass that module
visibility already blocks across crates. The lint is a best-effort grep and a
*secondary* net: the primary enforcement is the crate-private pool, module
visibility, and row-level security. It matches a fixed list of scoped table
names, so adding a new tenant-scoped table is a checklist item that must also add
the table to the lint's list (and to the CHECK-constraint and row-level-security
stanzas of the migration); a concatenated or computed table name can also evade a
grep. It catches the common accidental bypass, not a determined one.

### 3. Postgres row-level security

Every tenant-scoped table has row-level security ENABLED and FORCED, with
policies keyed on the transaction-local session variables
`ironauth.tenant_id` and `ironauth.environment_id` that the repository binds
with `set_config(.., true)` per transaction. Properties:

- **Deny by default, enforced.** A session with no scope set sees nothing on
  both connection states. On a pristine connection `current_setting(.., true)`
  is NULL and `column = NULL` is never true; on a pooled connection that already
  ran a scoped transaction, the transaction-local variable has reverted to the
  empty string, so the check is `column = ''`. A CHECK constraint forbids any
  scoped row from carrying an empty tenant or environment, so neither state can
  match a real row. Deny by default is thus an enforced invariant, not an
  artifact of NULL semantics.
- **FORCED.** Row-level security applies even to the table owner, so isolation
  does not depend on which role owns the table. The application connects as a
  low-privilege role that is neither a superuser (superusers bypass row-level
  security) nor an owner, so the policy always applies. An integration test
  proves a mis-scoped low-privilege session cannot read another tenant's rows
  even when the application-layer filter is deliberately bypassed.
- **Write side too.** The policy's `WITH CHECK` clause rejects writing a row
  that claims another tenant.

## The cross-tenant IDOR harness

`ironauth_store::idor_harness` is a reusable suite: given an isolation-relevant
operation, it exercises it with identifiers minted in another tenant and another
environment and asserts a uniform denial (the same not-found a genuinely absent
resource produces, with no error-shape oracle). It runs in CI against every
scoped-repository operation that exists today. Every future surface registers
its operations with it, so coverage grows with the system rather than lagging
it. The registration recipe is documented on the module.

## Scope of issue #6 (and what it defers)

This issue ships the schema decision and the isolation mechanism. It
deliberately does not ship:

- the full expand-contract migration framework and the same-transaction audit
  log (issue #7): the migration here is the minimal capability #6 needs;
- environments as promotable product objects with guardrails and issuers (M5);
- organizations as a product surface (M10; only the schema slot lands here);
- opt-in per-tenant database isolation (M5).

## Test database

The RLS and IDOR integration tests require a real Postgres, reached through
`DATABASE_URL`. The crate does not embed a Postgres binary: the only maintained
pure-Rust embedded-Postgres crate pulls a dependency tree with licenses outside
the project's permissive allowlist (the Community Data License Agreement and the
PostgreSQL license), which the supply-chain policy forbids. `DATABASE_URL` keeps
the dependency tree permissive, MSRV 1.85, and musl static clean.
`scripts/with-test-db.sh` brings up a throwaway local cluster and exports
`DATABASE_URL`; CI points it at a Postgres service. The tests fail loudly if it
is unset: an isolation test must never silently skip.
