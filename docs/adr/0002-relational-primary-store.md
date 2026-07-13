# ADR 0002: Postgres relations as the sole source of truth

Status: accepted (M1, relational-primary-store issue #7)

## Context

The storage-architecture decision for an identity provider is nearly
irreversible: it shapes every read and write path, the consistency model every
downstream feature inherits, and the upgrade story for the life of the product.
The field has already run the experiment, and the result is decisive.

A public post-mortem of a widely deployed open-source identity provider
(zitadel#9599) enumerates why an event-sourced core failed at identity-provider
write patterns:

- **Eventual consistency broke infrastructure-as-code.** A write acknowledged by
  the API was not yet visible to the next read, so Terraform-style reconcilers
  that write then immediately read saw their own writes missing and looped or
  errored.
- **Stuck projections looked like data loss.** When the projection that turns the
  event log into queryable state fell behind or wedged, operators saw resources
  simply absent, indistinguishable from real loss, with no relational row to
  point at.
- **No foreign-key integrity.** An event log has no referential constraints, so
  nothing at the storage layer prevented a client referencing a deleted tenant
  or an environment paired with the wrong tenant; integrity was left to
  application code that could forget.
- **Latency.** The read-model reconstruction put password login at a p95 of 12.3
  seconds under load.

The escape (their "V5") is a multi-year migration back to a relational core.
Everyone else in the field is already relational. There is no reason to pay the
same multi-year tax to arrive at the same destination.

## Decision

Postgres relations are the **sole source of truth** for IronAuth: normalized
tables, foreign keys enforced at the database, explicitly **not** event-sourced.

- **Relations are authoritative.** Every piece of durable state is a row in a
  normalized table. Reads and writes go to those rows directly, so a write is
  immediately visible to the next read (read-your-writes holds without a
  projection catching up), which is what infrastructure-as-code and admin flows
  require.
- **Foreign-key integrity is enforced by the database.** Scoped resources
  reference their tenant and their `(environment, tenant)` pair by foreign key,
  so the storage layer itself refuses a dangling or cross-tenant reference. This
  is the integrity the event-sourced design could not provide.
- **An append-only audit log records every mutation, but is never the source of
  truth.** Every repository mutation writes exactly one audit row in the *same
  transaction* as the data change, through a single audited-write primitive (see
  the crate documentation and `docs/design/TENANCY.md`). Because the data change
  and the audit row commit or roll back together, the audit log can never
  diverge from state and a failed mutation leaves no trace. Crucially, the audit
  log is a *record of* the authoritative relational state, not the state itself:
  the current value of a resource is always its row, never a fold over events.
- **Events exist for forensics and outbound integration only.** The audit
  envelope (actor, action, typed target, scope, timestamp, correlation id) is
  the substrate for later forensic query, the outbound event sink (the future
  IronBus integration, M11), and the auth-stream versus admin-stream separation
  (M11). Those are downstream consumers of a log derived from committed
  relational state; they never become the system of record.
- **Schema evolves by expand-contract migrations.** A runtime migration runner
  tracks applied migrations in a ledger, checksums each, applies them in order,
  and refuses out-of-order or checksum-drifted application. Every change moves
  through expand (additive), migrate (backfill), and contract (remove) phases.
  This is what later makes zero-downtime N/N+1 upgrades achievable, the recurring
  operational pain that other identity providers have publicly struggled with.

## Consequences

- **The consistency model is boring on purpose.** Read-your-writes and
  foreign-key integrity are the default, so infrastructure-as-code, admin
  tooling, and operators never reason about projection lag or eventual
  consistency for core state.
- **Audit integrity is structural, not procedural.** "A mutation without an audit
  row" is not a bug to be avoided by careful handlers; it is unrepresentable,
  because the only code path that commits a data change is the one that also
  writes the audit row in the same transaction. A reviewer never has to check
  that a new handler "remembered" to audit.
- **Audit rows are append-only and tenant-scoped.** The application role has
  SELECT and INSERT on the audit table and neither UPDATE nor DELETE; retention
  and pruning are a separate, explicitly privileged operation. Audit rows carry
  mandatory `(tenant, environment)` scope under the same forced row-level
  security as every other scoped table, so audit does not weaken tenant
  isolation.
- **Migrations inherit the isolation discipline.** Any migration that introduces
  a new tenant-scoped table must, in the same migration, enable and force
  row-level security, add the `(tenant, environment)` policy, and add the
  nonempty-scope CHECK, and must register the table with the scoped-table lint.
  The tenant-isolation rules do not stop at the first migration.
- **We forgo event-sourcing's audit-for-free and time-travel.** Reconstructing
  arbitrary historical state is not a first-class capability; the audit log
  answers "what changed, by whom, when, under which request", which is what
  compliance and forensics need, without making the log authoritative. If a
  genuine event-sourced sub-domain ever appears, it would be a bounded, opt-in
  decision recorded in a new ADR, never the core.
