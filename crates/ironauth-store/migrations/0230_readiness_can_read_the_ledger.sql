-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Let the serving role read the migration ledger, so `/readyz` can answer (issue #149).
--
-- # Why readiness needs this at all
--
-- `/readyz` used to open a bare TCP socket to the configured Postgres address and call that
-- ready. A socket connect cannot tell a serving database from one that refuses every
-- credential, has no such database, grants the role nothing, or was never migrated. All of
-- those answered `ready`, so `readyReplicas == desired` could hold against a pod that cannot
-- complete a single query.
--
-- The replacement asks the database, on the pool requests are served from, and part of that
-- answer is whether the schema is one this build can serve. That is what `_schema_migrations`
-- records, and `ironauth_app` could not read it. The chain's grants name application tables and
-- (in 0001 and 0003) schema usage; none of them names the ledger, which is the migration
-- runner's own bookkeeping, created by the runner outside every migration it then applies.
--
-- Without this grant the probe gets SQLSTATE 42501 on a perfectly healthy database, which is
-- indistinguishable at the driver from a connection problem. A readiness check that fails on
-- every healthy deployment is worse than the socket check it replaced: the socket check was
-- wrong in one direction, and that would be wrong in the other, and it would take out every
-- replica at once.
--
-- # SELECT only, and only this role
--
-- Readiness reads. It never writes the ledger, and the migration runner connects as the owner
-- for that, so nothing here needs INSERT or UPDATE. The control and audit-retention roles are
-- not granted: neither runs a readiness probe.
--
-- What the ledger exposes is which schema versions are applied and when. That is metadata about
-- the deployment's own upgrade state, held by a role that already reads every application
-- table in the database, so it widens nothing an operator would care about.
--
-- # IF EXISTS, and it is belt-and-braces rather than a case anyone has hit
--
-- The runner creates the ledger before it applies anything, so on every path that reaches this
-- migration through `MigrationRunner` the table is present and the check is always true. It is
-- here so that applying this file by hand, or through a harness that drives the SQL without the
-- runner, fails to grant rather than failing to run. That is a cheap guard on a one-line
-- migration, not a state the shipped code can produce.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = '_schema_migrations' AND relkind = 'r') THEN
        EXECUTE 'GRANT SELECT ON _schema_migrations TO ironauth_app';
    END IF;
END
$$;
