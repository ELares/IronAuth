-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Same-transaction audit log (issue #7).
--
-- Every repository mutation writes exactly one row here in the SAME transaction
-- as the data change, through the repository's single audited-write primitive.
-- Because the data change and the audit row commit or roll back together, a
-- mutation can never exist without its audit row and a failed mutation leaves no
-- audit trace. That atomicity is the enforcement; this table is append-only
-- storage for it.
--
-- The table is tenant-scoped exactly like `clients`: mandatory tenant_id and
-- environment_id, the nonempty-scope CHECK, forced row-level security keyed on
-- the same transaction-local session variables, and the same foreign keys. Audit
-- rows are therefore isolated per tenant and environment under the identical
-- policy, and audit does not weaken tenant isolation.
--
-- The envelope is the substrate for later OCSF mapping and the auth-stream
-- versus admin-stream separation (M11). Those are NOT built here; only the
-- fields they will need are carried: actor (kind + typed id), action, the typed
-- target (kind + id), scope, the wall-clock occurred_at (sourced from the
-- ironauth-env clock, never the database clock, so it is deterministic under
-- test), and the correlation id of the originating request.

CREATE TABLE audit_log (
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The verb, for example client.create (see the Action enum).
    action         text        NOT NULL,
    -- The acting principal: kind (human | service | agent) and its typed id.
    actor_kind     text        NOT NULL,
    actor_id       text        NOT NULL,
    -- The resource acted on: its typed-prefix kind (for example cli) and its id.
    target_kind    text        NOT NULL,
    target_id      text        NOT NULL,
    -- The originating request, so a row ties back to the call that caused it.
    correlation_id text        NOT NULL,
    -- When the mutation happened, from the application clock seam.
    occurred_at    timestamptz NOT NULL,
    -- When the row was persisted, from the database clock. Operational metadata
    -- only; occurred_at is the authoritative event time.
    recorded_at    timestamptz NOT NULL DEFAULT now(),
    -- Same invariant as every scoped table: an empty scope must never reach a
    -- row, so a warmed connection's empty-string scope variable can never match.
    CONSTRAINT audit_log_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX audit_log_scope_idx ON audit_log (tenant_id, environment_id, occurred_at);

-- Row-level security, ENABLED and FORCED, keyed on the same transaction-local
-- session variables the repository binds. Identical policy to the other scoped
-- tables, so an audit row is only ever visible and only ever writable within its
-- own (tenant, environment).
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_log_tenant_isolation ON audit_log
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- Append-only enforcement. The application role may only SELECT and INSERT;
-- there is deliberately NO GRANT of UPDATE or DELETE, so an attempt to rewrite
-- or erase an audit row fails with "permission denied" even for the role the
-- application connects as. Retention and pruning are a later, explicit operation
-- performed by a different, privileged path, never by the application role.
GRANT SELECT, INSERT ON audit_log TO ironauth_app;
