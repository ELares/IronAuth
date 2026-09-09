-- What the last completed pass saw in a directory (issue #142).
--
-- Absence detection needs a previous state to be absent FROM. Until now every pass swept against
-- an empty set, so every principal read as an arrival and no departure was ever computed: the
-- applier could provision and could not remove, which is the forever-alive-account failure #142
-- names authentik's #6408 for. This row is the missing half.
--
-- ONE SEALED BLOB, NOT A ROW PER PRINCIPAL. The stable identifier is `objectGUID`, `entryUUID`,
-- or -- where the server publishes neither -- the DN, and a DN carries a person's name and their
-- place in an organization. That is PII, and every other PII column in this schema is sealed
-- under the scope's DEK. A row per principal would be a plaintext index of everybody in the
-- customer's directory, readable by anything holding the control role, and no query wants it: the
-- diff needs the WHOLE set at once and never one member. So the set is serialized, sealed, and
-- stored as one value, exactly as `environment_secrets` seals a secret.
--
-- The size that implies is deliberate. Tens of thousands of identifiers is a few megabytes,
-- which Postgres stores out of line and reads in one go; the alternative -- a hundred thousand
-- individually sealed rows -- would be a hundred thousand AEAD opens per pass.
--
-- WRITTEN ONLY BY A PASS THAT SAW THE WHOLE DIRECTORY. A truncated read must not become the
-- snapshot: if a pass that saw half a directory recorded that half, the people it missed would be
-- silently forgotten, and a later complete pass would never report them as departed. The writer
-- enforces that; this table only records what it was given, so `principal_count` is here to make
-- a shrinking snapshot visible to an operator without opening the blob.
--
-- ONE ROW PER CONNECTOR, replaced in place. There is no history to keep: the diff compares the
-- last pass with this one, and a chain of previous passes answers no question the audit log does
-- not already answer better.
--
-- Expand-only: a new table with no writer on any older binary.

CREATE TABLE ldap_sync_snapshots (
    -- The `ldc_` connector this snapshot belongs to. One row per connector, so the connector is
    -- the key rather than a surrogate.
    connector_id     text        NOT NULL PRIMARY KEY,
    tenant_id        text        NOT NULL,
    environment_id   text        NOT NULL,

    -- The sealed set of stable identifiers, and the DEK generation it was sealed under.
    dek_version      integer     NOT NULL,
    ciphertext       bytea       NOT NULL,

    -- How many identifiers the blob holds. NOT authoritative -- the blob is -- but an operator
    -- watching a directory shrink should not have to decrypt anything to see it happening.
    principal_count  integer     NOT NULL,

    -- When the pass that produced it finished.
    taken_at         timestamptz NOT NULL,

    CONSTRAINT ldap_sync_snapshots_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT ldap_sync_snapshots_principal_count_nonnegative
        CHECK (principal_count >= 0),
    CONSTRAINT ldap_sync_snapshots_ciphertext_nonempty
        CHECK (octet_length(ciphertext) > 0),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- The snapshot dies with the connector: a set of identifiers whose directory has been removed
    -- is PII nothing will ever read again.
    FOREIGN KEY (connector_id) REFERENCES ldap_connectors (id) ON DELETE CASCADE
);

-- A pass reads every snapshot in the scope in one go, before it opens any connection.
CREATE INDEX ldap_sync_snapshots_by_scope_idx
    ON ldap_sync_snapshots (tenant_id, environment_id);

ALTER TABLE ldap_sync_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE ldap_sync_snapshots FORCE ROW LEVEL SECURITY;

CREATE POLICY ldap_sync_snapshots_scope ON ldap_sync_snapshots
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The sweep is a control-plane job, and it both reads and replaces this row. No DELETE: a
-- snapshot is removed by removing its connector, which cascades. A standalone delete would be a
-- way to make a directory's whole population read as new without touching the connector, and no
-- statement in the tree wants that.
GRANT SELECT, INSERT ON ldap_sync_snapshots TO ironauth_control;
-- UPDATE is column-scoped to exactly what the upsert writes.
GRANT UPDATE (dek_version, ciphertext, principal_count, taken_at)
    ON ldap_sync_snapshots TO ironauth_control;

-- The DATA plane gets NOTHING, for the reason 0212 gives about the connector row: no request path
-- reads a directory snapshot, and granting it would put a list of every person in the customer's
-- directory within reach of the token-issuance role.
