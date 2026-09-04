-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- 0190: what a downstream calls each subject an outbound connection pushes (issue #137).
--
-- The MIRROR of 0184, and the direction is the whole difference. Inbound, `scim_external_ids`
-- stores the identity provider's own id for a person IronAuth owns. Outbound, this stores the
-- DOWNSTREAM's id for a person IronAuth owns: RFC 7643 section 3.1 makes `id` server-issued, so
-- the downstream allocates it and the client must remember it or address the wrong resource
-- forever after.
--
-- WHY A MAP AT ALL, GIVEN THE CLIENT LOOKS UP BY externalId ANYWAY.
--
-- The lookup is what makes a push IDEMPOTENT: it is issued before every write so a replay after
-- a lost response converges instead of duplicating. This table is not a substitute for it and
-- must never become one. What it buys is the two things a lookup cannot:
--
--   1. PER-RESOURCE ERROR STATE, which issue #137 asks for by name. "Which of this org's users
--      is failing to provision, and with what" is a question about a resource, and there is
--      nowhere to record it without a row per resource.
--   2. AN ANSWER AFTER THE DOWNSTREAM FORGETS. If a downstream is rebuilt and loses a resource,
--      the lookup misses and the client creates a new one; the OLD downstream id is then the
--      only evidence of what was there, which an operator reconstructing a sync needs.
--
-- WHY THE NAMESPACE IS THE CONNECTION, for the reason 0184 gives in the other direction: two
-- connections can push the same person into two downstreams, and the two downstreams allocate
-- unrelated ids. Keyed per environment the second push would collide with or overwrite the
-- first, and overwriting is the worse of the two because the sync would appear to succeed.
--
-- WHY `resource_type` IS A COLUMN AND NOT TWO TABLES. A user and a group are pushed by the same
-- worker through the same protocol into the same downstream, and every query here is "for this
-- connection, what is this subject called". Two tables would duplicate that query, the cascade
-- below, and this comment.
--
-- Expand phase: a new table the old binary never reads or writes, so a rollback leaves it inert.

CREATE TABLE scim_push_links (
    id                text        PRIMARY KEY,
    tenant_id         text        NOT NULL,
    environment_id    text        NOT NULL,
    -- The outbound connection whose namespace this link lives in.
    connection_id     text        NOT NULL,
    -- Which collection the subject belongs to. A closed vocabulary, so a third value is a
    -- migration rather than a string somebody typed.
    resource_type     text        NOT NULL
                                  CHECK (resource_type IN ('user', 'group')),
    -- IronAuth's own id for the subject. NOT a foreign key to `users` or `org_groups`, and the
    -- omission is deliberate: the two collections live in different tables, so a single column
    -- cannot reference both, and splitting the table to gain the key would cost what the
    -- `resource_type` note above describes. What keeps it honest is the worker, which only ever
    -- writes an id it just read out of one of those tables.
    subject_id        text        NOT NULL,
    -- What the DOWNSTREAM calls it. Server-issued there, opaque here: never parsed, only
    -- echoed back in the path of a later PUT, PATCH or DELETE.
    downstream_id     text        NOT NULL,
    -- The externalId this connection sent for the subject. Recorded rather than recomputed
    -- because a connection's attribute mapping can change what is sent, and an operator asking
    -- "what did we tell them this person was called" wants what was sent, not what would be
    -- sent now.
    external_id       text        NOT NULL,
    last_synced_at    timestamptz,
    -- PER-RESOURCE ERROR STATE (issue #137). The connection-level health on 0189 answers "is
    -- this downstream reachable"; this answers "which users are failing", which is a different
    -- question and the one an operator asks second.
    last_error_at     timestamptz,
    last_error        text,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT scim_push_links_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT scim_push_links_subject_id_nonempty
        CHECK (subject_id <> ''),
    CONSTRAINT scim_push_links_downstream_id_shaped
        CHECK (downstream_id <> '' AND octet_length(downstream_id) <= 512),
    CONSTRAINT scim_push_links_external_id_shaped
        CHECK (external_id <> '' AND octet_length(external_id) <= 512),
    -- OCTET_LENGTH, not `char_length`, because the surface that refuses these first counts
    -- BYTES. Two bounds on one value must agree on the unit or one of them is unreachable and
    -- the other produces a 500 nobody predicted; 0189 records being caught by exactly that.
    CONSTRAINT scim_push_links_last_error_bounded
        CHECK (last_error IS NULL OR octet_length(last_error) <= 2048),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- ON DELETE CASCADE, and this is a decision the table FORCED rather than a preference.
    --
    -- `scim_push_connections` is HARD deleted (0189 grants DELETE and the repository issues
    -- one). Without a cascade, adding this key would make that delete fail with 23503 the
    -- moment a connection had ever pushed anything -- a working management route broken by a
    -- table it never heard of, which is exactly the shape of defect a foreign key added without
    -- asking what already deletes the parent produces.
    --
    -- Cascade is also the right answer on the merits: a link is what ONE connection calls a
    -- subject in ONE downstream, and with the connection gone there is no downstream to address
    -- and no credential to address it with. Keeping the rows would preserve ids nothing can use.
    --
    -- `scim_push_connections_delete_cascades_its_links` drives it.
    FOREIGN KEY (connection_id) REFERENCES scim_push_connections (id) ON DELETE CASCADE
);

-- THE NAMESPACE, as an index rather than a convention: one link per subject per connection.
-- A second link for one subject would make "what does this downstream call them" ambiguous, and
-- the worker would pick whichever row it read first.
CREATE UNIQUE INDEX scim_push_links_unique_per_subject
    ON scim_push_links (tenant_id, environment_id, connection_id, resource_type, subject_id);

-- AND THE REVERSE, because the relation is one to one in both directions: one downstream id
-- names one subject. Without this a bug that wrote two subjects onto one downstream id would be
-- invisible until the two started overwriting each other downstream.
CREATE UNIQUE INDEX scim_push_links_unique_per_downstream_id
    ON scim_push_links (tenant_id, environment_id, connection_id, resource_type, downstream_id);

-- The operator-facing listing: this connection's links, oldest first. The SORT COLUMNS are part
-- of the index because the listing pages on them; 0189 records what leaving them out costs.
CREATE INDEX scim_push_links_by_connection
    ON scim_push_links (tenant_id, environment_id, connection_id, created_at, id);

ALTER TABLE scim_push_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_push_links FORCE ROW LEVEL SECURITY;

CREATE POLICY scim_push_links_scope ON scim_push_links
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The DATA plane owns this one, unlike `scim_push_connections` next door, and for the reason
-- 0184 gives about its own mirror: a link is written when the worker pushes a person, which is
-- sync work rather than an operator action. Routing it through the control plane would put an
-- operator in the middle of every push.
--
-- SELECT, INSERT and a COLUMN-SCOPED UPDATE, which is exactly what the repository methods in
-- this change perform: `upsert` writes a link and refreshes what a re-push changes, and
-- `record_failure` writes the error columns. The identity columns are NOT updatable: a link
-- whose `subject_id` or `downstream_id` could be re-pointed in place would let one bug silently
-- redirect a person's provisioning at another person's downstream record, and re-pointing is
-- what a DELETE and an INSERT are for -- two rows in the log rather than one that says "edited".
--
-- No DELETE grant. Nothing in this change deletes a link: a deprovision leaves the link so a
-- rehire resolves through it, exactly as 0184 argues for the inbound direction, and a connection
-- being removed takes its links with it through the cascade above rather than through a
-- statement. A DELETE grant would be a capability with no caller.
GRANT SELECT, INSERT ON scim_push_links TO ironauth_app;
GRANT UPDATE (downstream_id, external_id, last_synced_at, last_error_at, last_error, updated_at)
    ON scim_push_links TO ironauth_app;

-- The CONTROL plane reads, and has no caller yet. Granted anyway on the precedent 0184 cites
-- from 0087: deferring a grant the design already knows it needs produced a revoke-and-re-grant
-- churn, and the operator-facing question this answers -- "which of this connection's users are
-- failing, and what does the downstream call them" -- is owned by the health-surface slice of
-- this same issue. A SELECT confers no ability to change anything.
GRANT SELECT ON scim_push_links TO ironauth_control;

COMMENT ON TABLE scim_push_links IS
    'Issue #137: what a downstream calls each subject an outbound connection pushes, namespaced '
    'per connection because two downstreams allocate unrelated ids for one person.';
COMMENT ON COLUMN scim_push_links.downstream_id IS
    'Issue #137: server-issued by the DOWNSTREAM (RFC 7643 section 3.1); never parsed here, only '
    'echoed back in the path of a later PUT, PATCH or DELETE.';
