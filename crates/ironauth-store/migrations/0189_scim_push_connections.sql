-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Outbound SCIM connections (issue #137): where an environment PUSHES its directory.
--
-- The mirror of `scim_connections` (0183), and the direction is the whole difference. Inbound, an
-- identity provider holds a token and writes into IronAuth; outbound, IronAuth holds a credential
-- and writes into a downstream application. That inversion is why `externalId` swaps sides
-- downstream and why this table needs a cursor: an inbound connection is driven by whoever calls
-- it, an outbound one has to remember how far it has got.
--
-- THE TOKEN IS NOT A COLUMN. `credential_secret_name` names an `environment_secrets` row, exactly
-- as `0144_log_stream_signing_secret.sql` does, and the value is resolved at push time through
-- the sealing path that already exists (per-scope DEK, AAD from `secret_seal_aad`). Two reasons:
-- a second sealed column would be a second sealing path to get right, and naming the secret gives
-- rotation for free -- an operator rotates the secret, and every connection naming it follows.

CREATE TABLE scim_push_connections (
    id                       text        PRIMARY KEY,
    tenant_id                text        NOT NULL,
    environment_id           text        NOT NULL,
    -- The organization whose users and groups are pushed. An outbound connection is per
    -- organization for the same reason an inbound one is: a credential that could reach two
    -- organizations is the IDOR this model exists to make unrepresentable.
    organization_id          text        NOT NULL,
    display_name             text        NOT NULL,
    -- The SCIM base URL of the downstream application, https only. Enforced at the surface
    -- rather than here, because a CHECK constraint cannot say why.
    base_url                 text        NOT NULL,
    credential_secret_name   text        NOT NULL,
    -- How IronAuth attributes map onto the downstream schema. Empty means the core mapping.
    attribute_mapping        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    -- RFC 7644 filters deciding WHICH users and groups are in scope for this connection. Parsed
    -- before they are written: an unparseable filter stored here would fail at every push
    -- instead of at configuration time, which is the wrong place to find out.
    user_scope_filter        text,
    group_scope_filter       text,
    write_mode               text        NOT NULL DEFAULT 'patch'
                                         CHECK (write_mode IN ('patch', 'put')),
    -- What a departure means downstream. `deactivate` is the default because it is what most
    -- deployments actually want: a DELETE against a downstream directory is not reversible and
    -- an accidental scope change should not be.
    deletion_policy          text        NOT NULL DEFAULT 'deactivate'
                                         CHECK (deletion_policy IN ('deactivate', 'delete')),
    active                   boolean     NOT NULL DEFAULT true,
    -- HOW FAR THE WORKER HAS GOT, and it advances only on success, so a downstream outage pauses
    -- the cursor rather than dropping events. That is the property that makes this a cursor
    -- consumer rather than an outbox consumer: the outbox substrate dead-letters after a bounded
    -- attempt budget and moves on, which is the opposite of what a directory push needs.
    cursor_sequence          bigint,
    backfill_state           text        NOT NULL DEFAULT 'pending'
                                         CHECK (backfill_state IN ('pending', 'users', 'groups', 'done')),
    backfill_after_created_at timestamptz,
    backfill_after_id        text,
    -- The newest sequence visible BEFORE the backfill began. Captured first and applied last, so
    -- an event that lands mid-backfill is replayed rather than skipped.
    backfill_from_sequence   bigint,
    -- Operator-facing health, in the shape `log_streams` (0137) already uses.
    last_success_at          timestamptz,
    last_error_at            timestamptz,
    last_error               text,
    consecutive_failures     integer     NOT NULL DEFAULT 0,
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT scim_push_connections_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT scim_push_connections_display_name_nonempty
        CHECK (display_name <> ''),
    -- BOUNDED. All three are operator supplied and none has a natural length, so without a
    -- bound the only limit is the request body limit and a single row can carry megabytes.
    --
    -- NOT "like the inbound mirror bounds its label", which an earlier version of this comment
    -- said and which is false: 0183 carries only `display_name <> ''` and no length constraint
    -- at all. The inbound bound lives in its HANDLER, at 252 bytes, precisely because 0183 is
    -- shipped and checksummed and cannot gain one. This table is new, so the bound can live
    -- where a bound belongs, with the surface refusing first so the CHECK is never what a
    -- caller meets.
    --
    -- OCTET_LENGTH, not `char_length`. The surface refuses these first, in Rust, where `len()`
    -- counts BYTES; a `char_length` bound would count CHARACTERS, so a 200-character string of
    -- three-byte characters would pass the column and be refused by the surface, or the reverse
    -- for a bound set the other way. Two bounds on one value must agree on the unit or one of
    -- them is unreachable and the other produces a 500 nobody predicted.
    CONSTRAINT scim_push_connections_display_name_bounded
        CHECK (octet_length(display_name) <= 252),
    CONSTRAINT scim_push_connections_credential_secret_name_shaped
        CHECK (credential_secret_name <> '' AND octet_length(credential_secret_name) <= 252),
    CONSTRAINT scim_push_connections_base_url_bounded
        CHECK (base_url <> '' AND octet_length(base_url) <= 2048),
    -- An OBJECT, not merely valid JSON. The column is documented as a mapping whose empty value
    -- is `{}`, and `jsonb` alone accepts `null`, `3` and `[]` for it. 0187 ships this same CHECK
    -- for the same shape of column.
    CONSTRAINT scim_push_connections_attribute_mapping_object
        CHECK (jsonb_typeof(attribute_mapping) = 'object'),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- The organization must EXIST, and that is ALL this key does. The distinction is worth
    -- spelling out because the slice's own prose got it wrong before a review measured it:
    -- referential integrity checks BYPASS row-level security, so an id-only key admits any
    -- globally existing organization, another tenant's included. What refuses a cross-scope one
    -- is the repository, which takes a scope-checked `OrganizationId`. A composite key would say
    -- it here too, but `organizations` carries no `UNIQUE (id, tenant_id, environment_id)` to
    -- reference. Identical to 0183; the first version of this table declared no keys at all
    -- while three comments elsewhere reasoned about the one it did not have.
    FOREIGN KEY (organization_id) REFERENCES organizations (id)
);

-- The management listing: every connection for one organization, oldest first. The SORT COLUMNS
-- are part of the index because the query orders by them and pages on them; without the pair the
-- index serves the filter and leaves the sort to a heap sort, which is what 0183 already learned.
--
-- There is no second index for the worker. One was here, justified in the present tense by a
-- worker this same file says does not exist yet, which is the rule this file states and then
-- broke: an index for a query nothing issues is a write cost nobody can account for. It arrives
-- with the worker.
CREATE INDEX scim_push_connections_by_org
    ON scim_push_connections (tenant_id, environment_id, organization_id, created_at, id);

ALTER TABLE scim_push_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_push_connections FORCE ROW LEVEL SECURITY;

CREATE POLICY scim_push_connections_scope ON scim_push_connections
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The CONTROL plane owns the lifecycle, as it does for inbound: creating one of these points a
-- credential at somebody else's directory, which is squarely an operator action.
--
-- UPDATE IS COLUMN SCOPED, and scoped to the TWO COLUMNS A STATEMENT ACTUALLY WRITES. The only
-- UPDATE against this table in the workspace is `set_active`, which sets `active` and
-- `updated_at`; nothing edits a connection in place.
--
-- The first version granted ten columns, on the reasoning that an operator legitimately edits a
-- connection's configuration. That reasoning describes an operation THIS SLICE DOES NOT HAVE:
-- there is no update route, no repository method, and no statement. A grant for a write nothing
-- performs is a permission nobody can account for, which is the rule stated three paragraphs
-- down for the data plane and which the control grant then broke. The columns arrive with the
-- edit route, if one is added.
--
-- WHAT COLUMN SCOPING DOES AND DOES NOT BUY. It stops an existing connection being silently
-- re-pointed: `organization_id` and `credential_secret_name` cannot be changed under a handle
-- that keeps its identity, so a connection an operator audited stays the connection they
-- audited. It is NOT a fence against the control role reaching another organization at all --
-- that role also holds INSERT and DELETE, so it can remove a connection and create a different
-- one. The difference is that doing so mints a NEW id and writes two audit rows with two
-- actions, which is visible, where an in-place UPDATE would have been one row saying the
-- connection was edited. An earlier version of this paragraph claimed the stronger property.
--
-- `cursor_sequence`, `backfill_*` and the health columns are NOT here. They are the worker's,
-- the worker runs on the data plane, and it does not exist yet: the grant that lets it advance
-- its own cursor belongs in the migration that adds it, so this one cannot be read as having
-- already permitted it.
GRANT SELECT, INSERT, DELETE ON scim_push_connections TO ironauth_control;
GRANT UPDATE (active, updated_at) ON scim_push_connections TO ironauth_control;

CREATE POLICY scim_push_connections_control ON scim_push_connections
    TO ironauth_control
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The DATA plane READS ONLY, for now. The push worker will need to advance its cursor and
-- record its health, and that grant arrives with the worker rather than ahead of it: a table
-- that permits a write nothing performs is a permission nobody can account for.
GRANT SELECT ON scim_push_connections TO ironauth_app;
