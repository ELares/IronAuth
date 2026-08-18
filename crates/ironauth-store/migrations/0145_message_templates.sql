-- The message template store (issue #111 criterion 3, and the store #619 is blocked on).
--
-- # One table, four levels
--
-- `message_template.rs` already resolves Default > ... no: Organization > Environment >
-- Tenant > Default, in that precedence. The DEFAULT level is what IronAuth ships and is not
-- stored, which is why resolution cannot fail; this table holds the three OVERRIDE levels.
--
-- The level is a column rather than three tables because resolution walks the levels in one
-- pass: three tables would be three reads and a join whose only purpose is to reassemble what
-- one ordered read already gives.
--
-- # Why `organization_id` is nullable rather than a separate table
--
-- A tenant-level and an environment-level override differ only in how much of the tree they
-- cover, and an organization-level one adds a third scope to the same key. Splitting them
-- would duplicate the body storage and the locale handling three times, and the uniqueness
-- rule below is what actually keeps the levels apart.
--
-- # Credentials
--
-- None here, ever, for the reason 0137 gives about log streams: a template is rendered into a
-- message, and a store that could hold an SMTP credential is a store that can leak one
-- through a config read, an export, or a promotion snapshot.

CREATE TABLE message_templates (
    -- The `mtp_` scoped identifier; embeds its (tenant, environment).
    id                text        PRIMARY KEY,
    tenant_id         text        NOT NULL,
    environment_id    text        NOT NULL,

    -- Which level defined it: 'tenant', 'environment' or 'organization'. NOT 'default' --
    -- the shipped template is code, not a row, which is what makes resolution total.
    level             text        NOT NULL,
    CONSTRAINT message_templates_level_valid
        CHECK (level IN ('tenant', 'environment', 'organization')),

    -- Set for an organization-level override, NULL otherwise. The CHECK ties the two
    -- together so a row cannot claim to be organization-level without naming one, or claim
    -- to be tenant-level while carrying one -- either would resolve in a way nobody wrote.
    organization_id   text,
    CONSTRAINT message_templates_organization_matches_level
        CHECK (
            (level = 'organization' AND organization_id IS NOT NULL)
            OR (level <> 'organization' AND organization_id IS NULL)
        ),

    -- Which message this is a template FOR (for example 'invitation', 'email_otp').
    kind              text        NOT NULL,
    -- The BCP 47 tag the body is written in. Locale fallback is the resolver's job.
    locale            text        NOT NULL,

    -- The rendered subject line and bodies. `body_ref` in the resolver is an opaque handle;
    -- here it is the row's own id, so the resolver stays free of storage concerns.
    subject           text        NOT NULL,
    body_text         text        NOT NULL,
    body_html         text,

    -- ISSUE #619's per-field lock, included NOW because it is cheap in a new table and
    -- expensive to add to one carrying data.
    --
    -- When TRUE, this level's override PINS: no narrower level may replace it. That is the
    -- "outermost pins only when it opts in" shape, and it is the only one of the three
    -- candidates on #619 that lets both readings coexist -- a tenant that wants to mandate
    -- its branding can, and one that does not leaves organizations free to override.
    --
    -- Defaulting to FALSE means the default behaviour is innermost-wins, which is what every
    -- other product does and what the branding use case wants. Nothing changes for anyone who
    -- never sets it.
    locked            boolean     NOT NULL DEFAULT false,

    created_at        timestamptz NOT NULL,
    updated_at        timestamptz NOT NULL,
    deleted_at        timestamptz,

    FOREIGN KEY (tenant_id, environment_id)
        REFERENCES environments (tenant_id, id) ON DELETE CASCADE
);

-- One LIVE template per (scope, level, organization, kind, locale). Partial on deleted_at so a
-- soft-deleted override frees its slot, matching every other soft-deleted resource here.
--
-- Two indexes rather than one because `organization_id` is nullable and NULLs are DISTINCT in
-- a unique index: a single index over the nullable column would let a tenant-level override be
-- created twice, since NULL never equals NULL. That is the nullable-column trap, and it is
-- silent -- the second row simply resolves ahead of or behind the first depending on read
-- order.
CREATE UNIQUE INDEX message_templates_unique_org
    ON message_templates (tenant_id, environment_id, organization_id, kind, locale)
    WHERE deleted_at IS NULL AND organization_id IS NOT NULL;

CREATE UNIQUE INDEX message_templates_unique_scope
    ON message_templates (tenant_id, environment_id, level, kind, locale)
    WHERE deleted_at IS NULL AND organization_id IS NULL;

-- Resolution reads every candidate for one (scope, kind) in one pass and lets
-- `resolve_template` pick, so the index is on what that read filters by.
CREATE INDEX message_templates_resolution
    ON message_templates (tenant_id, environment_id, kind)
    WHERE deleted_at IS NULL;

ALTER TABLE message_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE message_templates FORCE ROW LEVEL SECURITY;

CREATE POLICY message_templates_scope ON message_templates
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The app role RENDERS, so it reads. It must not author: authoring a template is a management
-- act, and an app role that could write one could rewrite what every recipient is sent.
GRANT SELECT ON message_templates TO ironauth_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON message_templates TO ironauth_control;
