-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Versioned hook deploys and rollback (issue #114 criterion 5).
--
-- Criterion 5 asks that "versioned deploy ... and rollback ... work through the admin surface".
-- `token_hooks` holds ONE row per client and a redeploy overwrites it in place, so the previous
-- component was gone the moment the next one landed. There was nothing to roll back TO.
--
-- # Why a history table and not a version column on `token_hooks`
--
-- The dispatch reads `token_hooks` on EVERY hooked issuance. Making it multi-row and adding an
-- "which one is active" predicate puts a filter on the hottest read in the feature for the
-- benefit of a management operation nobody performs during a login.
--
-- So `token_hooks` stays exactly what it was -- one row, the ACTIVE hook, read unchanged -- and
-- this table is the append-only history beside it. A deploy writes both. A rollback copies a
-- historical row back over the active one, which means rollback is a deploy of an older
-- component and needs no second code path in the dispatch at all.
--
-- The cost, said rather than discovered: the component bytes are stored twice for the active
-- version, and the history is otherwise unbounded. A component may be eight megabytes, so a
-- client redeployed a thousand times would hold eight gigabytes of history nobody will roll
-- back to. `TOKEN_HOOK_VERSION_RETENTION` in the store prunes to the newest N on every deploy,
-- which is what the DELETE grant below is for; the retention lives there rather than here
-- because it is a policy number and this is a shape.
CREATE TABLE token_hook_versions (
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    client_id       text        NOT NULL,
    -- MONOTONIC PER CLIENT, assigned by the writer rather than by a sequence: a global sequence
    -- would leak how many hooks other tenants deploy, and an operator reading "version 4" of
    -- their own hook should see the fourth deploy of it.
    version         integer     NOT NULL,
    component       bytea       NOT NULL,
    payload_version integer     NOT NULL,
    failure_policy  text        NOT NULL,
    -- WHO and WHEN, because the question a rollback is answering is "what did it look like
    -- before the change that broke it", and that is a question about time.
    created_at      timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, environment_id, client_id, version),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),

    CONSTRAINT token_hook_versions_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT token_hook_versions_client_nonempty
        CHECK (client_id <> ''),
    CONSTRAINT token_hook_versions_version_positive
        CHECK (version > 0),
    -- THE SAME BOUNDS the active table carries. Duplicated deliberately: a history row is a
    -- candidate for becoming the active row, so anything this table admits that `token_hooks`
    -- would refuse is a rollback that fails at the write instead of at the read.
    CONSTRAINT token_hook_versions_component_bounded
        CHECK (octet_length(component) > 0 AND octet_length(component) <= 8388608),
    CONSTRAINT token_hook_versions_payload_version_known
        CHECK (payload_version = 1),
    CONSTRAINT token_hook_versions_failure_policy_known
        CHECK (failure_policy IN ('fail_closed', 'fail_open'))
);

-- Newest first per client, which is the only order the surface lists them in.
CREATE INDEX token_hook_versions_by_client
    ON token_hook_versions (tenant_id, environment_id, client_id, version DESC);

ALTER TABLE token_hook_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE token_hook_versions FORCE ROW LEVEL SECURITY;

CREATE POLICY token_hook_versions_scope ON token_hook_versions
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- CONTROL PLANE ONLY, and the DATA plane gets nothing at all -- not even SELECT.
--
-- `token_hooks` grants the data plane SELECT because the issuance path reads the active hook.
-- Nothing on the issuance path reads HISTORY: the dispatch wants the component that is live,
-- and a previous one is a management concern. A grant held by nobody is one an attacker cannot
-- inherit, and this is the rare case where the honest answer is no grant rather than a narrow
-- one.
GRANT SELECT, INSERT, DELETE ON token_hook_versions TO ironauth_control;
