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
-- this table is the history beside it: append-on-deploy, pruned to a retention bound, and
-- never updated in place. A deploy writes both. A rollback copies a
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
    -- WHEN, AND ONLY WHEN. The question a rollback answers is "what did it look like before
    -- the change that broke it", which is a question about time. There is deliberately no WHO
    -- here: the actor is on the audit record for `token_hook.set`, which is the artifact that
    -- exists to answer who, and duplicating it into a table with different retention would let
    -- the two disagree about the same deploy.
    --
    -- `clock_timestamp()`, NOT `now()`. `now()` is `transaction_timestamp()` -- when the
    -- transaction BEGAN -- and the serialisation this table depends on is precisely the case
    -- where that is wrong: two concurrent deploys are ordered by the `token_hooks` row lock,
    -- so the loser's version number is higher while its transaction started EARLIER. With
    -- `now()` the history publishes a higher version carrying an earlier timestamp, and
    -- `created_at_unix_micros` is what an operator reads to pick a rollback target.
    -- `clock_timestamp()` is read at the moment of the INSERT, which is after the lock was
    -- won, so it agrees with the version order.
    created_at      timestamptz NOT NULL DEFAULT clock_timestamp(),

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

-- NO SECOND INDEX. An earlier revision added
-- `(tenant_id, environment_id, client_id, version DESC)` for the newest-first listing, which is
-- the PRIMARY KEY's own columns with the last one reversed -- and Postgres scans a btree
-- backwards at the same cost, so it served no query the primary key did not already serve. It
-- cost a second index to maintain on every deploy and a second set of pages on a table whose
-- rows are megabytes each.

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

-- BACKFILL, because an empty history and "never deployed a hook" are not the same thing.
--
-- Without this, every hook already running on an upgraded install gets a table that does not
-- mention it. `listTokenHookVersions` would answer 200 with an empty list -- which the surface
-- documents as "this client has never had a hook" -- for a client whose hook is shaping tokens
-- right now, and `rollbackTokenHook` would have no target at all for exactly the components
-- most likely to need one: the ones deployed before anybody could roll back.
--
-- Version 1, because it is the first version this table knows about and the numbering is
-- per client. It is NOT a claim that the running component was that client's first deploy;
-- the deploys before this migration were not recorded, and no backfill can invent them. What
-- it does mean is precise and useful: the component running at upgrade time is in the history,
-- so the first post-upgrade deploy is version 2 and rolling back to 1 restores what was there
-- before the upgrade.
--
-- Every column is copied from the live row rather than defaulted, `failure_policy` included,
-- so a rollback to version 1 restores the CONFIGURATION that was running and not merely its
-- bytes. `created_at` is deliberately left to the column default -- the moment of the
-- migration -- because the real deploy time was never recorded and inventing an earlier one
-- would put a timestamp in the history that nothing measured.
INSERT INTO token_hook_versions
    (tenant_id, environment_id, client_id, version, component, payload_version, failure_policy)
SELECT tenant_id, environment_id, client_id, 1, component, payload_version, failure_policy
FROM token_hooks;
