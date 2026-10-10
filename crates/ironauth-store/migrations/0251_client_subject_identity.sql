-- SPDX-License-Identifier: MIT OR Apache-2.0
-- Persist client identity policy and immutable issued-subject bindings (#19).
-- Existing clients remain public. Registration must not enable pairwise until
-- every serving binary understands the policy; old binaries ignore these columns.
ALTER TABLE clients
    ADD COLUMN subject_type text NOT NULL DEFAULT 'public',
    ADD COLUMN pairwise_sector text,
    ADD COLUMN sector_identifier_uri text,
    ADD COLUMN subject_policy_redirect_uris text[],
    ADD COLUMN subject_policy_revision bigint NOT NULL DEFAULT 0,
    ADD CONSTRAINT client_subject_policy_valid CHECK (
        (subject_type = 'public' AND pairwise_sector IS NULL
            AND sector_identifier_uri IS NULL AND subject_policy_redirect_uris IS NULL)
        OR (subject_type = 'pairwise' AND pairwise_sector IS NOT NULL
            AND length(pairwise_sector) BETWEEN 1 AND 255
            AND subject_policy_redirect_uris IS NOT NULL
            AND redirect_uris IS NOT DISTINCT FROM subject_policy_redirect_uris)
    ),
    ADD CONSTRAINT client_subject_policy_revision_nonnegative CHECK (subject_policy_revision >= 0);

-- A redirect edit invalidates a prior validation even if a later edit restores
-- the original URIs (ABA). All writers share this revision, including old writers.
CREATE FUNCTION bump_client_subject_policy_revision() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.redirect_uris IS DISTINCT FROM OLD.redirect_uris
        OR NEW.subject_type IS DISTINCT FROM OLD.subject_type
        OR NEW.pairwise_sector IS DISTINCT FROM OLD.pairwise_sector
        OR NEW.sector_identifier_uri IS DISTINCT FROM OLD.sector_identifier_uri
        OR NEW.subject_policy_redirect_uris IS DISTINCT FROM OLD.subject_policy_redirect_uris THEN
        NEW.subject_policy_revision := OLD.subject_policy_revision + 1;
    ELSE
        NEW.subject_policy_revision := OLD.subject_policy_revision;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER client_subject_policy_revision BEFORE UPDATE ON clients
    FOR EACH ROW EXECUTE FUNCTION bump_client_subject_policy_revision();

GRANT UPDATE (subject_type, pairwise_sector, sector_identifier_uri,
    subject_policy_redirect_uris) ON clients TO ironauth_app;

ALTER TABLE users ADD CONSTRAINT users_subject_scope_identity_unique
    UNIQUE (id, tenant_id, environment_id);

CREATE TABLE client_subject_bindings (
    tenant_id text NOT NULL,
    environment_id text NOT NULL,
    client_id text NOT NULL,
    user_id text NOT NULL,
    external_subject text NOT NULL,
    policy_revision bigint NOT NULL CHECK (policy_revision >= 0),
    created_at timestamptz NOT NULL,
    CONSTRAINT client_subject_bindings_scope_nonempty CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT client_subject_bindings_subject_valid CHECK (
        length(external_subject) BETWEEN 1 AND 255
        AND external_subject ~ '^[A-Za-z0-9_-]+$'
    ),
    PRIMARY KEY (tenant_id, environment_id, client_id, user_id),
    UNIQUE (tenant_id, environment_id, client_id, external_subject),
    FOREIGN KEY (client_id, tenant_id, environment_id)
        REFERENCES clients (id, tenant_id, environment_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id, tenant_id, environment_id)
        REFERENCES users (id, tenant_id, environment_id) ON DELETE CASCADE,
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);
ALTER TABLE client_subject_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_subject_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY client_subject_bindings_scope ON client_subject_bindings
    USING (tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true))
    WITH CHECK (tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true));
-- No UPDATE or DELETE: an issued identity is immutable. Explicit parent purge
-- removes the mapping through its scoped foreign key, never a reassignment.
GRANT SELECT, INSERT ON client_subject_bindings TO ironauth_app;
