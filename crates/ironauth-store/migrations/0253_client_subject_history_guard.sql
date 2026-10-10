-- SPDX-License-Identifier: MIT OR Apache-2.0
-- Existing clients may have public identities absent from retained history.
-- Do not enable pairwise until an explicit reconciliation has completed (#19).
-- Old client creators omit this field and remain pending. New creators set it
-- only on INSERT, because every new issuer now persists immutable bindings.
-- All serving issuers must be upgraded before pairwise activation; this schema
-- cannot make an old binary honor client identity policy.
ALTER TABLE clients
    ADD COLUMN subject_history_ready boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT client_subject_history_ready CHECK (
        subject_type = 'public' OR subject_history_ready
    );

-- Deliberately no UPDATE grant for the new column on either runtime role.
-- Reconciliation authority requires its own audited, narrow follow-up surface.
-- An unsupported partially deployed pairwise client makes this migration fail
-- rather than silently certifying its historical identity coverage.

CREATE OR REPLACE FUNCTION bump_client_subject_policy_revision() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.redirect_uris IS DISTINCT FROM OLD.redirect_uris
        OR NEW.subject_type IS DISTINCT FROM OLD.subject_type
        OR NEW.pairwise_sector IS DISTINCT FROM OLD.pairwise_sector
        OR NEW.sector_identifier_uri IS DISTINCT FROM OLD.sector_identifier_uri
        OR NEW.subject_policy_redirect_uris IS DISTINCT FROM OLD.subject_policy_redirect_uris
        OR NEW.subject_history_ready IS DISTINCT FROM OLD.subject_history_ready THEN
        NEW.subject_policy_revision := OLD.subject_policy_revision + 1;
    ELSE
        NEW.subject_policy_revision := OLD.subject_policy_revision;
    END IF;
    RETURN NEW;
END $$;
