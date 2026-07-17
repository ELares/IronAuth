-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Guarded account linking, the live wiring (issue #78, PR 2).
--
-- PR 1 landed the account_links table, the last usable method guard, and the pure
-- trust decision, all correct but unwired. PR 2 turns the subsystem on. Two additive
-- columns are all the schema this needs:
--
--   1. federation_login_states.link_target_user_id: the SERVER derived purpose marker
--      for the self service manual link flow. When an authenticated local user starts
--      a link (after a fresh re-authentication of their own account), the start leg
--      persists the TARGET local user id on the single use correlation row. The
--      callback re-derives it from the CONSUMED row (NEVER from anything the browser
--      sends), so the identity being linked is bound to the fresh re-auth that
--      authorized it and cannot be redirected to another account. NULL is an ordinary
--      federated login (no link purpose), today's behavior.
--
--   2. environments.auto_link_posture: the PER ENVIRONMENT auto-link posture override
--      (issue #78, FORK B). The deployment config carries the default posture
--      (oidc.federation.auto_link_posture, default off); this column lets an operator
--      set a DIFFERENT posture for a specific environment. NULL means "inherit the
--      deployment default", so the ADD COLUMN is additive and needs no backfill. The
--      closed set {off, verified_to_verified} is pinned by a CHECK so a value outside
--      the vocabulary can never reach a row. Like kind and custom_domain (0029) this
--      is ENVIRONMENT IDENTITY config on the environments LEVEL table: the data plane
--      reads it ONLY through the scope forced environment_guardrails projection view,
--      never through a direct grant on environments.
--
-- Migration safety obligation (see migrate.rs): both statements are additive ALTER
-- TABLE ADD COLUMNs plus one CREATE OR REPLACE VIEW that appends a column and one
-- column scoped GRANT. No table is created, no row is rewritten, so this is an EXPAND.

-- ---------------------------------------------------------------------------
-- The manual-link purpose marker on the single-use federation correlation row.
-- NULL for an ordinary federated login; a usr_ id for a self-service manual link.
ALTER TABLE federation_login_states ADD COLUMN link_target_user_id text;

-- ---------------------------------------------------------------------------
-- The per-environment auto-link posture override (NULL inherits the deployment
-- default). The CHECK pins the same two tokens the Rust AutoLinkPosture enum accepts,
-- so a value outside the closed set can never reach a row even if a caller bypassed
-- the application-layer parse.
ALTER TABLE environments ADD COLUMN auto_link_posture text;
ALTER TABLE environments
    ADD CONSTRAINT environments_auto_link_posture_valid
    CHECK (auto_link_posture IS NULL
        OR auto_link_posture IN ('off', 'verified_to_verified'));

-- Expose the new column to the data plane through the EXISTING scope-forced guardrail
-- projection (0029). Appending a column with CREATE OR REPLACE VIEW keeps the leading
-- columns and their order unchanged, so the existing guardrail read is unaffected. The
-- view is a definer projection whose WHERE clause pins the bound scope, so a data-plane
-- connection can only ever read its own environment's posture.
CREATE OR REPLACE VIEW environment_guardrails AS
    SELECT tenant_id, id AS environment_id, kind, custom_domain, auto_link_posture
    FROM environments
    WHERE tenant_id = current_setting('ironauth.tenant_id', true)
      AND id = current_setting('ironauth.environment_id', true);

-- The control plane sets the posture (a mutable per-environment operator setting,
-- unlike the create-time kind and custom_domain). A narrow, column-scoped UPDATE grant
-- keeps the control role from rewriting any other environment identity column.
GRANT UPDATE (auto_link_posture) ON environments TO ironauth_control;
