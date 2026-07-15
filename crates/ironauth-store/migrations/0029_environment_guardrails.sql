-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Environments as first-class objects with typed guardrails (issue #42).
--
-- The environment LEVEL table (0001) already carries the identity of an
-- environment (id, tenant, display name, soft-delete). This migration makes an
-- environment TYPED: it records the environment's KIND (a closed set of dev,
-- staging, or prod) and its configured custom domain. The kind drives the typed
-- guardrail asymmetry the platform enforces on every config write (dev and
-- staging inherit the relaxed non-production set; prod gets the hard production
-- set), and the custom domain is the value the production custom-domain guardrail
-- requires (verification and ACME issuance are a later issue; this only records
-- what a prod environment must have configured).
--
-- Both columns are ENVIRONMENT-IDENTITY (issue #41 classification): they are part
-- of what makes this environment itself, so a config snapshot (issue #43) and a
-- promotion (issue #44) never copy them. Promoting dev to prod carries the
-- promotable configuration between two environments that keep their own kind,
-- domain, issuer, and keys; the guardrail asymmetry is exactly why prod cannot
-- inherit dev's laxity through a promotion.
--
-- What this migration does NOT change, because it already holds:
--   - environments is a LEVEL table (operator > tenant > environment), NOT a
--     tenant-scoped data-plane table, so it carries no row-level security and the
--     data-plane role ironauth_app has no DIRECT grant on it at all (0001). The
--     kind and domain columns live on that level table, exactly like the display
--     name: the management API (ironauth_control) reads and sets them.
--   - ironauth_control already holds SELECT and INSERT on environments (0003), so
--     it can persist the two new columns at environment creation with no new
--     grant. No UPDATE path rewrites kind or custom_domain after creation, so no
--     additional column-scoped UPDATE grant is added here.
--
-- What this migration DOES add, so the guardrails are enforced on the DATA plane
-- too (issue #42 acceptance 1, the http-loopback-in-prod rejection): a narrow,
-- scope-forced PROJECTION the data-plane role CAN read. The redirect guardrail has
-- to fire on the OIDC client-registration path (dynamic registration and the
-- static redirect-URI registration), which runs as ironauth_app and never touches
-- the level tables. Rather than grant the data plane a blanket SELECT on the whole
-- environments level table (which would expose every tenant's environments), this
-- adds a VIEW that returns ONLY the two guardrail columns and ONLY for the row
-- whose (tenant, environment) matches the request-bound scope session variables
-- (the same variables the repository binds with set_config and forced row-level
-- security keys on). A view runs with the DEFINER'S rights, so ironauth_app reads
-- through it without a direct grant on environments, and the view's own WHERE
-- clause is the isolation boundary: a data-plane connection can only ever see the
-- guardrails of the scope it is already bound to, and nothing else. The columns are
-- non-secret environment identity (a kind and a domain), so this projection widens
-- no confidentiality boundary; it only exposes, per bound scope, what that scope's
-- own guardrail check needs.
--
-- Shape: two additive ALTER TABLE ADD COLUMNs, one CHECK constraint, and one
-- read-only projection view. Purely additive, so this is an EXPAND.

-- ---------------------------------------------------------------------------
-- The environment kind: the closed set of dev, staging, or prod.
--
-- DEFAULT 'dev' makes the ADD COLUMN safe on a table that may already hold rows
-- (the safest kind: dev has the relaxed guardrails and requires no custom
-- domain). Every environment created through the management API supplies its
-- kind explicitly; the default only backfills any pre-existing row. The CHECK
-- pins the same three tokens the Rust EnvironmentType enum accepts, so a value
-- outside the closed set can never reach a row even if a caller bypassed the
-- application-layer parse.
ALTER TABLE environments ADD COLUMN kind text NOT NULL DEFAULT 'dev';
ALTER TABLE environments
    ADD CONSTRAINT environments_kind_valid
    CHECK (kind IN ('dev', 'staging', 'prod'));

-- ---------------------------------------------------------------------------
-- The configured custom domain (NULL when none is configured).
--
-- A production environment requires a non-NULL custom domain (enforced in the
-- application layer so the failure is a structured guardrail error listing the
-- failed guardrail, rather than a raw constraint violation). A non-production
-- environment may leave it NULL. Verification and ACME issuance are owned by a
-- separate issue; this column only records the configured value.
ALTER TABLE environments ADD COLUMN custom_domain text;

-- ---------------------------------------------------------------------------
-- Let the control plane provision an environment's DAY-ONE signing key.
--
-- Creating an environment provisions its own signing key in the SAME transaction
-- (issue #42), so a fresh environment serves discovery with its own issuer and a
-- disjoint JWKS immediately (the per-environment issuer machinery from issue #19).
-- Environment creation is a CONTROL-PLANE operation (ironauth_control), so the
-- control role needs INSERT on signing_keys; normal key rotation stays a
-- DATA-PLANE operation and ironauth_app keeps its own grants (0005).
--
-- Forced row-level security on signing_keys (0005) applies to ironauth_control
-- too (it is neither the table owner nor a superuser), and the environment-create
-- transaction binds the (tenant, environment) scope session variables before the
-- insert, so the isolation policy's WITH CHECK permits exactly the new
-- environment's own key and nothing else. INSERT only: the control plane never
-- reads, updates, or deletes signing keys (the JWKS serving and rotation paths are
-- the data plane's).
GRANT INSERT ON signing_keys TO ironauth_control;

-- ---------------------------------------------------------------------------
-- The scope-forced guardrail projection the data plane reads (issue #42).
--
-- Returns the guardrail-bearing columns of ONE environment: exactly the row whose
-- (tenant, environment) equals the request-bound scope session variables. The
-- WHERE clause is the isolation boundary, mirroring the row-level-security policy
-- on every tenant-scoped table (0001): on a pristine or pooled connection the
-- session variables are absent or the empty string, and an environment id is never
-- empty, so the view yields no row (deny by default). A view executes with its
-- definer's privileges, so the low-privilege data-plane role reads through it
-- without any direct grant on the environments level table, and can never widen
-- the projection beyond its own bound scope. The kind drives the typed guardrail
-- set the OIDC registration paths enforce (dev and staging relax an http loopback
-- redirect; prod hard-requires https), so the data plane can reject an
-- http-loopback redirect in a prod environment without reading the level table.
CREATE VIEW environment_guardrails AS
    SELECT tenant_id, id AS environment_id, kind, custom_domain
    FROM environments
    WHERE tenant_id = current_setting('ironauth.tenant_id', true)
      AND id = current_setting('ironauth.environment_id', true);

-- The data plane reads the projection (the registration guardrail check); the
-- control plane may read it too (guardrail enforcement on the management surface).
GRANT SELECT ON environment_guardrails TO ironauth_app;
GRANT SELECT ON environment_guardrails TO ironauth_control;
