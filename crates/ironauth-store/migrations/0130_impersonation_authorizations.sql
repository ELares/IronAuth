-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The control plane's record that an operator may act as one user (issue #101).
--
-- WHY THIS TABLE EXISTS AT ALL, since a session already carries the same five facts.
--
-- Starting an impersonation means creating a session for the target user, and the control
-- plane cannot: 0006 and 0022 give `ironauth_control` SELECT on `sessions` plus a
-- column-scoped UPDATE for ending one, and INSERT belongs to `ironauth_app` alone.
--
-- The one-line fix, granting the control plane INSERT on `sessions`, is the wrong one.
-- `impersonator` is nullable, so nothing in such a grant distinguishes "start an audited
-- impersonation" from "mint an ordinary session for any user, unflagged and unaudited". A
-- grant cannot be conditioned on a column value, so there is no narrow version of it, and the
-- capability it would hand over is exactly the one the two-plane split exists to deny.
--
-- So the control plane writes an AUTHORIZATION and the app plane redeems it into a flagged
-- session. Session creation stays where it belongs, and the authorization becomes an auditable
-- object in its own right rather than a transient argument.
CREATE TABLE impersonation_authorizations (
    -- The `imp_` handle the operator redeems.
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The user to be impersonated.
    user_id        text        NOT NULL,
    -- The operator, as recorded on the session and in the `act` claim.
    impersonator   text        NOT NULL,
    -- The typed justification, in both halves. NOT NULL rather than an arc: unlike a session,
    -- which is ordinary until proven otherwise, this row has no meaning without them.
    reason_code    text        NOT NULL,
    reason_text    text        NOT NULL,
    -- Set by the WRITER from the same clock as the expiry, so the cap below compares two
    -- values from one clock. `created_at` is the database's and is deliberately not used for
    -- it, exactly as in 0128.
    started_at     timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    -- Redemption, single use. Both or neither.
    redeemed_at    timestamptz,
    redeemed_session_id text,
    CONSTRAINT impersonation_authorizations_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The same justification rule the sessions table carries, with the same explicit
    -- whitespace set: one-argument btrim strips spaces only, so a tab and a newline would
    -- otherwise pass for a written reason.
    CONSTRAINT impersonation_authorizations_reason_nonempty
        CHECK (
            btrim(impersonator, E' \t\r\n\f\v') <> ''
            AND btrim(reason_code, E' \t\r\n\f\v') <> ''
            AND btrim(reason_text, E' \t\r\n\f\v') <> ''
        ),
    -- THE HARD CAP, stated here as well as on the session it becomes. An authorization that
    -- could outlast the cap would simply move the problem one table earlier: the session it
    -- redeems into inherits this expiry.
    CONSTRAINT impersonation_authorizations_hard_cap
        CHECK (expires_at > started_at AND expires_at <= started_at + INTERVAL '60 minutes'),
    -- Redeemed means redeemed INTO something. A redemption stamp with no session would make
    -- the authorization spent with nothing to show for it, which reads in an audit as an
    -- impersonation that happened and left no trace.
    CONSTRAINT impersonation_authorizations_redemption_arc
        CHECK (
            (redeemed_at IS NULL AND redeemed_session_id IS NULL)
         OR (redeemed_at IS NOT NULL AND redeemed_session_id IS NOT NULL)
        ),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX impersonation_authorizations_scope_idx
    ON impersonation_authorizations (tenant_id, environment_id, created_at, id);

ALTER TABLE impersonation_authorizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE impersonation_authorizations FORCE ROW LEVEL SECURITY;
CREATE POLICY impersonation_authorizations_tenant_isolation ON impersonation_authorizations
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The control plane ISSUES and READS. It cannot mark one redeemed: redemption is the act of
-- creating a session, which is the app plane's alone, and a control plane that could stamp
-- `redeemed_at` could burn an authorization without one ever existing.
GRANT SELECT, INSERT ON impersonation_authorizations TO ironauth_control;

-- The app plane READS one to redeem it and stamps the result. It cannot INSERT: issuing is
-- the authorized, audited act and belongs to the plane that checked the permission.
GRANT SELECT ON impersonation_authorizations TO ironauth_app;
GRANT UPDATE (redeemed_at, redeemed_session_id)
    ON impersonation_authorizations TO ironauth_app;
