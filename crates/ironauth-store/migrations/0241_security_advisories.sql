-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The security-advisory store (issue #163).
--
-- The advisories a deployment has accepted: either ingested from the polled
-- signed feed (online) or imported as the same signed bundle (offline). Every
-- row was VERIFIED before insertion (the feed module's single path); the store
-- is the banner surface's projection, never the trust decision.
--
-- Scope: advisories are deployment-global (an advisory names VERSIONS, not
-- tenants), so the table is unscoped - the management plane reads and writes it.
--
-- EXPAND: new table.
CREATE TABLE security_advisories (
    id             text        PRIMARY KEY,
    title          text        NOT NULL,
    severity       text        NOT NULL,
    affected_versions text     NOT NULL,
    summary        text        NOT NULL,
    published_at   bigint      NOT NULL,
    imported_at    timestamptz NOT NULL DEFAULT now(),
    -- How this deployment got the advisory (online poll or offline bundle); the
    -- audit trail tells an operator where a banner came from.
    source         text        NOT NULL
);

GRANT SELECT, INSERT ON security_advisories TO ironauth_control;
GRANT SELECT ON security_advisories TO ironauth_app;