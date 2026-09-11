-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Time-boxed access requests with enforced requester/approver separation
-- (issue #145 criterion 4, EXPLORATORY).
--
-- The primitive behind "somebody needs this role for an afternoon". A member
-- asks, a different member decides, and an approval grants the role until a
-- deadline the approval itself sets. Nothing here is a general IGA engine:
-- there is no campaign, no catalogue, no risk scoring. It is the smallest
-- shape that answers the two questions an auditor asks about elevated access,
-- who agreed to it and when did it end.
--
-- # Separation of duties is a CONSTRAINT, not a handler check
--
-- The criterion asks for self-approval to be "impossible", and a handler
-- comparing two strings is not that: it is impossible only along the paths
-- that call it. Every other door -- a second handler added later, a bulk
-- import, a support script, a repair query run against the database at two in
-- the morning -- reaches the same table without passing it.
--
-- `access_grant_requests_decider_is_not_requester` is checked by Postgres on
-- every INSERT and every UPDATE from every connection, including the owner's.
-- A handler check is still worth having, because it returns a comprehensible
-- 403 instead of a constraint violation, but the constraint is what makes the
-- word "impossible" true.
--
-- # Why the grant deadline lives on this row
--
-- An approval that granted a role and forgot when to take it back would leave
-- the standing access this exists to avoid. `granted_until` is NOT NULL for an
-- approved row, so the deadline cannot be omitted; the read path treats a row
-- past it as granting nothing, and a sweeper moves it to `expired` so the
-- listing says so too. Both, deliberately: the sweeper keeps the record
-- honest and the read path means a sweeper that is not running cannot leak
-- access.

CREATE TABLE access_grant_requests (
    -- The `agr_` scoped identifier.
    id                  text        PRIMARY KEY,
    tenant_id           text        NOT NULL,
    environment_id      text        NOT NULL,
    -- Which organization's role is being asked for. Access requests are
    -- organization-scoped because the roles they grant are.
    organization_id     text        NOT NULL,
    -- WHO WOULD GET THE ACCESS. Usually the requester, but not necessarily: a
    -- manager may raise a request on behalf of somebody else, and that is the
    -- case the separation constraint must not be confused by. It keys on the
    -- requester and the decider, never on the subject.
    subject_id          text        NOT NULL,
    -- WHAT they would get: a role that must exist in this organization.
    role_slug           text        NOT NULL,
    -- WHO ASKED. An opaque principal string, matching `decided_by` below, so
    -- the constraint between them compares like with like.
    requested_by        text        NOT NULL,
    -- Why, in the requester's own words. Recorded because an approval whose
    -- reason nobody wrote down is one nobody can review afterwards.
    reason              text        NOT NULL,
    state               text        NOT NULL DEFAULT 'pending',
    -- WHO DECIDED, and when. NULL while pending.
    decided_by          text,
    decided_at          timestamptz,
    -- When the granted access ends. Set by the approval, never by the request:
    -- a requester who chose their own deadline would be deciding half of what
    -- the approver is there to decide.
    granted_until       timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT access_grant_requests_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT access_grant_requests_state_closed
        CHECK (state IN ('pending', 'approved', 'denied', 'expired')),
    -- THE SEPARATION OF DUTIES. An approver may not be the requester, on any
    -- path, from any connection. Written as `IS NULL OR <>` so a pending row
    -- (no decider yet) is unaffected and a decided one cannot name the person
    -- who asked.
    CONSTRAINT access_grant_requests_decider_is_not_requester
        CHECK (decided_by IS NULL OR decided_by <> requested_by),
    -- A decided row names when and by whom; a pending one names neither.
    CONSTRAINT access_grant_requests_decision_paired
        CHECK (
            (state = 'pending' AND decided_at IS NULL AND decided_by IS NULL)
            OR (state <> 'pending' AND decided_at IS NOT NULL AND decided_by IS NOT NULL)
        ),
    -- ONLY an approved row grants, and an approved row ALWAYS has a deadline.
    -- The second half is the one that matters: without it an approval could
    -- omit `granted_until` and grant for ever, which is the standing access
    -- this primitive exists to replace.
    CONSTRAINT access_grant_requests_granted_until_iff_approved
        CHECK (
            (state = 'approved' AND granted_until IS NOT NULL)
            OR (state <> 'approved' AND granted_until IS NULL)
        ),
    -- Non-empty where empty would mean "unspecified". A blank reason or role
    -- passes every type check and answers nothing.
    CONSTRAINT access_grant_requests_fields_nonempty
        CHECK (
            organization_id <> '' AND subject_id <> '' AND role_slug <> ''
            AND requested_by <> '' AND reason <> ''
        ),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    FOREIGN KEY (organization_id) REFERENCES organizations (id)
);

-- The queue listing: what is waiting in this organization, oldest first.
CREATE INDEX access_grant_requests_pending
    ON access_grant_requests (tenant_id, environment_id, organization_id, state, created_at);

-- The sweeper's query: approved rows whose deadline has passed, across the
-- whole scope. Partial, because the sweep only ever asks about approved rows
-- and the table is dominated by decided ones.
CREATE INDEX access_grant_requests_due
    ON access_grant_requests (granted_until)
    WHERE state = 'approved';

ALTER TABLE access_grant_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_grant_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY access_grant_requests_scope ON access_grant_requests
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The management plane raises, decides and sweeps. The data plane READS, so a
-- token-issuing path can ask whether a time-boxed grant is live, and writes
-- nothing: an access request the data plane could approve would be one the
-- holder of any client credential could approve.
GRANT SELECT, INSERT, UPDATE ON access_grant_requests TO ironauth_control;
GRANT SELECT ON access_grant_requests TO ironauth_app;
