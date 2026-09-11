-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Time-boxed access requests with enforced requester/approver separation
-- (issue #145 criterion 4, EXPLORATORY).
--
-- The primitive behind "somebody needs this role for an afternoon". A
-- principal asks, a DIFFERENT principal decides, and an approval grants the
-- role until a deadline the approval itself sets. Nothing here is a general
-- IGA engine: there is no campaign, no catalogue, no risk scoring. It is the
-- smallest shape that answers the two questions an auditor asks about elevated
-- access, who agreed to it and when did it end.
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
-- refusal instead of a constraint violation, but the constraint is what makes
-- the word "impossible" true.
--
-- # WHAT IT SEPARATES: principals, not people
--
-- `requested_by` and `decided_by` hold `Principal::credential_ref()`, which is
-- a CREDENTIAL's actor id. A management key gets its own service id per key
-- and a console session gets a subject-derived human id, and nothing in this
-- deployment binds two credentials to one person. So one human holding two
-- management keys can raise under the first and decide under the second, and
-- every layer above passes because the two strings genuinely differ.
--
-- That is a real bound and it is stated rather than papered over: the
-- constraint enforces separation of PRINCIPALS. Closing it to people would
-- need an identity this system does not have -- a binding from credential to
-- human that survives key rotation -- and inventing one here would be a
-- guess wearing the word "person". It is measured by
-- `two_credentials_of_one_operator_are_two_principals_and_the_rule_does_not_see_it`
-- so a later reader finds the limit as a test rather than as a surprise.
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
    -- WHAT they would get, by SLUG. No foreign key, and there cannot be one: a
    -- role is keyed by (organization, slug) and the slug alone identifies no
    -- row. The management edge checks the role exists in the organization when
    -- the request is RAISED, so a typo is refused by the person who made it
    -- rather than approved by somebody who trusted it -- but this column
    -- itself does not establish existence, and a role deleted after the
    -- request was raised leaves a slug here pointing at nothing.
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
    -- AN APPROVAL ALWAYS HAS A DEADLINE, and an EXPIRED row keeps the one it
    -- had. The first half is what stops an approval granting for ever, which
    -- is the standing access this primitive exists to replace. The second is
    -- what stops the sweep destroying the answer to "when did it end": an
    -- earlier version required NULL for every non-approved state, so
    -- relabelling an elapsed grant erased its deadline and a row recording a
    -- three-hour elevation became indistinguishable from one recording three
    -- weeks.
    --
    -- A pending or denied row still carries none: neither ever granted.
    CONSTRAINT access_grant_requests_granted_until_iff_granted
        CHECK (
            (state IN ('approved', 'expired') AND granted_until IS NOT NULL)
            OR (state IN ('pending', 'denied') AND granted_until IS NULL)
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
-- COLUMN-SCOPED UPDATE, like 189 of the 225 UPDATE grants across these
-- migrations and unlike the blanket one this file first shipped with. Only the
-- four columns a decision or a sweep writes are writable; `requested_by`,
-- `subject_id`, `role_slug`, `organization_id` and `reason` are fixed at
-- INSERT and stay that way.
--
-- That matters here more than it usually would. The separation of duties
-- compares `decided_by` against `requested_by`, so a role that could rewrite
-- `requested_by` after the fact could make any decided row look as though a
-- second party approved it. The CHECK is evaluated per statement, not
-- retroactively, and would not notice.
GRANT SELECT, INSERT ON access_grant_requests TO ironauth_control;
GRANT UPDATE (state, decided_by, decided_at, granted_until)
    ON access_grant_requests TO ironauth_control;
GRANT SELECT ON access_grant_requests TO ironauth_app;
