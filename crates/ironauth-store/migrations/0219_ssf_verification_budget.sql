-- Shared Signals: a verification budget the receiver cannot reset (issue #143).
--
-- 0218 put `last_verification_at` on `ssf_streams`, and that column is enough to space out
-- verification requests FOR ONE STREAM. It is not enough to bound the work, and the reason is
-- that the row it lives on is one the receiver owns outright: `DELETE /ssf/streams` removes it,
-- the next `POST /ssf/streams` returns a stream whose `last_verification_at` is NULL, and NULL
-- is admitted immediately. So `create -> verify -> delete -> create` mints signed SETs as fast
-- as a client can issue three requests, and the advertised floor stops none of it. Measured in
-- review, not hypothesised.
--
-- THIS TABLE IS KEYED ON THE CLIENT, whose row the receiver cannot delete, so the budget
-- survives every stream it churns through.
--
-- A FIXED WINDOW, AND THE ALLOWANCE IS THE STREAM CEILING. A receiver may legitimately hold
-- `ssf.max_streams_per_client` streams and verify each once per interval, so that count is
-- exactly the honest maximum and anything past it is a receiver asking for work it cannot use.
-- A fixed window rather than a token bucket because the quantity being bounded is coarse and
-- the simpler statement is the one whose atomicity is obvious: the claim is a single
-- `INSERT ... ON CONFLICT DO UPDATE ... RETURNING`, which takes the row lock, so concurrent
-- requests serialise rather than all reading one stale count.
--
-- BOTH FLOORS STAY. The per-stream column gives the precise refusal a receiver can act on
-- ("this stream, too soon"); this one is what makes the bound real. A request refused by the
-- per-stream floor does NOT reach here, and a request refused here has already spent nothing
-- else, because this is claimed first.

CREATE TABLE ssf_verification_budget (
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The receiver. One row per client per environment, for the whole life of the client.
    client_id      text        NOT NULL,
    -- When the current window opened. A claim arriving after `window_started_at + interval`
    -- opens a new window rather than extending this one.
    window_started_at timestamptz NOT NULL,
    -- How much of this window the receiver has used. CLAMPED at one past the allowance by the
    -- claiming statement, so a client hammering a closed window cannot grow the number without
    -- bound and cannot overflow it.
    spent          integer     NOT NULL,

    PRIMARY KEY (tenant_id, environment_id, client_id),

    CONSTRAINT ssf_verification_budget_spent_sane CHECK (spent >= 0),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- COMPOSITE, exactly as 0216 pins a stream's client: the client must be one in THIS
    -- environment, not merely one that exists. CASCADE because a deleted receiver has no budget
    -- to keep, and keeping one would refuse the next client that reused the identifier.
    FOREIGN KEY (client_id, tenant_id, environment_id)
        REFERENCES clients (id, tenant_id, environment_id) ON DELETE CASCADE
);

ALTER TABLE ssf_verification_budget ENABLE ROW LEVEL SECURITY;
ALTER TABLE ssf_verification_budget FORCE ROW LEVEL SECURITY;

CREATE POLICY ssf_verification_budget_scope ON ssf_verification_budget
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- THE DATA PLANE OWNS IT, because the claim happens on a request path. INSERT and a narrow
-- UPDATE: the claim is an upsert, so it needs both, and it writes only the two columns that
-- describe the window.
--
-- NO DELETE. A budget row is not the receiver's to discard, which is the entire point of moving
-- the counter off a row the receiver can delete. Rows go away with the client, by CASCADE.
GRANT SELECT, INSERT ON ssf_verification_budget TO ironauth_app;
GRANT UPDATE (window_started_at, spent) ON ssf_verification_budget TO ironauth_app;
-- The CONTROL plane reads them: an operator asking why a receiver is being refused wants this.
GRANT SELECT ON ssf_verification_budget TO ironauth_control;
