-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- CIBA backchannel authentication requests (issue #131, OpenID Connect Client
-- Initiated Backchannel Authentication Flow -- Core 1.0), poll and ping modes.
--
-- A client asks the backchannel authentication endpoint to authenticate a user it
-- names but does not have in front of it. The endpoint answers an auth_req_id; the
-- user approves on their own authentication device; the client then obtains tokens
-- either by POLLING the token endpoint (poll mode) or by being PINGED at its
-- notification endpoint and then fetching (ping mode). This migration ships the
-- single tenant-scoped table the flow lives in.
--
-- Numbered 0144, which two other open pull requests also claim (message templates,
-- flow targets). Whichever two land first take 0144 and 0145 and this one becomes
-- 0146. Skipping ahead to avoid the churn is NOT an option: the registry asserts
-- `registry_versions_are_contiguous_from_one`, so a gap fails the build. The
-- collision is invisible to git because the three filenames differ; what conflicts
-- is migrate.rs and the chain checkpoint, which is where it will surface.
--
-- Credential-at-rest discipline, modelled on device_codes (0021):
--
--   * auth_req_id_digest is the SHA-256 DIGEST of the WHOLE auth_req_id
--     (`ira_bar_<jti>~<secret>`), never the plaintext. The auth_req_id declares its
--     own (tenant, environment) through the embedded jti, so the GLOBAL /token
--     endpoint recovers the scope and runs this RLS-scoped digest resolve. A
--     database dump yields nothing replayable.
--
--   * client_notification_token is the one credential here that CANNOT be reduced
--     to a digest, and the reason is worth stating because it is the opposite of
--     the usual rule. It is a token the CLIENT supplies and the server must REPLAY
--     to the client's notification endpoint so the client can authenticate the
--     ping. A digest cannot be replayed. It is therefore stored under the same
--     envelope encryption as other recoverable secrets rather than hashed, it is
--     never logged, and it is column-scoped out of the data plane's UPDATE grant
--     below so it is write-once at INSERT.
--
-- Single-use redemption (CIBA Core section 11, and issue #131 criterion 3) is
-- enforced by the status column, not by deletion: a redeemed request keeps its row
-- so a replay is answered with a definite invalid_grant rather than the
-- indistinguishable "unknown id", and so the audit trail survives the redemption.
--
-- Tenant-scoped and isolated exactly like device_codes: mandatory tenant_id and
-- environment_id, the nonempty-scope CHECK, forced row-level security keyed on the
-- transaction-local session variables, isolation-preserving composite foreign keys,
-- and reachable only through the scoped repository (ironauth_app).
--
-- Migration safety obligation (see migrate.rs): each new tenant-scoped table
-- ENABLEs and FORCEs row-level security, adds the (tenant, environment) policy and
-- the nonempty-scope CHECK, and is registered in scripts/query-audit.sh. This table
-- does all four.

CREATE TABLE backchannel_authentication_requests (
    -- The SHA-256 hex digest of the WHOLE presented auth_req_id. The poll lookup
    -- key: the token endpoint hashes the presented auth_req_id and matches it here.
    -- Unique because the auth_req_id carries >= 256 bits of entropy. The plaintext
    -- is NEVER stored: only this one-way digest.
    auth_req_id_digest        text        PRIMARY KEY,
    tenant_id                 text        NOT NULL,
    environment_id            text        NOT NULL,
    -- The request's logical identifier (a bar_ scoped id, the routing handle
    -- embedded in the auth_req_id). A NON-secret handle: the approval surface
    -- carries it to bind a human's decision to a request WITHOUT ever seeing the
    -- auth_req_id, and it is the audit target. Unique per environment.
    id                        text        NOT NULL,
    -- The OAuth client (a cli_ scoped id string) the request belongs to. The
    -- redemption compares this against the AUTHENTICATED client at the token
    -- endpoint: an auth_req_id is bound to the client that asked for it, and
    -- another client presenting it is refused (issue #131 criterion 3).
    client_id                 text        NOT NULL,
    -- Which delivery mode the client registered for this request: 'poll' or 'ping'.
    -- 'push' is deliberately absent from the vocabulary rather than merely rejected
    -- in application code -- see docs/WILL-NOT-IMPLEMENT.md, which records that push
    -- has the weakest security properties of the three modes and is forbidden by the
    -- FAPI-CIBA profile. A CHECK is the enforcement that survives a future writer
    -- who has not read that document.
    delivery_mode             text        NOT NULL,
    -- The client's notification endpoint, required for ping mode and NULL for poll.
    -- Paired with delivery_mode by a CHECK below.
    client_notification_url   text,
    -- The client-supplied bearer token the ping notification must carry back, so the
    -- client can authenticate the notification as genuinely ours. Encrypted at rest
    -- (see the header note): it must be REPLAYED, so it cannot be a digest. Required
    -- for ping mode and NULL for poll, paired by the same CHECK.
    client_notification_token bytea,
    -- The OAuth scope requested at the backchannel endpoint, echoed into the issued
    -- tokens, or NULL when the request carried none.
    requested_scope           text,
    -- The RFC 9396 authorization_details document requested, as JSON, or NULL. Held
    -- verbatim so what is rendered for consent, what is issued, and what
    -- introspection returns are all the same bytes (issue #131 criterion 4).
    authorization_details     jsonb,
    -- The human-readable message the client asked to be shown on the authentication
    -- device, binding the approval to THIS request (CIBA Core section 7.1). NULL
    -- when the client sent none.
    binding_message           text,
    -- The request lifecycle: pending (awaiting the user's decision), approved (the
    -- user consented; the next poll or fetch issues tokens), denied (the user
    -- refused), expired (past its TTL), redeemed (tokens already issued; a further
    -- poll is invalid_grant). Single-use redemption lives here.
    status                    text        NOT NULL DEFAULT 'pending',
    -- The current minimum polling interval in seconds (CIBA Core section 11). Starts
    -- at the configured default and is INCREASED in place when the client polls
    -- faster than the current interval, so slow_down is enforced per request exactly
    -- as the device grant enforces it per device_code.
    interval_secs             integer     NOT NULL,
    -- The instant of the client's most recent poll (from the application clock seam,
    -- never the database clock), or NULL before the first poll. The slow_down check
    -- compares the next poll against this plus interval_secs.
    last_poll_at              timestamptz,
    -- Whether the ping notification has been delivered, so a retry does not ping the
    -- client twice for one approval. Always false in poll mode.
    notified                  boolean     NOT NULL DEFAULT false,
    -- The end-user subject (a usr_ id string) the client named and the request is
    -- for. Resolved at request time, because a request naming nobody resolvable must
    -- fail at the backchannel endpoint rather than after a human has been bothered.
    subject                   text        NOT NULL,
    -- The grant opened at approval (the revocation spine the issued tokens hang
    -- off), or NULL while pending.
    grant_id                  text,
    -- The consent decision recorded at approval (a con_ id string), or NULL.
    consent_ref               text,
    -- The authentication methods (space-separated RFC 8176 values) frozen from the
    -- approving user's authentication, the source the issued ID token's amr/acr
    -- derive from. NULL while pending.
    auth_methods              text,
    -- The approving user's authentication instant (from the application clock seam),
    -- frozen so the issued ID token's auth_time is truthful. NULL while pending.
    auth_time                 timestamptz,
    -- The request's expiry (from the application clock seam), after which a poll
    -- yields expired_token. Bounded at INSERT against the configured ceiling, so a
    -- client's requested_expiry can shorten but never extend it (criterion 3).
    expires_at                timestamptz NOT NULL,
    created_at                timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT backchannel_authentication_requests_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT backchannel_authentication_requests_status_known
        CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'redeemed')),
    -- The closed delivery-mode vocabulary. 'push' is not a value this column can
    -- hold, which is what makes criterion 6's refusal structural.
    CONSTRAINT backchannel_authentication_requests_mode_known
        CHECK (delivery_mode IN ('poll', 'ping')),
    -- Ping mode needs somewhere to ping and something to authenticate the ping with;
    -- poll mode must carry neither, so a poll-mode request cannot smuggle a
    -- notification target. Both halves stated, because "required for ping" alone
    -- would let a poll request carry an unused URL that a later reader might honour.
    CONSTRAINT backchannel_authentication_requests_ping_has_notification
        CHECK (
            (delivery_mode = 'ping'
                AND client_notification_url IS NOT NULL
                AND client_notification_token IS NOT NULL)
            OR
            (delivery_mode = 'poll'
                AND client_notification_url IS NULL
                AND client_notification_token IS NULL)
        ),
    -- A positive interval, so a misconfigured zero cannot disable slow_down.
    CONSTRAINT backchannel_authentication_requests_interval_positive
        CHECK (interval_secs > 0),
    UNIQUE (tenant_id, environment_id, id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- Isolation-preserving composite reference: the grant (when present) must exist
    -- in the SAME tenant and environment, so an approved request can never bind a
    -- grant belonging to another scope.
    FOREIGN KEY (grant_id, tenant_id, environment_id)
        REFERENCES grants (id, tenant_id, environment_id)
);

CREATE INDEX backchannel_authentication_requests_scope_idx
    ON backchannel_authentication_requests (tenant_id, environment_id);
CREATE INDEX backchannel_authentication_requests_grant_idx
    ON backchannel_authentication_requests (grant_id);

ALTER TABLE backchannel_authentication_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE backchannel_authentication_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY backchannel_authentication_requests_tenant_isolation
    ON backchannel_authentication_requests
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The data plane creates a request (INSERT), polls it, and approves/denies/redeems
-- it. CRITICAL (lesson from issue #31, applied identically in 0021): NEVER grant a
-- table-wide UPDATE. A table-level UPDATE auto-covers every column added later, so
-- it would let a compromised or buggy data-plane path rewrite immutable columns --
-- the digest, the client binding, the delivery mode, the notification token, the
-- expiry -- and thereby relocate a request to another client or extend its life.
-- Grant a COLUMN-SCOPED UPDATE over EXACTLY the columns the data plane writes after
-- creation: the polling bookkeeping (status, interval_secs, last_poll_at, notified)
-- and the approval linkage (grant_id, consent_ref, auth_methods, auth_time).
--
-- Note what is NOT here: client_id and expires_at are write-once, which is what
-- makes "cannot be redeemed by a different client" and "expires within
-- requested_expiry bounds" (criterion 3) properties of the schema rather than
-- promises of the application code. client_notification_token is write-once too, so
-- a compromised poll path cannot repoint where a ping's credential goes.
-- No DELETE: a spent request is invalidated by status, never removed, so a replay
-- is answered definitely and the audit trail survives.
GRANT SELECT, INSERT ON backchannel_authentication_requests TO ironauth_app;
GRANT UPDATE (
    status,
    interval_secs,
    last_poll_at,
    notified,
    grant_id,
    consent_ref,
    auth_methods,
    auth_time
) ON backchannel_authentication_requests TO ironauth_app;
