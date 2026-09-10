-- Every inbound RISC Security Event Token this deployment has already acted on (issue #144).
--
-- The Google Cross-Account Protection receiver applies real protections: it ends a user's
-- sessions and revokes their remembered devices. Those are not idempotent in the way a
-- delivery is. Re-applying them on a REPLAYED token would end sessions the user has since
-- legitimately started, revoke devices they have since re-trusted, and write a second audit
-- row describing an upstream event that happened once. An attacker who captured one genuine
-- SET could then re-lock the account at will, for as long as the transmitter's key stays
-- valid, without ever forging anything.
--
-- RFC 8417 section 2.2 makes `jti` the handle for exactly this: "the SET issuer MUST ensure
-- that the `jti` is unique for that issuer", and a receiver deduplicates on it. So this table
-- is the receiver's memory of which ones it has seen.
--
-- THE INSERT IS THE CHECK. The composite primary key makes a duplicate a unique violation
-- inside the transaction that is admitting the token, so two concurrent deliveries of one SET
-- admit exactly one. A read-then-write could not give that: both reads would miss and both
-- would act.
--
-- KEYED ON THE ISSUER AS WELL AS THE `jti`. Uniqueness is only ever promised BY an issuer FOR
-- that issuer, so two transmitters may legitimately mint the same string. Keying on the `jti`
-- alone would let the first transmitter to use a value silence the second, which is a denial
-- of service one configured transmitter could inflict on another by guessing.
--
-- WHY NO `exp` COLUMN AND NO EXPIRY WINDOW. A row is refused for as long as it exists, which
-- with no sweep is for ever, and that is deliberate here rather than an omission to be tidied
-- later. This deployment's position on SET freshness is written at `ssf_set::build_set_claims`
-- and at `VerificationPolicy::allow_absent_exp`: SSF 1.0 section 4.1.7 says the `exp` claim
-- MUST NOT be used in SETs, because "a SET represents something that has already occurred and
-- is historical in nature" and an expiry would make a receiver that was down through the
-- window discard the events it most needs. Replay is what `jti` is for. A dedup window would
-- put the expiry back by another name, at the receiver, and re-open the replay it closes.
--
-- The cost is bounded by what the transmitter sends: one row per genuine upstream event for
-- one environment's federated users. A sweep, if one is ever wanted, needs a retention
-- decision this issue does not have, and its DELETE grant belongs with it.

CREATE TABLE risc_received_sets (
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The transmitter that minted it: the `iss` the signature was verified under, which is
    -- the operator-configured issuer and never a value read off the token before verifying.
    issuer         text        NOT NULL,
    -- The token's own `jti`.
    jti            text        NOT NULL,
    -- From the application clock seam, like every other admission timestamp in this schema.
    seen_at        timestamptz NOT NULL,

    PRIMARY KEY (tenant_id, environment_id, issuer, jti),

    CONSTRAINT risc_received_sets_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT risc_received_sets_issuer_bounded
        CHECK (issuer <> '' AND octet_length(issuer) <= 512),
    CONSTRAINT risc_received_sets_jti_bounded
        CHECK (jti <> '' AND octet_length(jti) <= 256),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

ALTER TABLE risc_received_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE risc_received_sets FORCE ROW LEVEL SECURITY;

CREATE POLICY risc_received_sets_scope ON risc_received_sets
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT and INSERT only.
--
-- NO UPDATE: a row is the fact that a token was acted on, and there is nothing about it to
-- amend. NO DELETE: forgetting a `jti` re-admits the token it names, so the grant that allows
-- it is the grant that re-opens the replay. If a sweep is ever added, its DELETE grant and its
-- retention rule arrive together.
GRANT SELECT, INSERT ON risc_received_sets TO ironauth_app;
