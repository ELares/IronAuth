-- Which certificate expiry alerts have already gone out (issue #141).
--
-- WHAT #141 ASKS FOR. "A pinned certificate entering its expiry window triggers notifications to
-- the org's IT contacts AT EACH CONFIGURED LEAD TIME." Three leads -- thirty days, fourteen,
-- three -- means three notifications per certificate, one as each threshold is crossed, and
-- NEVER a fourth. Certificate rot is the number one silent killer of SAML connections precisely
-- because nobody is told in time; a sweep that re-sent the thirty-day warning on every pass
-- would be told about, once, and then filtered into a folder nobody reads. So the value of this
-- table is that it makes each (certificate, lead) pair announce exactly once.
--
-- THE INSERT IS THE CHECK, which is the same shape `saml_assertion_replay` (0198) uses and for
-- the same reason: a composite primary key makes a duplicate a unique violation, so two sweep
-- workers racing over one certificate announce exactly one notice between them and the loser
-- learns it BEFORE delivering. A read-then-write cannot give that, and a sweep is exactly the
-- kind of job an operator ends up running twice.
--
-- THE ROW AND THE ANNOUNCEMENT COMMIT TOGETHER. `record_sent` takes the domain event and
-- enqueues it in the row's own transaction, because a row that committed first and an
-- announcement that then failed would leave a ledger saying a customer was told when they were
-- not -- and nothing re-surfaces it: `due()` filters on exactly this row and no role may delete
-- one.
--
-- THE LEAD IS PART OF THE KEY, not a column beside it. Storing "last alerted at" instead would
-- make the thirty-day and fourteen-day notices one fact, so crossing the fourteen-day threshold
-- would either be suppressed by the thirty-day row or would overwrite it and let the thirty-day
-- notice fire again on the next pass. Each threshold is its own promise and gets its own row.
--
-- NO ROW MEANS NOT YET SENT, and that is the only reading. There is deliberately no `status`
-- column: a row recording that a notification FAILED would make absence ambiguous, and the
-- delivery machinery already owns retries. What this table answers is "has this threshold been
-- announced", which is a question with two answers.
CREATE TABLE saml_certificate_expiry_alerts (
    tenant_id           text        NOT NULL,
    environment_id      text        NOT NULL,
    -- The certificate this is about. `saml_connection_certificates.id`.
    certificate_id      text        NOT NULL,
    -- The lead time this row records, in SECONDS, as configured when the notice went out.
    --
    -- STORED RATHER THAN DERIVED, because the configured set can change. An operator who adds a
    -- seven-day lead should get a seven-day notice for certificates already inside thirty days,
    -- and one who REMOVES a lead should not have its rows resurface as unsent work. Keying on
    -- the configured number makes both of those fall out: a lead that is not configured is
    -- simply never looked up.
    lead_secs           bigint      NOT NULL,
    -- When the notice went out, from the application clock seam, like every other timestamp this
    -- system compares against.
    alerted_at          timestamptz NOT NULL,

    -- ONE NOTICE PER (CERTIFICATE, LEAD). See the header: this is the constraint the sweep
    -- relies on rather than a read it performs.
    PRIMARY KEY (tenant_id, environment_id, certificate_id, lead_secs),

    CONSTRAINT saml_certificate_expiry_alerts_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- A LEAD IS A POSITIVE DURATION. Zero would mean "warn at the moment it expires", which is
    -- not a warning, and a negative one names a time after expiry.
    CONSTRAINT saml_certificate_expiry_alerts_lead_positive
        CHECK (lead_secs > 0),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- REMOVING THE CERTIFICATE REMOVES ITS ALERT HISTORY. A pin that is gone cannot expire, and
    -- a certificate re-uploaded after removal is a NEW row with a new id, so it starts its own
    -- lead sequence -- which is what an operator replacing a certificate expects: the renewal
    -- they just performed should not inherit the old one's "already warned" state.
    FOREIGN KEY (certificate_id) REFERENCES saml_connection_certificates (id) ON DELETE CASCADE
);

-- THE INDEX 0197 DEFERRED TO "THE MIGRATION THAT ADDS THE SWEEP". This is that migration. The
-- sweep reads `saml_connection_certificates` by scope and expiry -- every certificate whose
-- `not_after` falls inside the widest configured lead -- and without this it is a sequential scan
-- of every pinned certificate in the deployment on every pass. The ordering matches the query's
-- own `ORDER BY not_after`, so the scan and the sort come from one structure.
CREATE INDEX saml_connection_certificates_by_expiry
    ON saml_connection_certificates (tenant_id, environment_id, not_after);

ALTER TABLE saml_certificate_expiry_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_certificate_expiry_alerts FORCE ROW LEVEL SECURITY;

CREATE POLICY saml_certificate_expiry_alerts_scope ON saml_certificate_expiry_alerts
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- THE CONTROL PLANE OWNS THIS. Deciding that a customer should be told their certificate is
-- about to expire is an operator-plane job: it reads the contact list, which 0207 grants to the
-- control role, and it writes an audited notification. The data plane signs people in and has no
-- part in it.
--
-- NO UPDATE AND NO DELETE. A row here is a statement that a notice went out, and that does not
-- become untrue. Rows leave only with the certificate they describe, by the cascade above.
GRANT SELECT, INSERT ON saml_certificate_expiry_alerts TO ironauth_control;
