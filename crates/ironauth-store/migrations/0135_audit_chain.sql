-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Per-stream tamper-evidence chain over the audit log (issue #109).
--
-- The chain lives in its own table rather than in columns on `audit_log`, and
-- that is the load-bearing decision here. Sealing a row in place would mean
-- UPDATE on `audit_log`, and 0002 withholds UPDATE from every role precisely so
-- that a written audit row can never be rewritten. A tamper-evidence scheme
-- whose own bookkeeping requires the privilege it is defending against is not
-- evidence of anything. So `audit_chain` is append-only too: the sealer holds
-- SELECT on `audit_log` and INSERT here, and no role anywhere gains UPDATE on
-- either table.
--
-- One chain per (tenant, environment, stream). The streams are chained
-- separately because they are retained separately: pruning the authentication
-- stream must not break the admin stream's chain.
--
-- `seq` is the position in the chain, dense and starting at 1. `prev_hash` is
-- the previous entry's `record_hash` (the empty string at seq 1), and
-- `record_hash` is `chain_link(prev_hash, canonical(row))`. Verification walks
-- a chain in `seq` order, recomputes each link from the referenced `audit_log`
-- row, and reports the FIRST seq that disagrees.
--
-- What each attack looks like to a verifier:
--   * MODIFY an audit row: its recomputed `record_hash` no longer matches the
--     stored one, and every later entry commits to the stored value.
--   * DELETE an audit row: the referenced row is gone, so its link cannot be
--     recomputed at all.
--   * INSERT an audit row into the past: it has no chain entry, which the
--     completeness check catches (every row at or below the seal watermark must
--     be chained exactly once).
--
-- What it does NOT defend against, stated plainly: an attacker who can delete a
-- SUFFIX of the chain and the rows it covers leaves a shorter but internally
-- valid chain. Detecting that needs the head digest held somewhere this
-- database cannot reach, which is the export half of SIEM streaming and is not
-- built here.

CREATE TABLE audit_chain (
    id             text        PRIMARY KEY,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- Which stream's chain this entry belongs to. Same vocabulary as
    -- audit_log.stream, and constrained the same way.
    stream         text        NOT NULL,
    -- Position in this chain, dense from 1.
    seq            bigint      NOT NULL,
    -- The audit row this entry seals.
    audit_id       text        NOT NULL,
    -- The previous entry's record_hash; the empty string at seq 1.
    prev_hash      text        NOT NULL,
    -- chain_link(prev_hash, canonical(audit row)), lowercase hex SHA-256.
    record_hash    text        NOT NULL,
    -- When the sealer wrote this entry, from the application clock seam.
    sealed_at      timestamptz NOT NULL,
    CONSTRAINT audit_chain_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT audit_chain_stream_known
        CHECK (stream IN ('admin_action', 'authentication')),
    -- A hash is 64 lowercase hex characters; prev_hash is that or empty at the
    -- head. A truncated or uppercase digest would compare unequal forever and
    -- look like tampering, so it is refused at write time instead.
    CONSTRAINT audit_chain_record_hash_shape
        CHECK (record_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT audit_chain_prev_hash_shape
        CHECK (prev_hash = '' OR prev_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT audit_chain_seq_positive CHECK (seq >= 1),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- One entry per position per chain. This is what makes a FORK impossible: two
-- sealers racing on the same chain cannot both commit a seq, so the loser's
-- transaction fails and retries against the winner's head rather than writing a
-- second history.
CREATE UNIQUE INDEX audit_chain_position_idx
    ON audit_chain (tenant_id, environment_id, stream, seq);

-- One entry per audit row. An audit row cannot be sealed twice into the same
-- chain, so a replaying sealer cannot inflate a chain with duplicate links.
CREATE UNIQUE INDEX audit_chain_audit_id_idx
    ON audit_chain (tenant_id, environment_id, audit_id);

-- Row-level security, ENABLED and FORCED, keyed on the same transaction-local
-- session variables every other scoped table uses. The chain is exactly as
-- tenant-isolated as the log it seals.
ALTER TABLE audit_chain ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_chain_tenant_isolation ON audit_chain
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT and INSERT only, to both application roles, exactly as `audit_log`
-- gets. No UPDATE and no DELETE to anyone here: an append-only log's evidence
-- table has to be append-only or it is not evidence. Retention's DELETE arrives
-- in 0136 and goes to a role that holds no INSERT on either table.
GRANT SELECT, INSERT ON audit_chain TO ironauth_app;
GRANT SELECT, INSERT ON audit_chain TO ironauth_control;
