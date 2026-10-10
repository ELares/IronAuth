-- SPDX-License-Identifier: MIT OR Apache-2.0
-- An explicit control-plane reconciliation receipt, separate from client config.
ALTER TABLE clients
    ADD COLUMN subject_history_evidence_sha256 text,
    ADD COLUMN subject_history_reconciled_at timestamptz,
    ADD CONSTRAINT client_subject_history_receipt_valid CHECK (
        (subject_history_evidence_sha256 IS NULL AND subject_history_reconciled_at IS NULL)
        OR (subject_history_ready AND subject_history_evidence_sha256 IS NOT NULL
            AND subject_history_evidence_sha256 ~ '^[a-f0-9]{64}$'
            AND subject_history_reconciled_at IS NOT NULL)
    );

-- History recovery may append public bindings, never rewrite or delete them.
-- The data plane does not gain readiness or receipt update authority.
GRANT SELECT, INSERT ON client_subject_bindings TO ironauth_control;
GRANT UPDATE (subject_history_ready, subject_history_evidence_sha256,
    subject_history_reconciled_at) ON clients TO ironauth_control;
