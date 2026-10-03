-- SPDX-License-Identifier: MIT OR Apache-2.0
-- Issue #1475. EXPAND only: controlled indexing does not infer verified ownership.
-- Serving sessions may insert fully indexed accounts but cannot rewrite an index.
GRANT UPDATE (recipient_email_bidx, recipient_email_indexed) ON users TO ironauth_control;
CREATE INDEX users_recipient_unindexed_batch_idx
    ON users (tenant_id, environment_id, id)
    WHERE NOT recipient_email_indexed;
