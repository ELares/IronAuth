-- SPDX-License-Identifier: MIT OR Apache-2.0
-- Historical identity recovery reads revoked and live grants for one scoped
-- client. The scope-only index makes every page inspect unrelated clients.
-- Keep all history and use the same leading scope columns as the repository/RLS.
-- This transactional index build blocks writes to grants while it runs. Apply
-- during the migration maintenance window; it changes no grants or row data.
CREATE INDEX grants_client_history_idx
    ON grants (tenant_id, environment_id, client_id);
