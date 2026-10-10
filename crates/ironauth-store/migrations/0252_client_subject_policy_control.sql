-- SPDX-License-Identifier: MIT OR Apache-2.0
-- Narrow control-plane identity configuration; no redirect or binding authority.
GRANT UPDATE (subject_type, pairwise_sector, sector_identifier_uri,
    subject_policy_redirect_uris) ON clients TO ironauth_control;
