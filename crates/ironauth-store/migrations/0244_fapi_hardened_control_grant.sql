-- SPDX-License-Identifier: MIT OR Apache-2.0
-- Migration 0237 added the FAPI switch after 0030 restricted environment updates
-- to named columns. Restore only the intended control-plane setter authority.
-- Data-plane roles still cannot change any environment policy.
GRANT UPDATE (fapi_hardened) ON environments TO ironauth_control;
