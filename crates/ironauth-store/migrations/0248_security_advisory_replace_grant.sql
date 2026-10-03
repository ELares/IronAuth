-- SPDX-License-Identifier: MIT OR Apache-2.0
-- EXPAND: complete the existing management-plane projection replacement grant.
-- A verified feed replaces its accepted set by DELETE followed by INSERT in one
-- transaction. Migration 0241 granted INSERT but omitted DELETE, so a control-role
-- import could never replace even an empty projection. Keep serving roles read-only.
GRANT DELETE ON security_advisories TO ironauth_control;
