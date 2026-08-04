-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Control-plane grants for the guarded SMS OTP configuration (issue #70).
--
-- 0050 shipped `sms_config` and `sms_country_allowlist` granted to ironauth_app ALONE,
-- and its own comment states the operating requirement: "Off by default in EVERY
-- tenant/environment: SMS OTP is unusable until a tenant explicitly turns it on AND
-- populates the country allowlist." Nothing could do either. The four store methods that
-- write and read that configuration (`set_config`, `allowlist`, `add_allowlist_country`,
-- `remove_allowlist_country`) had no production caller at all, and the management contract
-- published no SMS operation, so every deployment ran with no `sms_config` row and an
-- EMPTY allowlist. Since the allowlist is an allowlist rather than a blocklist, an empty
-- one refuses every country, so the factor was unreachable twice over.
--
-- This is the same ROOT CAUSE as 0098 (issue #441) and not the same defect. 0098 granted
-- the control role two relations whose management operations were PUBLISHED but answering
-- 500, and it derived its set two ways: statically from the relations the management
-- handlers reach, and empirically by driving every published operation. Both derivations
-- were correct and both necessarily missed these tables, because there were no SMS
-- handlers to resolve and no SMS operations to drive. The grant gap here sits UNDER a
-- mounting gap, so it could only surface by auditing the store for methods with no caller
-- rather than by auditing the surface.
--
-- The grants mirror 0050's app-role grants exactly, no wider. `sms_config` takes
-- SELECT/INSERT/DELETE plus the same COLUMN-SCOPED UPDATE on the mutable trio, never a
-- table-wide UPDATE (the #31 lesson); `sms_country_allowlist` is insert-and-delete only,
-- since a country code is its own key and is never rewritten in place.
--
-- The data plane KEEPS its grants. It reads this configuration on the send path
-- (`config`, `allowlist_contains`), so this is an addition rather than a handover, and the
-- two roles read the same rows exactly as they do for every other per-environment setting.
--
-- Migration safety obligation (see migrate.rs): this migration adds GRANTs and nothing
-- else. It creates no table, so it introduces no row-level-security obligation and no new
-- entry for scripts/query-audit.sh, and it alters no existing object, so it is an EXPAND
-- with no contract phase.

GRANT SELECT, INSERT, DELETE ON sms_config TO ironauth_control;
GRANT UPDATE (enabled, allow_factor_downgrade, updated_at) ON sms_config TO ironauth_control;
GRANT SELECT, INSERT, DELETE ON sms_country_allowlist TO ironauth_control;
