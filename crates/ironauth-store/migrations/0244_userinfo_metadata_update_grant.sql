-- SPDX-License-Identifier: MIT OR Apache-2.0
-- The existing dynamic-client metadata updater writes this column on every
-- update after 0238. Retain its existing app/control authority over that field;
-- immutable authority columns and every other role remain unchanged.
GRANT UPDATE (userinfo_signed_response_alg) ON clients TO ironauth_app, ironauth_control;
