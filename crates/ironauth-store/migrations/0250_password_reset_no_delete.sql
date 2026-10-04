-- SPDX-License-Identifier: MIT OR Apache-2.0
-- Hosted recovery retains challenge receipts and cancellation aliases. No
-- repository operation deletes these rows, so the data plane needs no DELETE.
-- Forward-only correction preserves 0249 checksums in qualification ledgers.
REVOKE DELETE ON password_reset_challenges FROM ironauth_app;
