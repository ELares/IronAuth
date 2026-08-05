-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The rotation overlap window for webhook signing secrets (issue #105, after 0111).
--
-- Standard Webhooks makes rotation a CONFIGURATION change rather than a coordinated
-- deploy: for an overlap window a delivery is signed under BOTH the outgoing and the
-- incoming secret, space-delimited in one `webhook-signature` header, so a consumer
-- holding either verifies and sees zero failures. `ironauth_jose::webhooks::sign_delivery`
-- already takes a SLICE of secrets for exactly this; these columns are what it reads.
--
-- All three are NULLABLE together and mean "no rotation in flight". An endpoint that has
-- never rotated, and one whose window has elapsed, are the same state as far as signing
-- is concerned: one secret.
--
-- The previous secret is SEALED like the current one rather than kept in the clear for
-- the window's duration. A window is measured in hours or days, which is precisely long
-- enough for "it is temporary" to become the reason a plaintext secret sat in a table.
--
-- `previous_expires_at` is stored rather than derived from `updated_at` plus a configured
-- window, so shortening the deployment's default window cannot retroactively invalidate a
-- rotation already in flight and strand a consumer that has not yet redeployed.
--
-- The 0111 control-plane UPDATE grant is COLUMN SCOPED, so it does not cover columns that
-- did not exist when it was written. Extending it here is required rather than tidy: a
-- rotation would otherwise fail with a permission error on the very write it exists for.

ALTER TABLE webhook_endpoints
    ADD COLUMN previous_secret_sealed      bytea,
    ADD COLUMN previous_secret_dek_version integer,
    ADD COLUMN previous_expires_at         timestamptz;

-- The three move together or not at all: a half-set rotation would sign under a secret
-- with no expiry, or expire a secret that is not there.
ALTER TABLE webhook_endpoints
    ADD CONSTRAINT webhook_endpoints_previous_secret_complete
    CHECK (
        (previous_secret_sealed IS NULL
         AND previous_secret_dek_version IS NULL
         AND previous_expires_at IS NULL)
        OR (previous_secret_sealed IS NOT NULL
            AND previous_secret_dek_version IS NOT NULL
            AND previous_expires_at IS NOT NULL)
    );

GRANT UPDATE (previous_secret_sealed, previous_secret_dek_version, previous_expires_at)
    ON webhook_endpoints TO ironauth_control;
