-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Broker-then-migrate cutover marker and the two missing step-up policy bounds
-- (issue #286, follow-up to #77 PR 2).
--
-- Three additive changes, all EXPAND. Nothing here is a data migration and nothing here
-- rewrites a shipped file: 0047 and 0059 stand as written, including their comments.
--
-- 1. users.local_cutover_marked_at
--
-- The per-account cutover marker the #56 lazy-migration hook cannot express. That hook's
-- `attempt()` needs a plaintext credential a brokered OIDC/OAuth2 login never possesses
-- (a JIT-provisioned federated user is created with no password hash at all), and
-- `record_migrated()` is a process-global counter whose own metric help text says "users
-- created locally by the lazy-migration hook on a verified first login". A step-up is not
-- that event, which is why #77 PR 2 REMOVED the misleading one-liner rather than ship a
-- counter that fires on the wrong thing.
--
-- NULLABLE: an account no overlay ever forced a local factor on carries no mark. The value
-- is an instant, not a subject value, so it is not PII and is never sealed. A column rather
-- than a table because the relation is 0-or-1 per user, the audit trail already exists
-- (the setter writes its audit row in the same transaction, exactly as set_org_connection
-- does), and the login path already reads this user row, so a column costs no extra round
-- trip where a table would cost one per brokered login. users.org_connection_id (0059) is
-- the precedent this follows byte for byte: nullable column, column-scoped UPDATE grant,
-- audited setter.
--
-- 2. org_connections.overlay_min_acr, pinned to the acr vocabulary
--
-- 0059 pinned overlay_min_class to the credential-class ladder with a CHECK and left the
-- acr column unconstrained, so a typo became an UNRANKED floor. An unranked floor is
-- satisfiable only by an exact string match, so the federated context can never reach it
-- and the ceremony is unsatisfiable. It fails CLOSED, which is why this is hardening and
-- not a fix.
--
-- The list admits BOTH the canonical acr values and the short aliases, and that is not
-- sloppiness: this column is canonicalized at READ time (the overlay resolves it through
-- canonical_step_up_acr when it builds the requirement), so a stored alias is a legitimate
-- value here. The sibling clients.step_up_acr is canonicalized at WRITE time by the CLI and
-- therefore only ever holds a canonical value; the two columns have genuinely different
-- contracts and this CHECK is written for THIS one. A test in ironauth-oidc, the only crate
-- that can see both this file and the acr registry, pins this set against the live
-- vocabulary so the two cannot drift, which is the discipline 0090 states for its own
-- factor vocabulary.
--
-- The federated acr is deliberately ABSENT: acr_values_supported() skips it, so it is not a
-- value any step-up floor may name.
--
-- 3. org_connections.max_age_secs and clients.step_up_max_age_secs, nonnegative
--
-- A negative value is silently dropped by the u64 conversion at the read, which is fail
-- OPEN on a nonsense value: the operator sets an age bound, the CLI reports success, and no
-- bound is ever enforced. 0047 gave exactly this CHECK to the scope_step_up_policies column
-- it CREATED and did not give it to the clients column it added in the same file; this
-- closes that gap.
--
-- ZERO IS VALID and means always reauthenticate, so the bound is >= 0 and never > 0.
--
-- The two org_connections constraints are plain, because that table has no production write
-- path in this tree and therefore no live row can violate them. The clients constraint is
-- added NOT VALID and then validated explicitly, so a pre-existing negative value fails the
-- migration by CONSTRAINT NAME rather than as an opaque table-scan error, and an operator
-- reading the failure knows which column to correct.

-- ---------------------------------------------------------------------------
-- The per-account broker-then-migrate cutover marker.
ALTER TABLE users
    ADD COLUMN local_cutover_marked_at timestamptz;

GRANT UPDATE (local_cutover_marked_at) ON users TO ironauth_app;

-- ---------------------------------------------------------------------------
-- The broker overlay acr floor names a rung of the ladder, canonical or alias.
ALTER TABLE org_connections
    ADD CONSTRAINT org_connections_overlay_min_acr_known
        CHECK (overlay_min_acr IS NULL
               OR overlay_min_acr IN (
                   'urn:ironauth:acr:pwd',
                   'urn:ironauth:acr:mfa_remembered',
                   'urn:ironauth:acr:mfa',
                   'phr',
                   'phrh',
                   'urn:ironauth:acr:attested_passkey',
                   'pwd',
                   'mfa_remembered',
                   'mfa',
                   'attested_passkey'
               ));

-- ---------------------------------------------------------------------------
-- The two missing nonnegative age bounds. Zero is valid and means always reauthenticate.
ALTER TABLE org_connections
    ADD CONSTRAINT org_connections_max_age_nonnegative
        CHECK (max_age_secs IS NULL OR max_age_secs >= 0);

ALTER TABLE clients
    ADD CONSTRAINT clients_step_up_max_age_nonnegative
        CHECK (step_up_max_age_secs IS NULL OR step_up_max_age_secs >= 0) NOT VALID;

ALTER TABLE clients
    VALIDATE CONSTRAINT clients_step_up_max_age_nonnegative;
