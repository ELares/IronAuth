-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- An impersonated refresh family carries its actor and its bound (issue #101).
--
-- The session read refuses a lapsed impersonation since the session half of this issue landed,
-- so no NEW code exchange succeeds past the cap. The families minted during the legitimate
-- window were untouched: ending a session cascades to its families, but an impersonation LAPSE
-- is not a session end and nothing fires at the cap. An operator who impersonated a user for a
-- justified ten minutes could keep refreshing indefinitely, on tokens carrying no actor claim,
-- so the audit trail showed nothing either.
--
-- Storing the bound HERE rather than reading the session at refresh keeps that path at zero
-- extra queries, and it is what an RFC 8693 exchange needs anyway: an exchange holds a grant
-- and not necessarily a live session.
--
-- EXPAND only. An ordinary family carries none of these and is unchanged.
ALTER TABLE refresh_families ADD COLUMN impersonator text;
ALTER TABLE refresh_families ADD COLUMN impersonation_reason_code text;
ALTER TABLE refresh_families ADD COLUMN impersonation_expires_at timestamptz;

-- All three or none, mirroring the arc on `sessions`. A family with an impersonator and no
-- bound is precisely the row this migration exists to prevent, and rejecting it in a handler
-- would leave it representable for anything that writes around that handler.
--
-- The written justification is deliberately NOT copied here. It lives on the session and in
-- the audit stream; a refresh family is read to mint tokens, and the only fields that need to
-- travel are the two that become the `act` claim plus the bound that stops it.
ALTER TABLE refresh_families ADD CONSTRAINT refresh_families_impersonation_arc
    CHECK (
        (impersonator IS NULL
            AND impersonation_reason_code IS NULL
            AND impersonation_expires_at IS NULL)
     OR (impersonator IS NOT NULL
            AND impersonation_reason_code IS NOT NULL
            AND impersonation_expires_at IS NOT NULL)
    );

-- Neither actor field may be blank, for the reason the sessions table gives: the arc above is
-- satisfied by an empty string, and the explicit character set matters because one-argument
-- btrim strips spaces only.
ALTER TABLE refresh_families ADD CONSTRAINT refresh_families_impersonation_nonempty
    CHECK (
        impersonator IS NULL
     OR (btrim(impersonator, E' \t\r\n\f\v') <> ''
         AND btrim(impersonation_reason_code, E' \t\r\n\f\v') <> '')
    );

-- The app plane mints families at code exchange and so writes these columns with the row.
-- Nothing updates them afterwards: an actor that can be edited after the fact is not an audit
-- record, and a bound that can be pushed out is not a bound.
GRANT INSERT (impersonator, impersonation_reason_code, impersonation_expires_at)
    ON refresh_families TO ironauth_app;
