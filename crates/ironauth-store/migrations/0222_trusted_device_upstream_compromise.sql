
-- A FIFTH trusted-device revoke reason: an upstream account compromise (issue #144).
--
-- Google Cross-Account Protection tells this deployment that a Google account one of its
-- users signs in with is believed compromised. The configured protection revokes that user's
-- sessions AND their remembered devices, and the second half is what makes the first half
-- mean anything: a remembered device is precisely the thing that lets the next sign-in skip
-- the strong factor, so revoking sessions while leaving device trust in place invites the
-- attacker who holds the upstream account to walk straight back in with one password.
--
-- WHY A NEW REASON RATHER THAN AN EXISTING ONE. 0053 pinned the reason to a closed set so an
-- unknown value can never be written, and the four it admits all name an act by someone
-- inside this system: the user, an admin, a password change, a factor change. None of them
-- is true here. Recording this as `admin` would put an operator's name on something no
-- operator did, and the reason column exists to be read by a human deciding whether a
-- revocation was expected.
--
-- WHY THE CHECK IS REPLACED RATHER THAN EDITED. 0053 has shipped and is checksummed; a
-- migration that has run somewhere is frozen. Dropping and re-adding the constraint here is
-- the only way to widen it, and the new definition repeats the ORIGINAL four verbatim so the
-- widening is visible as one added string rather than a rewritten rule.
--
-- The pairing half of the rule is unchanged: a reason is present exactly when the row is
-- revoked, and absent exactly when it is not.

ALTER TABLE trusted_devices
    DROP CONSTRAINT trusted_devices_revoke_reason_known;

ALTER TABLE trusted_devices
    ADD CONSTRAINT trusted_devices_revoke_reason_known
        CHECK (
            (revoked_at IS NULL AND revoke_reason IS NULL)
            OR (revoked_at IS NOT NULL AND revoke_reason IN (
                'user', 'admin', 'password_change', 'factor_change', 'upstream_compromise'
            ))
        );
