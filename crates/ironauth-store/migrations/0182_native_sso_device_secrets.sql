-- 0182: the Native SSO device secret (issue #133, PROTOTYPE).
--
-- OpenID Connect Native SSO for Mobile Apps 1.0 ID2. A vendor ships several apps on one phone;
-- the person signs in to the first and should not be asked again by the second. On mobile there
-- is no shared browser session to ride, and there should not be: each app gets its own web
-- session and the platforms deliberately keep one app from reading another's cookies.
--
-- So the family shares a SECRET instead of a cookie. The first app asks for the `device_sso`
-- scope and receives a device secret beside its tokens; a sibling presents that secret together
-- with the first app's ID token and gets its own tokens for the same person.
--
-- WHY THE SECRET IS ONLY EVER A DIGEST HERE.
--
-- The plaintext is returned once, to the app that asked, and is never stored. A device secret is
-- a bearer credential for a whole app family, so a database read that yielded one would be worth
-- more than any single token in this system: it would mint tokens for every sibling app, for
-- that person, until it expired. `trusted_devices` (0053) made the same choice for the same
-- reason, and this follows it exactly rather than inventing a second shape.
--
-- WHAT THE ROW IS BOUND TO, and why it is the underlying session id rather than `sid`.
--
-- The criterion this prototype has to meet is that revoking a device secret SEVERS THE SSO SET.
-- A set is only severable if it is identifiable, so the row names the sign-in it came from.
--
-- THE UNDERLYING SESSION ID, not the ID token's `sid`. Those are different values on purpose:
-- `sid` comes from `ensure_sid` and is per (client, session), so one relying party cannot
-- correlate a person across another's tokens. Keying this row on `sid` would sever only the app
-- that happened to ask and leave its siblings minting, with the revocation reporting success.
--
-- Revoking the secret ends the family's ability to bootstrap new siblings, and so does the
-- session ending by ANY route: redemption joins `sessions` and applies the SAME liveness
-- predicate `SessionRepo::get` uses, so anything that sets `revoked_at`, `ended_at` or
-- `superseded_by`, or lets the session pass its absolute or idle expiry, severs the set without
-- needing to know this table exists. Stated as the RULE rather than a list of routes, because a
-- list gets two of them wrong: a risk decision revokes nothing and a password change preserves
-- the session it is made from.
--
-- Severing on any of those is the property an operator actually wants: "sign this person out"
-- must not leave a credential behind that mints fresh tokens for them.
--
-- Expand phase: a new table the old binary never reads or writes, so a rollback leaves it inert.

CREATE TABLE native_sso_device_secrets (
    -- The nsd_ scoped identifier; embeds its (tenant, environment).
    id                  text        PRIMARY KEY,
    tenant_id           text        NOT NULL,
    environment_id      text        NOT NULL,
    -- The person the secret speaks for. Every sibling app's tokens are minted under this
    -- subject, so it is the thing the secret ultimately authorizes.
    subject             text        NOT NULL,
    -- The SIGN-IN this secret came from: the UNDERLYING session id, NOT the ID token's
    -- per-client `sid`. See the header for why the distinction is load bearing.
    session_id          text        NOT NULL,
    -- The client that asked for `device_sso`. Recorded for the audit trail rather than as a
    -- control: any sibling may redeem the secret, which is the entire point of the feature.
    issued_to_client_id text        NOT NULL,
    -- SHA-256 of the device secret. NEVER the secret. See the header.
    secret_hash         bytea       NOT NULL,
    -- The scope the sign-in was GRANTED, carried so a sibling's exchange has something to
    -- narrow from.
    --
    -- Without it the bootstrap presents an empty subject scope, and the exchange refuses that
    -- outright ("nothing to narrow from") -- so the whole feature would be unreachable rather
    -- than merely unscoped. It is the GRANTED scope rather than the requested one, so a sibling
    -- can never end up with more than the person actually authorized at sign-in.
    granted_scope       text        NOT NULL,
    -- Set by the WRITER from the same clock as `expires_at`, so the ordering CHECK below
    -- compares two values from ONE clock. `created_at` is the database's and is deliberately
    -- not used for it, exactly as 0128 and 0130 do it: `now()` here and an application clock
    -- there would make the constraint a comparison between two unrelated timelines, which is a
    -- REJECTED INSERT under any deployment whose database clock leads the application's, and a
    -- guaranteed one under a test clock that does not track wall time.
    issued_at           timestamptz NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    -- A device secret with no end is a permanent credential for an app family. The issuance
    -- path sets this; the column is NOT NULL so it cannot be forgotten into permanence.
    expires_at          timestamptz NOT NULL,
    -- Set once, never cleared. See the RESTRICTIVE policy below.
    revoked_at          timestamptz,

    CONSTRAINT native_sso_device_secrets_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT native_sso_device_secrets_subject_nonempty
        CHECK (subject <> ''),
    CONSTRAINT native_sso_device_secrets_session_nonempty
        CHECK (session_id <> ''),
    -- A SHA-256 digest is 32 bytes. A shorter value in this column is a truncated hash, and a
    -- truncated hash compares equal more often than it should.
    CONSTRAINT native_sso_device_secrets_hash_shaped
        CHECK (octet_length(secret_hash) = 32),
    -- The secret cannot outlive the moment it was issued, and cannot be revoked before it
    -- existed. Both compare against `issued_at`, the APPLICATION clock's value, never against
    -- `created_at`: see the column comment above.
    CONSTRAINT native_sso_device_secrets_expiry_after_issuance
        CHECK (expires_at > issued_at),
    CONSTRAINT native_sso_device_secrets_revocation_after_issuance
        CHECK (revoked_at IS NULL OR revoked_at >= issued_at),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- The REDEMPTION lookup: a sibling presents a secret, and the server must find the live row
-- whose digest matches. Scoped first, as every index here is.
CREATE UNIQUE INDEX native_sso_device_secrets_by_hash
    ON native_sso_device_secrets (tenant_id, environment_id, secret_hash);

-- The SEVERING query: every live secret from one sign-in. This is what makes revoking a session
-- able to end the SSO set rather than leave it minting.
CREATE INDEX native_sso_device_secrets_by_session
    ON native_sso_device_secrets (tenant_id, environment_id, session_id)
    WHERE revoked_at IS NULL;

ALTER TABLE native_sso_device_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE native_sso_device_secrets FORCE ROW LEVEL SECURITY;

CREATE POLICY native_sso_device_secrets_scope ON native_sso_device_secrets
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The DATA plane owns this one, unlike the agent tables next door, and the reason is where the
-- work happens: a device secret is minted at the TOKEN endpoint during an ordinary code
-- exchange and redeemed at the TOKEN endpoint during an ordinary token exchange. Both run on
-- `ironauth_app`. Routing either through the control plane would put an operator in the middle
-- of a sign-in.
GRANT SELECT, INSERT, UPDATE ON native_sso_device_secrets TO ironauth_app;

-- But plain UPDATE would let the data plane UN-REVOKE, which is the one thing revocation has to
-- survive: an attacker who reached the app role could restore a secret an operator had just
-- killed, and the severing criterion would be decoration.
--
-- AS RESTRICTIVE, deliberately. `native_sso_device_secrets_scope` above has no FOR clause and no
-- TO clause, so a PERMISSIVE narrowing would be OR'd with a check the offending update already
-- satisfies and would constrain nothing at all. Restrictive policies are AND'd, which is what
-- makes this a narrowing rather than a second way in. (0179 and 0181 record the same reasoning;
-- it is the rule that bites every time someone reaches for a policy to forbid something.)
--
-- USING is what the row must look like BEFORE: not yet revoked. WITH CHECK is what it must look
-- like AFTER: revoked.
--
-- THAT IS ALL IT ENFORCES, stated exactly because an earlier version of this comment claimed
-- four properties and the policy delivered one. It does NOT pin `subject`, `secret_hash`,
-- `session_id` or `expires_at`: an UPDATE that rewrites all of them AND sets `revoked_at`
-- satisfies both clauses. What makes that harmless is a consequence rather than the policy --
-- every permitted UPDATE leaves the row revoked, and no read path ever returns a revoked row.
-- Un-revocation is the one thing genuinely blocked, because USING can never match again.
--
-- The residual trust is the INSERT grant: minting runs on this role, so the role that can
-- revoke a row can also insert a fresh one. Narrowing that needs the mint to move behind a
-- function or the column set to be restricted, and neither is this prototype's to decide.
CREATE POLICY native_sso_device_secrets_app_revokes_only
    ON native_sso_device_secrets
    AS RESTRICTIVE
    FOR UPDATE
    TO ironauth_app
    USING (revoked_at IS NULL)
    WITH CHECK (revoked_at IS NOT NULL);

-- The CONTROL plane reads, so an operator surface can show and audit an SSO set without being
-- able to mint one.
GRANT SELECT ON native_sso_device_secrets TO ironauth_control;

COMMENT ON TABLE native_sso_device_secrets IS
    'Issue #133 PROTOTYPE, OpenID Connect Native SSO 1.0 ID2: the device secret an app family '
    'shares so a sibling app need not ask the person to sign in again. The plaintext is '
    'returned once and never stored; only its SHA-256 digest lives here.';
COMMENT ON COLUMN native_sso_device_secrets.granted_scope IS
    'Issue #133: the scope the ORIGINAL sign-in was granted. A sibling redeeming the secret '
    'narrows from this, so it can never obtain more than the person authorized; without it '
    'the exchange has an empty subject scope and refuses the bootstrap outright.';
COMMENT ON COLUMN native_sso_device_secrets.session_id IS
    'Issue #133: the sign-in this secret came from, the UNDERLYING session id and NOT the ID '
    'token per-client sid. Redemption joins sessions on it, so any route that ends the session '
    'severs the set.';
COMMENT ON COLUMN native_sso_device_secrets.secret_hash IS
    'Issue #133: SHA-256 of the device secret, never the secret. A read of this table must not '
    'yield a credential that mints tokens for an entire app family.';
