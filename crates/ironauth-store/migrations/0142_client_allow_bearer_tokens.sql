-- 0142: the per-client escape hatch from the DPoP-by-default posture for public
-- clients (issue #124, RFC 9449).
--
-- IronAuth's stated posture is that DPoP is the DEFAULT for public clients and bearer
-- is the exception. A public client is one that cannot keep a secret, so its tokens
-- are the ones a stolen credential most directly monetizes; sender-constraining them
-- is what turns a stolen token into a token an attacker cannot present. Enforcing that
-- as a default is the one step past every OSS peer this issue asks for.
--
-- A default cannot be an absolute, though. Some public clients cannot mint proofs at
-- all: an embedded or TV client on a runtime with no WebCrypto, a legacy native app
-- shipped before the operator adopted this posture, a vendor SDK the operator does not
-- control. Without an escape hatch the posture would force those deployments to leave
-- DPoP off entirely, which is strictly worse than letting them name the two clients
-- that need bearer and constrain everything else.
--
-- So: per CLIENT, not per deployment. A deployment-wide switch would have to be set
-- for the weakest client and would then silently relax every other client with it,
-- which is exactly the shape of accident this column exists to prevent.
--
-- DEFAULT false means "this client must use DPoP". A client row created before this
-- migration, or by any code path that does not name the column, therefore lands on the
-- SAFE side, and relaxing is always a deliberate, recorded act. That is the whole
-- reason the column is phrased as `allow_bearer_tokens` rather than `require_dpop`:
-- the boolean's false value has to be the strict one, or a forgotten default and a
-- missing column both fail open.
--
-- Expand phase: additive with a default, so an old reader that never selects this
-- column is unaffected and a rolling upgrade is safe in both directions.

ALTER TABLE clients
    ADD COLUMN allow_bearer_tokens boolean NOT NULL DEFAULT false;

-- The CONTROL plane may flip it; nobody else may.
--
-- Relaxing a client out of the posture is a management decision an operator makes,
-- like the PAR requirement (0115) and the scope allowlist (0031). The data plane READS
-- the flag on every token request and must never be able to write it: a data-plane
-- compromise that could relax a client would be able to switch off the very control
-- this column exists to enforce.
--
-- Column scoped, as every grant on this table is. The control role may flip this one
-- boolean and nothing else, so it notably cannot touch `redirect_uris`, `secret_hash`,
-- or `token_endpoint_auth_method`.
--
-- Granting the writer in the SAME migration that adds the column is deliberate. 0115
-- exists only because `require_pushed_authorization_requests` shipped in 0015 with a
-- reader, a setter, and no grant to anyone: the setter could not have had a production
-- caller, the per-client half sat at its default on every deployment for years, and
-- nothing surfaced it because the only callers were tests on a superuser pool.
GRANT UPDATE (allow_bearer_tokens) ON clients TO ironauth_control;

COMMENT ON COLUMN clients.allow_bearer_tokens IS
    'Issue #124: when true, this client may obtain plain bearer tokens without a DPoP '
    'proof. False (the default) means DPoP is required for a public client, which is '
    'the shipped posture. Confidential clients are unaffected either way: they '
    'authenticate, so the sender constraint a proof adds is not the control that '
    'protects them. Setting this surfaces a warning in admin diagnostics.';
