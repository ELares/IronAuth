-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The RFC 7521 / RFC 7523 JWT bearer assertion grant (issue #26).
--
-- This migration lands the trust and mapping configuration the jwt-bearer grant
-- reads, plus its OWN single-use jti replay cache, as three additive (expand)
-- tables:
--
--   1. external_assertion_issuers: the per-(tenant, environment) REGISTERED
--      external assertion issuers the grant will accept assertions from. Each
--      carries a key source (an inline pinned `jwks`, OR a `jwks_uri` fetched
--      through the SSRF-hardened fetcher), an optional per-issuer signing-alg
--      allowlist, and an enable switch. An assertion whose `iss` is not a
--      registered, enabled issuer in the request scope is rejected.
--   2. external_assertion_subject_mappings: the REGISTERED, explicit rules that
--      map an (external issuer + external `sub`, plus an optional claim match) to
--      an IronAuth principal. The mapped principal is the `sub` the issued token
--      carries. There is no auto-provisioning: an assertion whose (issuer, sub)
--      names no mapping rule is rejected.
--   3. external_assertion_jtis: the single-use jti replay cache for EXTERNAL
--      issuer assertions. It REUSES the #25 client-assertion prune-then-insert
--      single-use mechanism, but is a DISTINCT table keyed by the external
--      ISSUER (not the OAuth client id), so an external issuer's jti can NEVER
--      collide with a client-assertion jti (they live in different tables).
--
-- Migration safety obligation (see migrate.rs): each NEW tenant-scoped table
-- ENABLEs and FORCEs row-level security, adds the (tenant, environment) isolation
-- policy (USING + WITH CHECK), adds the nonempty-scope CHECK, takes LEAST-PRIVILEGE
-- grants, and is registered in scripts/query-audit.sh. All three tables do all of
-- this. Following the issue #31 lesson, grants stay COLUMN-SCOPED: the data plane
-- gets UPDATE on exactly the column it legitimately mutates (here only `enabled`, so
-- a compromised or decommissioned issuer can be disabled and a mis-authored mapping
-- revoked), and NEVER a table-wide UPDATE (which auto-extends to every later column,
-- including the app-immutable issuer id, keys, principal, and match rules).

-- ---------------------------------------------------------------------------
-- 1. Registered external assertion issuers (issue #26).
--
-- The trust anchors for the jwt-bearer grant. An assertion is accepted only when
-- its `iss` names a row here in the request's (tenant, environment), that row is
-- enabled, and the assertion's signature verifies against the row's keys through
-- the ONE allowlist JOSE verify path (never the token's own alg header). A client
-- key source is EXACTLY ONE of inline `jwks` or `jwks_uri` (an issuer that pins
-- both would make key resolution ambiguous, and an issuer that pins neither could
-- verify nothing): the XOR CHECK enforces it, exactly like the #25 private_key_jwt
-- client-key registration. `signing_alg_allow` is an OPTIONAL space-separated JOSE
-- algorithm allowlist (for example `EdDSA ES256`); NULL means the supported
-- asymmetric set applies. `enabled` is the enable switch: a disabled issuer's
-- assertions are rejected exactly as an unregistered issuer's are.
CREATE TABLE external_assertion_issuers (
    -- The `xai_` scoped identifier (embeds its tenant and environment), the row's
    -- primary key and the audit target of a registration. Not a secret.
    id              text        PRIMARY KEY,
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- The external issuer's `iss` claim value (its identifier / issuer URL). Unique
    -- per environment: one registration per issuer, and the assertion's `iss` looks
    -- it up.
    issuer          text        NOT NULL,
    -- The inline pinned JWK Set JSON document, OR NULL when the issuer publishes its
    -- keys at `jwks_uri`.
    jwks            text,
    -- The issuer's JWKS URL, fetched through the SSRF-hardened fetcher, OR NULL when
    -- the keys are pinned inline.
    jwks_uri        text,
    -- An OPTIONAL space-separated JOSE algorithm allowlist for this issuer's
    -- assertions; NULL means the supported asymmetric set applies. Never the token's
    -- own alg header.
    signing_alg_allow text,
    -- The enable switch. A disabled issuer is rejected exactly as an unregistered one.
    enabled         boolean     NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT external_assertion_issuers_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- A registered issuer pins EXACTLY ONE key source (jwks XOR jwks_uri): both is
    -- ambiguous, neither can verify anything. Fail LOUD at registration, not per
    -- request.
    CONSTRAINT external_assertion_issuers_one_key_source
        CHECK ((jwks IS NOT NULL) <> (jwks_uri IS NOT NULL)),
    UNIQUE (tenant_id, environment_id, issuer),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

ALTER TABLE external_assertion_issuers ENABLE ROW LEVEL SECURITY;
ALTER TABLE external_assertion_issuers FORCE ROW LEVEL SECURITY;
CREATE POLICY external_assertion_issuers_tenant_isolation ON external_assertion_issuers
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT to resolve a trust anchor at grant time, INSERT to register one, plus a
-- COLUMN-SCOPED UPDATE of exactly `enabled` so a compromised or decommissioned
-- issuer can be DISABLED through the data plane (revocation must be possible now;
-- the HTTP management surface for it is M13). This is the issue #31 lesson applied
-- correctly: grant UPDATE only on the column the data plane legitimately mutates,
-- NEVER a table-wide UPDATE (which auto-extends to later columns) and never UPDATE on
-- the app-immutable id / issuer / jwks / jwks_uri / signing_alg_allow. No DELETE
-- grant: a registration is disabled, not deleted, by the data plane.
GRANT SELECT, INSERT ON external_assertion_issuers TO ironauth_app;
GRANT UPDATE (enabled) ON external_assertion_issuers TO ironauth_app;

-- ---------------------------------------------------------------------------
-- 2. Registered subject-mapping rules (issue #26).
--
-- The explicit, minimal mapping from an external assertion's (issuer + `sub`) to an
-- IronAuth principal. The mapped principal becomes the `sub` of the issued token.
-- The mapping is deliberately minimal (one rule per (issuer, external_subject));
-- the richer federation presets are M13. An OPTIONAL additional claim match
-- (`match_claim` = `match_value`) further gates a rule, so a deployment can require,
-- for example, a particular `groups` or `repository` claim. Reject by default: an
-- assertion whose (issuer, sub) matches NO enabled rule is rejected and NEVER
-- auto-provisioned.
CREATE TABLE external_assertion_subject_mappings (
    -- The `asm_` scoped identifier (embeds its tenant and environment), the row's
    -- primary key and the audit target of a mapping creation. Not a secret.
    id                text        PRIMARY KEY,
    tenant_id         text        NOT NULL,
    environment_id    text        NOT NULL,
    -- The external issuer this rule maps FROM (matched against the assertion's `iss`).
    issuer            text        NOT NULL,
    -- The external `sub` this rule maps FROM (matched against the assertion's `sub`).
    external_subject  text        NOT NULL,
    -- An OPTIONAL additional claim NAME the assertion must carry with `match_value`
    -- for the rule to fire; NULL when the (issuer, sub) match alone suffices. Paired
    -- with `match_value` (both set or both NULL).
    match_claim       text,
    -- The value the OPTIONAL `match_claim` must equal; NULL when `match_claim` is NULL.
    match_value       text,
    -- The IronAuth principal the mapped token is issued under (the token's `sub`).
    principal         text        NOT NULL,
    -- The enable switch. A disabled mapping is rejected exactly as an absent one
    -- (reject-by-default): the resolve filters on `enabled = true`, so a mis-authored
    -- or decommissioned mapping can be revoked through the data plane.
    enabled           boolean     NOT NULL DEFAULT true,
    created_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT external_assertion_subject_mappings_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The optional claim gate is all-or-nothing: a claim NAME without a VALUE (or the
    -- reverse) is a half-configured rule that must be refused at authoring time.
    CONSTRAINT external_assertion_subject_mappings_match_paired
        CHECK ((match_claim IS NULL) = (match_value IS NULL)),
    -- One rule per (issuer, external_subject) in a scope: the resolve reads AT MOST
    -- one rule and applies its optional claim gate deterministically.
    UNIQUE (tenant_id, environment_id, issuer, external_subject),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

ALTER TABLE external_assertion_subject_mappings ENABLE ROW LEVEL SECURITY;
ALTER TABLE external_assertion_subject_mappings FORCE ROW LEVEL SECURITY;
CREATE POLICY external_assertion_subject_mappings_tenant_isolation
    ON external_assertion_subject_mappings
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT to resolve a mapping at grant time, INSERT to author one, plus a
-- COLUMN-SCOPED UPDATE of exactly `enabled` so a mis-authored or decommissioned
-- mapping can be DISABLED (revoked) through the data plane. The issue #31 lesson
-- applied correctly: UPDATE only the column the data plane legitimately mutates,
-- NEVER a table-wide UPDATE and never UPDATE on the app-immutable
-- id / issuer / external_subject / match_claim / match_value / principal. No DELETE
-- grant: a mapping is disabled, not deleted, by the data plane.
GRANT SELECT, INSERT ON external_assertion_subject_mappings TO ironauth_app;
GRANT UPDATE (enabled) ON external_assertion_subject_mappings TO ironauth_app;

-- ---------------------------------------------------------------------------
-- 3. The external-issuer single-use jti replay cache (issue #26).
--
-- REUSES the #25 client-assertion prune-then-insert single-use mechanism (a shared
-- UNIQUE constraint makes a second use of a jti a conflict, which is correct across
-- nodes because every node inserts into the same row space), but is a DISTINCT
-- table keyed by the external ISSUER rather than the OAuth client id. Because the
-- two tables are separate, an external issuer's jti and a client-assertion jti can
-- NEVER collide, even if a hostile external issuer chose a jti equal to some
-- client's assertion jti.
--
-- `expires_at` is the last instant the assertion could still be replayed (its `exp`
-- PLUS the configured skew PLUS one second), following the SAME +1s margin the #25
-- cache documents: acceptance floors `now` to whole seconds and rejects only once
-- `now_secs > exp + skew`, so the assertion stays acceptable for the entire
-- wall-clock second [exp+skew, exp+skew+1); retaining to exp+skew+1s makes the row
-- strictly OUTLAST acceptance, so a prune can never reopen a replay window.
CREATE TABLE external_assertion_jtis (
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The external issuer the assertion came from. A jti is unique PER issuer (RFC
    -- 7523), so the issuer is part of the single-use key (NOT the client id).
    issuer         text        NOT NULL,
    -- The assertion's jti (an issuer-chosen token identifier).
    jti            text        NOT NULL,
    -- The last replayable instant (assertion exp + skew + 1s), from the application
    -- clock seam, so pruning is deterministic under a manual clock in tests.
    expires_at     timestamptz NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT external_assertion_jtis_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- Single use: a second presentation of the same (issuer, jti) in this scope is a
    -- primary-key conflict, which the recording path maps to REPLAY.
    PRIMARY KEY (tenant_id, environment_id, issuer, jti),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- The prune path scans expired rows within scope by expiry.
CREATE INDEX external_assertion_jtis_expiry_idx
    ON external_assertion_jtis (tenant_id, environment_id, expires_at);

ALTER TABLE external_assertion_jtis ENABLE ROW LEVEL SECURITY;
ALTER TABLE external_assertion_jtis FORCE ROW LEVEL SECURITY;
CREATE POLICY external_assertion_jtis_tenant_isolation ON external_assertion_jtis
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT to check membership, INSERT to record a new jti, and DELETE for the
-- on-insert prune of already-expired rows (the ONLY DELETE the repository issues,
-- exactly like the #25 client-assertion cache). There is deliberately no UPDATE
-- grant: a jti row is never mutated in place.
GRANT SELECT, INSERT, DELETE ON external_assertion_jtis TO ironauth_app;
