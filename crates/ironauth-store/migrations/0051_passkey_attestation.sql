-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Passkey attestation: the FIDO MDS3 metadata cache, the per-scope AAGUID
-- allow/deny lists, and the reg-time attestation facts on the passkey
-- credential row (issue #66, PR B).
--
-- PR A landed the DECLARATIVE attestation config surface (attestation_config.mode
-- of 'none' or 'direct') DORMANT: nothing read it to gate a registration. PR B
-- lands the evaluation substrate the 'direct' mode composes with, and records the
-- attestation outcome on every registered credential:
--
--   mds3_blob_cache: the per-(tenant, environment) SINGLETON verified FIDO
--   Metadata Service (MDS3) BLOB cache. The MDS3 BLOB is a signed JWT the FIDO
--   Alliance publishes listing every certified authenticator's metadata; the
--   attestation path verifies its signature chain ONCE and caches the extracted,
--   trusted entries here so a registration evaluates against a verified snapshot
--   without a network fetch on the hot path. The cache is a REFRESH target, not a
--   log: exactly one row per scope, upserted when a newer BLOB (a higher `no`
--   sequence number) is fetched and re-verified. The raw BLOB's sha-256 digest is
--   stored so a refresh that returns the byte-identical BLOB is a cheap no-op. A
--   tenant-scoped resource with forced row-level security.
--
--   aaguid_rules: the per-scope AAGUID allow / deny list. Each row pins one
--   authenticator model (its 16-byte AAGUID) to a disposition ('allow' or 'deny').
--   Under 'direct' attestation the registration path consults these rules to admit
--   or refuse a specific authenticator model (an enterprise pinning a hardware key
--   family, or excluding a known-weak model). One rule per AAGUID per scope. A
--   tenant-scoped resource with forced row-level security.
--
--   webauthn_credentials.attestation_type / attestation_verified / attestation_fmt:
--   the reg-time IMMUTABLE record of what attestation a credential presented and
--   whether it verified. These are captured ONCE at registration (exactly like
--   backup_eligible, the other reg-time immutable fact) and never change, so they
--   are added with safe defaults ('none' / false / 'none' for every existing row)
--   and are DELIBERATELY absent from every GRANT UPDATE: the data-plane role can
--   INSERT them but has no privilege to name them in an UPDATE, so a later assertion
--   can never rewrite a credential's attestation history.
--
-- Migration safety obligation (see migrate.rs): the two NEW tenant-scoped tables
-- ENABLE and FORCE row-level security, add the (tenant, environment) isolation
-- policy, add the nonempty-scope CHECK, and are registered in
-- scripts/query-audit.sh. The webauthn_credentials additions are additive columns
-- with defaults plus two closed-set CHECKs. Every statement is additive, so this
-- migration is an EXPAND.

-- ---------------------------------------------------------------------------
-- 1. The per-scope verified MDS3 BLOB cache (issue #66, PR B).
--
-- id is an `mbc_` scoped identifier (embeds its (tenant, environment)), the audit
-- target and management handle. blob_no is the MDS3 `no` monotonic sequence number
-- (a refresh only supersedes a strictly higher one); next_update is the BLOB's own
-- `nextUpdate` (when the FIDO Alliance says a fresher BLOB is due). payload_jsonb
-- is the extracted, VERIFIED entry set the registration path evaluates against;
-- blob_digest is the sha-256 of the raw signed BLOB, so a refetch of the
-- byte-identical BLOB is detected and skipped. fetched_at / verified_at record when
-- the BLOB was retrieved and when its signature chain was last re-verified.
-- ---------------------------------------------------------------------------
CREATE TABLE mds3_blob_cache (
    id                 text        NOT NULL,
    tenant_id          text        NOT NULL,
    environment_id     text        NOT NULL,
    -- The MDS3 `no` monotonic sequence number of the cached BLOB.
    blob_no            bigint      NOT NULL,
    -- The cached BLOB's own `nextUpdate` (when a fresher BLOB is due).
    next_update        timestamptz NOT NULL,
    -- The extracted, VERIFIED authenticator entries the registration evaluates against.
    payload_jsonb      jsonb       NOT NULL,
    -- The sha-256 of the raw signed BLOB, for byte-identical-refetch change detection.
    blob_digest        bytea       NOT NULL,
    -- When the BLOB was fetched, and when its signature chain was last re-verified.
    fetched_at         timestamptz NOT NULL,
    verified_at        timestamptz NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL,
    CONSTRAINT mds3_blob_cache_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    PRIMARY KEY (tenant_id, environment_id, id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- Exactly one MDS3 BLOB cache per (tenant, environment): the scope-wide snapshot.
-- A refresh upserts onto this key.
CREATE UNIQUE INDEX mds3_blob_cache_scope_uk
    ON mds3_blob_cache (tenant_id, environment_id);

-- The standard scope index for scope-filtered reads.
CREATE INDEX mds3_blob_cache_scope_idx
    ON mds3_blob_cache (tenant_id, environment_id);

ALTER TABLE mds3_blob_cache ENABLE ROW LEVEL SECURITY;
ALTER TABLE mds3_blob_cache FORCE ROW LEVEL SECURITY;
CREATE POLICY mds3_blob_cache_tenant_isolation ON mds3_blob_cache
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The refresh path SELECTs the cached snapshot and upserts it (INSERT ... ON
-- CONFLICT DO UPDATE). COLUMN-scoped UPDATE only (the #31 least-privilege lesson):
-- a refresh may only advance the cached BLOB's own facts; the scope and the id are
-- immutable. There is NO DELETE: a cache is refreshed in place, never removed.
GRANT SELECT, INSERT ON mds3_blob_cache TO ironauth_app;
GRANT UPDATE (blob_no, next_update, payload_jsonb, blob_digest, fetched_at, verified_at, updated_at)
    ON mds3_blob_cache TO ironauth_app;

-- ---------------------------------------------------------------------------
-- 2. The per-scope AAGUID allow / deny list (issue #66, PR B).
--
-- id is an `aag_` scoped identifier. aaguid is the 16-byte authenticator model
-- identifier the rule pins. disposition is the closed set {allow, deny}: under
-- 'direct' attestation the registration path admits an 'allow'-listed model and
-- refuses a 'deny'-listed one. One rule per AAGUID per scope (a model has a single
-- governing disposition, so an upsert collapses onto the (scope, aaguid) key).
-- ---------------------------------------------------------------------------
CREATE TABLE aaguid_rules (
    id                 text        NOT NULL,
    tenant_id          text        NOT NULL,
    environment_id     text        NOT NULL,
    -- The 16-byte authenticator model identifier the rule pins.
    aaguid             bytea       NOT NULL,
    -- The disposition applied to the model: 'allow' or 'deny'.
    disposition        text        NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL,
    CONSTRAINT aaguid_rules_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT aaguid_rules_disposition_known
        CHECK (disposition IN ('allow', 'deny')),
    PRIMARY KEY (tenant_id, environment_id, id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- At most one rule per (tenant, environment, aaguid): a model has one governing
-- disposition, so an upsert collapses onto this key.
CREATE UNIQUE INDEX aaguid_rules_aaguid_uk
    ON aaguid_rules (tenant_id, environment_id, aaguid);

-- The standard scope index for scope-filtered listing.
CREATE INDEX aaguid_rules_scope_idx
    ON aaguid_rules (tenant_id, environment_id);

ALTER TABLE aaguid_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE aaguid_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY aaguid_rules_tenant_isolation ON aaguid_rules
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- The evaluation path SELECTs, and management upserts (INSERT ... ON CONFLICT DO
-- UPDATE), removes (DELETE) a rule. COLUMN-scoped UPDATE only (the #31 lesson):
-- only the disposition and updated_at may change on an upsert; the scope and the
-- pinned aaguid are immutable (a different model is a different row).
GRANT SELECT, INSERT, DELETE ON aaguid_rules TO ironauth_app;
GRANT UPDATE (disposition, updated_at) ON aaguid_rules TO ironauth_app;

-- ---------------------------------------------------------------------------
-- 3. The reg-time attestation facts on the passkey credential row (issue #66).
--
-- attestation_type is the closed set {none, self, basic, attca, anonca} (the
-- WebAuthn attestation trust-path types); attestation_verified records whether the
-- attestation statement was validated against the MDS3 snapshot; attestation_fmt is
-- the closed set {none, packed} (the attestation statement formats PR B verifies).
-- These are reg-time IMMUTABLE facts captured ONCE at registration, exactly like
-- backup_eligible: they default to the no-attestation values so every existing row
-- is well-formed, and they are DELIBERATELY absent from every GRANT UPDATE on
-- webauthn_credentials (they are INSERT-only), so a later assertion can never
-- rewrite a credential's attestation history.
-- ---------------------------------------------------------------------------
ALTER TABLE webauthn_credentials
    ADD COLUMN attestation_type     text    NOT NULL DEFAULT 'none',
    ADD COLUMN attestation_verified boolean NOT NULL DEFAULT false,
    ADD COLUMN attestation_fmt      text    NOT NULL DEFAULT 'none';

ALTER TABLE webauthn_credentials
    ADD CONSTRAINT webauthn_credentials_attestation_type_known
        CHECK (attestation_type IN ('none', 'self', 'basic', 'attca', 'anonca')),
    ADD CONSTRAINT webauthn_credentials_attestation_fmt_known
        CHECK (attestation_fmt IN ('none', 'packed'));
