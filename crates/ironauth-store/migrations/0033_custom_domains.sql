-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Per-environment custom domains with built-in ACME (issue #47, EXPLORATORY).
--
-- Issue #42 recorded an environment's CONFIGURED custom_domain on the
-- environments level table (the value the production custom-domain guardrail
-- requires). This migration adds the LIFECYCLE that turns a configured name into
-- a served, TLS-terminated hostname: the tenant proves control of the domain
-- through an ACME challenge, an ACME CA issues a certificate, and the issued
-- cert plus its private key are stored encrypted at rest. It persists two new
-- tenant-scoped tables:
--
--   1. custom_domains: the registered domains per environment, each with its own
--      verification status, selected challenge type, and (once issued) a handle
--      to the encrypted certificate bundle and the cert's not-after instant (the
--      renewal-scheduling anchor). A domain is ENVIRONMENT-IDENTITY (issue #41
--      classification, see classification.rs): it is part of what makes this
--      environment itself, so a config snapshot (issue #43) and a promotion
--      (issue #44) never copy it. The cert's PRIVATE KEY is a per-tenant secret
--      and is NEVER stored here in plaintext: it lives in encrypted_secrets
--      (issue #48 envelope encryption), sealed under the scope's DEK, and this
--      row carries only an OPAQUE handle to it (cert_secret_id). A database dump
--      of custom_domains therefore reveals no key material.
--
--   2. acme_challenges: the ACME challenge lifecycle rows (RFC 8555 section 7.5),
--      one per verification attempt for a domain. A challenge carries its type
--      (http-01 or dns-01), the challenge token (a PUBLIC value the tenant serves
--      or publishes, never a secret), its status (pending, valid, or invalid),
--      and the retry/backoff bookkeeping (attempt count and the next-attempt
--      instant) the renewal scheduler drives off. The status transition is the
--      "issued, validated, failed" lifecycle the exploratory deliverable
--      validates.
--
-- CROSS-TENANT EXCLUSIVITY (issue #47 acceptance: one tenant cannot claim
-- another tenant's verified domain). Both tables are RLS-forced and scoped to
-- (tenant, environment) exactly like clients (0001), so a tenant only ever reads
-- or writes its own rows. That alone does NOT stop two tenants from each VERIFYING
-- the same domain, because neither can see the other's rows to check. The
-- enforcement is a GLOBAL partial UNIQUE INDEX on the domain name of VERIFIED rows
-- (custom_domains_verified_domain_unique below): a unique index is maintained by
-- the storage engine across EVERY row regardless of row-level security, so the
-- second tenant's transition to 'verified' collides with the first tenant's
-- verified row and is refused with a unique violation, even though that tenant
-- cannot see the row it collided with. This is the single point that guarantees a
-- verified domain has exactly one owner platform-wide. A per-scope UNIQUE on
-- (tenant, environment, domain_name) separately keeps a single environment from
-- registering the same domain twice. Registration of a still-PENDING claim on a
-- name is intentionally NOT globally exclusive (two tenants may both hold a
-- pending intent); the race is resolved at VERIFICATION, where the CA challenge
-- proves control and the partial unique index admits exactly one verified owner.
--
-- Migration safety obligation (see migrate.rs): each new tenant-scoped table
-- ENABLEs and FORCEs row-level security, adds the (tenant, environment) isolation
-- policy, adds the nonempty-scope CHECK, and is registered in
-- scripts/query-audit.sh. All hold below. This whole migration is additive (two
-- new tables, their indexes, policies, and grants), so it is an EXPAND.

-- ---------------------------------------------------------------------------
-- The registered custom domains per environment.
CREATE TABLE custom_domains (
    -- The cdom_ scoped identifier (a public handle; embeds its scope).
    id                 text        PRIMARY KEY,
    tenant_id          text        NOT NULL,
    environment_id     text        NOT NULL,
    -- The fully-qualified domain name, normalized to lowercase by the
    -- application before it reaches a row. UNTRUSTED tenant input: it is
    -- validated (a real registrable hostname, never an internal name or an IP)
    -- above this column, and every outbound ACME/CA request that mentions it goes
    -- through the SSRF-hardened ironauth-fetch path.
    domain_name        text        NOT NULL,
    -- The selected ACME challenge type: 'http-01' or 'dns-01' (RFC 8555 8.3/8.4).
    -- The CHECK pins the closed set the Rust ChallengeType enum accepts.
    challenge_type     text        NOT NULL DEFAULT 'http-01',
    -- The verification lifecycle: 'pending' (registered, not yet proven),
    -- 'verified' (an ACME challenge succeeded and the CA confirmed control), or
    -- 'failed' (the challenge could not be satisfied). Only a 'verified' domain is
    -- ever served.
    verification_status text       NOT NULL DEFAULT 'pending',
    -- The OPAQUE handle (an encrypted_secrets id) to the sealed certificate
    -- bundle (cert chain plus private key), or NULL before a cert is issued. The
    -- key material lives ONLY in encrypted_secrets, sealed under the scope's DEK
    -- (issue #48); this column never carries a key or a certificate byte.
    cert_secret_id     text,
    -- The issued certificate's not-after instant (from the application clock
    -- seam), NULL before issuance. The renewal scheduler renews well before this.
    cert_not_after     timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    -- The last transition instant, from the application clock seam.
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT custom_domains_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT custom_domains_challenge_type_valid
        CHECK (challenge_type IN ('http-01', 'dns-01')),
    CONSTRAINT custom_domains_verification_status_valid
        CHECK (verification_status IN ('pending', 'verified', 'failed')),
    -- One registration per (scope, domain): an environment cannot register the
    -- same name twice. The cross-tenant verified exclusivity is the partial index
    -- below, NOT this per-scope constraint.
    UNIQUE (tenant_id, environment_id, domain_name),
    -- The environment-scoped unique target the acme_challenges FK references, so
    -- a challenge row can only ever point at a domain in its OWN scope.
    UNIQUE (id, tenant_id, environment_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX custom_domains_scope_idx ON custom_domains (tenant_id, environment_id);

-- The cross-tenant exclusivity guarantee (issue #47): AT MOST ONE tenant may hold
-- a given domain name in the 'verified' state platform-wide. A partial UNIQUE
-- INDEX is enforced by the storage engine across every row irrespective of
-- row-level security, so a second tenant's UPDATE to 'verified' for a name
-- already verified elsewhere is refused with a unique violation (SQLSTATE 23505,
-- reported against this index name), even though that tenant cannot SELECT the
-- conflicting row. Pending and failed rows are excluded, so a released or
-- never-completed claim never permanently blocks a name.
CREATE UNIQUE INDEX custom_domains_verified_domain_unique
    ON custom_domains (domain_name)
    WHERE verification_status = 'verified';

ALTER TABLE custom_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE custom_domains FORCE ROW LEVEL SECURITY;
CREATE POLICY custom_domains_tenant_isolation ON custom_domains
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT/INSERT to register and read domains. A COLUMN-SCOPED UPDATE over exactly
-- the columns the verification and issuance lifecycle rewrites: the verification
-- status, the certificate handle, the cert not-after, and the update instant. The
-- domain name and the challenge type are immutable after registration (they are
-- excluded from the UPDATE grant, so Postgres refuses any rewrite fail-closed).
-- Never a table-wide UPDATE (the #31 least-privilege lesson). No DELETE: a
-- domain's history (including a failed verification) is retained.
GRANT SELECT, INSERT ON custom_domains TO ironauth_app;
GRANT UPDATE (verification_status, cert_secret_id, cert_not_after, updated_at)
    ON custom_domains TO ironauth_app;

-- ---------------------------------------------------------------------------
-- The ACME challenge lifecycle rows.
CREATE TABLE acme_challenges (
    -- The chal_ scoped identifier.
    id             text        NOT NULL,
    tenant_id      text        NOT NULL,
    environment_id text        NOT NULL,
    -- The domain this challenge proves control of (in the same scope).
    domain_id      text        NOT NULL,
    -- The challenge type actually attempted: 'http-01' or 'dns-01'.
    challenge_type text        NOT NULL,
    -- The ACME challenge token (RFC 8555 8.1): a PUBLIC value the tenant serves at
    -- the well-known HTTP path (http-01) or publishes as a TXT record (dns-01).
    -- Not a secret; plaintext is correct.
    token          text        NOT NULL,
    -- The challenge lifecycle: 'pending' (issued, awaiting the CA), 'valid' (the
    -- CA confirmed control), or 'invalid' (the challenge failed).
    status         text        NOT NULL DEFAULT 'pending',
    -- The retry bookkeeping the renewal scheduler drives off: how many attempts
    -- have been made, and the next-attempt instant (from the clock seam, NULL when
    -- no retry is scheduled). Backoff timing is computed deterministically from
    -- the clock seam so the schedule is testable under a manual clock.
    attempts       integer     NOT NULL DEFAULT 0,
    next_attempt_at timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    CONSTRAINT acme_challenges_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    CONSTRAINT acme_challenges_challenge_type_valid
        CHECK (challenge_type IN ('http-01', 'dns-01')),
    CONSTRAINT acme_challenges_status_valid
        CHECK (status IN ('pending', 'valid', 'invalid')),
    -- The challenge belongs to a domain in its OWN scope: the composite FK targets
    -- the (id, tenant, environment) unique on custom_domains, so a challenge can
    -- never reference a domain in another scope.
    FOREIGN KEY (domain_id, tenant_id, environment_id)
        REFERENCES custom_domains (id, tenant_id, environment_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

CREATE INDEX acme_challenges_scope_idx ON acme_challenges (tenant_id, environment_id);
CREATE INDEX acme_challenges_domain_idx ON acme_challenges (domain_id);

ALTER TABLE acme_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE acme_challenges FORCE ROW LEVEL SECURITY;
CREATE POLICY acme_challenges_tenant_isolation ON acme_challenges
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- SELECT/INSERT to open and read challenges. A COLUMN-SCOPED UPDATE over exactly
-- the lifecycle columns a challenge result and a retry rewrite: the status, the
-- attempt count, the next-attempt instant, and the update instant. The type and
-- token are immutable after issuance (excluded from the grant). No DELETE: the
-- challenge history is retained as the verification audit trail.
GRANT SELECT, INSERT ON acme_challenges TO ironauth_app;
GRANT UPDATE (status, attempts, next_attempt_at, updated_at)
    ON acme_challenges TO ironauth_app;
