-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- Per-organization authentication policies (issue #95, milestone M10).
--
-- Creates `org_auth_policies`: at most ONE live policy document per organization,
-- holding the authentication dimensions an organization may TIGHTEN for its own
-- members. The organization IS the identity of the row, which is why every
-- mutation addresses it by `organization_id` alone.
--
-- EVERY dimension is NULLABLE and NULL means UNSET, which the pure resolution
-- engine (crates/ironauth-store/src/org_policy.rs) reads as "inherit the next
-- level up unchanged". An all-NULL row is the identity element of every
-- combinator and restricts nothing, which is the issue's "an empty policy object
-- restricts nothing" expressed in the storage model rather than in a default
-- somewhere downstream.
--
-- Discrete typed columns rather than one jsonb blob, decided against the whole
-- schema rather than by preference. Every real policy object here is discrete
-- columns with CHECK constraints (`credential_class_policies` 0049,
-- `scope_step_up_policies` 0047, and `org_connections` 0059, the closest analogue
-- of all: a per-organization overlay of nullable columns where NULL means
-- inherit). No jsonb column anywhere is read field by field by an auth decision.
-- Four properties are lost by a blob and all four are load-bearing here:
--
--   1. Closed-set CHECKs. A malformed row must be UNWRITABLE by the storage
--      engine, not merely unwritten by the application. A blob forfeits that.
--   2. Per-column GRANT scoping. A blob is ONE grantable unit, so the #31 lesson
--      (immutability as a GRANT property; see the grants below) cannot be
--      expressed inside it.
--   3. NULL is the natural encoding of "unset, inherit". The store COALESCEs a
--      None jsonb bind to '{}'::jsonb on insert, which ERASES exactly the
--      distinction this design depends on.
--   4. The intra-document contradiction becomes ROW LOCAL and therefore
--      expressible as a CHECK latch (`org_auth_policies_mfa_reachable` below).
--
-- Cost accepted and stated: the closed factor vocabulary is pinned into a CHECK,
-- so a new `AuthMethod` needs a migration before an organization may name it.
-- That cost was accepted twice already (0049:69-70, 0059:84-89) and it degrades
-- SAFELY: the list is an allowlist INTERSECTED across levels, so being unable to
-- add a value can only ever refuse more, never permit more.
--
-- ---------------------------------------------------------------------------
-- What deliberately does NOT live here (1): the credential-class ladder.
-- ---------------------------------------------------------------------------
-- There is NO `min_class` column, deliberately. An organization's minimum
-- credential class stays in `credential_class_policies` (0049) as a
-- `subject_kind = 'org'` row. 0049 built that discriminator as "the inert
-- attachment seam (end-to-end group/org attachment lands with the M10
-- organization model)", and issue #95 IS that unlock: as of #95 the `'org'` rows
-- are LIVE, and so are the `'group'` rows, now that issue #97 has shipped real
-- `grp_` groups and a bounded `effective_group_slugs` closure to fold them by.
--
-- Duplicating a `min_class` here would create TWO tables that can each state a
-- floor for one organization with no defined precedence between them. Two sources
-- of truth for one authorization decision is the drift hazard this repository
-- names by category, and issue #66's composition documentation already
-- anticipates the 0049 route (`authn::required_class` folds every applicable row
-- with strictest-wins max, and that fold "holds the moment the attachment surface
-- lands"). Exactly ONE ladder. An operator therefore looks in two places for an
-- organization's complete policy, which is the accepted cost.
--
-- ---------------------------------------------------------------------------
-- What deliberately does NOT live here (2): a session-lifetime LENGTHENING.
-- ---------------------------------------------------------------------------
-- `session_ttl_secs` and `session_idle_ttl_secs` are strictest-wins (MIN across
-- levels) like every other dimension: an organization may only SHORTEN a session,
-- never lengthen one. Three facts make that the only coherent semantics here. The
-- session cookie is minted ONCE and is never re-issued from /authorize, so a
-- LENGTHENED server-side lifetime is invisible to the browser and the user is
-- logged out early anyway; `sessions.absolute_expires_at` has no UPDATE grant for
-- either role, so post-creation tightening of an existing row is not even
-- expressible today; and uniform strictest-wins is what makes the resolution fold
-- ORDER INDEPENDENT, which is the property the engine's shuffle-oracle test
-- guards. The deployment ceiling (`OIDC_MAX_SESSION_TTL_SECS`) is a config value
-- and therefore not expressible as a CHECK; it arrives as a store-guard
-- parameter, mirrored in the store as `ORG_POLICY_MAX_SESSION_TTL_SECS` with a
-- cross-crate test pinning the two equal.
--
-- ---------------------------------------------------------------------------
-- The allowed-email-domain list and JIT: COLUMNS ONLY, no enforcement in #95.
-- ---------------------------------------------------------------------------
-- `allowed_email_domains` and `jit_provisioning` ship here with shape validation
-- and normalization, and NOTHING reads them until a later PR. Three commitments
-- are recorded here because getting any of them wrong later is a privilege
-- escalation rather than a bug:
--
--   (i)   The list is an UNVERIFIED OPERATOR ASSERTION. No domain-ownership proof
--         exists for membership purposes: `custom_domains` (0033) proves control
--         for SERVING only, and `routing_rules.domain_norm` (0059) has no proof at
--         all. The list is therefore usable ONLY as a NARROWING FILTER on an
--         address that has ALREADY been verified by some other means, and NEVER as
--         authority for the address itself. An unverified list plus JIT is an
--         account-absorption vector: an organization listing a public mail
--         provider with JIT on would absorb every login from it in the
--         environment.
--   (ii)  Matching is EXACT on the normalized form produced by
--         `ironauth_store::normalize_routing_domain`, NEVER suffix matching. Two
--         match semantics already coexist in this tree (#77 routing matches
--         exactly; #80 disposable matching walks PARENT domains), and silently
--         inheriting the suffix form would make listing `acme.example` admit
--         `anything.acme.example`, a privilege escalation wherever a subdomain is
--         delegated. If per-entry suffix matching is ever wanted it arrives as an
--         explicit flag, never as a silent semantic. The inherited limitation of
--         that normalizer is restated rather than diverged from: it performs no
--         IDNA/punycode mapping and no trailing-dot stripping, so `xn--` and
--         unicode spellings of one name are distinct selectors.
--   (iii) TWO ORGANIZATIONS MAY CLAIM THE SAME DOMAIN in one environment, so there
--         is deliberately NO unique index on a domain here, unlike
--         `routing_rules_domain_uniq` (0059:167-169). The two surfaces answer
--         different questions: routing must pick EXACTLY ONE IdP for a domain, so
--         a second claim there is ambiguity; two organizations may both
--         legitimately accept `contractor.example`, so a second claim here is
--         ordinary. The reason is recorded so issue #96 does not later merge the
--         two surfaces by mistake.
--
-- ---------------------------------------------------------------------------
-- Covenant.
-- ---------------------------------------------------------------------------
-- The table is NOT capped. There is no count constraint, no quota check, and no
-- advisory-lock-plus-COUNT gate anywhere: a project covenant forbids any cap or
-- paywall gate on the number of policies, allowed domains, or allowed factors an
-- organization may state. There is no advisory lock on this table at all: unlike
-- the 0087 group forest there is no tree here and nothing to serialize, and the
-- covenant forbids the counting gate the lock superficially resembles.
--
-- The delta vocabulary (what milestone M11 will consume). Every mutation of this
-- table writes an audit_log row in the SAME transaction as the mutation, under one
-- of two actions: `organization.policy.set` and `organization.policy.remove`.
-- Those two action strings ARE the delta contract for a policy. `set` rather than
-- `create`/`update` because the write is an upsert keyed on the organization (the
-- `credential_class.policy.set` precedent). Both rows carry an operator-safe
-- `detail` summary of the dimensions the write states, in a CLOSED token
-- vocabulary that never contains a domain string or a factor token: turning on
-- `mfa_required` forces enrollment for every member, so its blast radius is not
-- the target row and the audit row alone would otherwise not let an operator
-- reconstruct it. There is deliberately NO outbox table and no change feed (that
-- is M11; migration 0025 records why a shared outbox built without a concrete
-- consumer in view is very likely the wrong shape).
--
-- Migration safety obligation (see migrate.rs): `org_auth_policies` is a NEW
-- TENANT-SCOPED table, so it ENABLEs and FORCEs row-level security, carries the
-- (tenant, environment) isolation policy with byte-identical USING and WITH CHECK,
-- carries the nonempty-scope CHECK, and is registered in scripts/query-audit.sh.
-- Grants are least-privilege and COLUMN-scoped for the UPDATE (the #31 lesson).
-- Every statement is additive (a new table, its indexes, its policy, and its
-- grants; no existing column is altered or dropped), so this migration is an
-- EXPAND.

CREATE TABLE org_auth_policies (
    -- The oap_ scoped identifier; embeds its (tenant, environment).
    id                     text        PRIMARY KEY,
    tenant_id              text        NOT NULL,
    environment_id         text        NOT NULL,
    -- The organization this policy governs (an org_ id). ONE LIVE policy per
    -- organization; see org_auth_policies_org_live_uniq below.
    organization_id        text        NOT NULL,

    -- Whether a genuine SECOND FACTOR is required of this organization's members.
    -- This rides the `mfa_baseline_required` channel at enforcement and must NEVER
    -- be expressed as an `mfa` acr floor: the acr ladder ranks `phr` ABOVE `mfa`,
    -- so an `mfa` floor is silently satisfiable by a presence-only, non
    -- user-verified passkey, which performed no second factor at all.
    mfa_required           boolean,
    -- The allowed authentication methods, as AuthMethod persistence tokens. NULL
    -- means unconstrained; resolution INTERSECTS every level that states one, so a
    -- present list may only ever REMOVE options.
    allowed_factors        text[],
    -- The email domains this organization accepts, in normalized form. NULL means
    -- unconstrained. Read by nothing in this issue; see the header for the three
    -- commitments that govern it.
    allowed_email_domains  text[],
    -- Whether a matching login may be provisioned into this organization with no
    -- administrator acting. Read by nothing in this issue.
    jit_provisioning       boolean,
    -- Whether invitations (issue #94) may be issued for this organization.
    invitations_enabled    boolean,
    -- The absolute session lifetime and the idle window, in seconds. Strictest
    -- wins (MIN); an organization may only shorten. See the header.
    session_ttl_secs       integer,
    session_idle_ttl_secs  integer,

    -- Free-form policy metadata the admin surface reads and writes; never
    -- interpreted by the auth core.
    metadata               jsonb       NOT NULL DEFAULT '{}',
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    -- When the policy was removed (present only in a soft-deleted row). The row is
    -- retained so the audit foreign key to it stays satisfiable.
    deleted_at             timestamptz,

    CONSTRAINT org_auth_policies_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),

    -- A list is NULL (unconstrained) or NONEMPTY. An explicitly EMPTY list is
    -- UNWRITABLE: it would mean "permit nothing", a lockout dressed as a
    -- configuration, and it is exactly the shape a caller reaches by accident when
    -- it means "no restriction". Forcing NULL for unconstrained removes a whole
    -- class of the empty-intersection hazard at the storage engine.
    CONSTRAINT org_auth_policies_factors_nonempty
        CHECK (allowed_factors IS NULL OR cardinality(allowed_factors) > 0),
    CONSTRAINT org_auth_policies_domains_nonempty
        CHECK (allowed_email_domains IS NULL OR cardinality(allowed_email_domains) > 0),

    -- The closed factor vocabulary, byte-identical to AuthMethod::as_token()
    -- (crates/ironauth-oidc/src/authn.rs). ONE registry: an operator-facing synonym
    -- set would be a second one. A test in ironauth-oidc (the only crate that can
    -- see both) pins this set equal to the live AuthMethod registry, so a new
    -- method fails that test until it is classified and added here.
    CONSTRAINT org_auth_policies_factors_known
        CHECK (allowed_factors IS NULL OR allowed_factors <@ ARRAY[
            'pwd', 'federated', 'email_otp', 'sms', 'trusted_device',
            'totp', 'recovery_code',
            'passkey', 'passkey_uv', 'passkey_hw', 'passkey_hw_uv',
            'attested_passkey', 'attested_passkey_uv',
            'attested_passkey_hw', 'attested_passkey_hw_uv'
        ]::text[]),

    -- The ROW-LOCAL half of the empty-intersection hazard. A policy that requires
    -- MFA and names a factor list containing no method able to carry a GENUINE
    -- second factor is unsatisfiable on its face.
    --
    -- The six tokens are EXACTLY the AuthMethod values whose RFC 8176 amr contains
    -- "mfa", which is what authn::performed_second_factor tests. Note what is
    -- ABSENT and would be the plausible mistake: `email_otp` and `sms` are single
    -- PRIMARY factors here and carry no "mfa" amr, so a list of exactly
    -- {email_otp, sms} with mfa_required IS unsatisfiable and this CHECK refuses
    -- it. A constraint built on the wrong set would ACCEPT an unsatisfiable policy,
    -- which is the precise defect the validation exists to prevent.
    --
    -- This constraint is a DEFENSE-IN-DEPTH LATCH the application path never
    -- reaches. The pure store guard refuses first with a typed error, because a
    -- CHECK raised MID-transaction aborts it (SQLSTATE 25P02 thereafter) and every
    -- mutation here must write its audit row AFTER the mutation and BEFORE the
    -- commit, so a database-raised refusal would make the audit row impossible.
    -- That is the 0087 argument applied unchanged.
    CONSTRAINT org_auth_policies_mfa_reachable
        CHECK (
            mfa_required IS NOT TRUE
            OR allowed_factors IS NULL
            OR allowed_factors && ARRAY[
                'totp', 'recovery_code',
                'passkey_uv', 'passkey_hw_uv',
                'attested_passkey_uv', 'attested_passkey_hw_uv'
            ]::text[]
        ),

    -- Positive durations, and idle never beyond absolute: an idle timeout past the
    -- absolute cap can never fire. That is the ironauth-config rule
    -- (validate_session_lifetimes) restated ROW LOCALLY. The pair is checked AGAIN
    -- on the RESOLVED value, because an organization may state only one of the two
    -- and inherit the other, which no row-local CHECK can see. The deployment
    -- CEILING is NOT expressible here (it is a config value), so it is a store
    -- guard parameter.
    CONSTRAINT org_auth_policies_session_ttl_positive
        CHECK (session_ttl_secs IS NULL OR session_ttl_secs > 0),
    CONSTRAINT org_auth_policies_session_idle_positive
        CHECK (session_idle_ttl_secs IS NULL OR session_idle_ttl_secs > 0),
    CONSTRAINT org_auth_policies_idle_within_absolute
        CHECK (
            session_idle_ttl_secs IS NULL
            OR session_ttl_secs IS NULL
            OR session_idle_ttl_secs <= session_ttl_secs
        ),

    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id),
    -- The organization must exist. The organization id is globally unique and
    -- embeds its own scope, so an id-only foreign key is sufficient and is the
    -- backstop that makes a policy on a nonexistent or cross-scope organization
    -- impossible (the 0084 precedent, restated in 0086).
    FOREIGN KEY (organization_id) REFERENCES organizations (id)
);

-- At most one LIVE policy per organization. PARTIAL over live rows, so a removed
-- policy does not occupy its organization and a later `set` inserts a FRESH row
-- with a FRESH id; every read filters deleted_at IS NULL, so the reads and this
-- uniqueness invariant agree on exactly the live set. It is also the conflict
-- target the `set` upsert names, which is why it must be partial in exactly the
-- shape the reads filter.
--
-- The deliberate choice between the two precedents: org_memberships REVIVES a dead
-- row (0084) because its identity is the (organization, user) pair; org_roles does
-- NOT (0086) because reviving would silently restore every assignment that pointed
-- at the id. A POLICY follows org_roles. Its identity is the organization, like a
-- membership, but removing a policy is a SECURITY operation whose effects must not
-- be quietly reversible: a `set` after a `remove` states every dimension
-- explicitly, so a fresh row is observationally identical in VALUE while keeping
-- the audit trail honest about when this policy began.
CREATE UNIQUE INDEX org_auth_policies_org_live_uniq
    ON org_auth_policies (tenant_id, environment_id, organization_id)
    WHERE deleted_at IS NULL;

-- The scope-wide "policies in this environment" list, on the stable (created_at,
-- id) pagination key. The per-organization lookup on the login path uses the live
-- unique index above.
CREATE INDEX org_auth_policies_scope_idx
    ON org_auth_policies (tenant_id, environment_id, created_at, id);

ALTER TABLE org_auth_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_auth_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY org_auth_policies_tenant_isolation ON org_auth_policies
    USING (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    )
    WITH CHECK (
        tenant_id = current_setting('ironauth.tenant_id', true)
        AND environment_id = current_setting('ironauth.environment_id', true)
    );

-- Grants.
--
-- The CONTROL plane owns the policy surface: inspect (SELECT), create (INSERT),
-- and change or remove through a COLUMN-scoped UPDATE of EXACTLY the mutable
-- dimensions. `id`, `tenant_id`, `environment_id`, and `organization_id` are
-- deliberately ABSENT, so a policy row can never be moved between scopes or
-- between organizations; that is what keeps the containment invariant from being
-- defeatable by an UPDATE after the fact (the 0087 argument). DELETE is granted to
-- nobody on either plane: removal is the soft delete.
GRANT SELECT, INSERT ON org_auth_policies TO ironauth_control;
GRANT UPDATE (
    mfa_required, allowed_factors, allowed_email_domains,
    jit_provisioning, invitations_enabled,
    session_ttl_secs, session_idle_ttl_secs,
    metadata, updated_at, deleted_at
) ON org_auth_policies TO ironauth_control;

-- The DATA plane needs SELECT and NOTHING ELSE: the resolution engine runs on the
-- authorization path under the low-privilege app role. A data plane able to
-- rewrite its own MFA requirement is the whole threat, so INSERT, UPDATE, and
-- DELETE are granted to nobody there. The SELECT is granted HERE, in the creating
-- migration, rather than deferred to the PR that first needs it: the
-- 0027-then-0084 revoke-and-re-grant churn on `organizations` is the cautionary
-- precedent for deferring a grant the design already knows it needs.
GRANT SELECT ON org_auth_policies TO ironauth_app;
