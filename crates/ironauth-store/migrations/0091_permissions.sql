-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The permission vocabulary (issue #98, milestone M10).
--
-- Creates `permissions`: the set of named API CAPABILITIES an environment
-- defines. A permission in this migration is a NAME and a label only. The
-- organization-scoped role-to-permission mapping is the next migration of this
-- issue and adds no column here; the token claim, its budget, and the audience
-- opt-in add no column here either.
--
-- ---------------------------------------------------------------------------
-- (1) The vocabulary is PER ENVIRONMENT. There is deliberately NO
--     `organization_id`, and this is settled.
-- ---------------------------------------------------------------------------
-- A reader arriving from 0086 (`org_roles`), 0087 (`org_groups`), or 0090
-- (`org_auth_policies`) will look for the `organization_id` column those three
-- carry, and must not conclude one was forgotten. It was decided against, for
-- one reason that is about meaning rather than convenience:
--
--   A permission NAMES AN API CAPABILITY. One string cannot sensibly mean
--   different things to two organizations calling the SAME API. If
--   `billing.invoice.read` meant one thing for organization A and another for
--   organization B, the resource server reading the claim would have to know
--   which organization minted the token before it could interpret the string,
--   and the claim would stop being a capability name at all.
--
-- What varies per organization is WHICH permissions a role grants, and that is
-- exactly what the mapping table carries: it holds an `organization_id` because
-- ROLES are per organization. The vocabulary underneath them is shared.
--
-- Three consequences worth stating, because each one is load-bearing:
--
--   (i)   This table is scoped to exactly `(tenant, environment)` and to nothing
--         finer, so the row-level-security policy below IS THE COMPLETE FENCE
--         for it. Every #97 table needs an organization predicate repeated in
--         every statement on top of the policy, because the policy cannot see
--         that third dimension. This one does not. That is a genuine
--         simplification and not an omission.
--   (ii)  The escalation worry ("could an organization admin attach a foreign
--         organization's permission?") was checked in code rather than assumed:
--         management credentials are scoped to `(tenant, environment)` through
--         `Principal::require_environment`, and NO per-organization admin
--         credential exists in the product. Anyone who can attach a permission
--         to a role can already create that role. There is no privilege boundary
--         between organizations on the management plane to breach.
--   (iii) Issue #103 (entitlements, organization hierarchy) inherits this
--         decision rather than reopening it. Adding an `organization_id` later
--         would be a breaking migration on a table the token path reads.
--
-- ---------------------------------------------------------------------------
-- (2) The slug grammar, and why it is a STRICT SUBSET of the #97 role charset.
-- ---------------------------------------------------------------------------
--   permission-slug = segment ( "." segment )+
--   segment         = [a-z0-9] [a-z0-9_-]*
--   total length    = 1 to 63
--
-- The regex below is a strict subset of the SHIPPED role and group charset
-- `^[a-z0-9][a-z0-9._-]{0,62}$` (0086:76-77, 0087:118-119). Every valid
-- permission slug is therefore also a valid role slug. Three consequences:
--
--   * Nothing about the shipped role or group charset changes. There is no
--     migration on 0086 or 0087 and there is no second slug grammar in the
--     codebase. Reusing the charset is HOW the breaking change is avoided.
--   * The exclusions the role charset already bought are inherited for free:
--     `:` `/` `,` `@` `+` `~` `#` `?`, whitespace, uppercase, and every
--     non-ASCII byte are refused. Those exclusions are deliberate, so that a
--     consumer which ever joins a permission set on any of those characters is
--     safe by construction. Space joining in particular is what an OAuth
--     `scope` string does.
--   * The grammar ADDS three structural refusals the role charset permits: a
--     leading or trailing `.`, a doubled `..`, and a SINGLE-segment slug. A
--     permission is namespaced BY CONSTRUCTION, not by convention.
--
-- `.` is the delimiter and `:` deliberately is not, despite the familiarity of
-- the `read:orders` spelling. Three reasons in descending weight. `:` is absent
-- from the shipped role charset, so adopting it forks the tree into two slug
-- grammars. `:` is already a STRUCTURAL SELECTOR in `${secret:NAME}` and
-- `${var:NAME}` (crates/ironauth-store/src/esv.rs). And `:` is legal inside both
-- an RFC 8707 resource indicator and an OAuth scope token, which are precisely
-- the two adjacent vocabularies a reader is most likely to confuse a permission
-- with. `.` is already this repository's namespace delimiter in three
-- independent places (the role slug example is literally `billing.admin`, audit
-- action wire strings are dotted, and resource-type wire tokens are dotted).
--
-- The ASCII hyphen U+002D in the character class is deliberate and is not prose
-- punctuation (scripts/dash-scan.sh targets only the em and en dashes).
--
-- The length bound is a SEPARATE conjunct rather than a bounded repetition
-- inside the regex: a nested quantifier with an outer bound is unreadable and
-- Postgres will not fold it. `length()` counts characters, and the regex
-- conjunct confines an accepted value to ASCII, so on any value where the length
-- rule can be the deciding one, characters and bytes coincide with the Rust
-- validator's byte bound. The parity corpus reaches both measures.
--
-- ---------------------------------------------------------------------------
-- (3) Where the grammar is enforced, and why there is NO DOMAIN and NO shared
--     `slug_valid(text)` function.
-- ---------------------------------------------------------------------------
-- Two enforcement points, plus one thing #97 did not have:
--
--   1. This CHECK. It is the real guarantee.
--   2. A pure Rust validator at the management edge
--      (`ironauth_admin::require_permission_slug`), hand written as a segment
--      walk with no regex crate, never trimming and never case folding. Without
--      it a bad slug reaches this CHECK and surfaces as an opaque 500 instead of
--      a caller-facing 400 naming the field and the rule.
--   3. A PARITY TEST that feeds one seeded corpus to BOTH, asserting they agree
--      case by case in both directions, and that additionally pins the text of
--      this constraint. #97 has no such test, and nothing else in the tree would
--      catch the validator drifting from the CHECK.
--
-- A Postgres DOMAIN or a shared `slug_valid(text)` function was considered and
-- rejected: there is no DOMAIN anywhere in this 91-migration schema, introducing
-- one is a new schema idiom every later reader has to learn, and the parity test
-- buys the same protection at a fraction of the blast radius.
--
-- ---------------------------------------------------------------------------
-- (4) ENTITLEMENT HEADROOM: the `kind` column, shipped now, used by #103.
-- ---------------------------------------------------------------------------
-- The requirement is that a future FEATURE or PLAN slug fits this concept with
-- no second table and no breaking migration. It does, on all three axes:
--
--   Grammar. `feature.sso`, `plan.enterprise`, and `feature.audit_log_export`
--   all parse under the identical regex with zero change: they are two-segment
--   slugs whose first segment is a namespace, exactly like `billing.invoice.read`.
--
--   Schema. `kind` ships from day one with a CHECK that ALREADY ADMITS the value
--   #103 needs, and the live-uniqueness index is over
--   `(tenant_id, environment_id, kind, slug)`, so `plan.enterprise` may exist as
--   an entitlement while a permission of the same slug exists independently.
--   #103 inserts rows and writes no migration. This follows the shipped
--   precedent of 0090 landing `allowed_email_domains` and `jit_provisioning` as
--   columns with no reader, and it avoids a drop-and-re-add of a CHECK, for
--   which this schema has NO precedent at all (no `ALTER ... DROP CONSTRAINT` on
--   any CHECK exists across 0074 to 0090).
--
--   Claim isolation. Issue #98's own code only ever writes `kind = 'permission'`,
--   and the resolution projection a later PR adds filters `kind = 'permission'`
--   IN SQL. That filter is load-bearing: an entitlement row can never reach a
--   token claim even if some future write path creates one, because the tail
--   does not select it.
--
-- ---------------------------------------------------------------------------
-- (5) Covenant.
-- ---------------------------------------------------------------------------
-- The table is NOT capped. There is no count constraint, no quota check, no
-- counter column, and no advisory-lock-plus-COUNT gate anywhere: a project
-- covenant forbids any cap or paywall gate on how many permissions an
-- environment may define. An environment may define unlimited permissions.
--
-- The tension issue #98 must keep unmistakable, stated here in the schema
-- because the schema is where a cap would have to live if one ever existed: the
-- byte and count BUDGET a later PR of this issue adds is a SIZE BOUND ON ONE
-- TOKEN. It is never a cap on how many permissions may be STORED, attached, or
-- resolved. There is nothing in this file for such a cap to point at, and that
-- absence is the proof.
--
-- ---------------------------------------------------------------------------
-- (6) Classification and the delta vocabulary.
-- ---------------------------------------------------------------------------
-- `Permission` classifies RUNTIME in the resource model
-- (crates/ironauth-store/src/classification.rs), so the vocabulary does not
-- travel in a config snapshot. That is a SCOPE decision for this already large
-- issue and NOT a judgment that a permission vocabulary should never promote:
-- the promotion machinery is six coordinated sites plus a JSON schema, and
-- adding a snapshot projection later is EXPAND ONLY, so the choice is not a
-- one-way door. A follow-up issue tracks promoting the vocabulary in M5.
--
-- Every mutation of this table writes an audit_log row in the SAME transaction
-- as the mutation, through the store's single audited-write path, under one of
-- three actions: `permission.create`, `permission.update`, and
-- `permission.delete`. Those three action strings ARE the delta contract for a
-- permission, and they carry no `organization.` prefix precisely because the
-- vocabulary is environment scoped. The audited write repository that emits them
-- is the next PR of this issue; this migration ships the table, its isolation,
-- and its grants. There is deliberately NO outbox table and no change feed here
-- (that is M11; migration 0025 records why a shared outbox built without a
-- concrete consumer in view is very likely the wrong shape). ADR 0002 is
-- binding: the current value of a permission is always its row, never a fold
-- over events.
--
-- Migration safety obligation (see migrate.rs): `permissions` is a NEW
-- TENANT-SCOPED table, so it ENABLEs and FORCEs row-level security, carries the
-- (tenant, environment) isolation policy with byte-identical USING and WITH
-- CHECK, carries the nonempty-scope CHECK, and is registered in
-- scripts/query-audit.sh. Grants are least-privilege and COLUMN-scoped for the
-- UPDATE (the #31 lesson). Every statement is additive (a new table, its
-- indexes, its policy, and its grants; no existing column is altered or
-- dropped), so this migration is an EXPAND.

CREATE TABLE permissions (
    -- The prm_ scoped identifier; embeds its (tenant, environment).
    id              text        PRIMARY KEY,
    tenant_id       text        NOT NULL,
    environment_id  text        NOT NULL,
    -- What this row DEFINES: an API capability ('permission') or, from issue
    -- #103, a feature or plan entitlement ('entitlement'). Shipped now so #103
    -- needs no migration; see (4) in the header. IMMUTABLE by GRANT, like the
    -- slug: reclassifying a live row would silently change which resolution
    -- projections select it.
    kind            text        NOT NULL DEFAULT 'permission',
    -- The IMMUTABLE stable name. This is what a token claim carries, so a rename
    -- of display_name never changes an authorization decision. It is never
    -- granted in any UPDATE column list below, which makes the immutability a
    -- GRANT property rather than a convention: no code path, present or future,
    -- can rewrite it without a migration that says so. A permission slug is a
    -- DIRECT authorization input, so letting it be renamed under live mappings
    -- would silently repoint every grant that names it.
    slug            text        NOT NULL,
    -- The mutable human-facing label the admin console shows. Renaming a
    -- permission writes exactly this column (and updated_at).
    display_name    text        NOT NULL,
    -- Free-form vocabulary metadata the admin surface reads and writes; never
    -- interpreted by the auth core and never emitted in a token claim.
    metadata        jsonb       NOT NULL DEFAULT '{}',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    -- When the permission was deleted (present only in a soft-deleted row). A
    -- deleted permission is retained so the audit foreign key to it stays
    -- satisfiable.
    deleted_at      timestamptz,
    CONSTRAINT permissions_scope_nonempty
        CHECK (tenant_id <> '' AND environment_id <> ''),
    -- The closed kind vocabulary. 'entitlement' is admitted from day one and is
    -- written by nothing in issue #98; see (4) in the header.
    CONSTRAINT permissions_kind_known
        CHECK (kind IN ('permission', 'entitlement')),
    -- The namespaced slug grammar; see (2) in the header. The length bound is a
    -- separate conjunct on purpose.
    CONSTRAINT permissions_slug_valid
        CHECK (slug ~ '^[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)+$'
               AND length(slug) <= 63),
    CONSTRAINT permissions_display_name_nonempty
        CHECK (display_name <> ''),
    FOREIGN KEY (tenant_id) REFERENCES tenants (id),
    FOREIGN KEY (environment_id, tenant_id) REFERENCES environments (id, tenant_id)
);

-- At most one LIVE row per (scope, kind, slug). The index is PARTIAL over live
-- rows, so a soft-deleted permission does NOT occupy its slug and the name can
-- be used again by a NEW row; every read filters deleted_at IS NULL, so the
-- reads and this uniqueness invariant agree on exactly the live set.
--
-- `kind` is part of the key, which is what lets `plan.enterprise` exist as an
-- entitlement while a permission of the same slug exists independently (see (4)
-- in the header).
--
-- Note the deliberate difference from org_memberships (0084): re-creating a
-- deleted permission inserts a FRESH row with a FRESH id, it does not revive the
-- dead one. A membership revives because its identity is the (organization,
-- user) pair. A permission's identity is its id, and the mapping table hangs
-- role grants off that id, so reviving a deleted permission would silently
-- restore every grant that pointed at it. Deleting a permission is a security
-- operation and must not be quietly reversible in its authorization effects.
-- This follows org_roles (0086:94-100).
CREATE UNIQUE INDEX permissions_kind_slug_live_uniq
    ON permissions (tenant_id, environment_id, kind, slug)
    WHERE deleted_at IS NULL;

-- The admin "permissions in this environment" list, on the stable
-- (created_at, id) pagination key. The scope leads because the scope is this
-- table's complete fence.
CREATE INDEX permissions_scope_idx
    ON permissions (tenant_id, environment_id, created_at, id);

ALTER TABLE permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE permissions FORCE ROW LEVEL SECURITY;
CREATE POLICY permissions_tenant_isolation ON permissions
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
-- The CONTROL plane owns the vocabulary surface: list and inspect (SELECT),
-- define (INSERT), and relabel or delete through a COLUMN-scoped UPDATE of
-- EXACTLY the mutable columns. `slug` and `kind` are deliberately ABSENT from
-- that list (see their column comments): both are immutable by GRANT.
-- `tenant_id`, `environment_id`, and `id` are likewise absent, so a permission
-- row can never be moved between scopes (the #31 lesson). DELETE is granted to
-- nobody on either plane: removal is the soft delete.
GRANT SELECT, INSERT ON permissions TO ironauth_control;
GRANT UPDATE (display_name, metadata, updated_at, deleted_at)
    ON permissions TO ironauth_control;

-- The DATA plane needs SELECT and NOTHING ELSE: a later PR of this issue
-- resolves a subject's effective permission set on the token-issuance path,
-- which runs under the low-privilege app role. No data-plane path ever writes a
-- permission, so INSERT, UPDATE, and DELETE are granted to nobody there. A data
-- plane able to define the very capability names it is about to put into a token
-- is the whole threat these grants exist to prevent. The SELECT is granted HERE,
-- in the creating migration, rather than being deferred to the PR that first
-- needs it: the 0027-then-0084 revoke-and-re-grant churn on `organizations` is
-- the cautionary precedent for deferring a grant the design already knows it
-- needs.
GRANT SELECT ON permissions TO ironauth_app;
