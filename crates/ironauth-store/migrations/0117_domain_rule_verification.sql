-- Domain OWNERSHIP verification for routing rules (issue #96).
--
-- Migration 0059 gave a domain rule a selector, a target connection, a priority and an
-- enabled flag, and nothing that ties the selector to anyone entitled to it. The per-scope
-- unique index means the FIRST claimant of a domain wins it, so an organization in the
-- environment could create a rule for a domain it does not own and identifier-first logins
-- for users at that domain would broker to that organization's upstream IdP. That is a land
-- grab rather than a collision, and it is what this migration closes.
--
-- The state is a closed set. `pending` is what a fresh claim gets, `verified` is the only
-- state the router will match, and `failed` records a probe that ran and did not find the
-- token, which is deliberately DISTINCT from `pending`: an operator needs to tell "nobody has
-- checked yet" from "we checked and it is not there", and collapsing them would make a failed
-- claim look like a new one forever.
--
-- The token is the value the domain owner publishes in DNS. It is stored per rule rather than
-- derived, because a derived token would change whenever its inputs changed and silently
-- invalidate a record the owner had already published.
--
-- ONLY domain rules carry any of this. An app rule keys on a client id and a user rule on a
-- blind index; neither has an owner to prove. The CHECK below makes that structural rather
-- than conventional, exactly as 0059's own selector-matches-kind constraint does: a non-domain
-- rule carrying a verification state can never be written.
--
-- BACKFILL, and why it is `verified` rather than `pending`. Every routing_rules row that
-- exists when this migration runs was created by an operator through the management plane,
-- before any verification mechanism existed, and is presumed intentional. Defaulting them to
-- `pending` would silently stop routing every enterprise login in every deployment at upgrade,
-- which is an outage, not a security fix. New rules are written `pending` by the create path, so
-- the gate binds everything written from here on. This is the one place the two differ and it
-- is a deliberate, stated trade: the gate protects future claims, and existing claims are
-- grandfathered rather than re-proven.
--
-- Expand-only and safe for the old binary: three added columns, all nullable, and
-- a CHECK that only constrains rows a pre-migration binary never writes. A binary that predates
-- this migration reads and writes routing_rules exactly as before.

ALTER TABLE routing_rules
    ADD COLUMN domain_verification_state text,
    ADD COLUMN domain_verification_token text,
    ADD COLUMN domain_verified_at timestamptz;

-- Existing domain rules are grandfathered; see the BACKFILL note above.
UPDATE routing_rules
   SET domain_verification_state = 'verified',
       domain_verified_at = now()
 WHERE rule_kind = 'domain'
   AND domain_verification_state IS NULL;

-- No column DEFAULT, deliberately. A default applies to EVERY insert regardless of
-- rule_kind, so 'pending' would land on app and user rules too and violate the kind CHECK
-- below. Measured: with the default in place, `a_user_rule_resolves_by_blind_index_never_plaintext`
-- fails on the constraint. The writer sets 'pending' for a domain rule and NULL otherwise,
-- which puts the kind decision in one place that the CHECK then enforces.

-- The closed state set, and the structural rule that only a domain rule has ownership to
-- prove. A domain rule MUST carry a state; any other kind must carry none of these columns.
ALTER TABLE routing_rules
    ADD CONSTRAINT routing_rules_domain_verification_matches_kind CHECK (
        (rule_kind = 'domain'
         AND domain_verification_state IN ('pending', 'verified', 'failed'))
        OR (rule_kind <> 'domain'
            AND domain_verification_state IS NULL
            AND domain_verification_token IS NULL
            AND domain_verified_at IS NULL)
    );

-- A verified domain rule must record WHEN it was verified, so an operator auditing a claim can
-- see the instant rather than inferring it. `pending` and `failed` carry no such instant.
ALTER TABLE routing_rules
    ADD CONSTRAINT routing_rules_domain_verified_at_matches_state CHECK (
        (domain_verification_state = 'verified' AND domain_verified_at IS NOT NULL)
        OR (domain_verification_state IS DISTINCT FROM 'verified' AND domain_verified_at IS NULL)
    );

-- The router reads by (scope, selector, enabled) and now also by state, so the state joins the
-- index rather than being filtered after the fact.
CREATE INDEX routing_rules_domain_verified_idx
    ON routing_rules (tenant_id, environment_id, domain_norm)
    WHERE rule_kind = 'domain' AND domain_verification_state = 'verified';

-- The control plane owns the verification lifecycle: it creates the claim, stamps the token,
-- and records the probe's outcome. Column scoped per the #31 lesson, never a table-wide UPDATE.
-- `updated_at` is in the list because the write stamps it, and a column-scoped UPDATE that
-- omits a column the statement sets is `permission denied` for the whole statement, not a
-- silent skip. Measured: without it, `record_domain_verification` fails with
-- `permission denied for table routing_rules`. Same four-column shape as 0100's grant.
GRANT UPDATE (domain_verification_state, domain_verification_token, domain_verified_at, updated_at)
    ON routing_rules TO ironauth_control;
