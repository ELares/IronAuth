# ironauth-store changelog

All notable changes to the `ironauth-store` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- JWT bearer assertion grant trust and mapping stores (issue #26, migration 0019, expand).
  - **New scoped tables.** `external_assertion_issuers` (the registered external
    trust anchors the RFC 7521 / RFC 7523 jwt-bearer grant accepts assertions from,
    each with an inline `jwks` XOR a `jwks_uri`, an optional signing-alg allowlist,
    and an enable switch), `external_assertion_subject_mappings` (the explicit rules
    mapping an external (issuer + `sub`), optionally gated on a claim, to an IronAuth
    principal; reject-by-default, never auto-provisioned), and
    `external_assertion_jtis` (the external-issuer single-use jti replay cache). All
    three ENABLE + FORCE row-level security with the `(tenant, environment)`
    isolation policy (USING + WITH CHECK) and are registered in
    `scripts/query-audit.sh`.
  - **Distinct external jti cache.** `external_assertion_jtis` REUSES the #25
    client-assertion prune-then-insert single-use mechanism but is a DISTINCT table
    keyed by the external ISSUER (not the OAuth client id), so an external issuer's
    `jti` can never collide with a client-assertion `jti` (they live in separate
    tables). It retains a jti to `exp + skew + 1s`, the same +1s margin the #25 cache
    documents, so a prune never reopens a replay window.
  - **Least-privilege grants (the #31 lesson).** The two configuration tables take
    `GRANT SELECT, INSERT` (no table-wide UPDATE, which auto-extends to later
    columns; no DELETE), and the jti cache takes `GRANT SELECT, INSERT, DELETE` (the
    DELETE is the on-insert prune only), all to `ironauth_app`.
  - **Repositories and audited writes.** `ExternalAssertionIssuerRepo` /
    `AssertionSubjectMappingRepo` read the trust anchor and mapping at grant time;
    the mutating `ActingExternalAssertionIssuerRepo::register` and
    `ActingAssertionSubjectMappingRepo::create` route through the one audited-write
    primitive (`external_assertion_issuer.register` /
    `external_assertion_subject_mapping.create`). `ActingAuthorizationRepo` gains
    `issue_jwt_bearer_assertion`, which shares the machine-grant + access-token
    persistence with the client-credentials path but audits the distinct
    `jwt_bearer_assertion.issue` verb, so a federated issuance is legible in the
    trail as such. New `Action` variants back all three verbs.
  - **New identifier kinds.** `xai_` (a registered external assertion issuer) and
    `asm_` (a subject-mapping rule), both tenant-scoped and used as the row primary
    key and the audit target.
  - **Revocable trust config (column-scoped, the #31 lesson applied correctly).** The
    trust anchor and mapping must be DISABLE-able so a compromised or decommissioned
    issuer, or a mis-authored mapping, can be turned off through the data plane (the
    HTTP management surface for it is M13). Migration 0019 now adds an `enabled` column
    to `external_assertion_subject_mappings` (the issuers table already had one) and a
    COLUMN-SCOPED `GRANT UPDATE (enabled)` on BOTH trust tables to `ironauth_app` -
    only `enabled`, never a table-wide UPDATE and never the app-immutable
    id/issuer/keys/principal/match columns. New audited acting methods
    `ActingExternalAssertionIssuerRepo::set_enabled` and
    `ActingAssertionSubjectMappingRepo::set_enabled` toggle the switch (audited
    `external_assertion_issuer.set_enabled` / `external_assertion_subject_mapping.set_enabled`,
    two new `Action` variants), and `AssertionSubjectMappingRepo::resolve` now FILTERS
    on `enabled = true` so a disabled mapping resolves to no rule. New `tests/rls.rs`
    coverage proves the app role can flip `enabled` on both tables but is refused
    (42501) on every other column.
- Dynamic Client Registration abuse controls (issue #31, migration 0018, expand).
  - **New scoped tables.** `dcr_policies` (named, reusable policy-primitive chains),
    `dcr_initial_access_tokens` (SHA-256-hashed initial access tokens carrying a
    resolved policy-chain snapshot, an expiry, and a usage limit; the plaintext is
    never stored), and `dcr_rate_counters` (the endpoint's fixed-window rate counter).
    All three ENABLE + FORCE row-level security with the `(tenant, environment)`
    isolation policy (USING + WITH CHECK) and are registered in
    `scripts/query-audit.sh`; the schema-level migration test asserts the token table
    holds no plaintext/secret column.
  - **Two-role separation across the DCR lifecycle, column-scoped.** A token is MINTED
    by the control plane and CONSUMED by the data plane, so the grants are deliberately
    narrow and column-scoped where it matters. `ironauth_control` gets INSERT/SELECT on
    policies and tokens (mint) plus SELECT + `UPDATE(quarantined, verified_at)` on
    `clients` (verify). `ironauth_app` gets SELECT + `UPDATE(use_count)` ONLY on tokens
    (the atomic consume bumps only `use_count`, so a data-plane path can never rewrite a
    token's `max_uses`/`policy_chain`/`token_hash`/`expires_at` to lift its own cap or
    swap the bound policy), and SELECT/INSERT/UPDATE on the rate counters. Migration
    0001 had granted `ironauth_app` a TABLE-WIDE `UPDATE` on `clients`, which a
    table-level privilege auto-extends to columns added later; 0018 now REVOKEs it and
    re-grants a COLUMN-SCOPED `UPDATE` over every `clients` column EXCEPT `quarantined`
    and `verified_at`, so the two quarantine columns are control-plane-only and a
    data-plane path can no longer self-verify a quarantined client. Neither role is a
    superset of the other, verified by new grant-restriction tests in `tests/rls.rs`.
  - **Unverified-client quarantine columns.** `clients` gains `quarantined`,
    `verified_at`, and `dcr_policy_chain` (the policy snapshot that bound the
    registration, persisted so RFC 7592 updates re-apply the SAME chain for the
    client's lifetime).
  - **Operator-safe audit detail dimension.** `audit_log` gains a nullable `detail`
    column (NULL for every existing write) and `AuditRecord` a matching `detail` field.
    A `dcr.policy_rejected` event now records the OFFENDING policy property there
    (operator-authored, never attacker text), so an operator working from the audit
    table alone gets the actionable reason; the wire response stays opaque.
  - **Deferred.** The `dcr_rate_counters` table has no reaper: pruning rolled-over
    windows is the M15 layered rate limiter's job, tracked with that work. The
    endpoint rate limit is best-effort; the per-environment quota is the hard cap.
  - **Repositories.** `DcrPolicyRepo`/`ActingDcrPolicyRepo` (by-name resolve, create),
    `InitialAccessTokenRepo::consume` (one atomic UPDATE that increments the use count
    only when unexpired and under its limit, so a usage limit cannot be raced past),
    `ActingInitialAccessTokenRepo::mint`, `DcrRateLimiterRepo::check_and_increment`
    (an atomic window-rollover upsert), `ActingClientRepo::verify_dynamic_client`, and
    `record_dcr_event` (the one audited no-op-mutation event for a policy rejection,
    quota hit, or rate-limit hit). `register_dynamic` now enforces the per-environment
    client quota ATOMICALLY inside its transaction under a per-scope advisory lock, so
    two concurrent registrations cannot both slip past the cap. New typed
    `StoreError::QuotaExceeded`.
- Token revocation store support (issue #22, no migration).
  - **Grant-chain and family revocation.** `ActingAuthorizationRepo::revoke_grant`
    revokes a grant chain (the RFC 7009 access-token revoke: the append-only issued/opaque
    token rows derive their active state from `grants.revoked_at`, so this flips every
    derived token inactive), and `ActingRefreshRepo::revoke_family` revokes a refresh-token
    family AND its grant in one transaction (the refresh-token revoke: the #21 family spine
    plus the RFC 7009 cascade to the derived access tokens). Both are bespoke committing
    paths that write their audit row (`token.revoke` / the reused `refresh_family.revoke`)
    only when the revocation actually flipped a live grant/family, so a repeat revocation
    is a benign idempotent no-op. No new columns or tables were needed: revocation operates
    entirely on the existing `revoked_at` spines.
  - **Revocation locators.** `AuthorizationRepo::grant_for_access_token` and
    `grant_for_opaque_token` locate a presented access token's grant and owning client
    (the new `GrantOwner`) for the revocation endpoint's foreign-client check, WITHOUT
    filtering on expiry or revoked state, so revoking an already-invalid token is a benign
    no-op rather than a false "unknown".
  - **New audit action** `token.revoke` (`Action::TokenRevoke`) for an endpoint-driven
    access-token revocation; a refresh-token revoke reuses `refresh_family.revoke`.
- Client-credentials service-account principals and per-client custom claims
  (issue #23, migration 0017, expand).
  - **The service-account principal.** New `service_accounts` table: the
    `(client -> stable machine-sub)` mapping, one principal per client
    (`UNIQUE (tenant, environment, client_id)`), keyed by a new `sva_` scoped
    identifier (`ServiceAccountId`). The principal is minted lazily at the client's
    FIRST client-credentials issuance and read back on every subsequent one, so a
    client's `sub` is stable and DISTINCT from its `cli_` id. The table ENABLEs +
    FORCEs row-level security with the `(tenant, environment)` isolation policy, an
    isolation-preserving composite FK to `clients` (a new
    `clients_scope_identity_unique` anchors it), and is registered in
    `scripts/query-audit.sh`; it holds SELECT + INSERT only (a principal, once
    minted, is never mutated or deleted). `ServiceAccountRepo::principal_for` reads
    it; `ActingServiceAccountRepo::ensure` mints-or-reads it (audited
    `service_account.create`, idempotent under a first-issuance race via the
    unique-violation re-read).
  - **Per-client custom claims.** Additive nullable `clients.custom_token_claims`
    JSONB column: the declarative static claims embedded in a client's
    client-credentials tokens (opaque JSON to the store; the MINT is the single
    enforcement point for the reserved-claim guard, so the store persists the
    configuration verbatim and does not itself filter claim names).
    `ClientRepo::custom_token_claims` reads it; `ActingClientRepo::set_custom_token_claims`
    sets it (audited `client.custom_claims.set`, validated as JSON by the `::jsonb`
    cast). `RefreshRepo::count_in_scope` returns the scope's
    `(refresh_families, refresh_tokens)` row counts for the client-credentials
    no-refresh database negative (RFC 6749 4.4.3).
  - **Client-credentials issuance persistence.**
    `ActingAuthorizationRepo::issue_client_credentials` opens a fresh machine GRANT
    (subject = the `sva_` principal, no session/consent/claims) and records the
    access token against it (an `issued_tokens` row for an at+jwt, an
    `opaque_access_tokens` row for an opaque token) in ONE audited `token.issue`
    transaction, so a client-credentials token is revocable and introspectable by
    the SAME grant chain the #22 endpoints consume. NO refresh-token family is
    opened (RFC 6749 4.4.3). New `IssueClientCredentials` / `ClientCredentialsAccess`
    types; two new audit actions (`service_account.create`, `client.custom_claims.set`).
  - The migration guard test now pins the production chain at EIGHTEEN migrations.
- Refresh-token rotation, families, `offline_access`, and consent-mode persistence
  (issue #21, migration 0016, expand).
  - **Token families and digest-only tokens.** New `refresh_families` (the
    revocation spine: one family per original grant, carrying the hard-cap expiry,
    the `session_ref`, the `offline` flag, and the exactly-once `reuse_detected_at`
    marker) and `refresh_tokens` (one row per generation, storing ONLY the SHA-256
    digest of the whole `ira_rt_<jti>~<secret>` wire token, never the plaintext).
    Both tables ENABLE + FORCE row-level security with the `(tenant, environment)`
    isolation policy and are registered in `scripts/query-audit.sh`; a
    schema-level migration test asserts no plaintext-token column exists.
  - **Rotation and reuse gate.** `RefreshRepo::load` resolves a presented token's
    live state; `ActingRefreshRepo::issue` opens a family at first issuance;
    `ActingRefreshRepo::redeem` is the authoritative single-use, rotation, and
    reuse gate (a bespoke committing path): it rotates a live token, classifies a
    superseded-token presentation as a benign within-grace concurrent refresh or a
    genuine reuse that revokes the WHOLE family and emits the typed reuse event
    exactly once, and returns `invalid_grant` for an expired or revoked
    family/grant. `ActingRefreshRepo::revoke_session_bound` revokes a session's
    session-bound families at RP logout while leaving `offline_access` families
    intact.
  - **Within-grace refreshes CONVERGE, they do not fork.** A within-grace
    duplicate presentation (the loser of the atomic rotate, a multi-tab retry, or a
    lost rotation response) now records ONLY a fresh access token against the
    family's grant (audited as `token.issue`) and mints NO second successor leaf, so
    a family always holds EXACTLY ONE live (unrotated, unrevoked) leaf: the winner's
    successor. Previously each within-grace duplicate minted its own successor,
    forking the family into independent chains that never presented each other's
    tokens, so reuse detection could never fire (a stolen token replayed within the
    grace window yielded a persistent undetected parallel chain). The new outcome is
    `RefreshRedeemOutcome::RefreshedWithinGrace` (was `RotatedWithinGrace`). The
    strict benign window is `[0, grace)`. `RefreshRepo::live_leaf_count` reads a
    family's live-leaf count, the ground truth a concurrency test asserts is always
    at most one. Accepted, documented limitation: a client that ENTIRELY loses the
    winner's rotation response never receives the new refresh token and must
    re-authenticate; no plaintext token is cached for replay (that would violate the
    no-replayable-material-at-rest guarantee).
  - **`refresh_tokens.created_at` dropped.** The generation's creation instant is
    already recorded by the clock-seam `issued_at`; a `DEFAULT now()` DB-clock column
    would only diverge from the seam and be invisible to a deterministic-clock test.
  - **Consent modes and offline expiry.** `clients` gains `consent_mode`,
    `skip_consent`, `store_skipped_consent`, and an optional `refresh_rotation`
    override (all defaulted to today's behavior), surfaced on `ClientRecord` /
    `ClientAuthRecord` and set through `ActingClientRepo::configure_policy`
    (audited as `client.configure`). `consents` gains a nullable `expires_at`
    (with a column-level UPDATE grant), surfaced on `GrantedConsent` and written
    through `ActingConsentRepo::grant_with_expiry` so a `remembered` consent lapses
    after its TTL.
  - **Audit actions.** New `refresh_token.issue`, `refresh_token.rotate`,
    `refresh_token.reuse`, `refresh_family.revoke`, and `client.configure`.
- Dynamic Client Registration persistence (issue #30, migration 0014, expand).
  - **DCR clients columns.** `clients` gains `registration_access_token_hash`,
    `registration_client_uri`, `id_token_signed_response_alg`, `application_type`,
    and a `dcr_registered` origin flag (default false), all additive so every
    pre-existing client is unaffected. Only the SHA-256 HASH of the RFC 7592
    registration access token is stored; the plaintext is never persisted.
  - **Repository surface.** `ClientRepo::dynamic_registration` reads a DCR client
    within scope (a non-DCR or absent client is the uniform `NotFound`, so the RFC
    7592 surface is no existence oracle). `ClientRepo::id_token_signing_alg` reads a
    client's stored `id_token_signed_response_alg` within scope (or `None` for a
    client with no per-client preference), so the token endpoint can sign that
    client's ID token under the algorithm DCR recorded.
    `ActingClientRepo::register_dynamic` creates a client from validated metadata
    (auditing `client.registered`) and `ActingClientRepo::update_dynamic` applies an
    RFC 7592 full-replacement update that ROTATES the registration access token in
    the same transaction (auditing `client.updated`), so a superseded token stops
    matching immediately; a `PUT` that transitions the client to a secretless method
    (`none` / `private_key_jwt`) also NULLs any stored `secret_hash`, so no dead
    credential material lingers. Both re-validate every redirect URI as an RFC 8252
    registrable target and map the key-source CHECK (SQLSTATE 23514) to a `Conflict`.
    New public types `DynamicClientRecord`, `NewDynamicClient`,
    `DynamicClientUpdate`, and `DynamicClientRegistration`; the record's Debug
    redacts the token hash.
  - **Audit actions.** New `Action::ClientRegistered` (`client.registered`) and
    `Action::ClientUpdated` (`client.updated`); the DCR delete reuses the existing
    `client.delete`.
- Pushed authorization request persistence (PAR, RFC 9126, issue #27, migration
  0015, expand).
  - **Single-use pushed requests.** New tenant-scoped
    `pushed_authorization_requests` table (`id`, `client_id`, the serialized
    request parameters, `expires_at`, and a nullable `consumed_at`), with RLS
    enable, force, and a scope policy, plus a nonempty-scope CHECK.
    `ActingPushedRequestRepo::push` writes the row through `write_audited`;
    `consume` runs the atomic
    `UPDATE ... SET consumed_at = now WHERE ... AND consumed_at IS NULL AND
    expires_at > now RETURNING request_params` under READ COMMITTED (mirroring the
    authorization-code redeem), so a `request_uri` is redeemable exactly once. The
    presenting `client_id` is a filter INSIDE that UPDATE, so a request pushed by
    client A and presented by client B matches zero rows: it is rejected AND not
    burned. Only the winning consume writes an audit row.
  - **Non-consuming peek.** A read-only `PushedRequestRepo::read`
    (`ScopedStore::pushed_authorization_requests`) returns a live (unconsumed,
    unexpired, client-bound) request's stored parameters WITHOUT consuming it, using
    the same `client_id` filter and clock-seam expiry as the consume. It lets the
    authorization endpoint resolve a `request_uri` at every login/consent
    interaction hop while deferring the single-use consume to the moment of code
    issuance, so a fresh-login user's request survives the round-trip; it changes no
    state and writes no audit row.
  - **Per-client require-PAR flag.** `clients` gains
    `require_pushed_authorization_requests`; `ClientRecord` carries it and
    `ActingClientRepo::set_require_pushed_authorization_requests` sets it (audited),
    so PAR can be required per client independent of the environment switch.
  - **New identifier and actions.** `PushedRequestId` (`par_` prefix, redacted
    Debug); audit actions `pushed_authorization_request.push`,
    `pushed_authorization_request.consume`, and
    `client.require_pushed_authorization_requests.set`.

- Client JWT-assertion authentication persistence (issue #25, migration 0013,
  expand).
  - **Client key registration.** `clients` gains `jwks`, `jwks_uri`, and
    `token_endpoint_auth_signing_alg`, with a `clients_client_keys_exclusive`
    CHECK forbidding both an inline `jwks` and a `jwks_uri` on one client.
    `ClientAuthRecord` carries the three columns and
    `ActingClientRepo::create_jwt_auth` registers a `private_key_jwt` client
    (mapping the CHECK violation, SQLSTATE 23514, to a `Conflict`).
    - **Registration key-source rules (fail loud).** A `clients_private_key_jwt_has_one_key`
      CHECK requires a `private_key_jwt` client to register EXACTLY ONE key source
      (`jwks` XOR `jwks_uri`), so a keyless client (which would fail every request
      silently) or a dual-source one is a `Conflict` at registration, not a per-request
      failure. `create_jwt_auth` additionally refuses `client_secret_jwt` outright (the
      method is inert and no CHECK expresses it), so no `client_secret_jwt` client can
      ever be created.
  - **Cross-node single-use `jti` cache.** New tenant-scoped
    `client_assertion_jtis` table keyed on the assertion `jti`, with a unique
    constraint that makes replay a database-level conflict every node observes,
    not a per-process guess. `ClientAssertionJtiRepo::record` prunes rows already
    past their stored `expires_at` and then inserts, returning `Replayed` on the
    unique violation and `Recorded` otherwise. `expires_at` is the assertion
    `exp` plus the configured skew PLUS one second: acceptance floors `now` to
    whole seconds and accepts while `now_secs <= exp+skew`, so an assertion stays
    acceptable for the entire wall-clock second `[exp+skew, exp+skew+1)`; the +1s
    margin makes the retained row strictly outlast acceptance so microsecond-precision
    pruning never drops a jti whose assertion is still acceptable and never opens a
    replay window.
  - **Out-of-band failure diagnostics.** New tenant-scoped
    `client_auth_diagnostics` table records a structured reason (`unparsable`,
    `unknown_client`, `method_mismatch`, `bad_secret`, `assertion_invalid`,
    `replayed_jti`, `client_secret_jwt_unsupported`) with the offending client,
    method, key id, and signing alg, for operators -- never on the wire, so the
    HTTP response stays an opaque `invalid_client`. `ClientAuthDiagnosticsRepo`
    records and reads within scope. The table is BOUNDED: each row carries an
    `expires_at` (occurred_at + a fixed 7-day retention window) and the recorder
    prunes expired rows before each insert (prune-then-insert, exactly like the jti
    cache), so #22 introspection/revocation reusing the `authenticate_client` seam
    PRE-grant cannot grow it without limit from unauthenticated requests. This is a
    growth bound, not rate limiting.
  - Both new tables get ENABLE + FORCE row-level security, the
    `(tenant, environment)` isolation policy (USING + WITH CHECK), the
    nonempty-scope CHECK, and least-privilege grants (`SELECT, INSERT, DELETE` for
    both the `jti` cache and diagnostics, the DELETE being the on-insert retention
    prune only). Like `idempotency_keys` they sit off the audited-write path (an
    authentication attempt is not a tenant data mutation). Migration guard bumped to
    thirteen.
- Access-token formats: resource-server registry and opaque, digest-only access
  tokens (issue #29).
  - **New `resource_servers` table (migration 0011, expand).** A tenant-scoped
    audience-to-format registry: `audience` (unique per environment), `token_format`
    (`at_jwt` or `opaque`, CHECK-constrained), and an optional per-resource-server
    `access_token_ttl_secs`. Isolated exactly like every other scoped table (ENABLE
    + FORCE row-level security, the `(tenant, environment)` isolation policy with
    USING + WITH CHECK, the nonempty-scope CHECK, isolation-preserving foreign keys),
    with least-privilege `SELECT, INSERT` to `ironauth_app`. New `ResourceServerRepo`
    (read `by_audience`) and audited-mutating `ActingResourceServerRepo` (`register`,
    a `resource_server.register` audit row in the same transaction). A new `rsv_`
    scoped identifier kind (`ResourceServerId`), a `TokenFormat` enum, and the
    `resource_server.register` audit action.
  - **New `opaque_access_tokens` table (migration 0012, expand).** The digest-only
    store for opaque reference tokens: `token_digest` (SHA-256 hex, PRIMARY KEY, the
    lookup key), plus `subject`, `client_id`, `audience`, `scope`, `jti`, an optional
    `grant_id` (the revocation spine, where applicable), and `expires_at`. The token
    PLAINTEXT is never stored, only its digest, so a database dump contains nothing
    replayable as a valid token. Same forced-RLS + isolation-policy + least-privilege
    (`SELECT, INSERT`) discipline. New `NewOpaqueAccessToken` write input,
    `ActiveOpaqueToken` result, and the exported `opaque_access_token_digest` helper
    (the ONE canonical digest so the mint and the resolve can never disagree).
    `ActiveOpaqueToken` now also returns `expires_at_unix_micros` (the token's `exp`)
    and `issued_at_unix_micros` (its `iat`, from the row's `created_at`), read back as
    exact epoch microseconds, so the RFC 7662 introspection response (issue #22) the
    resolve seam feeds is complete; the resolve semantics are unchanged (an expired
    token still resolves to `None`).
  - **`AuthorizationRepo::resolve_opaque_access_token`.** The INTERNAL resolve the
    RFC 7662 introspection endpoint (issue #22) will expose: it hashes the presented
    token and matches it against `token_digest` within scope, returning the live
    claims only when the row exists, its grant (when present) is not revoked, and it
    has not expired at the supplied clock-seam instant. There is no offline
    validation path for opaque tokens.
  - **`ActingAuthorizationRepo::redeem` records an opaque access token.** It now
    takes an `opaque: Option<NewOpaqueAccessToken>` and, on the winning consume,
    inserts the digest-only row in the SAME transaction as the code consume and the
    redeem audit (binding it to the consumed code's grant, so grant-chain revocation
    reaches it exactly as it reaches an at+jwt jti). The existing at+jwt path is
    unchanged (`opaque = None`).
  - **`scripts/query-audit.sh`** now lists `resource_servers` and
    `opaque_access_tokens` among the scoped tables, and the production-chain guard
    test expects twelve migrations (versions 1..=12, both new ones `expand`).

- Scope-aware consent (issue #196), a hard prerequisite for enabling OIDC
  (issue #13).
  - **`ConsentRepo::granted_ref` now returns the granted scope.** Its return type
    is a new `GrantedConsent { id, granted_scope }` (was a bare `con_` id string),
    and the `SELECT` reads `granted_scope` alongside `id`. The authorization
    endpoint checks a later request's scope against this granted scope, so a consent
    recorded for a narrow scope never silently auto-grants a broader one.
  - **`ActingConsentRepo::grant` is now an UPSERT that returns the ACTUAL row id and
    audits AGAINST it.** The `ON CONFLICT (tenant_id, environment_id, subject,
    client_id)` clause is `DO UPDATE SET granted_scope = EXCLUDED.granted_scope` (was
    `DO NOTHING`) with a `RETURNING id`, so re-consenting to a broadened scope
    PERSISTS it instead of dropping it (which previously re-prompted forever). A
    re-consent's UPDATE branch keeps the row's ORIGINAL id, so `grant` now PRE-READS
    the existing consent row's id for `(subject, client)` in the same scope and uses
    it as BOTH the INSERT candidate id AND the `consent.grant` audit target. The audit
    row's `target_id` therefore equals the persisted consents row id on a first insert
    AND on a re-consent, so an investigator can always pivot from the audit row (or the
    returned id) to the real consent row; the earlier code targeted a freshly
    generated id the UPDATE branch discarded, which left a scope-broadening event's
    audit row pointing at a phantom, never-persisted id. Two truly concurrent FIRST
    grants can still leave the loser's audit target naming its own discarded candidate
    (the unique constraint admits exactly one row, so no duplicate is created); a
    scope-BROADENING re-consent always finds the row in the pre-read and is never
    subject to it, so the security-relevant event's linkage is always intact. The
    audit write stays in the same transaction. Runtime `sqlx::query` only.
  - **The tenth production migration** (`0010_consent_scope_upsert`, Expand) is a
    single `GRANT UPDATE (granted_scope) ON consents TO ironauth_app`: PostgreSQL
    requires the UPDATE privilege for any `INSERT ... ON CONFLICT DO UPDATE`, and the
    upsert only ever sets `granted_scope`, so the grant is COLUMN-SCOPED to that one
    column (strictly least-privilege: the role cannot UPDATE
    id/subject/client_id/tenant_id/environment_id even within a tenant). It adds no
    table, column, index, constraint, or policy (the `granted_scope` column and the
    row-level-security policy already exist from `0006`), and is additive and safe
    for the old binary (which only ever runs `ON CONFLICT DO NOTHING`).
- UserInfo standard-claim persistence and the frozen `claims` request parameter
  (issue #15).
  - **The ninth production migration** (`0009_userinfo_claims`, Expand) adds the
    additive `users.claims` (`text NOT NULL DEFAULT '{}'`) column backing the
    scope-derived and claims-parameter-selected claim sets, plus the nullable
    `grants.claims_request` and `authorization_codes.claims_request` columns holding
    the canonicalized `claims` parameter frozen at authorization (read by UserInfo
    and at the token endpoint). All are additive columns on already-RLS-forced
    tables, so they inherit the existing tenant/environment isolation.
  - **Access-token resolution** (`resolve_access_token`) is scope-bound and
    registered in the cross-scope IDOR harness, so a token minted in one
    environment yields a uniform not-found in another; the repository reads and
    writes the claim columns through the runtime query API only.
- Registered redirect URIs and the exact-string redirect comparator (issue #13).
  - **The redirect-matching policy** lives here as two pure functions,
    `redirect_uri_matches` and `redirect_uri_is_registrable` (`src/redirect.rs`),
    since the store owns the client registry and thus the registered set matched
    against. Matching is EXACT byte string, with the single RFC 8252 section 7.3
    loopback deviation (a variable port on an `http` loopback IP literal:
    `127.0.0.1` or `[::1]`, never `localhost`). Registrability accepts exactly the
    three RFC 8252 redirect shapes (claimed `https`, `http` loopback IP literal, a
    reverse-domain private-use scheme) and rejects everything else. A permanent CVE
    regression corpus (wildcard, substring, case-fold, normalization, encoding, and
    homograph classes) and a cargo-fuzz target (`fuzz/`, `redirect_match`) guard
    against any accepted bypass. The loopback port exception range-checks the port
    (`1..=65535`, so `:0`/`:99999` are not port variants), and a registrable `https`
    redirect carrying userinfo (`https://good@evil/cb`, a host-confusion vector) is
    refused rather than stored and later matched byte-for-byte.
  - **The eighth production migration** adds the additive `clients.redirect_uris`
    (`text[]`) column, the registered set; `ClientRecord` now carries
    `redirect_uris` and `auth_method`, and `ActingClientRepo::register_redirect_uris`
    validates each URI as a registrable redirect target BEFORE storing it (a
    malformed scheme is `StoreError::InvalidRedirectUri`, rejected at registration).
    New audit action `client.redirect_uris.register`.
- OIDC authorization-code grant persistence (issue #12). Adds the fourth
  production migration and the scoped `authorization` repository, all under the
  existing tenant-isolation model (RLS enabled and forced, nonempty-scope CHECK).
  - **Three tenant-scoped tables:** `grants` (the revocation spine linking a code
    to its session, consent, and issued tokens), `authorization_codes` (single
    use, binding the `client_id`, `redirect_uri`, `nonce`, and PKCE
    `code_challenge`), and `issued_tokens` (the `jti` of each token, so
    grant-chain revocation is observable). Registered in
    `scripts/query-audit.sh`; granted to the data-plane `ironauth_app` role.
  - **Atomic single use.** `ActingAuthorizationRepo::redeem` consumes a code in
    one `UPDATE ... WHERE consumed_at IS NULL RETURNING ...`; zero rows is a
    replay, classified so the caller can revoke the grant chain. The consume
    audits `authorization_code.redeem` in the same transaction. No in-memory
    marker, so single use holds across N stateless nodes.
  - **New scoped identifiers** (`ac_`, `grt_`, `tok_`), audit actions
    (`authorization_code.issue`/`.redeem`/`.reuse`, `token.issue`), and the
    `authorization_codes.redeem` / `issued_tokens.token_status` IDOR probes.
- Management-plane control substrate (issue #11). Adds the control-plane role,
  the management repositories, and the third production migration; the #6 and #7
  isolation and audit tests stay green.
  - **A distinct control-plane role, `ironauth_control`.** Migration 3 GRANTs it
    the operator, tenant, and environment LEVEL tables that the data-plane
    `ironauth_app` cannot see, plus append-only audit and the two new management
    tables, and nothing on `clients`/`organizations`. Like `ironauth_app` it is a
    peer, never a superset (never a superuser or owner, so forced row-level
    security applies), and the migration GRANTs but never creates it or ships a
    password. The test harness (`test_support`) provisions it race-safely and
    exposes a separate `control_store()`; the two pools are kept distinct.
  - **Management repositories reusing `write_audited`.** `Store::management()`
    reaches `TenantRepo`/`EnvironmentRepo` (operator plane, level tables) and the
    tenant-scoped `ManagementCredentialRepo`, plus the credential-scoped
    `IdempotencyRepo`. Every mutation routes through the same single audited-write
    primitive, so a management mutation without its same-transaction audit row is
    as impossible as a data-plane one. The primitive is now generic over an
    `AuditTarget` so a level-id target (a tenant, an environment) audits through
    the same path as a scoped-id target. New `Action` variants: `tenant.create`,
    `tenant.delete`, `environment.create`, `environment.delete`,
    `management_key.create`, `management_key.delete`.
  - **Operator-plane audit scoping.** Creating a tenant creates its first
    environment in the same transaction and audits scoped to that fresh
    `(tenant, environment)`; environment CRUD scopes to `(tenant, environment)`;
    tenant deactivation scopes to the tenant's retained oldest environment. See
    `docs/adr/0005-management-api.md`.
  - **New scoped tables.** `management_credentials` (environment-scoped `mak_`
    keys: forced row-level security, nonempty-scope CHECK, the same foreign keys
    as `clients`; only the key hash is stored) and `idempotency_keys` (the
    Idempotency-Key replay store, deliberately CREDENTIAL-scoped rather than
    tenant-RLS-scoped, because an operator-plane POST is looked up before any
    tenant exists). Both are added to `scripts/query-audit.sh`'s scoped-table
    list. `tenants` and `environments` gain a `deleted_at` soft-delete column, so
    a DELETE is a deactivation that keeps the row and the append-only audit
    foreign keys satisfiable.
  - New id types and helpers: `ManagementKeyId` (`mak_`, scoped),
    `ScopedId::parse_declared_scope` (recovers a credential token's declared scope
    without a caller scope, for self-authenticating tokens only),
    `LevelId::from_seed_bytes`/`ScopedId::unique_bytes` (well-known and derived
    identities: the bootstrap operator and a management key's service actor).
  - No new dependency; still runtime sqlx only and musl/MSRV-1.85 clean.

- Relational primary store with a same-transaction audit log and an
  expand-contract migration framework (issue #7). Builds directly on the #6
  isolation substrate.
  - **Postgres relations are the sole source of truth** (normalized tables,
    foreign keys enforced, explicitly not event sourced). The decision and the
    zitadel#9599 evidence are recorded in
    `docs/adr/0002-relational-primary-store.md`.
  - **Same-transaction audit log, structurally enforced.** A new tenant-scoped
    `audit_log` table (scoped, forced row-level security, nonempty-scope CHECK,
    same foreign keys as `clients`). Every repository mutation routes through a
    single private audited-write primitive (`write_audited`) that performs the
    data change and writes exactly one audit row in one transaction and is the
    only committing write path; the public mutators cannot commit without it, so
    "a mutation without an audit row" is unrepresentable and a failed mutation
    leaves no trace. The envelope carries a typed `ActorRef`
    (`Human`/`Service`/`Agent`, each with a typed actor id), an `Action`, the
    typed scoped target, `(tenant, environment)`, `occurred_at` (from the
    `ironauth-env` clock seam, never the database clock), and a `CorrelationId`.
    It is the substrate for later OCSF mapping and stream separation (M11); no
    streams or OCSF are built here.
  - **Acting context for writes.** Reads (`ScopedStore::clients`,
    `ScopedStore::audit`) need no actor; writes are reachable only through
    `ScopedStore::acting(actor, correlation)`, so an actor and correlation id are
    required at the type level for every mutation. This changed the
    `create`/`delete` signatures; all #6 call sites and the IDOR delete probe
    were updated and every #6 isolation test stays green.
  - **Append-only enforcement.** The application role is granted SELECT and
    INSERT on `audit_log` and neither UPDATE nor DELETE; a privilege test as
    `ironauth_app` proves UPDATE and DELETE are refused while INSERT/SELECT in
    scope work. Retention is a later, explicit operation.
  - **Expand-contract migration runner** (`MigrationRunner`), replacing the
    single-file raw apply. Tracks applied migrations in a `_schema_migrations`
    ledger (version, name, SHA-256 checksum, phase, applied_at), applies pending
    migrations in order each inside its own transaction, and refuses out-of-order
    application, checksum drift on an already-applied migration, and a ledger
    version unknown to the running build (the N/N-1 downgrade guard), all as
    typed `MigrationError`s. Concurrent runners (several replicas booting during
    a rolling upgrade) serialize through a session-level Postgres advisory lock,
    so the losers wait and find the chain applied instead of racing to create the
    same objects. The production chain is exactly two migrations: the #6 schema
    (version 1) and the audit log (version 2); it ships no throwaway objects. The
    worked expand-contract example (add a nullable column, backfill, drop the old
    column) exercises all three phases in the migration test only, never in a
    real schema. Migration safety: any migration adding a tenant-scoped table
    must set up forced row-level security, the isolation policy, and the
    nonempty-scope CHECK (extended to `scripts/query-audit.sh`'s scoped-table
    list, now including `audit_log`).
  - Minimum PostgreSQL 14: the audit `occurred_at` is read back exactly (its
    integer microseconds) only where `EXTRACT(EPOCH FROM timestamptz)` returns
    numeric, which is PostgreSQL 14+; older versions return double precision and
    can round the read-back by +/- 1 us. The stored value is exact regardless.
  - Adds `sha2` (migration checksums): pure Rust, permissive (MIT OR
    Apache-2.0), already present transitively via sqlx, so no new crate enters
    the dependency graph; MSRV 1.85 and the musl static lane are unaffected.
  - New integration tests against a real database: transactional atomicity
    (injected mid-transaction failure leaves no orphan data or audit row, and a
    data-insert failure writes no audit row), every-mutation-audits with the full
    envelope, append-only privilege (UPDATE, DELETE, and TRUNCATE all denied to
    the application role; INSERT/SELECT in scope allowed), and the migration
    framework (in-order/idempotent, out-of-order rejection, checksum-mismatch
    rejection, NotSorted for descending and duplicate versions, the N/N-1
    downgrade guard, per-migration rollback of a failed DDL, concurrent-runner
    serialization via the advisory lock, the production chain being exactly two
    migrations with no demo object, and the test-only expand-contract example end
    to end).

- Initial persistence and tenant isolation layer (issue #6). Isolation is
  enforced below the application in three independent layers:
  - **Typed scoped identifiers** (`TenantId`, `EnvironmentId`, `OperatorId`,
    and the scoped `ScopedId<K>` with `ClientId`/`OrganizationId`): non-guessable
    (128-bit, entropy from `ironauth-env`), non-recyclable (random, never
    serial), typed-prefixed and URL-safe. Scoped identifiers embed their tenant
    and environment; `parse_in_scope` fails cross-scope as a uniform not-found
    with no existence or error-shape oracle.
  - **Scope-only repositories** (`Store::scoped(scope)` -> `ScopedStore` ->
    `ClientRepo`): constructible only from a `Scope`, which is applied to every
    query; the pool and scoped tables are crate-private. Compile-fail tests
    prove a repository cannot be built without a scope and a scoped handle
    cannot query another tenant.
  - **Postgres row-level security**: every tenant-scoped table has RLS ENABLED
    and FORCED with policies keyed on the transaction-local `ironauth.tenant_id`
    and `ironauth.environment_id`. Deny-by-default is an enforced invariant: a
    CHECK constraint forbids any scoped row from carrying an empty scope, so an
    unset session denies whether its scope variable is NULL (pristine connection)
    or the empty string (pooled connection that reverted a scope). The shipped
    migration never creates the low-privilege role or a password; the role is
    provisioned out of band (production) or by the test harness (race-safely),
    so no credential for the isolation-boundary role is committed.
  - The reusable cross-tenant `idor_harness` (feature `testing`) that every
    future surface registers with, plus the `test_support` real-database
    harness.
  - Four-level resource model schema (operator, tenant, environment,
    organization) with a minimal `Store::migrate()`. The full migration
    framework and the same-transaction audit log are issue #7.
  - Uses the runtime sqlx query API only (never the compile-time `query!`
    macros), rustls + ring with the OS trust store (no native-tls/openssl, no
    webpki-roots, no aws-lc), so every database-free lane stays database-free and
    the musl static and MSRV-1.85 lanes hold.
