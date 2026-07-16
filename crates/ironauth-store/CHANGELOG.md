# ironauth-store changelog

All notable changes to the `ironauth-store` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- Migrations as an invariant-checked state machine (issue #59, exploratory, migration
  0043, expand): a wrapped long-running migration walks an explicit, audited state
  machine (`defined -> validating -> running -> reconciling -> complete | abandoned`)
  whose `complete` state is GATED. `ActingMigrationRunRepo::try_complete` re-evaluates
  three invariant families LIVE from the database on every attempt (never a cached
  verdict) and refuses the transition while any is violated: the COUNT invariant
  (`source_total == imported + failed + skipped`, no unaccounted remainder), the
  CONSISTENCY invariant (zero inconsistent identities), and the BACKFILL SENTINEL (every
  touched record marked). `MigrationRunRepo` exposes the run, its live per-state
  tallies, its live invariant evaluations, and a paginated view of the records
  violating an invariant; `abandon` is an explicit audited terminal transition. Two new
  tenant-scoped tables (`migration_runs`, `migration_run_records`) with forced RLS, the
  `(tenant, environment)` isolation policy, closed-set CHECKs, and column-scoped grants;
  a record's natural subject is envelope-sealed and blind-indexed (issue #48), never
  plaintext. Every transition is audited via `write_audited` with actor attribution
  (`migration_run.create` / `.transition` / `.ingest` / `.backfill` / `.complete` /
  `.abandon`). Applied to two concrete kinds (bulk import #55 via `ironauth-import`,
  schema migration jobs #53); a tenant move (M5) fits the same model without being
  wired. New public types: `MigrationRun{,Id,Kind,RecordId,RecordKind}`,
  `MigrationState`, `MigrationRecordOutcome`, `NewMigrationRun`, `RecordOutcomeInput`,
  `MigrationRunTallies`, `InvariantKind`, `InvariantEvaluation`, `CompletionOutcome`,
  `OffendingRecord`, and the `migration_runs()` accessors on `ScopedStore` / `ActingStore`.
- `UserRepo::migration_progress` (issue #56): a scoped, master-key-free count of the
  environment's lazy-migration progress (total live users and how many still carry an
  imported foreign password hash, the #55 straggler tail). Returns the new
  `MigrationProgress` value; the management-plane progress endpoint reads it to report how
  far a migration has come and when the hook can be disabled. No schema change (a COUNT over
  `users` with the existing `deleted_at IS NULL` filter).
- Exit-export credential registry (issue #58, review, migration 0042, expand):
  `UserExportRecord` now carries the user's enrolled `account_credentials` (a new
  `ExportedCredential` list: factor kind, opened friendly name, last-used instant),
  and `ActingAccountCredentialRepo::enroll_restored` re-enrolls an exported credential
  under a fresh user, preserving the last-used instant, for the exit-import restore.
  Migration 0042 grants the control plane SELECT + INSERT on the existing
  `account_credentials` table (least privilege: no UPDATE / DELETE) so the export
  reads and the import restores the credential registry; it adds no table, column, or
  policy.
- Exit-friendliness covenant support (issue #58, no migration): the read and write
  halves of the full identity export. A new `UserRepo::export_page` reads every field
  the identity model holds one keyset-paginated, bounded page at a time (opening the
  sealed identifier, claims, external id, and traits, and returning the native and
  foreign password verifiers), so a 100k-user export streams without loading the
  whole set; `UserExportRecord` is its redacting read model. `NewAdminUser` gains
  `traits_json` / `traits_schema_version`, and `admin_create` seals a traits document
  VERBATIM (like it seals claims, skipping schema re-validation) so the streaming
  import restores traits losslessly even into a fresh scope with no active schema.
  `ActingUserRepo::record_export_audit` writes the `user.export` audit row (a new
  `Action` variant) attributed to the acting principal. Purely additive: the users
  table already carried every column the export reads, so this needs no migration.
- Flexible identifiers on the central canonicalization seam (issue #54, migration
  0041, expand). Multiple typed login identifiers per user with uniqueness as
  configuration, built around one canonicalization function so the
  canonicalization-mismatch CVE class (Authelia CVE-2026-47203 / CVE-2025-24806 /
  CVE-2026-48794, Zitadel CVE-2025-31124) is designed out by construction.
  - **The one seam.** New `identifier` module: `canonicalize_identifier(kind, raw)`
    is the SINGLE entry point that produces a `CanonicalIdentifier` (email, username,
    or phone). It strips Unicode invisible and control characters by PROPERTY (General
    Category Cc/Cf/Zl/Zp plus the derived Default_Ignorable set, via the
    `unicode-properties` crate) rather than a hand-curated list with gaps, applies NFKC
    (folding fullwidth and other compatibility homoglyphs), strips ALL whitespace
    (interior included, since a login handle has none), and case-folds per type with
    full Unicode Default Case Folding (the `caseless` crate, so the German sharp s and
    the Greek final sigma fold correctly) rather than simple lowercase. Email folds
    local part and domain; phone normalizes to structural E.164 `+<digits>`. A
    degenerate all-invisible / whitespace-only input, or an email with no `@` shape,
    canonicalizes to the EMPTY form (rejected at the write boundary, see below). It is
    TOTAL (never panics) and IDEMPOTENT, proven by property tests and the
    `canonicalize_identifier` fuzz target. `CanonicalIdentifier`'s fields are private,
    so a raw handle cannot reach a comparison without passing the seam;
    `scripts/canonicalization-seam.sh` backstops it in CI. Documented structural
    limits (not folded): cross-script confusables (UTS-39 skeleton, out of scope),
    NFKC over-folding, and phone-extension merge.
  - **The `user_identifiers` table.** One new tenant-scoped table (RLS forced, the
    (tenant, environment) isolation policy, closed-type CHECK, column-scoped grants):
    the canonical form as a per-tenant keyed-HMAC blind index (`canonical_bidx`, for
    lookup and uniqueness), the raw input AEAD-sealed for display (`raw_sealed`, issue
    #48; the plaintext never lands on a column), a per-identifier `verified` flag, and
    a `uniqueness_key` discriminator.
  - **Uniqueness as configuration, not code.** A partial unique index over the
    `uniqueness_key`: environment-wide (the default), org-scoped (falling back to the
    environment scope for a membership-free user until M10), or non-unique. A
    post-canonicalization collision within the configured scope is refused as the
    deterministic `StoreError::Conflict`.
  - **Identifier-first resolution.** `UserIdentifierRepo::resolve` canonicalizes a
    submitted identifier and returns each matching account with only the
    authentication methods it actually has (`LoginMethod::Password` / `Passkey`),
    consumed later by M7/M9. `list_for_user` and the `collisions_for_mode`
    mode-change validation pass round it out; `ActingUserIdentifierRepo::add` is the
    audited (`user.identifier.add`) mutation.
  - **Degenerate identifiers are refused.** `ActingUserIdentifierRepo::add` rejects an
    empty canonical form (an all-invisible / whitespace-only submission, or a malformed
    email with no `@` shape) with the new deterministic `StoreError::InvalidIdentifier`
    before any write, so an all-invisible submission cannot squat the empty slot; a
    `resolve` of an empty canonical form returns an empty result without querying (never
    an oracle). New `CanonicalIdentifier::is_empty()` helper.
  - **Mode tightening actually recomputes keys.** New audited, single-transaction,
    scope-fenced `ActingUserIdentifierRepo::apply_uniqueness_mode(mode)`
    (`user.identifier.uniqueness.apply`): it refuses (deterministic `Conflict`) while
    `collisions_for_mode(mode)` reports any collision the new mode would enforce, then
    recomputes every row's `uniqueness_key` under the new mode in the same transaction.
    This closes the gap where a pre-existing NULL-keyed (non-unique) row stayed exempt
    from the partial unique index after a tightening, allowing a later three-way
    "unique" collision.
  - **`collisions_for_mode(OrgScoped)` agrees with `add`.** The org-scoped collision
    scan now groups by the SAME discriminator `add` uses (including the org key), so a
    legitimate cross-org duplicate is no longer falsely reported as a blocking
    collision.
- User invitation persistence (issue #60, migration 0040, expand): the one new
  piece of durable state the admin-initiated invitation flow needs, a tenant-scoped
  `user_invitations` table with RLS forced and the (tenant, environment) isolation
  policy. Everything else reuses existing state (the invited identity is a normal
  `users` row created and activated through the #52 repos; the credential is the
  #20 Argon2id verifier).
  - **Digest-only, single-use token.** Only the SHA-256 digest of the whole
    `ira_inv_<inv-id>~<secret>` token is stored (the #21/#29 reference-credential
    form), so a database dump yields nothing replayable. A partial unique index on
    (scope, digest) keeps resolve and resend unambiguous.
  - **PII-sealed invited identifier.** `target_identifier_sealed` (the AEAD-sealed
    value under the scope DEK, issue #48) plus `target_identifier_bidx` (per-tenant
    keyed blind index for the resend-by-identifier lookup); the plaintext identifier
    never lands on a column.
  - **Guarded atomic accept.** `InvitationRepo::accept` consumes the invitation in
    one transaction (a guarded `pending -> accepted` flip that also activates the
    invited user `pending_verification -> active` and, for a password invitation,
    writes the Argon2id verifier), so a second accept or a concurrent double-accept
    redeems AT MOST ONCE. `resolve_pending`, `create`, `revoke`, and `resend` (a
    fresh digest and expiry on a still-pending invite) round it out; every mutation
    audits. Column-scoped grants only (the #31 lesson): control plane
    creates/lists/revokes/resends, the data plane accepts.
- Foreign password-hash storage for bulk import (issue #55, migration 0039,
  expand): the persistence half of the streaming import engine (the engine and the
  algorithm-tagged verify/rehash scheme layer live in the new `ironauth-import`
  crate).
  - **Two additive `users` columns.** `foreign_password_hash` (the imported
    verifier in its canonical algorithm-tagged string, stored AS-IS) and
    `foreign_password_algo` (the non-secret algorithm tag). A password hash is a
    one-way verifier, not PII, so both are stored as text exactly like the native
    `password_hash`; neither is in the PII taxonomy. A user with no imported
    credential stores NULL for both.
  - **`NewAdminUser` foreign fields.** `admin_create` now accepts
    `foreign_password_hash` / `foreign_password_algo`, so the import path creates
    users through the same audited, isolation-scoped, PII-sealing write path as the
    management create (issue #52). `UserRecord` (the login read) carries the two
    columns.
  - **Verify-then-rehash landing.** `ActingUserRepo::upgrade_foreign_password`
    writes the fresh native Argon2id verifier onto the user and clears the foreign
    hash and its tag atomically, guarded on the foreign hash still being present so
    two concurrent logins race safely (the loser is a benign no-op, no audit row),
    and audits `user.password.upgrade`. A column-scoped UPDATE grant on exactly the
    two import columns to the data and control roles (never table-wide, the #31
    lesson) backs it.
- JSON Schema identity traits with versioning and migration jobs (issue #53,
  migration 0038, expand): custom user profile fields (traits) beyond the standard
  OIDC claims, validated against a per (tenant, environment) JSON Schema (draft
  2020-12), with immutable schema versioning and a Postgres-backed migration/dry-run
  job substrate.
  - **Self-contained validator (`trait_schema`).** A purpose-built draft 2020-12
    validator over `serde_json` (no new external dependency): `type`, `properties`,
    `required`, `additionalProperties`, `items`/`prefixItems`, `enum`, and the
    length/size/range assertions. Validation failures carry an RFC 6901 JSON Pointer
    to the exact failing location; schema compilation and instance validation are
    DEPTH BOUNDED (`MAX_DEPTH`) so a hostile deeply nested schema or payload cannot
    exhaust the stack (the fuzz obligation). Arrays and nested objects are
    first-class (the named Ory Kratos regression is a unit test). The IronAuth
    behavior vocabulary (`x-ironauth`: login identifier, verification address,
    recovery channel, admin-only visibility) parses off the schema, and the
    admin-only visibility split is enforced by `TraitAnnotations::redact_for_user`.
    A declarative transform (`rename`/`default`/`drop`) applies deterministically.
  - **Versioned registry (`trait_schemas`).** `ActingTraitSchemaRepo::create_version`
    (a malformed schema is refused before anything is written) mints an immutable
    per-scope `candidate` version; `activate_version` is the cutover, REFUSED while
    any identity's traits fail the target schema (`CutoverBlocked`), and at most one
    `active` version per scope (a partial unique index). `TraitSchemaRepo` reads the
    active version, a specific version, and the full list.
  - **Sealed per-user traits.** `users` gains `traits_sealed` (the trait document
    sealed under the scope's envelope DEK, issue #48: trait data is user profile PII
    and never lands on a plaintext column), `traits_dek_version`, and
    `traits_schema_version`. `ActingUserRepo::set_traits` validates against the active
    schema at write (an invalid document is refused with per-field JSON Pointer
    failures and nothing is persisted), seals, and records the version; `UserRepo::traits`
    and `traits_user_visible` read it back (the latter with admin-only fields stripped).
  - **Migration / dry-run jobs (`trait_migration_jobs`).** `ActingTraitMigrationJobRepo::create`
    (dry-run or migrate) counts the candidate population and queues the job;
    `advance` runs one bounded batch, deterministically (identities ascending by id),
    idempotently (a terminal job is a no-op and a migrated identity is filtered out,
    so re-running double-migrates nothing), resumably (the cursor commits per batch),
    and per (tenant, environment) scoped. Per-record failures are reported by subject
    and JSON Pointer reason (never a trait value, so a job carries no PII). Every
    mutation audits (`trait_schema.create`/`activate`, `user.traits.update`,
    `trait_migration_job.create`/`advance`).
  - Deferred to a follow-up: the `ironauth-admin` HTTP control-plane surface over
    these repositories (set/get schema, trigger/inspect a job) and its OpenAPI
    contract; the store seam #54 (flexible identifiers) and #59 build on is complete.

- Admin user CRUD, lifecycle states, and external IDs (issue #52, migration 0037,
  expand): the foundational M6 promotion of the bootstrap `users` directory into a
  full control-plane managed entity, with no weakening of its isolation or PII
  guarantees.
  - **Lifecycle state machine.** A first-class `UserState` (active, blocked,
    disabled, `pending_verification`, `scheduled_offboarding`) with an explicit,
    validated state machine (`can_transition_to`): a no-op and a move into
    `pending_verification` are refused fail closed; every other move between live
    states is permitted. `ActingUserRepo::set_state` transitions guarded on the
    source state and audits `user.state_change` with the target on the operator-safe
    detail. A session-ending target (block, disable) and `delete` cascade the user's
    sessions and non-offline refresh families and publish to the session-ended
    fan-out (issue #35), so a lifecycle change actually ends live sessions and
    notifies relying parties (`hard_kill` also kills the offline families).
  - **External IDs.** A per-tenant blind-index + sealed value (issue #48) so an
    external correlation id is lookup-able (`UserRepo::by_external_id`) and filterable
    without a plaintext column, unique per `(tenant, environment)` (a second claim is
    refused), and cross-tenant isolated (the same string in two tenants is two
    different users). `link_external_id` / `unlink_external_id`, audited.
  - **CRUD.** `admin_create` (optional caller-supplied id, 409 on collision; optional
    credential and external id; a chosen creatable initial state), `UserRepo::get` /
    `list` (cursor paginated, filterable by state / external id / identifier),
    `update_claims` (RFC 7396 profile patch, re-sealed under the row's DEK version),
    and a soft-delete `delete` (a tombstone that reads as not-found and cascades).
  - **Login fence.** `UserRecord` now carries `state`; the login read path
    (`by_identifier`) reports it and skips a soft-deleted user, so a blocked, disabled,
    or pending-verification user cannot authenticate (`UserState::can_authenticate`).
  - **Scheduled offboarding.** `execute_scheduled_offboardings` disables every due
    scheduled-offboarding user and cascades identically to a manual disable,
    idempotently and audited (`user.offboarding.execute`).
  - **Refresh-grant fence support.** `UserRepo::state_for_subject` resolves a live
    user's lifecycle state by its subject (the `usr_` id a refresh family carries),
    reading only the `state` column (no master key, no PII decrypt) and filtering the
    soft-delete tombstone; an absent, cross-scope, deleted, or corrupt-state row reads
    as `None` (fail closed). The OIDC `refresh_token` grant reads this to re-check the
    token subject before minting, so a user fenced after a surviving `offline_access`
    family was opened mints nothing. See `docs/design/USER-LIFECYCLE.md`.
  - New `Action` variants (`user.create`/`update`/`delete`/`state_change`/
    `external_id.link`/`external_id.unlink`/`offboarding.execute`); new public
    `UserState`, `UserAdminRecord`, `UserListFilter`, `NewAdminUser` types; new
    `IdorHarness::register_user_admin_probes`, now covering EVERY scope-embedding user
    surface (`users.get`, `users.list`, `users.by_external_id`, `users.delete`,
    `users.set_state`, `users.update_claims`, `users.external_id.link`,
    `users.external_id.unlink`) so the IDOR harness proves uniform cross-tenant
    not-found on the mutating and the reading surfaces alike. Migration 0037 grants
    the control plane SELECT/INSERT + a column-scoped UPDATE on `users` and
    SELECT/INSERT on the envelope key tables (it manages user PII), with a per-scope
    partial unique index on the external-id blind index.
- Self-service account management: sessions and credentials (issue #61, migration
  0036, expand). The store layer of the end-user account surface.
  - **Password change (`ActingUserRepo::change_password`).** Writes a fresh Argon2id
    verifier (the caller has already verified the current password and hashed the new
    one through the entropy seam; no plaintext or hash is ever logged) and, in the
    SAME transaction (session-fixation defense), revokes every OTHER session of the
    user while KEEPING the one the change is made from, cascading each revoked session
    through the unified session-ended fan-out (issue #35) exactly as an admin revoke
    does. One `account.password.change` audit row targets the user; a new column-scoped
    `GRANT UPDATE (password_hash) ON users` is the only new users privilege (the #31
    least-privilege lesson). `UserRepo::password_hash_for_subject` reads the stored
    verifier for the current-password check.
  - **Self-service session revoke (`ActingSessionRepo::self_revoke` /
    `self_revoke_others`).** A user revokes ONE of their own sessions (subject-bound in
    SQL, so another user's session id is a uniform no-op) or all of their OTHER sessions
    ("sign out everywhere else"), both flowing through the same session-ended fan-out as
    an admin revoke and audited as `account.session.revoke` /
    `account.sessions.revoke_others` attributed to the end user.
  - **Credential registry (new `account_credentials` table + `AccountCredentialRepo` /
    `ActingAccountCredentialRepo`).** Enroll, list, and remove a subject's OWN
    credentials (passkeys, TOTP, recovery-code sets), every read and write bound to the
    subject so a cross-user id is the uniform not-found. The user-authored friendly name
    is sealed under the scope's envelope DEK (issue #48; a raw column probe yields no
    plaintext). Removing the last usable (primary-login) credential is BLOCKED unless the
    documented recovery acknowledgment is present, so a user cannot silently strand
    themselves. Enroll and remove are audited as `account.credential.enroll` /
    `account.credential.remove`; the audit `detail` records the declared step-up policy.
    New `CredentialType`, `AccountCredentialSummary`, `CredentialRemoveOutcome`,
    `CredentialId`/`CredentialKind`, and the `AccountCredential` classification
    (`runtime`). The cross-tenant IDOR harness gains an `account_credentials.remove`
    probe.
- Server-side config promotion: diff, plan, and apply (issue #44, migration 0035,
  expand). The flagship differentiator, at the store layer.
  - **Engine (`promotion` module, pure and deterministic).** `diff` compares a
    source snapshot against a target snapshot and produces a structured, ordered
    per-resource difference (create, update, or delete with before and after);
    `evaluate_plan` turns a diff into a reviewable `Plan` with a stable,
    content-derived id, the target's base and result revisions (a content hash over
    the promotable projection, the optimistic-concurrency token), and the resolved
    references, failing closed on any reference the target cannot resolve. The
    engine operates on the promotable types with a SCOPE-INDEPENDENT natural key
    (resource server by `audience`, DCR policy by `name`, variable by `name`);
    environment-identity never enters a snapshot (issue #41/#43), so it is never
    promoted. Clients are carried in the snapshot for review but not promoted: a
    client identifier embeds its `(tenant, environment)`, so a client's key cannot
    address the same logical client across environments (a follow-up).
  - **Transactional apply (`ActingStore::apply_promotion`).** All-or-nothing in one
    scoped transaction: it re-derives the target's revision inside the transaction
    (no TOCTOU), is a NO-OP when the target already matches (idempotent re-apply),
    fails with a structured DRIFT error when the target changed since the plan, and
    re-validates every reference (fail closed). Every resource change and one
    `config_promotion.apply` audit row commit together, or none do; a mid-apply
    failure rolls back completely (proven by a fault-injection test comparing the
    target's byte-for-byte export before and after).
  - **Grants (migration 0035).** The control role (promotion is a control-plane
    operation) is granted exactly the apply privileges on the promoted tables:
    create, column-scoped overwrite, and remove on `resource_servers`,
    `dcr_policies`, and `environment_variables`, plus SELECT on `environment_secrets`
    for the reference presence check. Least privilege preserved: every UPDATE is
    column-scoped, and the control role holds no master key so a secret VALUE stays
    unreachable through the control plane. A pure-grant additive expand.
  - **Audit.** New `Action::ConfigPromotionApply` (`config_promotion.apply`).

- Environment-scoped secrets and variables (issue #45, migration 0034, expand).
  - **Persistence.** Two new tenant-scoped, RLS-forced tables. `environment_variables`
    holds non-secret promotable config (name to plaintext value, readable);
    `environment_secrets` holds write-only secrets whose value is sealed under the
    scope's envelope DEK (issue #48, the same AEAD substrate the users PII columns
    use) and stored as ciphertext, with the tenant, environment, secret name, and
    DEK version bound as associated data. There is NO plaintext value column, so a
    database dump of a secret yields only ciphertext. Column-scoped grants only (the
    #31 lesson); the control role is granted SELECT on `environment_variables` (for
    the snapshot export) and nothing on `environment_secrets`.
  - **Repositories.** New `EnvironmentVariableRepo` / `ActingEnvironmentVariableRepo`
    (get, exists, list, list_all, referents; set and delete, audited) and
    `EnvironmentSecretRepo` / `ActingEnvironmentSecretRepo` (metadata, exists, list,
    open_value; put and delete, audited). A secret is WRITE-ONLY: a read returns
    metadata (name, version, updated-at) only, never the value; `open_value` (under
    the master key) is the sole value-returning path and is used only by
    apply-time resolution. A set/put reuses a stable row id across overwrites and
    bumps a version; a name is validated against the reference-key alphabet first.
  - **Reference syntax and resolution (`esv` module).** `Reference::parse` reads a
    config field value as a whole `${var:NAME}` or `${secret:NAME}` token, failing
    CLOSED on anything malformed. `reference_resolves` is the plan-time existence
    check (no value read); `resolve_value` is the apply-time value injection (a
    variable's string, or a secret's value opened from ciphertext), reading only the
    bound scope so the SAME reference resolves to different values per environment.
  - **Snapshot binding.** A `variable` is PROMOTABLE (issue #41): `VariableSnapshot`
    joins the canonical export (issue #43), so a variable's name and value travel in
    the snapshot (a field may carry a `${secret:NAME}` reference). An
    `environment_secret` is ENVIRONMENT-IDENTITY: its VALUE never travels; only a
    reference does. New `Action` variants `environment_variable.set`/`.delete` and
    `environment_secret.put`/`.delete`, and a new `StoreError::InvalidName`.
  - **Deletion protection.** Deleting a secret or variable still referenced by a
    live variable value is rejected (`referents` names the referents); an
    unreferenced one deletes.

- Canonical secret-free config snapshot export (issue #43, migration 0031, expand).
  - **New `snapshot` module.** `Snapshot`/`SnapshotResources` plus the per-type
    secret-free projections (`ClientSnapshot`, `ResourceServerSnapshot`,
    `DcrPolicySnapshot`) and `SecretRef`. `export` reads the promotable resource
    types in scope and returns a `Snapshot`; `Snapshot::to_canonical_string`/
    `to_canonical_bytes` emit a canonical, deterministic form (recursively sorted
    keys, compact, no volatile fields), so two exports of the same config are
    byte-identical. `validate_document` validates a full document WITHOUT applying,
    enumerating every violation with a JSON Pointer path and rejecting raw
    secret-shaped material and private JWK parameters (the secret-free invariant).
  - **Classification-bound coverage.** `SNAPSHOT_RESOURCE_TYPES` and
    `classification_coverage_gaps` are checked by a unit test against
    `classify() == Promotable`, so a newly promotable type forces snapshot coverage
    and an environment-identity or runtime type can never appear.
  - **Repository reads.** New `ResourceServerRepo::list` and
    `DcrPolicyRepo::list_all` (ordered by their stable natural keys) feed the
    export.
  - **Migration 0031.** `GRANT SELECT ON resource_servers TO ironauth_control`, so
    the management-plane export (the first control-plane reader of the
    resource-server registry) can read it. A pure grant, no schema change.
  - Adds a direct `serde` dependency (already in the tree; no new crate).

- Per-environment custom domains with built-in ACME (issue #47, EXPLORATORY,
  migration 0031, expand). Behind the default-off `custom-domains-acme` config flag.
  - **Persistence.** Two new tenant-scoped, RLS-forced tables: `custom_domains` (a
    domain per environment with its verification status, challenge type, an opaque
    handle to its sealed certificate bundle, and the cert not-after) and
    `acme_challenges` (the ACME challenge lifecycle rows with type, token, status,
    and the retry/backoff bookkeeping). Column-scoped grants only (the #31 lesson);
    the domain name and challenge type are immutable after registration.
  - **Cross-tenant exclusivity.** A GLOBAL partial unique index on the domain name
    of `verified` rows gives a verified domain exactly one owner platform-wide: a
    second tenant's transition to verified for a name already verified elsewhere is
    refused with `StoreError::Conflict`, enforced by the storage engine irrespective
    of row-level security (a tenant cannot even see the row it collided with).
  - **Cert key at rest.** A stored certificate's PRIVATE KEY is sealed under the
    scope's envelope DEK (issue #48, `encrypted_secrets`) and the domain row carries
    only the opaque secret handle; the key never touches a plaintext column and
    never appears in a database dump. A custom domain is ENVIRONMENT-IDENTITY (new
    `ResourceType::CustomDomain`, classified `environment-identity`), excluded from
    every snapshot so a promotion never copies it.
  - **Untrusted input.** A custom domain is tenant-controlled: `domain_is_registrable`
    rejects an IP literal, an internal single-label name, or a value carrying a
    scheme/port/path/whitespace before it is ever written (`StoreError::InvalidCustomDomain`),
    and every outbound ACME/CA request rides the SSRF-hardened `ironauth-fetch` path.
  - **Repositories.** `CustomDomainRepo` (reads) and `ActingCustomDomainRepo`
    (`register`, `record_challenge_result`, `store_certificate`), new value types
    (`ChallengeType`, `VerificationStatus`, `ChallengeStatus`, `ChallengeOutcome`,
    `CustomDomainRecord`, `AcmeChallengeRecord`), new `cdom_`/`chal_` ids, and new
    `custom_domain.*` audit actions. Challenge backoff is computed from the clock
    seam, so the retry schedule is deterministic under a manual clock.
  - **Deferred / infra-gated (be honest).** The live ACME handshake against a real
    CA, renewal scheduling, multi-replica HTTP-01 answering, SNI serving, and the
    management/admin API surface are NOT built here: they need a provisioned CA
    account and a reachable domain (validate against a local test CA such as Pebble)
    and are the exploratory graduation's remaining work.
- Tenant lifecycle state machine, residency attributes, data-plane fence, and the
  offboarding pipeline (issue #46, migration 0029, expand).
  - **Lifecycle status.** `tenants.status` (`active`/`suspended`) plus
    `TenantStatus` on `TenantRecord`. New `ActingTenantRepo::suspend`/`resume`
    enforce the state machine (only `active -> suspended` and `suspended -> active`
    are valid; every other transition is refused fail closed with
    `StoreError::Conflict`, and a deleted tenant is a uniform `NotFound`). New
    `Action::TenantSuspend`/`TenantResume` audit variants.
  - **Residency.** `tenants.home_region` AND a per-environment `environments.region`
    pin, both recorded on create, returned on reads, and IMMUTABLE after create:
    migration 0029 narrows the control role's table-wide UPDATE on `tenants` and
    `environments` to a COLUMN-SCOPED grant that excludes the residency columns, so
    Postgres itself refuses a rewrite. `ActingTenantRepo::create` gained a
    `home_region` argument; `ActingEnvironmentRepo::create` gained a `region`
    argument; `EnvironmentRecord` gained `region`.
  - **Data-plane fence.** New tenant-scoped `environment_states` table records each
    scope's serving status; a tenant suspend/resume/delete cascades it per
    environment. New `ScopedStore::environment_state` (data-plane read) returns
    `EnvironmentServingState` so a suspended or offboarded scope can be fenced.
  - **Offboarding pipeline.** A tenant delete is now the GRACE stage: it fences
    every environment but keeps all keys INTACT (no crypto-shred), so a restore
    inside the configured retention window loses no data. New
    `ActingTenantRepo::restore` (in-window) and `ActingTenantRepo::hard_delete`
    (terminal, only after the window elapses), each taking the retention window and
    gated by it (`Conflict` on the wrong side of the boundary). Only the terminal
    hard delete crypto-shreds each environment's envelope KEK (reusing the #48
    substrate), permanently, while a sibling tenant is untouched; migration 0029
    grants `ironauth_control` exactly the column-scoped crypto-shred UPDATE on
    `tenant_keks`. The ordinary tenant and environment deletes no longer shred (the
    crypto-shred erasure mechanism is deferred to a later erasure issue per #46's
    out-of-scope). New `Action::TenantRestore`/`TenantPurge` audit variants.
- Environments as first-class typed objects with guardrails and scoped keys (issue
  #42, migration 0029, expand). Environments become the load-bearing promotable object
  under snapshot export (#43) and promotion (#44).
  - **Typed kind and guardrails.** New `environment` module: `EnvironmentType` (a closed
    `dev`/`staging`/`prod` set whose `parse` rejects an unknown token rather than coercing
    it), the two `GuardrailClass`es the three kinds map onto (dev and staging inherit the
    relaxed non-production set; prod gets the hard production set), and `GuardrailSet`, a
    typed, purely-derived set that validates a redirect URI (production is https-only per
    RFC 9700, non-production allows the RFC 8252 http loopback) and a custom domain
    (production requires one). `GuardrailReport` accumulates every failed guardrail so a
    caller learns all failures at once.
  - **Environment columns.** Migration 0029 adds `environments.kind` (with a CHECK pinning
    the closed set) and `environments.custom_domain`; `EnvironmentRecord` carries both.
    They are ENVIRONMENT-IDENTITY (issue #41 classification): a snapshot and a promotion
    never copy them, so promoting dev to prod never carries dev's laxity.
  - **Day-one scoped key.** Environment creation (`ActingEnvironmentRepo::create` and the
    first environment in `ActingTenantRepo::create`, now taking a `NewEnvironment` and a
    `NewSigningKey`) provisions the environment's own signing key in the same transaction,
    so a fresh environment serves discovery with its own issuer and a disjoint JWKS
    immediately. Migration 0029 grants the control role `INSERT` on `signing_keys` for
    exactly this; normal rotation stays a data-plane operation. The signing-key INSERT is
    factored into a shared `insert_signing_key_row` helper.
- The four-level resource model as public APIs (issue #41, migration 0027, expand).
  Completes the operator > tenant > environment > organization hierarchy at the store
  layer so the management API can expose all four levels as first-class resources.
  - **Organization lifecycle.** New `OrganizationRepo` (parse-in-scope, get, list) and
    `ActingOrganizationRepo` (create, delete), reached through `ManagementStore` and its
    acting door. Organizations are environment-scoped: each repository is constructible
    only from a `(tenant, environment)` `Scope`, binds forced row-level security before
    every statement, and rejects a cross-scope `OrganizationId` as the uniform
    not-found. Create and delete route through the same `write_audited` primitive, so
    every mutation writes its audit row in the same transaction (new `Action`s
    `organization.create` and `organization.delete`).
  - **Operator read repository.** New `OperatorRepo` (parse, get, list) over the
    operator-plane level table (no row-level security; the operator embeds neither a
    tenant nor an environment).
  - **Soft-delete on organizations.** `migration 0027` adds a nullable
    `organizations.deleted_at` so an organization deactivates without ever hard-deleting
    a row the append-only audit log references, exactly as tenants and environments do.
    The control role gains `SELECT, INSERT` and a COLUMN-SCOPED `UPDATE (deleted_at)`
    (never a table-wide UPDATE: the #31 lesson). The existing `ENABLE`/`FORCE` row-level
    security, the `(tenant, environment)` isolation policy, and the nonempty-scope CHECK
    from migration 0001 are unchanged.
  - **Machine-readable classification.** New `classification` module: a closed
    `ResourceType` enum, an exhaustive `classify()` mapping every type to `Promotable`,
    `Runtime`, or `EnvironmentIdentity`, and a `ResourceType::ALL` registry. The single
    source of truth the config snapshot (5.3) and promotion (5.4) will consume, so the
    "does this travel in a snapshot?" decision is declared in the schema, never
    reverse-engineered. `scripts/classification-lint.sh` fails CI if a type lands
    unclassified or unlisted, or if any of the three classes goes unused.
  - **IDOR coverage.** `register_management_probes` now also registers `organizations.get`
    and `organizations.delete`, so the #6 cross-tenant harness proves a foreign-scope
    organization is a uniform not-found on every new resolve-by-id surface.
- Per-tenant envelope encryption for PII and secrets (issue #48, migration 0027,
  expand). The DEK/KEK envelope substrate at the persistence layer: PII and secret
  values are encrypted at rest under a per-tenant key, and destroying a tenant's
  KEK crypto-shreds all of that tenant's data (the offboarding property #49
  extends). The AEAD primitive is the standard `ring::aead` AES-256-GCM scheme in
  the new `ironauth_jose::envelope` module (the one crate allowed a direct `ring`
  dependency); this crate owns the key lifecycle, the context binding, and the
  encrypted columns.
  - **Three new tenant-scoped tables.** `tenant_keks` (per-(tenant, environment)
    key-encryption keys, stored wrapped under the platform master key, versioned,
    with a `destroyed` crypto-shred state), `tenant_deks` (per-(tenant,
    environment) data-encryption keys, stored wrapped under the active KEK,
    versioned), and `encrypted_secrets` (the transparent encrypted-secret store:
    each row holds ONLY ciphertext, never a plaintext column). All three ENABLE +
    FORCE row-level security, carry the (tenant, environment) isolation policy and
    the nonempty-scope CHECK, and use COLUMN-SCOPED data-plane UPDATE grants (the
    #31 lesson), and are registered in `scripts/query-audit.sh`.
  - **Scoped repositories.** `EnvelopeRepo` (read: `open_secret`,
    `secret_dek_version`, `active_kek_version`, `active_dek_version`) on
    `ScopedStore::envelope`, and `ActingEnvelopeRepo` (audited writes:
    `provision_kek`, `provision_dek`, `rotate_kek`, `rotate_dek`, `destroy_kek`,
    `put_secret`, `reencrypt_secret`) on `ActingStore::envelope`. Every key and
    ciphertext is scope-filtered and runs under the row-level-security session
    variables, so another tenant's key or ciphertext is not expressible.
  - **Rotation without downtime.** `rotate_kek` re-wraps every DEK under a fresh
    KEK version in one transaction with NO record-payload rewrite (old ciphertext
    still reads); `rotate_dek` versions new writes while old versions stay readable,
    and `reencrypt_secret` performs the observable background re-encryption onto the
    active DEK version (the plaintext never changes).
  - **Crypto-shredding.** `destroy_kek` overwrites every KEK version's wrapped
    bytes with an empty blob and marks it destroyed, so the scope's DEKs can never
    be unwrapped and all of its ciphertext is permanently unreadable, while the
    ciphertext rows are retained on disk (shredded, not deleted).
  - **Fail-closed structured errors.** A new `StoreError::Encryption`, distinct
    from `NotFound`, so a caller tells "this ciphertext did not authenticate" (a
    wrong/crypto-shredded key, a tampered blob, or a cross-row/tenant/column replay)
    apart from "there is no such record". It carries no key material or plaintext.
  - **CI classification lint.** `scripts/pii-encryption-scan.sh` fails the build
    when a schema column whose name matches the PII/secret taxonomy is declared
    without an encryption declaration (a `bytea` sealed column, or an inline
    `pii-encryption-allow: <reason>` marker), wired into `scripts/gate.sh`.
  - New audited actions: `envelope.kek.provision`, `envelope.kek.rotate`,
    `envelope.kek.destroy`, `envelope.dek.provision`, `envelope.dek.rotate`,
    `encrypted_secret.put`, `encrypted_secret.reencrypt`.
  - The migration is additive (three new tables), safe for the old binary; the
    DB-backed guard test now asserts a twenty-seven-migration production chain and
    the new tables' wrapped-key/ciphertext columns (and the absence of any
    plaintext-key or plaintext-secret column). New `tests/envelope.rs` proves the
    round-trip, cross-tenant and cross-context decryption failure, KEK rotation
    without payload rewrite, DEK rotation with observable re-encryption,
    crypto-shredding with sibling isolation, and a database-dump-yields-no-plaintext
    check.
  - **The bootstrap `users` PII columns now route through the substrate.** Migration
    0027 additionally converts the two plaintext PII columns the login/consent
    bootstrap shipped (`users.identifier`, the login handle, and `users.claims`, the
    standard-claim JSON) into sealed envelope columns, so the acceptance criterion
    "no plaintext PII in a database dump" holds for the live schema, not only for the
    substrate. `users.claims` becomes `claims_sealed` (a `bytea` sealed under the
    scope's active DEK, decrypted transparently by `UserRepo::claims_for_subject`).
    `users.identifier` becomes a BLIND INDEX (`identifier_bidx`, a deterministic
    per-tenant HMAC that `UserRepo::by_identifier` queries for the equality lookup)
    plus a sealed `identifier_sealed` for display/round-trip; `pii_dek_version`
    records the sealing DEK version. The plaintext `identifier`/`claims` columns are
    dropped (a full expand-contract folded into 0027, justified in the migration
    header: `users` is the pre-1.0 M2 bootstrap slice with no cross-release contract).
    Registration provisions the scope's KEK/DEK lazily and seals in the same audited
    transaction. The `Store` now carries an optional platform `MasterKey`
    (`Store::with_master_key`); the PII paths FAIL CLOSED (`StoreError::Encryption`)
    when no key is wired, never falling back to plaintext.
  - **The classification lint is no longer blind to these columns.**
    `scripts/pii-encryption-scan.sh` gains `identifier`/`claims` (and the JSON
    aggregate case) to its taxonomy and a drop-aware pass: a plaintext PII column is
    compliant only if it is `bytea`, allow-marked, OR dropped by a later migration, so
    the expand-contract passes while a NEWLY added undropped plaintext PII column
    fails. New `tests/user_pii.rs` proves no plaintext handle/claims in a dump, login
    lookup through the blind index, exact claims round-trip, a duplicate-handle
    conflict, and cross-tenant non-collision/non-leak of both the blind index and the
    sealed values.
- Front-Channel Logout registration (issue #39, migration 0025, expand). The per-client
  opt-in the OIDC `end_session` flow reads when front-channel logout is enabled.
  - **Registered front-channel logout columns.** Two additive `clients` columns:
    `frontchannel_logout_uri text` (nullable; the endpoint the OP loads in a hidden
    iframe on logout) and `frontchannel_logout_session_required boolean NOT NULL DEFAULT
    false` (whether `iss` and the RP's own `sid` are appended). They read into
    `ClientRecord::{frontchannel_logout_uri, frontchannel_logout_session_required}` and
    are written by the new audited `ActingClientRepo::register_frontchannel_logout` (an
    `https`-only URI validated before anything is stored; a
    `client.frontchannel_logout.register` audit row in the same transaction). The
    data-plane write is a COLUMN-SCOPED
    `GRANT UPDATE (frontchannel_logout_uri, frontchannel_logout_session_required)` (the
    #31 lesson: never a table-wide UPDATE).
  - **Participant lookup.** `ClientSessionRepo::frontchannel_participants(session_id)`
    joins `client_sessions` to `clients` and returns, per participating RP, its
    `frontchannel_logout_uri`, its `session_required` flag, and its OWN `sid`, so the
    logout page builds a per-RP iframe URL that only ever carries that RP's own `sid`.
  - The migration is additive (two `ALTER TABLE clients ADD COLUMN` plus a column-scoped
    grant), safe for the old binary; the DB-backed guard test now asserts a
    twenty-five-migration production chain and the two new columns.
- Back-Channel Logout persistence (issue #34, migration 0025, expand). Lets the
  back-channel logout delivery worker resolve participants and drive an at-least-once,
  per-RP delivery queue on top of the #35 session-ended outbox.
  - **Client registration columns.** Two additive `clients` columns:
    `backchannel_logout_uri text` (the RP-controlled URL a signed Logout Token is POSTed
    to; a client with none registered is not a participant) and
    `backchannel_logout_session_required boolean NOT NULL DEFAULT false`. Written by the
    new audited `ActingClientRepo::register_backchannel_logout` (the URI validated as an
    https target before anything is stored; a `client.backchannel_logout.register` audit
    row in the same transaction, a new `Action` variant). The data-plane write is a
    COLUMN-SCOPED `GRANT UPDATE (backchannel_logout_uri, backchannel_logout_session_required)`
    (the #31 lesson, never a table-wide UPDATE).
  - **The per-RP delivery queue (`backchannel_logout_deliveries`).** A new tenant-scoped
    table the worker EXPLODES each drained session-ended event into: one row per
    participating RP, each carrying that client's OWN `sid` (never another client's) and a
    snapshot of its `logout_uri`, with its own `attempts`, `next_attempt_at` backoff gate,
    `claimed_at` lease, `last_error`, and the two terminal markers `delivered_at` /
    `dead_lettered_at`. ENABLE + FORCE row-level security with the (tenant, environment)
    isolation policy, the nonempty-scope CHECK, a UNIQUE (scope, event, client) idempotency
    key, and COLUMN-SCOPED grants (the app role INSERTs and mutates only the six lifecycle
    columns; the control role gets read-only SELECT for a future status surface).
  - **The `BackChannelDeliveryRepo` (via `ScopedStore::backchannel_deliveries`).**
    `enqueue_for_event` explodes an outbox event into per-RP rows idempotently (a join of
    `client_sessions` and `clients` where a `backchannel_logout_uri` is registered);
    `claim_due` leases due, not-yet-terminal rows `FOR UPDATE SKIP LOCKED` (multi-worker
    safe); `mark_delivered` retires a row on a 2xx; `record_failure` schedules a bounded
    backoff retry or dead-letters the row at the caller-decided attempts cap; `pending` and
    `list` read the queue. A new `bld_` scoped id and a `LogoutDelivery` typed row.
  - **`ManagementStore::list_environment_scopes`** enumerates every `(tenant, environment)`
    scope on the control plane, so a per-scope background worker can iterate the scopes to
    drain (a control-plane read of the non-RLS `environments` table).
- RP-Initiated Logout persistence (issue #33, migration 0023, expand). Lets the OIDC
  `end_session` endpoint terminate an SSO session and, only on an exact match with a
  verifiable `id_token_hint`, redirect back to a client.
  - **Registered post-logout redirect set.** A new additive `clients` column
    `post_logout_redirect_uris text[]` (default `{}`), the exact-string set the
    `end_session` endpoint matches a presented `post_logout_redirect_uri` against
    (RFC 9700 section 2.1, the same discipline `redirect_uris` uses). It is read into
    `ClientRecord::post_logout_redirect_uris` and written by the new audited
    `ActingClientRepo::register_post_logout_redirect_uris` (each entry validated as a
    registrable RFC 8252 target before anything is stored; a
    `client.post_logout_redirect_uris.register` audit row in the same transaction). The
    data-plane write is a COLUMN-SCOPED `GRANT UPDATE (post_logout_redirect_uris)` (the
    #31 lesson: never a table-wide UPDATE).
  - **`sid` to session reverse lookup.** `ClientSessionRepo::session_for_sid(sid)` maps
    the per-(client, session) `sid` an `id_token_hint` carries back to the tier-one SSO
    `session_id` the logout ends, so the hint (not merely the browser cookie) identifies
    the session to terminate. Scope-fenced: a `sid` from another tenant loads zero rows.
  - The SSO session termination itself reuses `ActingSessionRepo::revoke` with
    `SessionEndCause::LoggedOut` and `hard_kill = false`, which already preserves the
    `offline_access` families (issue #21), so an offline token survives an RP logout.
- `ActingSessionRepo::revoke_all_for_user` now returns the ids of the sessions it
  actually revoked, in the new `UserRevocation::revoked_session_ids` field (issue #36).
  Captured with `RETURNING` in the same transaction, it lets a caller (the Global Token
  Revocation receiver) fan a terminal session-ended signal out per truly-revoked session
  with no list-then-revoke race and no spurious signal for an already-revoked one.
  `UserRevocation` is no longer `Copy` (it now owns a `Vec`); no migration.
- The durable session-ended event fan-out substrate (issue #35, migration 0024, expand).
  The transactional-outbox seam the back-channel logout worker (#34) and the external
  webhooks (M11) drain the session-ended signal off, closing the field's most-reported
  logout gap (missing PROPAGATION) structurally: ONE internal event, EVERY terminal
  cause, ONE fan-out.
  - **Transactional outbox.** A `session_ended_events` row is enqueued in the EXACT
    transaction that flips the session (in `revoke_session_in_tx`, so the single revoke,
    the bulk revoke, and the replaced-by-other-subject rotation branch are all covered,
    and in `revoke_all_for_user`, one row per ended session). The event and the
    revocation commit together or not at all: never emitted for a rolled-back revoke,
    never lost for a committed one, exactly as the audit row is.
  - **A rotation is not a session end.** Only a TERMINAL flip enqueues (guarded by the
    same `RETURNING` on the `revoked_at IS NULL AND ended_at IS NULL` update), so a
    re-authentication (which re-points a session's lineage onto its successor and never
    reaches the revoke path) enqueues nothing. A naive consumer never logs a user out on
    a re-auth. Enqueue is exactly-once by construction and a `UNIQUE (scope, session_id)`
    makes a second event for one session impossible.
  - **The drain seam.** `ScopedStore::session_events()` hands out a
    `SessionEventOutboxRepo`: `claim` atomically leases a batch of undelivered events
    (stamping `claimed_at`, `FOR UPDATE SKIP LOCKED` so two workers never take the same
    row and a crashed worker's event reappears once its lease lapses), `pending` peeks
    the undelivered tail, and `mark_delivered` sets `delivered_at` idempotently.
    Delivery is at-least-once, so consumers dedup on the event `id` (the `sev_`
    idempotency key). The typed `SessionEndedEvent` is the STABLE contract a consumer
    receives (scope, ended session, subject, terminal cause, actor, correlation,
    instant, and a monotonic `sequence` that is a best-effort drain ORDERING HINT, not a
    safe high-water-mark: under concurrent producers a lower sequence can commit after a
    higher one, so the drain stays at-least-once per row and consumers never skip past a
    sequence mark); the affected (client, session) pairs are resolved by joining
    `client_sessions` at delivery, not denormalized here.
  - **Least privilege.** `session_ended_events` ENABLEs and FORCEs row-level security
    with the (tenant, environment) isolation policy and the nonempty-scope CHECK, so the
    outbox is cross-tenant isolated. The data-plane role holds SELECT + INSERT and a
    COLUMN-SCOPED `UPDATE (claimed_at, delivered_at)` ONLY (never a table-wide UPDATE,
    the #31 lesson), so a drain can lease and mark but can never rewrite the immutable
    event body; the control role can enqueue but not drain. Added `SessionEventId`
    (`sev_`) and `SessionEndCause::from_wire`.

- The authoritative two-tier session model with fleet operations (issue #32, migration
  0022, expand). Closes the M4 slice of tracking issue #206: this model SUPERSEDES the
  #20 bootstrap session.
  - **Two tiers, authoritative in Postgres.** The `sessions` table is EXPANDED (never
    replaced) with revocation state (`revoked_at`, `revoke_reason`), rotation lineage
    (`superseded_by`), the session-expiry columns this issue OWNS (`idle_expires_at`,
    `absolute_expires_at`, `ended_at`, `end_cause`; a later issue must not re-add them),
    and the fleet metadata (`last_seen_at`, plus the OFF-BY-DEFAULT binding inputs
    `user_agent` and `peer_ip`). The NEW `client_sessions` table is tier two: one row per
    (SSO session, client), carrying the STORED per-(client, session) `sid`. No
    in-memory-only authoritative state, so a rolling restart loses no session.
  - **IMMEDIATE revocation.** `SessionRepo::get` refuses a session whose `revoked_at`,
    `ended_at`, or `superseded_by` is set REGARDLESS of expiry, so a revoked or rotated
    session stops resolving at once. An expiry-only guard would have let every logout
    silently no-op until the lifetime elapsed.
  - **The sid tier.** `ClientSessionRepo::ensure_sid` gets-or-creates the per-(client,
    session) row and returns its STORED `sid` (an independent 128-bit value from the
    entropy seam, never `sid = session_id`), so the claim is stable across refreshes for
    one pair and distinct across two clients of the same SSO session: colluding relying
    parties cannot correlate the user, and back-channel logout can target one client.
  - **Rotation and revocation, each one audited transaction.**
    `ActingSessionRepo::rotate` mints a fresh id and invalidates the prior one in the
    SAME transaction (session-fixation defense; audits `session.rotate` distinctly from
    `session.create`). `revoke`, `bulk_revoke`, and `revoke_all_for_user` flip the
    session, end its per-client sessions, and cascade to the refresh families in one
    transaction with the audit row (and the optional Idempotency-Key record). A
    forced-rollback test proves the data change and its audit row are joint.
  - **Offline-preserving cascade.** The cascade revokes the session-bound refresh
    families and PRESERVES the `offline_access` families (issue #21's
    offline-survives-logout semantic); an explicit `hard_kill` flag also revokes the
    offline families AND their grants, so their access tokens die immediately.
  - **Scope-fenced fleet surfaces.** `SessionFleetRepo` and `RefreshFamilyFleetRepo`
    list and inspect sessions and refresh families (searchable by user and by client
    within the environment scope). A bulk revoke silently skips a foreign-scope id
    rather than reaching across the boundary. All seven surfaces register an
    `IsolationProbe` (`register_session_fleet_probes`) and run under forced RLS.
  - **Column-scoped grants (no table-wide UPDATE).** `ironauth_app` and
    `ironauth_control` each get only the COLUMN-SCOPED `UPDATE` the surfaces need on
    `sessions`, `client_sessions`, `refresh_families`, and `grants`.
  - **New audit actions.** `session.rotate`, `session.revoke`, `sessions.bulk_revoke`,
    and `user.sessions.revoke_all`.
  - **Rotation carries or terminates the prior lineage (never orphans it).** A rotation
    now reconciles the prior session INSIDE its existing transaction and returns a
    `PriorSessionOutcome`. When the prior session is the SAME subject (a re-authentication
    in the same browser) its per-client sessions and refresh families are RE-POINTED onto
    the successor, so the `sid` stays stable and a later revoke/logout still cascades to
    everything the earlier lineage segment opened. When it is a DIFFERENT subject (a login
    while presenting somebody else's cookie) the prior session is TERMINALLY revoked with
    the full cascade and the incoming user inherits nothing, with a distinct
    `replaced_by_other_subject` end cause. Previously the supersede moved only the
    `sessions` row, orphaning the prior lineage's families and per-client sessions so a
    logout of the successor never revoked them.
  - **Idle timeout actually slides.** `SessionRepo::get` now takes the configured idle
    window and, on a successful resolve past roughly half of it, rewrites
    `idle_expires_at`/`last_seen_at` (re-asserting the full liveness guard, so a revoked
    session is never resurrected). Previously nothing slid the window after insert, so a
    continuously active session was killed at the idle TTL as if it were a second
    absolute cap.
  - **`ensure_sid` refuses a dead session.** The per-client session is inserted only if
    the SSO session still resolves live (same guard as the read path), so a code minted
    before a revoke and redeemed after it can never mint a fresh live `sid` bound to a
    dead session. Returns `NotFound` for a dead session.
  - **Fleet LIST isolation probes.** `session_fleet.list` and `refresh_family_fleet.list`
    now register `IsolationProbe`s too (the list surfaces, where a broken policy would
    leak a whole tenant at once rather than one row).
  - **Removed.** `ActingSessionRepo::create` (the bootstrap create path): `rotate` with
    no prior session is now the single create path, so no session can be created that
    skips the rotation seam.

- Device authorization grant persistence (issue #24, migration 0021, expand).
  - **New scoped table.** `device_codes` holds a device-authorization flow keyed by the
    SHA-256 digest of the WHOLE device code (never the code itself): the non-secret
    `dc_` handle, the SHA-256 `user_code_hash` (unique per environment), the client,
    requested scope, `status` (pending / approved / denied / expired / redeemed), the
    enforced `interval_secs` and `last_poll_at` for slow_down bookkeeping, the
    `failed_attempts` counter, a coarse `initiation_hint`, and the approval linkage
    (subject, `grant_id`, consent, auth methods, auth time). It ENABLE + FORCEs
    row-level security with the `(tenant, environment)` isolation policy and is
    registered in `scripts/query-audit.sh`; the schema-level migration test asserts it
    holds a digest and a user-code hash but no plaintext device_code / user_code /
    secret column.
  - **Column-scoped grants (no table-wide UPDATE).** `ironauth_app` gets SELECT + INSERT
    on `device_codes` plus a COLUMN-SCOPED `UPDATE` over only the poll/approval columns
    (`status`, `interval_secs`, `last_poll_at`, `failed_attempts`, `subject`,
    `grant_id`, `consent_ref`, `auth_methods`, `auth_time`), so a data-plane path can
    never rewrite the digest, the user-code hash, the client, or the expiry. The migration
    also adds `clients.grant_types` (default `authorization_code`, the per-client device
    opt-in) and `clients.logo_uri`, re-granting `ironauth_app` a column-scoped
    `UPDATE(grant_types, logo_uri)` rather than widening its `clients` grant.
  - **Repository API.** A read-and-bookkeeping `DeviceCodeRepo` (user-code lookup that is
    non-oracular Active/Dead/NotFound, the client display profile, `record_failed_user_code`
    that atomically invalidates a flow at its bound, and a `FOR UPDATE` `poll` state
    machine enforcing expiry and an in-place slow_down interval increase) and an audited
    `ActingDeviceCodeRepo` (issue / approve / deny / atomic `redeem_approved`). New
    `DeviceCodeId` (`ira_dc_` opaque-credential id kind, redacted from `Debug`),
    `device_code_digest` / `user_code_hash`, and the `device_code.issue` /
    `device_code.approve` / `device_code.deny` audit actions.
- JWT bearer assertion grant trust and mapping stores (issue #26, migration 0020, expand).
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
    HTTP management surface for it is M13). Migration 0020 now adds an `enabled` column
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
- RFC 8707 Resource Indicators storage (issue #28, migration 0019, expand).
  - **New columns.** `clients` gains `allowed_resources` (a JSON array; NULL means no
    per-client allowlist, `[]` means allow nothing) and `resource_indicator_policy`
    (a CHECK-constrained `default_audience` / `refuse` string for the no-resource
    case). `grants` and `authorization_codes` gain `granted_resources` (the JSON array
    of resources approved at authorization, frozen for the downscope-not-expand check).
    `opaque_access_tokens` gains `audiences` (the JSON array of recorded audiences so
    introspection can report them).
  - **Column-scoped grant.** `ironauth_app` receives `UPDATE (allowed_resources,
    resource_indicator_policy)` on `clients` only (never a table-wide UPDATE), so the
    policy write cannot touch any other client column.
  - **New store surface.** `ClientRepo::resource_policy` reads a client's
    `ClientResourcePolicy`; `ActingClientRepo::set_resource_indicator_policy` is an
    audited write (new `client.resource_indicator_policy.set` action). `IssueCode` and
    `NewOpaqueAccessToken` carry the resources/audiences; the code, grant, refresh, and
    opaque-token resolutions surface them. Encoding empty to NULL keeps the pre-#28
    single-audience behavior byte-identical.

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
