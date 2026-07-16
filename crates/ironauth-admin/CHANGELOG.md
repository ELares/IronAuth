# ironauth-admin changelog

All notable changes to the `ironauth-admin` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- Exit-export coverage for the TOTP second factor (issue #69/#58): the identity
  export now carries a user's enrolled TOTP authenticators (with the OPENED seed,
  sealed at rest and opened only for the gated, audited export) and their
  recovery-code hashes, and the field-coverage guard classifies every column of the
  new `totp_credentials` and `recovery_codes` tables, so the exit covenant stays
  honest and the guard stays green.

- In-admin Argon2id tuning probe (issue #62): a new env-scoped, permission-gated
  `POST /v1/tenants/{tenant}/environments/{environment}/password-hashing/probe` runs the
  host-measured `ironauth_oidc::run_probe` (on a blocking thread, never inline on the
  request thread) and returns the recommended parameters, the measured latency, whether
  the target was met, and the projected logins/s per core and across the host. It closes
  the acceptance requirement that the tuning helper ship in BOTH the admin UI and the
  CLI. The probe is a read-only measurement, so it carries only an optional
  Idempotency-Key; an optional JSON body overrides the target latency and memory budget.
  The OpenAPI spec and the committed `docs/openapi/management.json` gain the endpoint.
- Export field-coverage extended for WebAuthn passkeys (issue #65): the exit-covenant
  field-coverage guard now classifies the new `webauthn_credentials` table. A
  registered passkey is DEVICE-BOUND and not portable across IdP instances (the
  private key never leaves the authenticator and the stored COSE public key is scoped
  to this deployment's RP ID), so the credential material is classified OPERATIONAL
  device state (the scope/structural columns DERIVED) and documented as the honest
  exception in docs/exit-guide.md; the guard still fails the build if the table grows
  an unclassified column. The export record format is unchanged (the portable
  identity, the user and its password hash, round-trips as before).

- Migration state-machine operator view (issue #59, exploratory): three env-scoped,
  permission-gated read endpoints over the invariant-checked migration state machine.
  `GET .../migration-runs` lists a scope's runs (cursor paginated);
  `GET .../migration-runs/{run_id}` reports one run's current state, its per-state
  record counts, and its LIVE invariant evaluations (re-derived from the database on
  every call, with the blocking invariants surfaced) so an operator can see exactly why
  a run cannot complete; `GET .../migration-runs/{run_id}/violations?invariant=...`
  pages the specific records violating an invariant, each naming the offending identity
  and its reason. Environment-scoped reads (operator plane or the environment's own
  management key), documented in the OpenAPI contract. New views:
  `MigrationRunSummaryView`, `MigrationRunList`, `MigrationRunCountsView`,
  `InvariantView`, `MigrationRunDetailView`, `OffendingRecordView`,
  `MigrationRunViolationList`.
- Lazy-migration progress endpoint (issue #56):
  `GET /v1/tenants/{tenant}/environments/{environment}/migration/progress` reports how far
  an environment's inbound lazy migration has come (total users, how many are on the native
  Argon2id verifier, and the foreign-hash straggler tail a #55 bulk import closes out) and,
  when this node runs the data plane with a hook installed, the node's circuit-breaker state.
  Environment-scoped read (operator plane or the environment's own management key), reads
  only counts (decrypts no PII), and is documented in the OpenAPI contract. `AdminState`
  gains an optional shared `LazyMigrationHook` (installed by the boot path, the SAME Arc the
  OIDC data plane holds) so the breaker state is visible cross-plane in-process.
- Exit-export hardening (issue #58, review): the export now carries the enrolled MFA
  / login credential REGISTRY (`account_credentials`), not merely the password: each
  passkey / TOTP / recovery-code enrollment (factor kind, opened friendly name,
  last-used instant) rides the record and re-imports losslessly. The field-coverage
  guard now enumerates the FULL identity model (`users` AND `account_credentials`),
  so a new column on either table, including the M7 credential-secret columns, fails
  the build until it is exported or explicitly justified. The outbound
  verify-credential endpoint is now (a) not a user-enumeration timing oracle: an
  absent or fenced account spends the same Argon2id work as a wrong password through
  one shared verify entry; (b) SCOPE-BOUND to one configured `(tenant, environment)`,
  so a request to any other scope, even with the correct token, is a uniform 404 and
  never a cross-tenant oracle; and (c) evaluated enablement-first, so a disabled
  endpoint is a uniform 404 even to an unauthenticated probe (indistinguishable from
  an absent route). The audited export count now equals the lines actually emitted.
- Exit-friendliness covenant (issue #58): the full identity export and the outbound
  lazy-migration hook. `GET .../export` streams every identity of an environment as
  the same newline-delimited record format the streaming bulk import consumes
  (`application/x-ndjson`, one user per line), carrying login handle, external id,
  lifecycle state, claims, traits and schema version, and the password verifier with
  its algorithm tag and full parameters (native Argon2id, or an imported foreign
  hash), so an export re-imports into a fresh instance losslessly with logins intact.
  It is permission-gated (operator or the environment's own key), audited
  (`user.export`), and streams one bounded page at a time. `POST
  .../migration/verify-credential` is the mirror outbound hook: a successor system
  presents an identifier plus password and receives a verdict and optional profile,
  verifying native and foreign credentials through the same dispatch as login,
  DISABLED BY DEFAULT and gated by an environment-scoped shared token (`admin`
  config). A field-coverage test fails the build on a user column the export does not
  cover; the exit guide is `docs/exit-guide.md`.

- User invitation management API (issue #60): the admin side of the invitation
  flow, on the M1 API discipline (OpenAPI source of truth, cursor pagination,
  `Idempotency-Key` on POST, audit-on-mutation, uniform cross-tenant not-found).
  Create an invitation (provisions a `pending_verification` user through the #52
  path, mints the single-use token, seals the invited identifier), list and inspect
  invitations, revoke a pending one, and resend (rotate the token digest and
  expiry). The plaintext token is returned to the caller exactly once, at create and
  resend, and is never persisted or re-readable.
- Foreign password import follow-through (issue #55): the admin user create path
  passes the new `NewAdminUser` foreign-hash fields as `None` (the management create
  surface sets no imported credential; the streaming bulk import path in
  `ironauth-import` is where an imported foreign hash enters).

- Admin user management API (issue #52): complete control-plane user CRUD,
  lifecycle transitions, and external-id correlation under an environment, on the M1
  API discipline (OpenAPI source of truth, cursor pagination, `Idempotency-Key` on
  POST, audit-on-mutation, uniform cross-tenant not-found). Endpoints:
  `POST /users` (create, with an optional caller-supplied id honored and a 409 on
  collision, an external id, and a chosen initial state), `GET /users` (cursor
  paginated, filterable by `state` / `external_id` / `identifier`),
  `GET/PATCH/DELETE /users/{user_id}` (read; RFC 7396 profile patch; a soft-delete
  offboarding that cascades sessions and reads as not-found after),
  `POST /users/{user_id}/state` (a validated lifecycle transition, 409 on an invalid
  one, with a session cascade + back-channel logout fan-out on block/disable), and
  `PUT`/`DELETE /users/{user_id}/external-id` (link/unlink, 409 when the external id
  is already claimed in the scope). A management response never returns the password
  hash. New `users` tag, eight new operations, and the wire types (`UserView`,
  `UserList`, `UserStateView`, `CreateUserRequest`, `UpdateUserRequest`,
  `SetUserStateRequest`, `UserStateChangeView`, `LinkExternalIdRequest`,
  `UserExternalIdView`) in the committed OpenAPI document. The control-plane store
  now carries the platform master key so it seals/opens user PII (issue #48).
  DEFERRED out of #52 met-scope (documented, not stubbed, in
  `docs/design/USER-LIFECYCLE.md`): assigning roles/groups at user creation depends on
  the RBAC model, a separate M6 issue that builds on this one, so `POST /users`
  carries no role/group field yet; and emitting `external_id` in webhook / event
  payloads depends on the M11 eventing surface, which does not exist yet (the external
  id is stored, blind-indexed, and readable now, but there is no event channel to
  carry it). Both are tracked against their owning milestones.
- Server-side config promotion (issue #44): the write half of the flagship. Two
  operator-plane POSTs on the target environment scope:
  `POST .../config/promotion/plan` dry-runs a promotion of a submitted source
  snapshot document into the target and returns a reviewable plan (a stable plan id,
  the base and result revisions, the resolved references, and the structured diff),
  failing closed (422) on a reference the target cannot resolve;
  `POST .../config/promotion/apply` transactionally applies a plan's source snapshot
  onto the target all-or-nothing, gated on the plan's `base_revision` (a target that
  drifted fails 409 with a structured drift error and changes nothing; an
  already-applied plan is an idempotent no-op). Both validate the source document
  (secret-free) before doing anything and run under the target scope's forced
  row-level security; apply audits in the same transaction as the changes.

- Canonical secret-free config snapshot export (issue #43). New
  `GET /v1/tenants/{tenant_id}/environments/{environment_id}/config/snapshot`
  returns the environment's promotable configuration as a canonical, deterministic,
  secret-free JSON document (the format defined in `docs/snapshot/`), the read half
  of the config-promotion flagship. Environment-scoped authorization: the operator
  plane, or the environment's own management key. Reads the three promotable
  resource types through the control-plane scoped repositories, so a snapshot
  exports only its own scope's config; a confidential client's secret appears as a
  named reference, never a value. Applying a snapshot (issue #44) and resolving
  secret references (issue #45) are separate.

- Tenant lifecycle API and residency attributes (issue #46). Operators can suspend
  and resume tenants and record data-residency regions through documented
  operator-plane endpoints.
  - **Lifecycle endpoints.** `POST /v1/tenants/{tenant_id}/suspend`, `.../resume`,
    and `.../restore`, all Idempotency-Key honored and audited, returning the
    tenant's new status as the post-condition. An invalid transition (for example
    suspending an already-suspended tenant) is a loud `409`, distinct from the
    anti-oracle `404`. A suspended tenant stays visible to control-plane reads.
  - **Residency.** `CreateTenantRequest` gained an optional `home_region` and
    `CreateEnvironmentRequest` gained an optional per-environment `region`, each
    validated against the operator's configured region set (`admin.allowed_regions`)
    and rejected with `400` when outside it or when no region set is configured.
    `TenantView` carries `status` and `home_region`; `EnvironmentView` carries
    `region`.
  - **Offboarding pipeline.** `DELETE /v1/tenants/{tenant_id}` is now the GRACE
    stage: it fences the tenant and keeps its keys intact, restorable within the
    configured retention window (`admin.offboarding_retention_secs`). `POST
    /v1/tenants/{tenant_id}/restore` restores a grace tenant in-window (`409` once
    the window has elapsed). The delete no longer crypto-shreds; erasure is deferred
    to the terminal hard-delete stage per issue #46's out-of-scope.
- Typed environments with guardrails and scoped keys (issue #42). Environment
  creation is a single call that types the environment and provisions its identity.
  - **Typed create.** `POST /v1/tenants/{tenant_id}/environments` now takes a required
    `kind` (`dev`, `staging`, or `prod`) and an optional `custom_domain`; the tenant-create
    body takes the same for its first environment (defaulting to `dev`, which needs no
    domain, so a tenant is always creatable in one call). An unknown kind is a `400`; a
    production environment with no configured custom domain is a `422 guardrail_violation`
    naming each failed guardrail in a new `failed_guardrails` field on the error body.
  - **Guardrails on the view.** `EnvironmentView` now exposes `kind`, `guardrail_class`,
    `custom_domain`, and a `guardrails` object (a new `GuardrailView`) with the derived
    flags: insecure-redirect allowance, https-only redirects, custom-domain requirement,
    one-time-view secrets, hosted-page noindex, and the environment banner.
  - **Day-one signing key.** Creation generates the environment's own `EdDSA` day-one
    signing key from the entropy seam (`provision::DayOneSigningKey`) and provisions it in
    the same transaction, so the new environment serves discovery with its own issuer and
    a disjoint JWKS immediately. The key is the environment's identity, never promoted.
- The four-level resource model as public APIs (issue #41). Operator, tenant,
  environment, and organization are now each manageable through documented endpoints,
  and every resource type carries a machine-readable promotion classification.
  - **Organization endpoints.** `POST` and `GET /v1/tenants/{tenant_id}/environments/{environment_id}/organizations`
    and `GET`/`DELETE .../organizations/{organization_id}`, following the M1 discipline:
    cursor pagination, `Idempotency-Key` on create, rate-limit headers, and a
    same-transaction audit row on every mutation. Reachable by the operator or by a
    management key scoped to exactly that environment (a sibling-environment key is the
    LOUD wrong-scope 403). Create enforces containment: the parent environment must
    exist and be live, and a cross-scope `org_` id is the uniform not-found.
  - **Operator-plane read surface.** `GET /v1/operators` and
    `GET /v1/operators/{operator_id}`, the root of the resource model exposed for
    inspection (a single-binary deployment self-bootstraps its one operator; a
    management key here is the wrong-plane 403).
  - **Resource-type classification catalog.** `GET /v1/resource-types` serves every
    resource type with its scope level and its promotable / runtime /
    environment-identity classification, the machine-readable metadata the snapshot and
    promotion engines consume. Readable by any valid management credential.
  - **Contract.** New views (`OperatorView`, `OrganizationView`,
    `CreateOrganizationRequest`, `ResourceTypeView`, and their list wrappers), seven new
    operations pinned in the OpenAPI contract test and regenerated into
    `docs/openapi/management.json`, and organization probes added to the management IDOR
    harness run.
- Session and refresh-family FLEET OPERATIONS (issue #32). Sessions and refresh-token
  families are now first-class, searchable, metadata-carrying management resources
  rather than an opaque internal table.
  - **New endpoints.** `GET /sessions` (searchable by `subject` and `client_id`, cursor
    paginated), `GET /sessions/{session_id}` (inspect any lifecycle state: live, revoked,
    or rotated away), `POST /sessions/{session_id}/revoke`, `POST /sessions/revoke` (bulk),
    `POST /users/{user_id}/sessions/revoke` (revoke everything for a user, cascading to
    the refresh-token families), `GET /refresh-families`, and
    `GET /refresh-families/{family_id}`, all under the environment scope.
  - **Offline-preserving by default.** A revoke cascades to the session-bound refresh
    families but PRESERVES the `offline_access` families (issue #21's
    offline-survives-logout semantic). The documented `hard_kill` flag also ends those,
    and their grants with them.
  - **Scope-fenced.** Every id is parsed under the caller's own scope, so a foreign
    session or family is the uniform not-found, and a BULK revoke silently drops a
    foreign id rather than reaching across the boundary. Each surface registers an
    `IsolationProbe` with the #6 IDOR harness.
  - **Deterministic revocation responses.** Each revoke reports the POST-CONDITION rather
    than a row count, so the Idempotency-Key record (written in the SAME transaction as
    the revocation) replays byte-identically and an absent, foreign, or already-revoked
    session stays indistinguishable from a live one.
  - **Test-helper adaptation.** The shared admin test harness follows the new
    `SessionRepo::get` signature (which now takes the idle-window for the idle slide);
    no admin behavior changed.

- DCR abuse-control management surface (issue #31). Five operator-plane endpoints,
  all honoring the crate's contract (Idempotency-Key, same-transaction audit,
  RateLimit headers, cursor pagination, OpenAPI as source of truth):
  - `POST` / `GET` `.../dcr/policies`: author a named, reusable policy (its primitives
    validated at create time against the OIDC policy engine, one source of truth for
    the shape; a duplicate name is a 409) and list policies (cursor paginated).
  - `POST .../dcr/initial-access-tokens`: mint an initial access token attaching a
    policy chain by name (resolved to a primitive snapshot so a later policy edit
    never changes an already-minted token). The plaintext token is returned exactly
    ONCE (HTTP 201); an idempotent replay omits it (HTTP 200). Only its SHA-256 is
    stored.
  - `GET` / `POST .../clients/{client_id}` (+`/verify`): read a dynamically registered
    client's quarantine state, and verify it (lifting the quarantine) idempotently. A
    not-found is a uniform anti-oracle 404.
  - The DCR resources are DATA-plane scoped, so these control-plane endpoints route
    through the control role's narrow grants (mint/verify), never a second data-plane
    store. New `ApiError::Conflict` (409). Now depends on `ironauth-oidc` for the
    shared policy-primitive type. The policy-create schema documents the `restrict`
    omission footgun (an omitted property is unconstrained and then takes the spec
    default; pair `restrict` with `default` or `force` to make a property mandatory).

- Initial OpenAPI-first management API skeleton (issue #11). Establishes the
  management API contract and discipline once, so the later admin SPA, CLI,
  Terraform, and MCP surfaces inherit it as thin clients.
  - **OpenAPI 3.1 as source of truth.** The spec is derived from the
    `#[utoipa::path]` annotations on the axum handlers with `utoipa` (MIT OR
    Apache-2.0, MSRV 1.75); the handlers are listed once in `#[derive(OpenApi)]`
    `paths(...)` and wired to the same paths in the router, a contract test pins
    the documented (method, path) set, and `scripts/openapi-check.sh` regenerates
    the committed `docs/openapi/management.json` and `git diff --exit-code`s so
    drift fails the build. Served at `GET /openapi.json`. The utoipa-axum
    route-binder is deliberately not used: it pulls the unmaintained `paste` crate
    (RUSTSEC-2024-0436) that `cargo deny` rejects, so the router is wired by hand
    and no new advisory enters the graph.
  - **Cursor pagination on every list endpoint.** Opaque base64 cursors over a
    stable `(created_at, id)` key, a config-capped page size
    (`admin.max_page_size`, `admin.default_page_size`), and no offset pagination
    anywhere.
  - **Idempotency-Key on every POST** (draft-ietf-httpapi-idempotency-key). Keys
    are scoped to the acting credential and stored with the original response in
    the SAME transaction as the mutation, so a replay returns the original result
    and writes no second audit row. A key reused with a different request is a
    422.
  - **RateLimit headers on every response.** Structured `RateLimit` and
    `RateLimit-Policy` (draft-ietf-httpapi-ratelimit-headers) plus the legacy
    `X-RateLimit-*` triplet, wired to a placeholder limiter so the header
    contract is fixed before the real limiter lands.
  - **Environment-scoped credentials, two wrong-scope behaviors.** Management API
    keys (`mak_`) are bound to `(tenant, environment)` via the typed-ID
    substrate; the presented token is `<mak_id>.<secret>` and only the token hash
    is stored. A config bootstrap operator token authorizes the operator plane
    (tenant CRUD) in M1; the full operator-plane credential class lands in M5.
    Cross-scope resource probes are a uniform not-found (registered with the #6
    IDOR harness); a credential against the wrong environment or plane fails LOUD
    with an error naming expected and actual scope.
  - **Audit on every mutation.** Every management mutation writes its audit row in
    the same transaction, through the store's audited-write primitive, connecting
    as the distinct `ironauth_control` role.
  - First resource endpoints proving the discipline end to end: tenants CRUD
    (operator plane), environments CRUD (under a tenant), and management-key CRUD
    (under an environment). Idempotent PUT/DELETE semantics (RFC 9110): DELETE is
    a soft deactivation that is idempotent and keeps the append-only audit log's
    foreign keys satisfiable.
