# ironauth-admin changelog

All notable changes to the `ironauth-admin` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- Review fold on the streaming bulk-import job surface (issue #55).

  - **Resuming a TERMINAL run no longer creates identities before answering 409.** The
    resume checked the run's kind and its reconciling back edge but never
    `state.is_terminal()`, so the refusal arrived from the ledger ingest at the first batch
    flush, up to 256 audited `admin_create` calls too late. MEASURED: a `complete` run
    resumed with five records answered 409 and took the environment from one user to SIX,
    every one accounted in no ledger anywhere. The shipped test asserted only the status
    code, so it passed throughout; it now asserts the POPULATION.
  - **A body the server could not read to the end is REFUSED rather than answered 202.**
    The reader's fault was recorded in a private field nothing ever read. MEASURED with one
    good record, a line one byte over the 1 MiB cap, and four more good records against a
    declared `source_total` of 6: `202 Accepted`, one user, five records dropped on the
    floor, and no signal to the caller. The same silent path absorbed a mid-upload transport
    error, which is the common production case. The fault now reaches the handler, which
    answers `400` naming the cause and the run id to resume; the records delivered before it
    stay durable and accounted.
  - **`POST .../migration-runs/{run_id}/abandon`**, the audited, reason-carrying terminal
    giving-up, mounted as a management route with its own grant in migration 0101. Without
    it a wedged run is wedged FOREVER: a source carrying two records under one login handle
    accounts one row against a declared two, a failed record is accounted inconsistent and
    nothing on this plane reconciles it, and 0101 withholds `UPDATE (source_total)`,
    `UPDATE` on the ledger rows, and `DELETE` on purpose. It is idempotent (a run already
    abandoned answers 200 with its FIRST reason) and refuses a `complete` run with 409,
    because a completion may not be quietly taken back.
  - **`progress_path` no longer promises fields the progress view does not publish.**
    `MigrationRunCountsView` has exactly `imported`, `failed`, `skipped`, `inconsistent`,
    `unmarked_backfill`, and `accounted`: there is no `processed` and no `remaining`. The
    false sentence shipped in `docs/openapi/management.json` and in the generated SPA
    bindings, and is corrected at its source and regenerated.
  - **The one-input-shape justification rests on the THREAT MODEL alone.** It also claimed a
    vendor route would "buy no capability", which is false twice: `ironauth-importers` has
    no dependent in the shipped graph, no `[[bin]]`, and no command-line entry point, so the
    exit guide was instructing operators to pipe the output of a program that does not
    exist; and its issue-#57 validation-only gap report is a fact about the VENDOR document
    that the line-delimited format structurally cannot carry.

- **The streaming bulk-import JOB surface** (issue #55): `POST .../imports` creates a
  migration run declaring the source record count and streams a newline-delimited identity
  record set into it; `POST .../imports/{run_id}` resumes that run. This is the write half
  the import engine never had. Before it, `ironauth_import::import_stream` and
  `import_into_run` both existed, were tested, and had ZERO production callers (the only
  apparent one was a commented-out line inside a doc comment), so nothing that shipped could
  perform an import at all.

  - **The body is read one frame at a time**, not through axum's `Bytes` extractor, which
    buffers the whole request before the handler runs. A 100k-record upload therefore holds
    one record plus one frame between the socket and the `INSERT`. A single line is capped at
    1 MiB so a body carrying no newline cannot grow the reader without bound either.
  - **Resumability is keyed on the record, never on a position.** There is no byte offset and
    no server-side cursor into the caller's file: a resume may re-present anything, including
    the whole source, because a duplicate identity is refused by the scope's unique
    constraints and reported as an idempotent skip, and a duplicate ledger row is refused by
    the run's per-subject unique index. A killed caller generally cannot compute where the
    kill landed, which is exactly what a byte offset would require of it.
  - **Progress is the surface that already exists.** The handlers answer `202 Accepted` with a
    job HANDLE (the run id and the path to read it at) and no counters; the counters are
    `getMigrationRun`, which shipped with issue #59. That is also what lets the
    `Idempotency-Key` record commit in the SAME transaction as the run creation: the stored
    response has to be knowable BEFORE the import runs, and a counter in the body is not.
  - **The active trait schema is not bypassed.** The job drives the same engine path issue #53
    PR 1 gave the schema check to, so a record violating the target scope's active schema
    fails that record and no other, with the rest of the import proceeding.
  - **One input shape, deliberately.** The route accepts the first-party line-delimited record
    format only, and not a Keycloak realm export, an Auth0 bulk export, or a Firebase
    `auth:export`, even though `ironauth-importers` parses all three: those front-ends
    translate a vendor document INTO this format, so a vendor-shaped route would put a second
    parser of attacker-supplied documents on the network surface, and those parsers consume
    whole documents rather than a line at a time, giving up this route's memory bound with
    it. The threat model is the whole justification; see the fold entry above for the two
    capabilities a vendor route WOULD buy.

- Review fold on the identity trait-schema surface (issue #53, PR 1).

  - **A connector claim mapping that targets an admin-only trait is refused at CONFIG time**,
    on both the create and the update, naming `/claim_mapping/traits/<field>`. The claim
    mapping is the other configuration surface that can name a trait and it had NO admin-only
    gate at all (`grep -rn "is_admin_only|admin_only|visibility"` over `ironauth-connector`
    and `connectors.rs` returned nothing), so an upstream identity provider could write
    admin-only metadata onto a local identity. The store's write class refuses it too, but a
    LOGIN-time refusal breaks the end user for a fault only the operator can fix; this is the
    same posture `validate_signup_form` already takes on the signup-form surface.
  - **The import path validates when the target scope HAS an active schema.** It skipped
    validation unconditionally; the exit covenant only needs that when the target has NO
    schema (a lossless restore into a fresh scope). A violating record is now that record's
    failure through the existing `ImportReport`, with an RFC 6901 pointer and no trait value
    in the reason, and the rest of the import proceeds.
  - `scripts/idempotent-write-audit.sh`'s `MINIMUM_ROWS` floor moves 42 to 45, matching the
    inventory this surface grew; at 42 the floor permitted a silent shrink of three sites.
  - `tests/sudo.rs` drives the trait-schema CREATE and ACTIVATE gates, the activate half
    separately so it cannot ride on the create's elevation.
  - Verdicts written down where a reader returns the FULL document on purpose: the outbound
    migration verify-credential endpoint (armed by the operator's per-environment sealed
    bearer, and lossy for the successor if redacted, exactly like `exportIdentities`), and
    why `getUserTraits` writes no audit row while `exportIdentities` does (the audited event
    is a whole-environment EGRESS, not a decryption; no single-identity management read on
    this plane audits).
  - The module doc records that a traits LIST was deliberately omitted (the bulk read is
    `exportIdentities`, which is paginated and audited; a trait-valued filter would need a
    queryable projection of a column that is sealed at rest).

  Test vacuities the review found, all fixed and all re-measured: the export round trip
  asserted a `traits_schema_version` of 1 that was the only value its fixture could produce
  (it now activates a second version and asserts 2, and the constant mutation is killed by
  this file rather than only by `tests/export.rs`); the cutover refusal asserted a count of 1
  that a hardcoded 1 satisfied (it now plants two failing identities, asserts 2, fixes one,
  and asserts the count FOLLOWS the population down to 1); the round-trip PATCH payload now
  actually does the three things its comment claims (removes an array element, reverses the
  survivors, adds a nested member), asserted against the created document; and the
  "no failure echoes a value" loop now submits a `zip` that FAILS, so it is not ranging over
  failures that could never have mentioned it.

- Identity trait schemas as a management surface (issue #53, PR 1). The versioned
  trait-schema registry, the validator, and the visibility split all existed in the store
  and had ZERO production callers: `docs/openapi/management.json` contained no path matching
  `trait` or `schema`, `createUser` passed `traits_json: None`, and `activate_version` and
  `list_versions` were reachable only from tests. This PR is the surface that makes them
  live, targeting acceptance criteria 1, 3 and 4.

  **The registry.** Five endpoints under
  `/v1/tenants/{tenant_id}/environments/{environment_id}/trait-schemas`, mirroring the
  journey-version registry (issue #92) because it is the same shape of thing: an append-only
  set of IMMUTABLE versions with one active pointer. `POST` appends a candidate version
  (Idempotency-Key required, replayed on retry, sudo gated, `require_live_environment`);
  `GET` lists them; `GET /{version}` reads one; `GET /active` is the schema INTROSPECTION
  endpoint, serving the active document together with its parsed behavior annotations, so a
  form generator reads both from one response; `POST /{version}/activate` is the cutover.
  There is no PUT and no DELETE: a version is immutable, and a change is a new version.

  **Traits on the user surface.** `createUser` and `updateUser` now take a `traits`
  document. It is VALIDATED against the environment's ACTIVE schema before anything is
  written, and a violating document is a `422` carrying one `trait_errors` entry PER FAILING
  FIELD, each with its RFC 6901 JSON Pointer, with nothing written. A valid document is
  persisted together with the schema version it validated against, and a later activation
  does NOT restamp it (that stamp is what lets a migration job select the identities still on
  an older version). `GET .../users/{user_id}/traits` reads the document back. An environment
  with no active schema refuses a traits-carrying write with a legible `422` rather than
  performing an unvalidated one.

  **The per-field errors are STRUCTURED, and that needed one deliberate interception.** The
  central `From<StoreError>` renders through `Display`, which JOINS the failures into a
  sentence; that is exactly the information a form cannot reconstruct (which INPUT failed).
  `StoreError::TraitsInvalid` is therefore lifted out ahead of the wire conversion into
  `ApiError::TraitsInvalid`, so every route that converts through the one impl gets the
  structured contract without carrying an arm of its own. `ErrorBody` grew a `trait_errors`
  list and a private `plain` constructor; the ten arms of the render used to re-spell every
  optional field as `None`, which meant the only thing keeping a new field off an unrelated
  error was ten identical hand edits.

  **The cutover rule ships GATED, and by the stronger of the two available gates.**
  `activateTraitSchemaVersion` refuses while ANY identity fails the target schema: the store
  counts them on a live scan INSIDE the activation transaction, and a non-zero count is a
  `422` naming the count with nothing moved. That is deliberately not a gate on dry-run or
  migration job state, which is a claim about a moment that has passed (an identity written
  after the report finished would satisfy it while still failing the schema). The later jobs
  PR adds the operator ergonomics and can add a second precondition; it cannot loosen this
  one.

  MEASURED and fixed during the work: the first cut built the response view off the SUBMITTED
  schema document, so a malformed schema answered `500` instead of the `400` the store's typed
  `SchemaMalformed` already carried. A submitted schema now compiles through `validated_schema`
  (a loud 400 naming the offending location in the schema), and only a STORED schema reaches
  the view builder, where a compile fault genuinely is an internal fault.

  `tests/trait_schemas.rs` pins the four decisive properties (a per-field-pointered refusal
  that writes nothing, the persisted-and-not-restamped version, the visibility split in both
  directions, and the arrays-and-nested-objects round trip through create, PATCH and export)
  plus the registry's own contract.

- Per-environment outbound migration verification (issue #250), the follow-up the #58
  adversarial review asked for. `POST .../migration/verify-credential` now reads its
  enablement AND its shared bearer from the ADDRESSED environment's own sealed
  `environment_secrets` row (the reserved name `ironauth.outbound_verification_token`),
  never from `AdminConfig`. Several concurrent outbound migrations can run in one
  deployment, each with an independent token, each rotatable on its own schedule, each
  sealed under its own environment's envelope key and invisible to every other environment
  by forced row-level security. Enablement and the credential are ONE fact (the secret's
  existence IS the enablement), so there is no "enabled but uncredentialed" state, and
  disabling destroys the credential rather than leaving it sealed and dormant.

  **The uniform not-found got STRICTER, and it had to.** The endpoint used to answer `401`
  for a missing or wrong bearer inside its one configured scope. With enablement per
  environment that `401` is an ENUMERATION ORACLE: anyone who can reach the management port
  could walk the `(tenant, environment)` space and read off which environments have an
  outbound migration armed, one unauthenticated request each. So there is no `401` on this
  endpoint any more. A missing bearer, a wrong bearer, a disabled environment, an absent
  environment, an absent tenant, and a malformed path id are ONE byte-identical `404`, and
  the missing-bearer refusal is answered BEFORE ANY DATABASE ACCESS, which is also what
  keeps the route answerable over a never-connected pool. `tests/outbound_verification.rs`
  drives all six states and asserts the status, the response headers, and the body bytes are
  identical. The `Bearer` scheme is matched case insensitively (RFC 7235 section 2.1): a
  case-sensitive match fails closed, but with a uniform `404` everywhere a successor whose
  client uppercases the scheme would present a correct token and get an answer identical to
  "not enabled", with nothing to debug.

  **The check ORDER is pinned by counting connections, not by reading a status.** The
  bearer-first order is what makes the refusal free of any database access, and a status
  assertion cannot see it: a handler mutated to read the secret FIRST answers the same `404`
  over the same pool and survives the whole crate suite (MEASURED: 392 tests over 46
  binaries, green). `openapi_contract::the_outbound_bearer_check_runs_before_any_database_access`
  drives a router whose store carries a master key over a lazy pool aimed at a socket that
  counts connections, and requires the no-bearer probe to answer `404` having opened NONE
  while a garbage-bearer control opens one.

  **The timing residual was flattened rather than conceded, because the concession was
  measured wrong twice.** It is reachable with NO credential (any garbage bearer reaches the
  envelope open, and nothing rate limits it), and the delta was not the AEAD but TWO DATABASE
  ROUND TRIPS: the plain sealed read costs one `SELECT` on a miss and three on a hit. The read
  now goes through `EnvironmentSecretRepo::open_value_under_platform_key_at_uniform_cost`,
  whose miss branch spends the same two key lookups and the same three AEAD opens.
  `tests/outbound_timing_probe.rs` is the harness (`#[ignore]`d: a wall-clock assertion in CI
  is a flake generator), run with

  ```
  scripts/with-test-db.sh cargo test -p ironauth-admin --features testing \
      --test outbound_timing_probe -- --ignored --nocapture
  ```

  600 interleaved unauthenticated samples per branch, on one throwaway local Postgres.
  BEFORE, the armed median was 1.437x the disabled median, the armed 1st percentile sat
  ABOVE the disabled median, and a single-sample classifier at the midpoint of the medians
  got 0.977 recall at 0.022 false positives: one request per `(tenant, environment)` pair.
  AFTER, over three runs, the ratio is 1.041 to 1.045, the armed 1st percentile is BELOW the
  disabled median in every run, and the same classifier gets 0.69 to 0.81 recall at 0.21 to
  0.36 false positives, which is close enough to a coin toss that a prober needs many
  separated windows rather than ten requests. The residual is real and is stated as a number
  rather than as an adjective: about 14 microseconds on a 318 microsecond baseline, from the
  hit branch decoding two key rows and unwrapping two real keys where the miss branch's decoy
  lookups return none.

  Token comparison is `hash::constant_time_eq`, which SHA-256s both sides before an
  XOR-accumulating compare, so neither the length nor the position of the first differing
  byte leaks. The opened value is wrapped in `SecretString` (redacted `Debug` and `Display`)
  and reaches nothing but that one comparison: no log, no tracing field, no error body. The
  plaintext is NOT zeroized, and this change makes that residue larger rather than smaller,
  because it moves the credential from a once-at-boot read to a once-per-request read.
  `SecretString` has never zeroized on drop, on this or any other secret in the tree, so this
  is a pre-existing design point recorded here rather than a regression introduced here.

- Three management endpoints for that credential (issue #250), under
  `.../migration/outbound-verification`: `GET` reads whether the environment is armed plus
  the stored version and timestamps (metadata only, built from a `SELECT` that does not name
  the ciphertext column, so there is no code path from the response to a value), `PUT`
  enables or rotates it, and `DELETE` disables it and destroys the token. They take the
  ordinary management credential and resolve through `resolve_scope`, so a management key
  scoped elsewhere gets the loud wrong-scope refusal, and both writes pass the sudo guard.
  They are deliberately NOT a generic environment-secrets API: they address exactly the one
  reserved name, so this surface cannot read or write any other environment secret, and
  migration 0100 enforces that at the DATABASE as well as in the handler. A token under 32
  bytes is refused and nothing is stored; the refusal names the floor, never the token.
  `DELETE` is idempotent, because a `404` for an already-disabled environment would rebuild
  the enablement oracle on the management side.

  **The environment precondition differs by DIRECTION, and that asymmetry is the point.**
  `PUT` requires a LIVE environment, because arming a credential oracle inside something an
  operator believes is decommissioned is the defect issues #411 and #451 are about. `GET` and
  `DELETE` require only that the environment EXIST. Requiring liveness to DISARM turned the
  soft delete into a ONE WAY DOOR, and it was measured end to end: environment `DELETE` 204,
  then `POST .../verify-credential` 200 with `{"verified":true}` plus the subject and profile,
  then `DELETE .../outbound-verification` 404 and `PUT` 404, with `GET` still reporting
  `{"enabled":true}`. Soft-deleting an environment cascades to almost nothing, so the sealed
  credential survives it, and with no environment-restore route and no generic
  environment-secrets route the only remedies left were a direct database write or a full
  tenant crypto shred. The verify endpoint answering inside a soft-deleted environment is
  deliberate and older than this change (a successor draining an environment is exactly who
  is still reading it); what was new was deleting the off switch, since before this change an
  operator always had `admin.outbound_verification_enabled = false` plus a restart.
  `outbound_verification::a_soft_deleted_environments_credential_can_still_be_destroyed`
  drives the whole sequence, and `live_surface` records the disarm as the one documented
  write exception that lands a row change, pinning the exact per-table delta rather than
  tolerating one.

  The absent case still refuses on all three, and that half is carried by
  `org_context::require_present_environment` rather than by the database: deleting a row that
  was never there violates no foreign key, so the store answers its own not-found and the
  idempotency arm would turn it into a `204`. The claim that "absent is already refused by
  the store's own foreign keys" is true of insert-shaped writes and false of this delete.

  No `Idempotency-Key` arm, following `client_scopes` and `resource_servers`: the key exists
  so a retried CREATE cannot mint two rows, and a `PUT` of an absolute value onto a per-scope
  singleton is naturally idempotent.

- **BEHAVIOR FIX. A failed invitation create no longer wedges the identifier it named**
  (issue #247). `POST /v1/tenants/{tenant_id}/environments/{environment_id}/invitations`
  provisioned the `pending_verification` user in one store transaction and wrote the
  invitation (with the Idempotency-Key record) in a second. A failure of the second after
  the first committed left an orphaned user with no invitation and no stored key: the retry
  under the SAME key missed the replay store, re-ran the user create, hit the identifier
  unique violation and answered **409**, and the identifier stayed unusable behind a ghost
  account until an operator deleted it through #52. The handler now makes ONE store call
  that writes the user, the invitation, both audit rows and the idempotency record in one
  transaction, so a partial create leaves NOTHING and the retry re-executes cleanly
  (MEASURED over HTTP by
  `a_create_whose_second_write_fails_leaves_no_ghost_and_the_same_key_then_creates`: the
  retry that used to be a 409 is a 201). The user id is minted in the handler now, because
  both the response body and the body stored under the key name the user and so must be
  knowable before the write. The 409 stays exactly what it always was, a genuinely taken
  login handle; the astronomically-improbable collision on one of the three values the path
  mints from 256 bits (that `usr_` id, the `inv_` handle, the token digest) keeps its own
  500 and can no longer be mistaken for one. No wire change.
- **BEHAVIOR FIX. A CONCURRENT same-key invitation create now replays the winner instead of
  answering 409** (issue #247). This is a SEPARATE half of the same defect, and joining the
  two writes did not fix it. Both racers pass the replay lookup and reach the store, so one
  blocks on a unique index; which index it blocks on is what it gets told. With the
  Idempotency-Key record written last inside the joined transaction the loser blocked on
  the login-handle index and still answered 409 "a user or invitation with this identifier
  already exists", naming the caller's identifier as taken when nothing but their own
  in-flight twin held it (MEASURED against a live cluster: `201` against `409`). The record
  is written FIRST now, so the loser blocks on `idempotency_keys`, reaches the idempotency
  race, and replays the winner's committed 201, which is what the header contract promises
  (MEASURED over HTTP by
  `two_concurrent_same_key_creates_land_once_and_the_loser_replays_the_winner`). No wire
  change.
- **BEHAVIOR FIX. Approving an admin-gated recovery no longer strands the flow on a failed
  completion** (issue #247, same shape). `POST .../recovery-approvals/{flow_id}/approve` ran
  the audited decision (which committed the Idempotency-Key record) and then completed the
  recovery in a SECOND store call whose result it discarded. A failed completion therefore
  left an approved-but-unfinished flow that the replay store could not see: a retry under
  the same key replayed the stored 200 and never re-attempted the completion, so only a
  FRESH Idempotency-Key could ever finish that flow. The decision and the completion are one
  store transaction now. The #81 delay gate is unchanged: an approve inside the hold window
  still decides the case and still declines to complete, and the admin re-approves after the
  window to finalize. No wire change.
- **AUDIT LOG CHANGE on the recovery-approval approve.** A HELD approve used to write a
  `recovery.complete` audit row unconditionally, because the old second call went through
  `write_audited_detailed`, which audits whether or not the guarded UPDATE matched. The
  joined path writes that row only when the flow actually FLIPPED. So an approve inside the
  #81 hold window now records `recovery.approved` alone, where it used to record a
  `recovery.complete` for a completion that did not happen. This is more accurate and it is
  a change to what the recovery audit log CONTAINS: an operator query counting
  `recovery.complete` rows will see fewer of them, and the ones it sees are now completions.
- **BEHAVIOR FIX. Two concurrent first writes into a brand-new environment no longer answer
  500** (issue #247, found by the concurrency test above). The scope's day-one KEK and DEK
  are provisioned lazily by a check-then-insert, and `ensure_scope_keys` already tolerated
  the resulting conflict, but the insert reported its unique violation as a persistence
  fault rather than as that conflict, so the tolerance was unreachable under an actual race
  and the loser got an opaque server error (MEASURED at the store: `duplicate key value
  violates unique constraint "tenant_keks_tenant_id_environment_id_version_key"`; the
  management create path races on the DEK rather than the KEK, measured by reverting the
  KEK half alone, which the concurrency test survives, and then both halves, which it does
  not). Losing that race means the key already exists,
  which is exactly what the read arm reports.
- **BEHAVIOR FIX. `POST /v1/tenants/{tenant_id}/restore` reports the status it actually
  committed** (issue #438). The 200 body was built BEFORE the store call, hardcoded to
  `active` and commented as the deterministic post-condition, and that same string was
  stored as the Idempotency-Key replay body. It is not a post-condition: a restore undoes
  the DELETE without touching the lifecycle status, so a tenant suspended before its grace
  deletion is restored still suspended, `GET /v1/tenants/{tenant_id}` reads `suspended`, and
  the restore's own 200 said `active` anyway, as did every replay of that key, forever. The
  body is now rendered from the status the store committed, by one renderer used twice: once
  by the store to fill the Idempotency-Key record inside the write's own transaction, and
  once by the handler for the 200 itself, so the response, its replays and a subsequent read
  cannot drift. This is the #395 pattern, applied to the second endpoint that needed it. The
  wire SHAPE is unchanged; the documented 200 description and the `TenantStatusView` schema
  description are corrected, so `docs/openapi/management.json` and the generated console
  bindings move with it.
- **WIRE ADDITION. Per-environment BRANDS have a management surface** (issue #475): `GET`,
  `PUT` and `DELETE` on `/v1/tenants/{tenant_id}/environments/{environment_id}/brands` and
  `.../brands/{slug}`. `brands` shipped with a store-level writer and no endpoint, so a brand
  could not be created through the public API at all: both asset endpoints 404 while the brand
  row is absent, which left a brand's only birth path a config promotion, and blocked the
  promotion asset transport itself, since an operator must be able to create the target brand
  before uploading the bytes a promotion resolves by digest. Reachable by the operator or by a
  management key scoped to exactly this environment, exactly like the locale bundles and signup
  forms it mirrors. The two mutating verbs are SUDO-gated (a brand is the visible chrome of the
  auth pages, a social-engineering surface); `GET` is not. The gate is measured on both verbs.
- **Every brand write is validated before it is stored, on BOTH doors into the table.**
  `tokens` and `tokens_dark` must fit the closed typed design-token grammar (hex-only colors, an
  allowlisted font enum, clamped numerics), never CSS; a `slots` key must be a known slot id
  within the per-slot size cap and its value passes the one allowlist sanitizer at ingest, so a
  stored slot is sanitizer output and an unknown key is a loud 400 rather than a silent drop;
  `client_id`, the per-client selection key, must parse as a real client id IN THIS SCOPE, since
  a foreign environment's id there is dead config no authorize request could ever match. The
  config-promotion PLAN and APPLY now run that same wall over their source document, which they
  previously bypassed entirely: snapshot validation checks only that a brand's `tokens` and
  `slots` are JSON objects, so a submitted document could store an unknown slot key, unsanitized
  markup and a CSS breakout in a color token. Refusing at plan time (a 400 naming every faulty
  brand at once) means an operator learns the document is unstorable before reviewing a plan
  built from it. A document that names two brands claiming one host, or two environment
  defaults, is refused for the same reason: the apply releases the other claimant, so a document
  with two could never converge.
- **WIRE ADDITION. `applyConfigPromotion` can answer 422 `brand_asset_bytes_unavailable`.** A
  snapshot carries a brand's logo and favicon by content reference (the sha256), never as inline
  bytes, so the apply materializes one only from bytes the target already holds under that exact
  digest. When it cannot, it changes NOTHING rather than leaving the target with metadata
  pointing at bytes it does not have; the body names the slug, kind and digest, and the remedy is
  to upload the asset here and re-plan. That remedy is now honest in every key order: the digests
  are resolved before any change is applied, so the refusal cannot be a false one aimed at an
  asset the operator already uploaded.

- The console `at+jwt` bridge's `typ == at+jwt` check is no longer bolted on after
  `verify` returns; it is part of the `VerificationPolicy` (issue #192), which cannot be
  built without naming the profile it accepts. Same rule, same RFC 9068 section 4, one
  fewer line a future edit can drop. The existing wrong-`typ` 401 vector is unchanged and
  still passes, which is what shows the enforcement moved rather than went away.

- CORRECTION to the diagnostics module doc and to `PolicyTraceView`, which said a secret is
  unrepresentable in the records these views serve (issue #423). The records' free-form
  string fields would carry one, so the views serve whatever the recorder put there. Both
  now separate what the PROJECTION guarantees (a field that does not exist cannot be served)
  from what it does not. The two hand-written redacting `Debug` impls in `views.rs`
  (`ManagementKeyCreated`, `InitialAccessTokenCreated`) promised in prose that a live
  credential can never reach a log line through `{value:?}` and had no test; they now
  have four, covering the masked and the absent case for each, so the promise is checked
  rather than asserted.
- **WIRE CHANGE. `impl From<StoreError> for ApiError` is now EXHAUSTIVE and no longer
  collapses every unmapped store refusal into an opaque 500** (issues #442, #449, #279).
  It mapped five variants explicitly and wildcarded the other seventeen, so a typed refusal
  the store already knew how to describe reached the caller as a server fault. FOURTEEN of
  those seventeen now answer a typed status; the other three (`Database`, `Migration`,
  `Encryption`) are genuine FAULTS and deliberately stay `500`, so the count of behaviour
  changes on the wire is fourteen and not seventeen. Exhaustiveness
  runs in two links and neither can be skipped: `StoreError::into_wire` classifies in the
  crate that defines the type, where the match can be exhaustive, so a new VARIANT fails the
  build there; and `StoreErrorWire` is not `#[non_exhaustive]`, so the match here is
  exhaustive too and a new CLASS fails the build here.
- **What changed on the wire, and what each newly mapped class reveals.** A uniqueness or
  state collision is now `409` rather than `500`; an Idempotency-Key RACE is `409` with a
  retry message rather than `500`, and is logged at WARN so the create path that skipped its
  replay stays visible; a malformed submitted value is `400`; a well-formed value a policy or
  structure refuses is `422`; and a typed environment-guardrail refusal is the `422` carrying
  the failed guardrail's stable code, the same shape this crate's own pre-check already emits
  for the same condition. Every one of these is reachable only by a caller already authorized
  for the scope, and every message is read from the store's `Display`, whose caller-facing
  arms are value free by construction: each names a DIMENSION or a structural fact, never an
  offending value or a resource id. Reading the message from there rather than restating it
  is what stops the log line and the caller's message from drifting apart.
- **The old wildcard's stated defense is kept and generalized rather than discarded.** It
  argued that "a handler that forgets its explicit arm degrades to the correct 422 instead of
  a server error"; every caller-facing class still has a central answer, so that remains
  true. What is gone is the SILENCE, which is the half that was doing the damage.
- **`tests/unsealed_environment.rs`: an ABSENT user in a live environment that has never
  sealed any PII is the uniform not-found on every user-scoped route** (issue #442). The
  subject list is derived from `docs/openapi/management.json`, so a new user-scoped route
  fails this file the moment it is documented rather than joining `external-id` as the one
  nobody drove against a fresh environment. The sealing-against-non-sealing differential
  inside it asserts the shared answer IS the `404`, not merely that the two verbs agree:
  agreement alone survives a total collapse of the not-found, which was measured by mapping
  the store's uniform not-found to an opaque 500 and watching the differential stay green.

- **The whole management surface is now driven against a LIVE environment by one sweep**
  (issue #441), `tests/live_surface.rs`. It enumerates every operation
  `docs/openapi/management.json` publishes, addresses each at a real seeded row with a real
  operator credential, and fails when any of them answers a server error. Its coverage is
  checked against the committed contract in both directions, so a new route fails it the
  moment it is documented and a case whose path drifts matches no template and fails too.
  The abuse-ban surface shipped completely dead because nothing drove it; this is the guard
  that makes that class of omission structurally hard to repeat.
- **`createBan`, `liftBan`, `listBans`, and `getMds3Health` answer** (issue #441). All four
  were refused by Postgres before any application logic ran, because the relations behind
  them carried no privilege for the role this plane connects as. Migration 0098 settles the
  privilege; this crate gains the tests that would have caught it: the ban round trip
  including the canonicalized subject and the sealed value read back, the cross-plane proof
  that a ban the operator places is the ban the login path refuses on, the audit sequence,
  the metadata health read across its three verdicts, and the two least-privilege refusals
  that pin what the control role must NOT be able to do.
- **The sibling absent-environment sweep no longer pins two routes at 500.** It carried
  `createBan` and `liftBan` as documented deadness so that the deadness could not quietly
  become something else, and that is how this change was noticed: the pins went red. They
  now carry the answers a live environment gives, and the sweep additionally refuses a
  server error at a live environment for every route it drives.

- **The role-to-permission attach response now carries a budget verdict** (issue #425, the
  #98 follow-up): `POST .../organizations/{org}/roles/{role}/permissions` answers 201 with
  `role_permission_budget` beside the mapping. Issue #98's acceptance criterion asked for an
  admin-time warning "before overflow occurs" and only the effective-roles READ satisfied it,
  which meant an operator learned they had crossed a threshold by separately reading the
  view of some membership that happened to hold the role. The write is where their attention
  is, and it is the only moment at which the actor, the correlation id and the intent are all
  present.
- **`PermissionBudgetView` now carries a REQUIRED `scope` discriminator**, `"role"` on the
  attach and `"membership"` on the effective-roles read, and that is a breaking addition to
  the published contract on purpose. The two verdicts were byte-shape identical, so the only
  thing separating an authoritative answer from a different question was the JSON KEY the
  object arrived under; an SDK, a console component or a log pipeline handed a bare
  `PermissionBudgetView` had lost the distinction irrecoverably. A discriminator inside the
  object travels with it and makes the two carriers non-interchangeable by construction.
  There is still exactly ONE `PermissionBudgetView::evaluate`, now taking the scope as a
  parameter, so a caller cannot produce a verdict without stating which set it counted.
- **The field is named for the set it measures, and the name plus the discriminator are the
  mitigation, not decoration.** The verdict is computed over THAT ROLE'S OWN live mappings,
  which is what the write transaction already addresses. The alternative, the resolved set of
  every affected membership, is the honest question but its blast radius is the whole
  effective member set of the role, direct and group-inherited through the recursive closure,
  so it is an unbounded fan-out read on a WRITE and issue #98 refused exactly that shape
  everywhere else.
- **CORRECTION, and the reason the paragraph above is worded the way it is.** An earlier
  draft of this entry, of the field docs, of `docs/openapi/management.json` and of
  `docs/config-schema.json` said one role's mappings were a LOWER BOUND on any membership's
  resolved set. That is FALSE. It is a DIFFERENT SET and bounds the membership figure in
  NEITHER direction, by three measured mechanisms:
  a soft-deleted PERMISSION is still counted by the role figure while the membership
  resolution filters it out (measured: attach 3 with `budget_exceeded`, membership 1 with no
  overflow); a DISABLED organization stays writable on this plane while the resolution
  closure seeds only on an active one (measured: attach 2 and overflowing, membership 0 with
  empty roles and permissions); and the figure is a SNAPSHOT taken at the write, so a
  concurrent DETACH leaves it LONG just as a concurrent attach leaves it short, and an
  Idempotency-Key REPLAY faithfully reproduces that snapshot by design (measured: a replay
  reporting 2 and `approaching` against a live count of 1). Every "at least that bad and
  possibly worse" and every "never the other way" is gone.
- The verdict is present on the attach 201 ONLY, absent (not null) on every item of the
  mapping list, because a verdict per listed row would be one count query per item and every
  row of one page would carry the same number. It is computed BEFORE the insert and reported
  as that count plus this attach, which is forced BY THE CURRENT `assign()` SIGNATURE rather
  than by anything intrinsic: that signature takes a PRE-SERIALIZED body as the
  Idempotency-Key REPLAY body, so the body has to be complete before the write and a 201
  would otherwise disagree with its own replay. `write_audited`'s closure already holds the
  transaction, so a store variant counting INSIDE the write would be snapshot exact and still
  land in the stored body; issue #430 tracks it, and records that it would close the
  concurrent window in both directions but NOT the replay staleness, which is inherent.
- **THE COVENANT IS UNCHANGED and is re-asserted past the maximum.** No count and no size
  turns the attach into a 4xx or a 5xx and nothing truncates anywhere.
  `the_management_plane_never_truncates_a_permission_set_past_the_budget` now drives four
  attaches through a maximum of 2 and a warn threshold of 1, inspecting every 201 body: the
  crossing of the WARN threshold is reported on the write that caused it (the criterion that
  had no surface before), the crossing of the MAXIMUM is a 201 naming the configured marker,
  the attach one FURTHER past the maximum is still a 201, and the mapping list plus the
  effective-roles view are still complete and un-truncated.
- Four coverage gaps of the first draft are closed on this plane.
  `the_attach_verdict_names_the_set_it_counted` pins the discriminator on BOTH surfaces at
  once, so an attach stamped `"membership"` and a verdict with no `scope` at all are each a
  red test. `a_detached_mapping_stops_being_counted_by_the_attach_verdict` drives a detach
  through HTTP and asserts the next attach counts the live set, so dropping the liveness
  filter is visible on this plane and not only in the store suite.
  `a_maximum_of_zero_is_over_on_the_very_first_attach` exercises the documented
  `permission_claim_max_count = 0` posture, where the first attach is already past the
  maximum and still a 201. And the round trip's field-for-field comparison now asserts the
  verdict through the same helper every other budget assertion uses.
- `PermissionBudgetView`'s SINGLE SOURCING is preserved and is measured over every overflow
  mode: `the_attach_the_read_and_the_configured_overflow_marker_are_one_string` asserts, for
  each of `PermissionOverflow::ALL`, that the attach 201's marker and the effective-roles
  read's marker are BOTH the configured
  `ironauth_config::PermissionOverflow::permissions_status` (which is what the MINT stamps on
  the token) and are each other. That is TWO surfaces compared against one source, not three
  independent readings: a closing assertion that the observed strings were as many as the
  modes has been DELETED, because it read those strings from `permissions_status` itself and
  therefore asserted the injectivity of the source and nothing about either surface, which is
  already `ironauth-config`'s own
  `the_overflow_mode_owns_the_two_wire_strings_both_planes_read`. A surface that hard-coded a
  single marker still dies, at the in-loop equality, which was measured. A coordinated swap
  of BOTH arms of `permissions_status` is invisible to this test by construction and is
  `ironauth-config`'s test to catch. Both management surfaces share the one
  `PermissionBudgetView::evaluate`, so the comparisons cannot drift either.
- The three doc sentences PR 13 corrected are corrected again, now that the 201 half is
  true: `AdminState::with_token_claims`, `[token_claims]`'s section doc in `ironauth-config`
  (regenerating `docs/config-schema.json`), and the test comment that pinned the absence.
  `docs/openapi/management.json` and `packages/admin-spa/src/api/management.gen.ts` are
  regenerated; `openapi-typescript` drops the description of a nullable `$ref` member, so
  `packages/admin-spa/src/api/client.ts` carries the scope statement where a console reader
  meets the type.

- **The per-client scope-allowlist management surface** (issue #98, PR 15): `GET` and `PUT`
  on `.../clients/{client_id}/allowed-scopes` (`getClientAllowedScopes`,
  `setClientAllowedScopes`), a static suffix under the client and a sibling of
  `.../signing-algorithm`. ENVIRONMENT level and taking no organization, because a `clients`
  row carries none, so `resolve_scope` plus the typed `ClientId` are the two layers and
  there is no cross-parent guard to forget. THREE addressing failures and not the usual
  four: `clients` has no soft delete, so a deleted client reads exactly like one that was
  never registered, and malformed / foreign / absent are one uniform 404 on BOTH verbs. The
  body refusal runs AFTER the address resolves, so a 400 is never visible for a client the
  caller cannot address.
- The PUT is sudo gated (`a_client_scope_allowlist_write_is_sudo_gated`); the GET is not,
  matching every other read on this surface. The write goes through
  `state.store().management()`, because migration 0096 grants the column-scoped UPDATE to
  the control role alone, so this endpoint needs none of `signing_algorithm`'s cross-role
  idempotency machinery. No `Idempotency-Key`: an absolute-value PUT addressed by an
  existing client is naturally idempotent.
- `allowed_scopes` is REQUIRED in the body and MAY be `null`, and the distinction is the
  whole shape of it. An ABSENT key is a 400 that names the field, because `{}` would
  otherwise be a legal request that did nothing and a caller could not tell it apart from
  one that was applied. A PRESENT `null` is the explicit clear. An empty array is a real,
  maximally restrictive value and is never collapsed into the clear. The published schema
  SAYS required (`#[schema(required = true)]`) rather than leaving utoipa to infer it. The
  field is `Option<Option<T>>` under the `named_field` seam and utoipa reads the outer
  `Option` as "optional field", so the generated document would have carried no `required`
  array and a generated client would have let a caller omit a key the server answers 400
  for. The two other bodies in this crate on that seam are genuinely optional, so the
  inferred shape is right for them and only this one contradicted its own server;
  `the_set_allowed_scopes_body_declares_its_required_field` pins it, because the drift is
  silent everywhere else.
- ONE well-formedness rule, and it is deliberately NOT charset validation: an entry that is
  empty or carries whitespace is a typed 400 naming it, because the matcher splits a REQUEST
  on whitespace so such an entry could never match and would be silently dead configuration.
  Nothing else about a scope token is policed; `read:orders`, `urn:x:y`, `*`, and non-ASCII
  all pass, which a test asserts alongside the refusals so a reader can see that no
  character class is being narrowed.
- The read reports what is IN FORCE, never a repaired value: a stored value the server could
  not parse reads as `[]` (the store's fail-safe parse), and the GET answers `[]`. Answering
  `null` would tell an operator their client is unrestricted while every one of its SCOPED
  machine tokens is refused, which is the most misleading answer available. A request
  carrying no `scope` still mints, since `scope` is optional.
- Console: a "Machine grant scope allowlist" panel on the clients surface, one scope token
  per line (the only editor shape that can express the empty list distinctly from a single
  blank token), with SEPARATE "Set allowlist" and confirm-gated "Clear the allowlist"
  buttons rather than one that guesses, because `[]` and `null` are one keystroke apart and
  mean opposite things. Its vitest suite drives both bodies.

- The effective-roles view gains `permissions` and `permission_budget` (issue #98, PR 13),
  as a pure addition under the object wrapper issue #97 shipped for exactly this. The
  permission set is the WHOLE resolved set, un-paginated and un-truncated, read through the
  same repository, key and depth bound the mint uses, so the console and the token cannot
  answer differently for one membership. `permission_budget` is ADVISORY: it refuses
  nothing, and no endpoint anywhere in issue #98 answers 4xx or 5xx for a count or a size
  reason. It evaluates the ELEMENT half of the budget only, and says so in the schema: an
  exact compact-token byte size needs the environment's signing key and the whole rest of
  the exchange, so an estimate here would be a lie in exactly the direction that matters.
  The byte VERDICT belongs to the mint, which measures. Two properties the view's own docs
  rest on are now measured rather than argued. The element comparisons are STRICTLY
  greater-than, the same way the mint's are, which matters only at the boundary and is
  driven there by `a_count_exactly_at_the_warn_threshold_is_not_yet_approaching` (at the
  threshold nothing is approaching, one past it something is); an off-by-one here is the
  worst possible place for the console and the token to disagree, and every other fixture
  in the suite sits clear of a threshold. And the depth bound really is the CONFIGURED one
  on both planes, which is what the claim that the console and the token cannot answer
  differently rests on: `the_effective_roles_view_resolves_permissions_through_the_full_ancestor_walk`
  resolves a capability inherited two group levels up, beside `ironauth-oidc`'s
  `the_configured_group_depth_is_the_bound_the_permission_resolution_uses` on the mint.
- CORRECTION to a sentence that shipped with PR 9 and was never true: the budget's
  management-plane statuses were described as "200 and 201 carrying a warning field". The
  200 half is right (the effective-roles read carries `permission_budget`); the 201 half is
  not, because the role-to-permission attach returns `OrgRolePermissionView`, which has no
  budget field. The covenant is intact either way (the budget produces no 4xx and no 5xx
  anywhere on this plane), so this is a missing surface and not a defect: the sentence is
  corrected on `AdminState::with_token_claims` and in `[token_claims]`'s own section doc
  (regenerating `docs/CONFIG.md` and `docs/config-schema.json`), and the attach 201's lack of
  a budget field was ASSERTED so a later change had to say so. Issue #425, in this same
  unreleased section, is that later change: the attach now carries
  `role_permission_budget` and those sentences are corrected a second time. Read the two
  entries together; neither describes a released state on its own.

- Two new operational warning kinds, `permission_budget_overflow` and
  `permission_budget_approaching`, on `GET .../diagnostics/warnings` (issue #98, PR 12),
  read out of the SAME `token_size_events` sink the `token_size` kind already reads and
  aggregated the same way. NO schema change and NO console change were needed:
  `WarningItemView.kind` is a string, not an enum, and the admin console groups warnings by
  kind generically. The `subject` is the `(organization, audience)` pair rendered as a
  composite string (the organization id, one space, the audience) rather than a client id,
  because a permission set is resolved per (organization, subject), so one client can hit
  the budget for one organization and be fine everywhere else and a client id alone leaves
  an operator unable to act. The audience half is APPENDED only when the verdict names one:
  the budget produces one verdict per TOKEN and a token may target several resource servers,
  in which case the subject is the organization alone rather than a fabricated placeholder.
  Splitting the composite at the first space is unambiguous because the ORGANIZATION half is
  an `org_` prefix over a URL-safe base64 payload, an alphabet with no space; nothing
  validates the audience's shape and nothing needs to, because it is the remainder.
  Aggregation happens at READ time, matching the sink beside it rather than the quota
  engine's in-memory latch, because the mint path is multi process and a per-replica latch
  would UNDER report. Read-time aggregation does NOT abolish under reporting, and the read
  no longer claims it does: each family is read through its OWN clamped window
  (`recent_by_kind`) so neither can evict the other, and a FULL window renders every count
  as "at least N" rather than as a figure, because rendering the clamp as an exact number is
  an under report presented as precision. A row whose `reason` this build cannot parse is
  skipped, which is the right answer for both cases that produce one (an access-token row
  with no reason, and a row written by a newer build mid rolling upgrade), and that skip is
  now measured at the READ and not only at the enum. An overflow detail says WHICH bound was
  crossed (the permission count budget, the token byte budget, or both), because the
  remediations differ. BEHAVIOUR CORRECTION to the existing `token_size` kind: it now reads
  the `id_token` window only. Its detail claims to count oversized ID tokens, and once
  access-token budget events share the sink, counting those would make that claim false;
  every row the sink held before issue #98 is an `id_token` row, so nothing that shipped
  changes. The OpenAPI descriptions for the warning kind, the subject, and the item ordering
  were updated to match (and the item order is now pinned by a test rather than only
  promised), so `docs/openapi/management.json` and the generated
  `packages/admin-spa/src/api/management.gen.ts` are regenerated. The console's warnings
  panel hint, which still described only connector health and token sizes, now names the
  budget verdicts.

- Resource-server registry management API (issue #98, PR 11), a NET-NEW surface: the
  audience-to-format registry issue #29 shipped has never had a management route.
  `GET .../resource-servers` (`listResourceServers`, cursor paginated), `GET
  .../resource-servers/{resource_server_id}` (`getResourceServer`), and `PATCH` on the
  same path (`updateResourceServerPermissionClaims`). Addressed by `rsv_` id and never
  by audience, because an audience is an absolute URI containing `:` and `/` and cannot
  be a path segment; the list exists so a console can resolve an audience to its id.
  ENVIRONMENT level and not per organization, because `resource_servers` carries no
  `organization_id`, so the row-level-security policy is the table's complete fence.
  The PATCH is narrow by design and writes exactly `permission_claims_enabled`; full
  resource-server CRUD is out of scope for this issue, and a body that NAMES
  `token_format`, `audience`, or `access_token_ttl_secs` is a typed 400 saying which
  field and why rather than a 200 that dropped it (presence, so `null` is refused like a
  value; genuinely unknown keys are still ignored as everywhere else). Permission claims
  are an `at+jwt`-ONLY feature, so the PATCH REFUSES enabling the opt-in on a resource
  server whose `token_format` is anything other than `at_jwt` with a typed 422 naming the
  reason (an opaque access token carries no claims, so the setting could only be silently
  dropped at mint time); clearing the flag on an opaque resource server stays allowed,
  because a config promotion can land that combination with no handler in the path and a
  refusal would trap the row there. The refusal is reachable only AFTER the row resolves
  in this scope, so it is not a token-format oracle. Sudo gated like every management
  mutation; every addressing failure is one byte-identical `not_found`. The OpenAPI
  op-id/path/count contract and `docs/openapi/management.json` are updated accordingly
  (138 -> 141 routes), along with `packages/admin-spa/src/api/management.gen.ts` and a
  new `docs/THREAT-MODEL.md` section.

- Per-connector health-diagnostics read for issue #76:
  `GET .../connectors/{connector_id}/health` (`getConnectorHealth`, operator-gated,
  secret-free) returns THIS node's live federation health for a connector (state, recent
  upstream error rate, consecutive failures, last success / failure, and the backoff retry
  instant). It reads the SAME in-memory `FederationRuntime` health registry the OIDC data
  plane records into (shared as one `Arc` by the boot path via `AdminState::with_federation`);
  a connector that exists but has never been exercised on this node reports `state = "unknown"`,
  and an absent id is a uniform not-found. The OpenAPI op-id/path/count contract and
  `docs/openapi/management.json` are updated accordingly (68 -> 69 routes).
  - Review hardening (issue #76): the read is now FINGERPRINT-aware. It passes the connector's
    current definition version (its store-row `updated_at` micros) to the health snapshot, so a
    record left by a PRIOR definition reads as never-exercised (`state = "unknown"`) rather than
    reporting a stale `config_error` after a reconfiguration until the next login.
- Waitlist approval via the existing user-lifecycle management API (issue #80): the
  `UserStateView` wire enum gains a `waitlisted` variant (round-tripping the new
  `UserState::Waitlisted`), so a waitlisted self-service signup is listable and filterable,
  and an admin APPROVES it by transitioning it to `active` (or REJECTS it to `disabled`)
  through the existing `setUserState` operation; no new endpoint is added, so the OpenAPI
  operation-id/path/count contract is unchanged (only the served schema regenerates).
- Declarative federation connector management (issue #75, PR A): CRUD plus a
  capability-matrix read endpoint on the management API. `POST .../connectors` parses
  the body with the strict, I/O-free `ironauth-connector` layer (`deny_unknown_fields`
  plus the semantic validator) and REJECTS an unknown key or a semantic fault with a 400
  carrying its RFC 6901 JSON POINTER; a valid definition seals the upstream client
  secret and writes the capability matrix. `GET .../connectors` (cursor paginated),
  `GET .../connectors/{id}`, `GET .../connectors/{id}/capabilities`,
  `PUT .../connectors/{id}`, and `DELETE .../connectors/{id}` round out the surface.
  Every response is SECRET-FREE: the sealed upstream secret is never returned, and a
  new connector's `email_verified_trust` reads back `untrusted`. Six routes and their
  schemas are added to the OpenAPI spec, the served router, and the hardcoded contract
  test (op-id set, path set, and the served-route count 62 -> 68).
  - Review fix (MEDIUM 1): `PUT .../connectors/{id}` now REJECTS a slug change with a
    409 (the `connector_id` in the body must equal the stored `connector_slug`, the
    immutable natural key the sealed-secret AAD anchors on), before any mutation, so the
    stored slug and the definition can never diverge. The error names no secret value.
  - Review fix (LOW 4): create and update now honor the definition's `enabled` flag
    (default `true` on create; an update honors the submitted value), so an operator can
    disable a connector without deleting it, instead of the previously hardcoded `true`.
    An integration test covers the slug-change rejection and the enabled round-trip.
- Admin session privilege separation (sudo mode), EXPLORATORY and off by default (issue
  #73). Behind the new per-environment `admin.sudo_mode_enabled` flag, admin READS are
  unaffected but an environment-scoped MUTATION requires a RECENT re-authentication: the
  acting credential must have a server-recorded elevation whose freshness window
  (`admin.sudo_mode_window_secs`, default 10 minutes) has not lapsed, evaluated by the
  reused step-up `privilege_is_fresh` seam. A mutation without a fresh elevation returns a
  structured RFC 9470 `insufficient_user_authentication` challenge (a 401 carrying `max_age`
  in the body and the `WWW-Authenticate` header) and executes nothing. A new
  `POST .../admin/sudo/elevate` endpoint records a fresh elevation, server-side, from the
  clock seam and audits it (`admin.privilege.elevated`); a refused mutation audits
  `admin.privilege.challenged`. The gate covers ALL environment-scoped audited mutators:
  users, sessions, management keys, organizations, bans, invitations (create / revoke /
  resend), DCR policy and initial-access-token creation, environment deletion, and the
  config-promotion APPLY flagship (the most powerful environment-scoped write). It is
  placed immediately after scope resolution and before any idempotency replay or write, so
  a challenge never leaves a partial write. The tenant-plane operator operations (tenant
  create / delete / suspend / resume / restore, environment create) and the promotion PLAN
  dry-run are outside the environment-scoped prototype and are intentionally not gated. The
  enforced guarantee is that the elevation is SERVER-RECORDED and never CLIENT-ASSERTED: it
  derives only from the recorded event, never from any client-supplied header or flag, so a
  forged header cannot elevate (tested with a forged-header adversarial case). When the flag
  is off the surface behaves exactly as before and the elevate endpoint is a uniform
  not-found. The freshness seam is factored so end-user apps can adopt the same mechanism
  later without rework. HONESTY CAVEAT: the admin plane authenticates via a single
  non-interactive bearer credential with no second factor, so sudo mode does NOT yet defeat
  a fully-stolen admin bearer, which can call the elevate endpoint itself and then mutate;
  it bounds a header-forgery or replay path, not a stolen bearer. Binding the elevation to a
  DISTINCT interactive re-auth factor (an operator passkey) is a documented graduation step;
  end-user application sessions, which have that factor split, get the full guarantee
  through the same seam.
- OpenAPI contract sync for the MDS3 health route (issue #66 PR B, adversarial review):
  the hardcoded `openapi_contract` assertions now include `getMds3Health` and its
  `GET .../webauthn/mds3/health` path and pin the served-route count at 61, matching the
  regenerated `docs/openapi/management.json` (the route landed in sync but the contract
  assertions had not been updated, a CI-red gap).
- FIDO MDS3 cache health + attestation export coverage (issue #66 PR B): a new
  environment-scoped read `GET .../webauthn/mds3/health` surfaces the cached MDS3 BLOB
  sequence number, verify time, `nextUpdate`, entry count, and a fresh/stale/missing
  verdict against the `env.clock()` instant (revocation is deferred for v1, so this is
  the operator's freshness signal). The three new reg-time-immutable
  `webauthn_credentials` attestation columns are documented as non-portable operational
  device state in the #58 export field-coverage.
- Credential-abuse ban management (issue #64): new environment-scoped endpoints
  `POST`/`GET /v1/tenants/{tenant}/environments/{environment}/abuse/bans` and
  `POST .../abuse/bans/lift` to place, list, and lift durable credential-abuse bans, the
  management-plane parity for the CLI ban commands. Each writes through the SAME audited
  store repository; an identifier subject is canonicalized through the login seam so an
  admin ban matches the form the request path checks, and a listed subject is opened from
  its envelope seal. OpenAPI spec and the committed artifact regenerated.
- Exit-export of the TOTP second factor now round-trips for REAL (issue #69/#58,
  review, HIGH). The prior mapping opened the seed under the DEK and then DROPPED it
  before serialization (`export_record_to_import` read only `account_credentials`), so
  a re-import yielded a metadata echo: the factor did not verify. `export_record_to_import`
  now emits the user's `totp` (opened seed, parameters, status, single-use step) and
  `recovery_codes` (one-way hashes) into the import record, and the tests assert on the
  EMITTED bytes plus a full API round-trip: a user with an active TOTP factor exports,
  imports into a fresh scope, and afterward a code from the ORIGINAL seed verifies
  against the re-imported factor and an original recovery code redeems once. The
  field-coverage guard classifies the new `recovery_codes.code_bidx` column.

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
    a soft deactivation that is idempotent and RETAINS the row, so the audit row
    naming it keeps a resolvable target. For tenants and environments `audit_log`
    really does carry a foreign key to the retained row; for a management key it
    does not, and the retention is an application rule.
