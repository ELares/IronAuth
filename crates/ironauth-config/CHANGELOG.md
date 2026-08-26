# ironauth-config changelog

All notable changes to the `ironauth-config` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- **The `wasm-hooks` experimental feature (issue #114 criterion 7).** Off by default and
  acknowledgment-gated. The reason is the ABI rather than the runtime: the sandbox is
  adversarially tested and the latency is benchmarked and gated, but a hook is a compiled
  artifact built against a WIT interface, and issue #114's differentiator is a version-stable
  one. Promising decade stability for an interface with one implementation and no external users
  is a promise made before the evidence.

- **New section `[flow_targets]`** (issue #112 criterion 2), with two settings and a new
  public const. `flow_targets.delivery_enabled` (default `false`) gates whether THIS process
  drains the `flow_target.delivery` queue and POSTs to registered async targets, matching the
  covenant every other background worker here is held to: no mandatory background
  infrastructure. `flow_targets.delivery_timeout_secs` (default `10`) is the per-delivery HTTP
  budget, bounded at least 1 and at most `FLOW_TARGET_MAX_DELIVERY_TIMEOUT_SECS` (300, an
  alias of the webhook ceiling so both outbound consumers answer to one bound).

  Two new `ConfigError::Invalid` refusals, and the split between them is deliberate. The
  BOUNDS are checked unconditionally, because a zero budget is meaningless even while no
  worker reads it: `Duration::from_secs(0)` times out before it connects, so every delivery
  would exhaust its attempts without one POST reaching a receiver. The LEASE rule
  (`delivery_timeout_secs` must be strictly less than `outbox.visibility_timeout_secs`) is
  gated on `delivery_enabled`, because the two numbers are inert where no worker runs and
  refusing a boot over an inert pair would make a deployment that drains nothing unbootable.

- **New setting `oidc.client_jwks_ttl_secs`** (default `300`, bounded 1 to
  `OIDC_MAX_CLIENT_JWKS_TTL_SECS` = 3600, a new public const; a new
  `ConfigError::Invalid` naming the setting). How long a CLIENT's fetched `jwks_uri` key set
  is cached, on all three surfaces that resolve one: `private_key_jwt` client
  authentication, the `urn:ietf:params:oauth:grant-type:jwt-bearer` assertion grant, and
  `jwks_uri` dynamic client registration.

  BOTH bounds exist for their own reason, and both are tested. Zero would make every request
  refetch, which is the outbound-request amplifier the resolver's per-URI rate limit exists
  to prevent, reached through configuration instead of through an attacker. Above the
  ceiling, a key the client has ROTATED OUT stays trusted for longer than the rotation was
  meant to take. The ceiling's VALUE is asserted too, not only the bounds relative to it: the
  doc comment and `docs/CONFIG.md` hand-write "at most 3600", and the resolver's fail-closed
  argument for a marker-only cache entry rests on the TTL being unable to grow without limit.

  WHAT IT DOES NOT GOVERN: on the assertion grant a rotated-IN key is picked up without
  waiting, because an assertion naming an unknown `kid` triggers a refetch. `private_key_jwt`
  resolves with no kid hint, so on THAT surface this value is the whole rotation window.
  That sentence is in the setting's FIRST doc paragraph deliberately, because
  `scripts/config-schema.sh` renders only the first paragraph into `docs/CONFIG.md` and an
  operator tuning the setting reads the rendered row, not the source.

  `Config::validate` also lost its client-credential bounds to a new
  `validate_client_credential_bounds`, which is a refactor with no behaviour change: the
  function had grown past its line bound, and the skew bound and this one are the same
  question asked twice (how long a client credential this provider did not mint stays
  acceptable).

- **Five `[outbox]` retention knobs, two of which read the OPPOSITE way to
  `diagnostics.retention_secs` (issue #104, PR 3).** `outbox_messages` had no retention at
  all, so these are the settings of the reaper that gives it one.

  - `outbox.reap_enabled` (default `true`) is the only switch in THIS section the sweeper
    answers to, and it is not gated on `oidc.backchannel_logout_enabled`, because that
    switch gates ONE consumer of a generic queue and the next consumer will run behind a
    different one. Two other things stop a sweeper and neither is a setting: a missing
    control-plane DSN (the default deployment; logged at error) and a deployment whose
    consumers never run, where only a consumer makes a message reapable. See
    `docs/design/RETENTION.md`.
  - `outbox.completed_retention_secs` (default seven days) has a FLOOR of one hour
    (`OUTBOX_MIN_COMPLETED_RETENTION_SECS`), where `diagnostics.retention_secs` deliberately
    has none, and the floor stands for `max(evidence window, longest producer re-enqueue
    horizon)`. A completed outbox row is the only evidence that a message was DELIVERED, so
    a window shorter than an operator's reaction time makes a lost delivery permanently
    unanswerable; and it also holds the row's slot in the outbox's idempotency-key unique
    index, so reaping it early would let a producer still inside its retry window enqueue
    the same work a second time. OPERATOR OBLIGATION: raising `max_attempts`,
    `retry_base_secs` or `visibility_timeout_secs` lengthens the second term and this window
    must stay above it (documented rather than cross-validated, because the exact horizon
    would need the store's backoff schedule copied into this crate). The default and the
    ninety day ceiling are `DIAGNOSTICS_DEFAULT_RETENTION_SECS` and
    `DIAGNOSTICS_MAX_RETENTION_SECS`, so the tree has one answer to how long an operational
    record is kept.
  - `outbox.dead_letter_retention_secs` (default `0`) means NEVER REAP, not "reap
    immediately". This is the exact inversion of `diagnostics.retention_secs`, where `0`
    prunes everything on the next insert. A dead letter is work given up on, and for the
    back-channel logout fan-out it can be an entire session's relying parties left
    un-notified with nothing else recording that it happened.
  - `outbox.reap_batch` (default 1000, ceiling `OUTBOX_MAX_REAP_BATCH`) is a HARD bound per
    pass, not a chunk size to loop over: an unbounded delete across an accumulated backlog
    stalls a replica. In arithmetic, the default at the default cadence removes at most
    `1000 * (604800 / 3600) = 168,000` rows a week per (scope, consumer) per tail, which is
    about 33,600 ended sessions a week at five relying parties each. Past that, passes report
    SATURATED and the batch or the interval has to move.
  - `outbox.reap_interval_secs` (default one hour) is the sweep cadence.

  Retention is not latency-sensitive, so nothing waits on these; what they trade is
  database load against how far the table runs ahead of the window.

- **BREAKING: three `oidc` back-channel logout keys are REMOVED rather than deprecated
  (issue #104, PR 2).** `oidc.backchannel_logout_max_attempts`,
  `oidc.backchannel_logout_retry_base_secs` and `oidc.backchannel_logout_poll_interval_secs`
  are gone. Back-channel logout delivery is now a consumer on the generic outbox, so those
  three are `outbox.max_attempts`, `outbox.retry_base_secs` and `outbox.poll_interval_secs`,
  which every consumer shares. They are removed rather than deprecated because a duplicate
  knob that no longer reaches anything is worse than an absent one: it agrees with the
  section that DOES reach the worker only until an operator tunes either side, and then it
  silently describes a schedule nothing runs. Their defaults and the `[outbox]` defaults
  are identical today (5 attempts, a 10 second base, a 5 second poll), so a deployment that
  never tuned them keeps exactly the behaviour it had.

  `oidc.backchannel_logout_enabled` STAYS: it is the posture switch, not a tuning knob.
  `oidc.backchannel_logout_request_timeout_secs` STAYS: it is an ironauth-fetch budget on a
  single outbound request and has no equivalent in `[outbox]`.

- **`Config::validate` now refuses a logout HTTP budget its outbox lease cannot cover
  (issue #104, PR 2).** With `oidc.backchannel_logout_enabled` on,
  `oidc.backchannel_logout_request_timeout_secs` must be strictly LESS than
  `outbox.visibility_timeout_secs`.

  This check exists because the collapse above removed the thing that used to make the
  disagreement impossible. Before #104 the worker DERIVED its visibility lease from the
  request timeout, so raising one raised the other. The lease is now
  `outbox.visibility_timeout_secs` and the two numbers are independent, so an operator who
  raises the request timeout to accommodate a slow relying party, and does not know to
  raise the lease with it, gets a handler that outruns its lease on EVERY slow delivery:
  the message is re-claimed while the first POST is still in flight, the RP is POSTed
  twice, and nothing anywhere reports it. The comparison is `>=` and not `>` because
  equality is already too late, and it is gated on the SAME predicate the boot path spawns
  the pools under, `oidc.enabled && oidc.backchannel_logout_enabled`, because a deployment
  running no such handler must not be refused a boot over an inert number. Gating it on the
  posture switch alone (which is what the first cut did) refused exactly the boot that
  reasoning says to allow: with the OIDC provider off, `backchannel_worker_inputs` returns
  `None` and no pool is ever built. It fails CLOSED either way, so the defect was a wrong
  refusal rather than a missed one, but a check whose predicate does not match its stated
  rationale is one somebody later widens in the wrong direction.

- **`oidc.backchannel_logout_enabled`'s documentation said something FALSE about the default
  build (issue #104, PR 2, review fold).** It read "the default build enqueues nothing and
  sends nothing". The second half is true; the first is not, and the correction is in the
  generated `docs/CONFIG.md` because it is regenerated from this doc comment. Ending an SSO
  session enqueues one durable `session_ended` message inside the revoking transaction
  whatever this switch is set to, because `session_ended` is a DOMAIN EVENT and back-channel
  logout is one consumer of it; the switch gates the consumers, not the producer. With the
  switch off nothing consumes those messages, so they accumulate in `outbox_messages` and
  turning the switch on later begins by draining the backlog.

  The accumulation itself is deliberately NOT changed here, and the reasoning is worth
  recording rather than leaving as a silent choice. Gating the producer on this switch would
  make an OIDC-specific posture flag decide whether a domain event is recorded at all, which
  is the wrong layer: the store crate has no view of configuration, the enqueue is inside the
  session-revoke transaction on the hot path of every logout, and any FUTURE consumer of
  `session_ended` (a SIEM sink, an audit export) would silently receive nothing on a
  deployment that happens to have back-channel logout off. The general answer is retention
  for `outbox_messages` as a whole, which no consumer has today either (nothing prunes
  COMPLETED messages, so every consumer accumulates); that is a substrate-level decision
  about the whole table rather than something to decide inside a logout change.

- **BREAKING, and the four keys are removed rather than deprecated (issue #250).**
  `admin.outbound_verification_enabled`, `admin.outbound_verification_token`,
  `admin.outbound_verification_tenant`, and `admin.outbound_verification_environment` are
  GONE. The outbound lazy-migration credential-verification endpoint's enablement and its
  shared bearer now live in the addressed environment's own sealed per-environment secret
  (issue #45), so each environment carries an independent, rotatable credential instead of
  one deployment-global value with a single authorized scope. There is deliberately no
  fallback to the old keys: keeping one would mean "environment-scoped config" was still not
  literally true, which is the entire point of the issue.

  **OPERATOR OBLIGATION.** If your config carries any of the four keys, IronAuth will REFUSE
  TO START and name the key: `AdminConfig` is `deny_unknown_fields`, so their removal is a
  loud load failure, not a silent one. That is the deliberate choice. All four defaulted to
  `false` or unset, so a deployment that never enabled the feature is unaffected and has
  nothing to do. Assume more of them did than you would guess, though: the SHIPPED exit guide
  (`docs/exit-guide.md`) carried a worked example that set `outbound_verification_enabled =
  true` along with the other three keys, so any deployment that followed the documentation to
  turn the feature on is carrying all four. A deployment that DID enable it must, in this
  order:

    1. delete the four keys from its config, so the process starts;
    2. re-arm each environment that was using the feature, through the management API:
       `PUT /v1/tenants/{tenant}/environments/{environment}/migration/outbound-verification`
       with `{"token": "<the same or a new token>"}`. The token must be at least 32 bytes.

  Between those two steps the endpoint answers its uniform not-found, which is the same
  answer it gives when disabled, so the failure direction is CLOSED: an in-flight outbound
  migration pauses and resumes, and no request is ever verified against a token nobody
  configured. Nothing is backfilled automatically, and it deliberately is not: the old value
  is a deployment-wide secret and the new one is per environment, so a backfill would have to
  guess which environments should receive a copy of a credential a third party holds.

- `[outbox]` (issue #104): the tuning of the shared transactional outbox and job queue every
  async path dispatches through, as a top-level section rather than knobs rediscovered under
  each subsystem. `worker_concurrency`, `visibility_timeout_secs`, `poll_interval_secs`,
  `claim_batch`, `max_attempts`, and `retry_base_secs`, each with a safe default and each
  range-checked at load. Two defaults are choices rather than roundings: the worker count
  defaults to 2, because a default of 1 would ship the mandatory-singleton posture this
  substrate exists to avoid and leave "we are not a singleton" a property nobody exercises;
  and `max_attempts` has no unlimited value, because a message that can never reach a
  terminal state wedges its whole ordering group forever. There is no mode selection here and
  no mention of a durable message bus: the Postgres queue is the only implementation that
  exists, and a knob whose value does nothing is worse than an absent knob. The six defaults
  are pinned against `ironauth_store`'s `WorkerSettings::default()` by a cross-crate test, so
  the two declarations of the same numbers cannot drift; the store cannot depend on this
  crate, so without that pin nothing would notice.

  Two of the settings are documented against the substrate's real behaviour rather than the
  behaviour a batch queue usually has, because the store side re-stamps each message's lease
  before handing it to a handler: `visibility_timeout_secs` must exceed ONE handler call, not
  `claim_batch` of them, and `claim_batch` is therefore a memory and wasted-lease knob rather
  than a divisor of the timeout.

  **Operator note for a deployment with `oidc.backchannel_logout_enabled` set.** Migration
  0099 does not move the rows already in `session_ended_events`, and the new queue-depth
  metrics do not count them, so an undelivered tail there is invisible after the upgrade. A
  default deployment is unaffected (the only consumer of that table is off by default). With
  back-channel logout ON, before retiring the LAST replica running the previous binary, run
  `SELECT count(*) FROM session_ended_events WHERE delivered_at IS NULL;` and require it to
  reach 0. A rolling upgrade alone does not achieve this: new replicas already write the new
  table while old ones drain the old one.

- `oidc.id_token_ttl_secs` (issue #192): the ID-token lifetime, split out of
  `oidc.access_token_ttl_secs`, which it used to silently inherit. Defaults to 300, the
  value the ID token effectively had, and is range-checked exactly like the other OIDC
  lifetimes.

- New `Warning::IdTokenOutlivesAccessToken`, raised when `oidc.id_token_ttl_secs` is
  longer than `oidc.access_token_ttl_secs` (issue #192). A flat 300 default for the ID
  token means it no longer follows the access token DOWN, so a deployment that lowers
  the access TTL as a hardening measure and leaves the ID token alone has lengthened the
  front-channel token by editing a different key. Advisory, like every other warning:
  a longer receipt than credential is a legitimate posture, just rarely the intended one.
  It cannot fire at the shipped defaults, which are equal.

- CORRECTION to `DiagnosticVerbosity`'s doc, which attributed a structural redaction
  guarantee to the diagnostic record types that they do not have (issue #423). The true and
  useful half is unchanged and now stands on its own: no verbosity setting ADDS a field, so
  no setting makes an assertion body, a secret, or a token value representable.
- CORRECTION to `[token_claims]`'s section doc, which said the management plane's verdict
  rides the effective-roles read alone and that the attach carried no budget field (issue
  #425 has since added it). The section now names BOTH surfaces and, more importantly, the
  two DIFFERENT sets they measure: the read's `permission_budget` is over one membership's
  whole RESOLVED set and is what predicts the next token, while the attach's
  `role_permission_budget` is over that role's own mappings. It states that the second is
  NEITHER an upper NOR a lower bound on the first, and names why: a soft-deleted permission
  is still counted by the role figure and resolves for nobody, a disabled organization stays
  writable while resolving nothing, and the figure is a snapshot taken at the write that a
  concurrent change can outdate in either direction and an idempotent replay reproduces
  unchanged. An intermediate version of this section claimed a LOWER BOUND and was wrong.
  Regenerates `docs/config-schema.json`. The covenant sentence around it is unchanged and
  still true: no management endpoint answers 4xx or 5xx for a count or a size reason.

- The `[token_claims]` budget keys are LIVE (issue #98, PR 13): the mint reads them on every
  `at+jwt` access token that carries a resolved permission set, and the management plane
  reports the same verdict against them. Issue #413 is DISCHARGED; the six
  "NOTHING CONSULTS THESE KEYS YET" paragraphs the section shipped with are deleted and
  `docs/CONFIG.md` plus `docs/config-schema.json` are regenerated.
- `PermissionOverflow::permissions_status` returns the `permissions_status` claim value a
  withholding under each mode puts on the wire. It exists so the two strings are spelled in
  ONE place across both planes: the data plane stamps the value into the access token and
  the management plane reports which value the next token will carry, and two independent
  `match` arms in two crates would be two chances to drift. Single-sourcing is the whole
  justification, so it is now pinned HERE, in the crate that owns the strings, rather than
  only through the two crates that delegate:
  `the_overflow_mode_owns_the_two_wire_strings_both_planes_read` fixes both values and
  additionally requires the markers to be DISTINCT per mode, because a mapping that
  collapsed two modes onto one string would leave a resource server unable to tell
  "authorize from roles" from "consult the policy decision point".
- `PermissionOverflow::ALL` and `DiagnosticVerbosity::ALL`: the single definition of "every
  variant" for each closed enum, so a caller that must cover them all iterates the enum's
  own list instead of writing a literal in another crate. Two crates were doing exactly
  that, and the comments above both literals claimed a compile-time exhaustiveness the
  arrangement did not have: a total `match` beside a hand-written array is satisfied by
  adding an arm, leaving the array one variant short and the loop quietly narrower. The
  completeness of these two arrays is now a MEASUREMENT rather than a convention.
  `the_overflow_mode_list_holds_every_variant_the_schema_declares` and its verbosity twin
  compare each array against the variant list `schemars` DERIVES from the enum itself, which
  is an independent witness: the derive macro sees the real variant list and a hand-written
  expectation does not. Adding a variant without extending `ALL` turns those tests red, and
  extending `ALL` then breaks the total `match` in `ironauth-oidc` that gives each variant a
  slot, so both halves have to be dealt with before anything builds and passes.

- Token claim budget for issue #98: the new top-level `[token_claims]` section
  (`TokenClaimsConfig`) with `token_claims.access_token_max_bytes` (default
  `TOKEN_CLAIMS_DEFAULT_ACCESS_TOKEN_MAX_BYTES` = 4096, refused above the
  `TOKEN_CLAIMS_ACCESS_TOKEN_MAX_BYTES_CEILING` = 32768 ceiling at load),
  `token_claims.access_token_warn_bytes` (default
  `TOKEN_CLAIMS_DEFAULT_ACCESS_TOKEN_WARN_BYTES` = 3072, deliberately the same number
  the shipped ID-token growth signal uses, refused above `access_token_max_bytes`),
  `token_claims.permission_claim_max_count` (default
  `TOKEN_CLAIMS_DEFAULT_PERMISSION_CLAIM_MAX_COUNT` = 256, refused above the
  `TOKEN_CLAIMS_PERMISSION_CLAIM_MAX_COUNT_CEILING` = 4096 ceiling at load),
  `token_claims.permission_claim_warn_count` (default
  `TOKEN_CLAIMS_DEFAULT_PERMISSION_CLAIM_WARN_COUNT` = 192, refused above
  `permission_claim_max_count`), and `token_claims.permission_claim_overflow` (a closed
  `PermissionOverflow` enum of exactly `roles_only` (the default) and `pdp_required`).
  THE BUDGET IS A SIZE BOUND ON A TOKEN, never a cap on how many permissions or roles
  may be STORED: every key is named for the CLAIM it bounds rather than for the model,
  so `permission_claim_max_count` bounds what one claim carries, there is no
  `max_permissions_per_role` and there never will be, and no count column, quota row, or
  count CHECK exists anywhere for permissions, roles, or their mappings. `PermissionOverflow`
  has no `truncate` variant and will not get one: a partial permission set is
  indistinguishable to a resource server from a complete one, so its having exactly two
  variants is what makes truncation UNCONFIGURABLE. It does not by itself make a truncating
  emitter unwritable, and the enum's doc now says where that boundary falls.
  `0` is valid on every numeric key and means the STRICTEST posture (no NON-EMPTY
  permission claim is ever emitted), never unlimited; none of them has an unlimited
  value. Setting a
  MAXIMUM to `0` requires setting its sibling threshold to `0` in the same edit, because
  the shipped threshold default would otherwise exceed the lowered maximum and the load
  is refused (the refusal names both keys and both values); this is the general shape of
  lowering any maximum below its threshold, not a zero special case. A top-level
  section rather than a field on `[oidc]` because the budget is consumed on BOTH planes
  (the mint enforces it, the management API reports the approach warning against it), so
  one bound has one operator-visible name. Threaded to both planes by the boot path
  through `OidcState::with_token_claims` and `AdminState::with_token_claims`, each taking
  the whole section and re-clamping it through the new `TokenClaimsConfig::clamped` as
  defense in depth. The keys are installed but NOT YET CONSULTED: the permission claim
  and its budget enforcement land with the claim itself, so setting them changes no
  response and no token on this build. That qualifier is stated in the FIRST paragraph of
  the section doc and of all five field docs, so it survives into the generated operator
  reference (which keeps only the first paragraph), and each copy cites issue #413, which
  tracks deleting them when the mint activates the claim. The 3072 parity with the
  ID-token growth signal is now enforced rather than merely asserted in prose:
  `ironauth_oidc::ID_TOKEN_BLOAT_THRESHOLD_BYTES` is public and `ironauth-admin` pins the
  two equal, beside the session-TTL and group-depth ceiling agreements. `docs/CONFIG.md`
  and `docs/config-schema.json` regenerate.
- Corrected the `token_claims.permission_claim_max_count = 0` posture sentence (issue #98).
  It said `0` means "no permission claim is ever emitted"; the budget core proves it means
  no NON-EMPTY one. The bound is at-the-maximum-EMITS at both ends, so a set of exactly `0`
  elements is within a bound of `0` and `permissions: []` is still emitted, which is a
  meaningful statement (the subject is in an organization and holds nothing) rather than an
  oversight. The code boundary is deliberately unchanged: special-casing `0` would make it
  the one bound in the section that excludes its own maximum. The sentence now also points
  an operator at the switch that DOES turn the claim off deployment-wide, the
  per-resource-server `permission_claims_enabled` opt-in, since somebody reading the `0`
  posture is looking for exactly that. The correction sits in the FIRST paragraph, so it
  reaches the generated operator reference; `docs/CONFIG.md` and `docs/config-schema.json`
  regenerate.
- Organization group nesting bound for issue #97: the new top-level `[organizations]` section
  (`OrganizationsConfig`) with `organizations.max_group_depth` (default
  `ORGANIZATIONS_DEFAULT_MAX_GROUP_DEPTH` = 8, refused above the
  `ORGANIZATIONS_MAX_GROUP_DEPTH_CEILING` = 32 ceiling at load). It is the largest nesting
  depth an organization's group hierarchy may reach, measured in EDGES from a root, and it is
  a STRUCTURAL SAFETY bound rather than a cap on any count: the number of groups, roles,
  members, and role assignments is deliberately uncapped, and `max_group_depth` bounds only
  the ancestor walk that runs on the token-issuance path so that walk terminates. `0` is valid
  and means flat groups only, never unlimited. A top-level section rather than a field on
  `[admin]` because the value is consumed on BOTH planes (write-time enforcement on the
  management API, and the read-side termination guard at token issuance). This is a promotable
  per-environment setting in spirit; the process value is the deployment default until
  per-environment overrides ride the M5 promotion pipeline. `docs/CONFIG.md` and
  `docs/config-schema.json` regenerate.
- Federation privacy note surfaced in the operator-facing config docs (issue #76 review): the
  `oidc.federation` description now records that a connector may forward the downstream
  `login_hint` to its upstream provider, DISCLOSING an end-user identifier, and that a connector
  suppresses it with the per-connector stored `passthrough.login_hint = false`. Docs-only (the
  passthrough itself is per-connector stored data, not config); `docs/CONFIG.md` regenerates.
- Connector failure-isolation health probe window for issue #76:
  `oidc.federation.health_probe_window_secs` (default 30, bounded 1..=86400 via
  `OIDC_MAX_FEDERATION_TTL_SECS`, validated at load even while federation is disabled). It is
  the BASE health-driven backoff interval a per-connector unavailable upstream waits (growing
  exponentially per consecutive failure, capped) before it is probed again, and the window
  over which the exported per-connector error rate is measured. Threaded into
  `FederationRuntime::new` by the boot path.
- Generic OIDC upstream federation settings for issue #75 (PR B), off by default: the
  `oidc.federation` block (`FederationConfig`). `oidc.federation.enabled` (default false) is
  the master switch the server boot path reads to wire inbound federation (with it off the
  `/federation` routes stay a uniform not-found, so an existing deployment is unaffected).
  `oidc.federation.discovery_ttl_secs` and `oidc.federation.jwks_ttl_secs` (both default 3600,
  one hour, bounded 1..=86400 via `OIDC_MAX_FEDERATION_TTL_SECS`) govern the discovery / JWKS
  cache windows; both are validated at load even while federation is disabled, so a
  misconfigured window fails fast. The connectors themselves are per-connector STORED data,
  not config.
- Registration abuse defenses config for issue #80, off by default: the
  `oidc.registration_abuse` block (`RegistrationAbuseConfig`). `pow` (`PowConfig`) holds
  `enabled`, `difficulty_bits` (bounded 1..=24), `challenge_at` (`off`/`low`/`med`/`high`
  reusing the #79 threshold set), `challenge_ttl_secs`, `provider` (`builtin`/`turnstile`/
  `recaptcha`, the built-in self-contained PoW is the DEFAULT), `fail_policy`
  (`fail_closed`/`fail_open` for adapter outages only), and `adapter_secret` (a `Secret`
  indirection, so the VALUE never lands in a config dump or snapshot; only a named reference
  travels). `disposable_email` (`DisposableEmailConfig`) holds `mode` (`off`/`flag`/`block`)
  plus updateable per-environment `denylist`/`allowlist` domain data. `waitlist`
  (`WaitlistConfig`) holds `enabled`. Every field is validated at load (closed sets and
  bounds) so a misconfiguration fails fast, and the whole block promotes with the config
  snapshot.
- Account-recovery windows for issue #81: the `oidc.recovery_cooldown_secs` per-account
  cooldown between recovery initiations (at least 1 second, default 300, five minutes) and
  the `oidc.recovery_delay_secs` delay a security-reducing recovery is HELD for (bounded to
  1..=2592000, the 30-day ceiling, default 259200, 72 hours, matching the Apple/Google
  platform recovery-delay patterns). Both are validated at load even when recovery is
  otherwise idle, so a misconfigured window fails fast.
- Minimal risk-engine settings for issue #79, off by default: the `oidc.risk` block
  (`RiskConfig`). `oidc.risk.enabled` (default false) is the master switch; each signal is
  independently toggleable per environment (`new_device_enabled`,
  `impossible_travel_enabled`, `ip_reputation_enabled`, `velocity_enabled`, all default
  true but gated by the master switch). `oidc.risk.require_mfa_at` (`off` / `low` / `med` /
  `high`, default `off`) is the step-up threshold a MED-or-stronger score forces MFA at;
  `block_on_high` (default true) blocks a hard-deny HIGH with a uniform failure;
  `notify_on_new_device` (default true) sends the new-device notification. The velocity
  window and MED/HIGH thresholds, the impossible-travel km/h floor, the per-environment IP
  allow/deny lists, and the disavowal-token TTL round it out. All bounds are validated at
  load even when the engine is off (the threshold is a closed set, the velocity thresholds
  are ordered, the km/h floor stays above ordinary travel, the TTL is bounded), so an
  out-of-band value cannot take effect the moment it is enabled.
- Adversarial-review hardening (issue #79): adds `oidc.risk.notify_cooldown_secs` (default
  3600, one hour; 0 disables), the window over which repeated new-device notifications to
  the same (subject, device/User-Agent fingerprint) are suppressed, bounding a
  notification-flood abuse (bounded to at most `OIDC_MAX_LIFETIME_SECS`, validated at load).
  Corrects the `block_on_high` field doc (ONLY an IP deny-list hit hard-denies; a velocity
  flood raises the score and can force step-up but NEVER blocks, so a shared NAT cannot lock
  a victim out) and adds an enforcement NOTE to `require_mfa_at` (enabling the engine with
  `require_mfa_at="off"` and no IP deny-list is inert for non-deny HIGH scores, which only
  Allow/Notify; set `require_mfa_at` and/or the deny-list to actually enforce).
- Remember-device (trusted-device) policy for issue #71, off by default: the
  `oidc.trusted_devices_enabled` toggle, the `oidc.trusted_device_user_opt_in` choice
  (user checkbox vs the tenant decides), the `oidc.trusted_device_max_age_secs` absolute
  cap (bounded to 3600..=2592000, the NIST SP 800-63B 30-day reauthentication ceiling,
  default 30 days), the `oidc.trusted_device_idle_secs` idle window (at least one hour and
  never wider than the max age, default 7 days), and the
  `oidc.trusted_device_revoke_on_password_change` invalidation policy (default on). The
  duration bounds are validated at load even when the feature is off, so an out-of-band
  value cannot take effect the moment it is enabled.
- Review fix (issue #71): the shipped `oidc.acr_order` default now matches the canonical
  code ladder `OIDC_DEFAULT_ACR_ORDER` (`pwd`, `mfa_remembered`, `mfa`, `phr`, `phrh`,
  `attested_passkey`), deriving the default from a single source of truth so a new acr
  rung cannot silently drift out of the default; a pinning test in the oidc crate asserts
  the config default equals `step_up::default_acr_order()`. This also repairs a
  pre-existing #66 gap where `attested_passkey` was unranked under the default config
  (an attested login could not satisfy a lower floor by rank). A non-empty operator
  override is now validated at load to be a PERMUTATION of the known rungs (no unknown
  value, no duplicate, nothing left unranked) and to keep `mfa_remembered` STRICTLY below
  `mfa`, closing the honesty footgun where a remembered device could satisfy a genuine
  `mfa` floor.
- Two EXPLORATORY per-environment feature flags for issue #73, both default OFF and
  independently toggleable: `oidc.webauthn_signal_api_enabled` (the WebAuthn L3 Signal API
  hosted-page surface) plus its `oidc.webauthn_conditional_create_enabled` policy and
  `oidc.webauthn_conditional_create_min_interval_secs` frequency cap; and
  `admin.sudo_mode_enabled` (admin session privilege separation) plus its
  `admin.sudo_mode_window_secs` re-authentication window (default 600). When off, each
  feature is fully inert. A config flag-matrix test proves both are off by default and turn
  on independently. The `admin.sudo_mode_enabled` docstring (and the generated
  docs/CONFIG.md row) carries the honest guarantee: the enforced property is that the
  elevation is SERVER-RECORDED and never CLIENT-ASSERTED (a forged header cannot elevate),
  but because the admin plane uses a single non-interactive bearer with no second factor,
  sudo mode does NOT yet defeat a fully-stolen admin bearer (which can self-elevate);
  binding elevation to a distinct interactive re-auth factor is a documented graduation
  step, and the freshness seam is factored so end-user apps get the full guarantee.
- Password-strength score minimum (issue #66 PR C): `password_policy.min_password_strength_score`
  (integer 0-4, default 0 = scoring off, validated at most 4) wires through to
  `PasswordPolicy`. Off by default so an existing deployment sees no regression; a higher
  value refuses a password that is long enough but easily guessable, scored before the
  breach screen. The key is deliberately NOT named `min_zxcvbn_score`: the backing
  estimator is a COARSE in-tree length/charset/pattern floor that is BLIND to dictionary
  words and l33t substitution (e.g. `summer2024` scores the maximum 4), NOT a
  zxcvbn-equivalent guard; the mandatory HIBP/offline breach screen is the primary defense
  that backstops it. The field carries a `schemars(range(max = 4))` bound so the generated
  schema reports `maximum: 4` (not the `u8` type's 255) matching the runtime validation.
  Config schema and docs regenerated.
- MDS3 endpoint override (issue #66 PR B): `webauthn.mds3_base_url` (optional, validated
  as an https URL, mirroring `hibp_base_url`) lets a deployment point the FIDO MDS3 sync
  at an alternate endpoint; the pinned FIDO Alliance root stays compiled in and is never
  fetched.
- Guarded SMS-OTP settings note (issue #70, adversarial review LOW-3): the
  `oidc.sms_route_throttle_secs` / `oidc.sms_conversion_window_secs` relationship is now
  safe by construction. A `throttle_secs < conversion_window_secs` ratio was previously a
  footgun (a still-pumping route could deliver freely once its throttle lapsed but before
  the window rolled); the persistence layer now RE-ARMS the route alarm on throttle lapse
  so the route re-throttles on its next send, so no additional validation constraint is
  imposed on the ratio (the settings and their bounds are unchanged).
- Guarded SMS-OTP settings (issue #70): new `oidc.sms_otp_enabled` (default FALSE, the
  off-by-default deployment kill switch; its doc surfaces the NIST SP 800-63B-4
  restricted-authenticator caveat), `oidc.sms_otp_code_digits` (6..=8),
  `oidc.sms_otp_code_ttl_secs` (the 120..=600 band), `oidc.sms_otp_max_attempts`, the
  velocity caps `oidc.sms_per_number_send_cap` / `oidc.sms_per_number_window_secs` /
  `oidc.sms_send_cooldown_secs` / `oidc.sms_per_tenant_send_cap` /
  `oidc.sms_per_tenant_window_secs` / `oidc.sms_per_route_send_cap` /
  `oidc.sms_per_route_window_secs`, `oidc.sms_phone_scoring_enabled`, and the pumping-defense
  knobs `oidc.sms_conversion_window_secs` / `oidc.sms_conversion_min_samples` /
  `oidc.sms_conversion_alarm_threshold_percent` (1..=100) / `oidc.sms_route_throttle_secs`,
  all validated at startup with safe defaults (an empty configuration is valid and leaves
  SMS OFF). Per-tenant enablement and the country allowlist are per-tenant DB state, not
  static config, so there is no allow-all shortcut.
- `oidc.email_otp_max_attempts` scope note (issue #68, adversarial review): the per-code
  wrong-guess budget now ALSO bounds the cross-device magic-link short code (a low-entropy
  6-8 digit secret that flows through the same brute-force surface), so one setting governs
  both attempt limits. No new key; the existing setting's reach is widened.
- Email OTP and scanner-safe magic-link settings (issue #68): new `oidc.email_otp_enabled`,
  `oidc.email_otp_code_digits` (6..=8), `oidc.email_otp_code_ttl_secs` (the 300..=600
  five-to-ten-minute band), `oidc.email_otp_max_attempts`, `oidc.magic_link_enabled`,
  `oidc.magic_link_ttl_secs` (300..=3600), `oidc.magic_link_fragment_mode` (carry the token
  in the URL fragment, out of server logs and scanner request paths), and
  `oidc.magic_link_short_code_digits` (6..=8), all validated at startup with safe defaults.
- Clarified the `screening_failure_policy` documentation (issue #63 review): the default
  `fail_open` is availability-biased and lets a known-breached password through during a
  provider outage (audited/detectable); hard enforcement uses `fail_closed` or the offline
  corpus provider. Documentation only; no schema or behavior change.
- `[password_policy]` section and the `ScreeningProvider` / `ScreeningFailurePolicy` enums
  (breached-password screening and NIST SP 800-63B-4, issue #63). The shipped defaults are
  the modern 63B-4 posture: `min_length_sole_factor = 15` (SHALL), `min_length_mfa_factor =
  8`, `max_length = 64` (SHOULD), no composition (`require_lowercase`/`uppercase`/`digit`/
  `symbol` all false), `rotation_max_age_days = 0` (no forced rotation), and
  `screening_enabled = true` (MANDATORY) over the online `hibp` provider with
  `screening_failure_policy = fail_open`. Legacy compliance regimes enable composition,
  rotation, or different lengths as settings; validation rejects an unusable policy (a
  minimum above the maximum, a zero length, a rotation beyond ten years, a non-https
  `hibp_base_url`, or the `offline` provider with no `offline_corpus_path`). Lengths are
  counted in code points. Constants: `PASSWORD_POLICY_NIST_MIN_LENGTH_SOLE_FACTOR`,
  `PASSWORD_POLICY_NIST_MIN_LENGTH_MFA_FACTOR`, `PASSWORD_POLICY_NIST_MIN_MAX_LENGTH`,
  `PASSWORD_POLICY_MAX_LENGTH_CEILING`, `PASSWORD_POLICY_MAX_ROTATION_DAYS`.
- `oidc.acr_order` setting (RFC 9470 step-up, issue #72): the DEPLOYMENT-level `acr` order
  (weakest first) the step-up comparison ranks against, so an acr floor is met by the same
  value or a rank at least as strong. Resolved once from config and applied across the
  deployment (per-(tenant, environment) resolution is a future enhancement). Defaults to the
  credential-ladder order
  (`urn:ironauth:acr:pwd`, `urn:ironauth:acr:mfa`, `phr`, `phrh`); an empty list falls back
  to that default; duplicate entries are a boot-time `ConfigError::Invalid`.
- `oidc.webauthn_related_origins` (issue #67, WebAuthn Level 3 Related Origin
  Requests): a per-environment list of additional https origins permitted to use this
  environment's RP ID, including origins on a different registrable domain (a
  multi-brand or ccTLD estate). The serving origin is always permitted implicitly;
  this list adds the others, published at `GET /.well-known/webauthn`. Each entry is
  validated at STARTUP to be a well-formed https origin (`scheme://host[:port]`, no
  path). A malformed entry is a boot error, and validation now also rejects the
  malformed-but-inert forms `http::Uri` tolerated (a non-numeric port, a trailing-dot
  host, a bracketed IP-literal host), so the allowlist stays clean. The distinct
  registrable-label count of the estate (serving origin plus related origins) is an
  ADVISORY soft-guard against the browser budget of five: reaching OR exceeding it
  emits `Warning::WebauthnRelatedOriginLabelBudget`, never a boot error (the browser
  is the real enforcer of its own cap, and an over-budget boot error would wrongly
  reject a valid one-brand-many-ccTLD estate, which is a single label to a browser).
  The label count now groups by the SLD label of the registrable domain (matching the
  browser), using a curated common multi-part-suffix table (`co.uk`, `com.au`, ...) so
  `example.co.uk` counts as the label `example`, not `co.uk`; it is a documented
  conservative approximation, not a public-suffix-list dependency.
  Unlike the RP ID, a related origin need not be a registrable-suffix of the RP ID
  (that cross-domain reach is the point); the authorization is this explicit list. The
  existing `oidc.webauthn_rp_id` continuity rule (the RP ID must be a
  registrable-suffix of the serving origin) is unchanged and documents the RP ID
  migration mechanics in `docs/design/PASSKEY-RP-ID-MIGRATION.md`. Empty by default.
- `[oidc.regulation]` settings (issue #64): a new `RegulationConfig` table for
  credential-abuse regulation and the anti-enumeration posture. The DEFAULT is
  account-DoS-safe: risk-based escalating `Retry-After` delays (`soft_threshold`,
  `base_delay_secs`, `max_delay_secs`, `window_secs`) that target the attacker's
  dimensions, never a hard lockout. `hard_lockout` is an explicit per-tenant OPT-IN
  (documented weaponization tradeoff) confined to the password path;
  `registration_closed` switches `/register` to the uniform, send-suppressing Logto
  posture. Each field is floor/ceiling validated at load. The `hard_lockout` field doc now
  states BOTH tradeoffs it accepts: the DoS weaponization tradeoff (Keycloak
  CVE-2024-1722) AND, separately, a login ENUMERATION oracle (a real account auto-bans
  once its per-account counter crosses the threshold while an unknown identifier never
  does, so the 429 ONSET is earlier for a present account); that onset difference is
  inherent, while the avoidable response-shape leak is closed. On the default posture
  neither applies.
- `mfa_required` doc honesty (issue #69, review): the `[oidc].mfa_required` field doc
  (and the regenerated `docs/CONFIG.md`) now states that TODAY it drives the
  enrollment PROMPT and the `/account/mfa/plan` surface only; HARD login-flow
  enforcement (challenging the second factor before a full session) lands with the
  step-up issue (#72). `validate_totp` gains unit coverage for every bound (digits,
  period, drift, recovery count, and unknown/duplicate `mfa_factor_order`).
- TOTP second-factor settings on `[oidc]` (issue #69): `totp_enabled` (on by
  default; the endpoints fail closed with a 404 when off), `totp_issuer` (the
  authenticator-app label, derived from the serving scope when unset),
  `totp_period_secs` (15..=60), `totp_digits` (6..=8), `totp_drift_steps` (0..=2,
  the bounded skew window), `totp_recovery_code_count` (8..=16), plus the factor
  orchestration knobs `mfa_required` and `mfa_factor_order` (a duplicate-free subset
  of passkey/totp/password). A new `validate_totp` bounds each at startup, so a
  misconfiguration is a boot-time error rather than a per-request surprise.

- `[password_hashing]` settings (issue #62): a new `PasswordHashingConfig` table for the
  Argon2id parameters of NEWLY set passwords and the dedicated hashing worker pool.
  `memory_kib`/`iterations`/`parallelism` default to the OWASP recommendation
  (`19456`/`2`/`1`) and are bounded at config load (a security floor of 8 MiB up to a
  4 GiB ceiling, iterations 1..=16, parallelism 1..=64) so a tuning mistake can neither
  ship a weaker-than-defensible hash nor an unbootable one. `max_queue_depth` is the
  PER-TENANT fair-share queue bound (issue #62 hardening): the pool keeps a sub-queue per
  `(tenant, environment)` and dequeues round-robin, and a generous global memory backstop
  (a multiple of this bound) caps total waiting work, so one tenant's fill can neither
  head-of-line-block nor shed another tenant. They are per-environment in
  spirit and apply to new hashes, with existing hashes upgrading on next login.
  `pool_threads` (0 derives from the host core count), `max_queue_depth` (default 512),
  and `probe_target_latency_ms` (default 250, bounded 10..=5000) size and tune the pool.
  Also adds a `password_hashing` dimension to `[quota.tenant]`/`[quota.environment]`
  (`password_hashing_per_second`/`password_hashing_burst`) so the issue #50 fair-share
  engine admits hashing per tenant; 0 burst is unlimited (the self-hoster posture).
- Reject a single-label WebAuthn RP ID at startup (issue #65 review hardening): a bare
  label such as a public suffix (`com`) is no longer accepted, since it passed the
  registrable-suffix check against a host like `auth.example.com` yet the browser
  rejects it at ceremony time. A registrable RP ID must contain a dot; `localhost`
  stays the single-label dev exception. It is a boot-time `ConfigError::Invalid`.
- WebAuthn passkey settings on `[oidc]` (issue #65): `webauthn_enabled` (default on),
  `webauthn_rp_id` (the per-environment Relying Party ID; when unset it is derived
  from the serving origin's host), `webauthn_challenge_ttl_secs` (default 300),
  `webauthn_require_user_verification` (default on), and
  `webauthn_clone_detection_block` (default off, warn). The RP ID is validated at
  STARTUP against the serving origin: when set, `server.public_url` must be
  configured and the RP ID must be the origin host or a parent (registrable-suffix)
  domain of it, so a misconfiguration is a boot-time `ConfigError::Invalid` rather
  than a per-ceremony runtime surprise.

- `[oidc.lazy_migration]` inbound lazy-migration hook settings (issue #56): a new nested
  config table arming the login-time verification of an unknown identifier against a legacy
  store. `enabled` (default false) gates it; `endpoint` (an https URL, required and https
  when enabled, validated at config load) is the verification webhook; `secret` is the
  shared bearer, through the existing Secret indirection and covered by the literal-secret
  lint; `timeout_secs` (default 5, bounded by `OIDC_MAX_LAZY_MIGRATION_TIMEOUT_SECS = 30`)
  is the per-call timeout; and `breaker_failure_threshold` / `breaker_window_secs` /
  `breaker_cooldown_secs` (defaults 5 / 30 / 30) tune the circuit breaker. Config over a new
  DB table, promotable per environment in spirit like the other OIDC toggles.
- Lazy-migration endpoint validation tightened (issue #56, adversarial review): the
  `endpoint` is now parsed as a well-formed absolute https URL with a non-empty host and no
  userinfo at config LOAD, instead of the prior bare `starts_with("https://")` check. A
  malformed-but-https endpoint (`https://` with no host, an embedded space, an unterminated
  `[` host, or smuggled `user:pass@`) is now a clear load error rather than silently failing
  every unknown-identifier login and tripping the breaker at runtime (criterion 6). Adds a
  dependency on the `http` crate purely for this syntactic URL parse.
- `[admin]` outbound verification SCOPE binding (issue #58, review):
  `admin.outbound_verification_tenant` and `admin.outbound_verification_environment`
  (both unset by default) pin the outbound credential-verification endpoint to exactly
  one `(tenant, environment)`. A request whose path scope does not match is a uniform
  not-found regardless of the token, so the shared token can never verify credentials
  across tenants. Unset either half fails closed (matches nothing).
- `[admin]` outbound lazy-migration verification settings (issue #58), DISABLED BY
  DEFAULT. `admin.outbound_verification_enabled` (default false) leaves the outbound
  credential-verification endpoint a uniform not-found; `admin.outbound_verification_token`
  (unset by default, via the `file`/`env` secret indirection) is the shared bearer a
  successor system presents, a credential distinct from the operator token and every
  management key that authorizes ONLY that endpoint. Exposing a live credential oracle
  to a third party is an explicit per-deployment opt-in.
- `[identifiers]`: flexible-identifier settings (issue #54). `identifiers.uniqueness`
  selects the per-environment login-identifier uniqueness policy: `environment_wide`
  (the safe default, one canonical identifier per tenant-environment), `org_scoped`
  (unique within an org, falling back to the environment scope for a membership-free
  user once M10 org membership ships), or `non_unique` (multiple accounts may share
  one identifier; identifier-first login still resolves deterministically). Changing
  the mode on a populated environment requires a validation pass that reports
  post-canonicalization collisions before it applies. New public
  `IdentifiersConfig` and `IdentifierUniqueness` types.
- `[byok]`: bring-your-own-key customer-managed encryption settings (issue #49),
  EXPERIMENTAL and DEFAULT-OFF. `byok.enabled` (default false) leaves every BYOK
  path unreachable; `byok.provider` (default `local`) selects the key-management
  driver; `byok.endpoint` is the external KMS URL for an external provider,
  outbound through the SSRF-hardened fetcher and owner/infra-gated.
- Registered the `custom-domains-acme` EXPERIMENTAL feature flag (issue #47,
  EXPLORATORY): per-environment custom domains with built-in ACME. Off by default
  and ack-gated on `CUSTOM_DOMAINS_ACME_VERSION` (a live issuance needs a
  provisioned CA account and a reachable domain, which is infra/owner-gated), so an
  operator enabling it acknowledges the exact implemented revision. New public
  `CUSTOM_DOMAINS_ACME_FEATURE` and `CUSTOM_DOMAINS_ACME_VERSION` constants.
- `admin.allowed_regions`: the operator's configured data-residency region set
  (issue #46). A tenant's `home_region` and a per-environment `region` pin must be
  one of these; empty (the default) leaves residency pinning unavailable and refuses
  any residency pin on a create.
- `admin.offboarding_retention_secs`: the tenant-offboarding retention window in
  seconds (issue #46), the grace period a soft-deleted tenant can be restored
  within before the terminal hard deletion. Tunable, safe default 30 days.
- Per-tenant and per-environment quota fairness settings (issue #50), on a new
  `[quota]` section consumed by the `ironauth-quota` engine.
  - `[quota.tenant]` and `[quota.environment]`: the two nested tiers, each with a
    sustained rate and burst capacity per dimension (`requests_per_second` /
    `requests_burst`, `token_issuance_per_second` / `token_issuance_burst`,
    `hook_seconds_per_second` / `hook_seconds_burst`). Safe defaults; the
    per-tenant envelope is larger than the per-environment share. A `*_burst` of
    0 is the documented unlimited form for a single-tenant self-hoster.
  - `quota.usage_thresholds_percent` (default `[80, 100]`): the utilization
    percentages at which a saturation webhook fires per dimension. Validated to
    be at most `QUOTA_MAX_USAGE_THRESHOLDS` entries, each 1..=100, with no
    duplicates; an empty list disables saturation webhooks.
  - `quota.idle_bucket_ttl_secs` (default `3600`): how long an idle per-tenant or
    per-environment token bucket is retained before the reaper evicts it, bounding
    the in-memory footprint under legitimate scope churn. `0` disables the reaper
    (buckets live for the process lifetime); the key space is still bounded by real
    tenancy, because only a verified, existing scope ever allocates a bucket.
- Session Management 1.0 and Front-Channel Logout 1.0, behind default-off flags for
  certification completeness (issue #39).
  - `oidc.session_management_enabled` (default `false`): when set, the OP serves the
    `check_session_iframe`, discovery advertises `check_session_iframe`, and every
    authorization response carries `session_state`. Off by default because these iframe
    mechanisms are degraded under third-party-cookie partitioning (Session Management
    1.0 section 5.1); enabling still requires a per-client opt-in.
  - `oidc.frontchannel_logout_enabled` (default `false`): when set, the `end_session`
    flow renders a hidden iframe per participating RP that registered a
    `frontchannel_logout_uri`, passing `iss` and the RP's own `sid` when it registered
    `frontchannel_logout_session_required`. Best-effort only; it never blocks or
    reorders the authoritative back-channel logout path. Off by default; enabling still
    requires the per-client registration.
- Back-Channel Logout delivery worker settings (issue #34), all on `[oidc]`:
  - `backchannel_logout_enabled` (default `false`): whether the delivery worker runs. Off
    by default (the covenant: no mandatory background infrastructure). Discovery advertises
    `backchannel_logout_supported` regardless; this switch governs only the worker.
  - `backchannel_logout_max_attempts` (default `5`, at least 1): the attempts cap after
    which a per-RP delivery is dead-lettered.
  - `backchannel_logout_retry_base_secs` (default `10`): the base delay for the worker's
    exponential backoff between retries.
  - `backchannel_logout_poll_interval_secs` (default `5`): how often the worker polls the
    queue for due work.
  - `backchannel_logout_request_timeout_secs` (default `10`): the per-delivery time budget
    the SSRF-hardened fetcher enforces, so a slow RP cannot wedge the worker.
  - The three second-valued knobs are validated to be at least 1 and at most
    `OIDC_MAX_LIFETIME_SECS`; the attempts cap must be at least 1.
- Global Token Revocation, an EXPERIMENTAL receiver (issue #36).
  - The `global-token-revocation` feature is registered on the maturity ladder as
    Experimental: off by default, and enabling it requires an `ack` equal to the exact
    implemented draft revision (`GLOBAL_TOKEN_REVOCATION_DRAFT`,
    `draft-parecki-oauth-global-token-revocation-01`). A future draft that changes the
    wire shape bumps that version and invalidates the old ack. The implemented draft
    revision is surfaced in `docs/CONFIG.md` (the feature ladder table) so an interop
    mismatch with another implementer is diagnosable.
  - `oidc.global_token_revocation_hard_kill`: whether a global revoke ALSO revokes the
    subject's `offline_access` families (not only the session-bound ones). Off by default
    (offline grants survive, matching the platform-wide revoke-everything semantic); set
    it for an account-takeover posture. Effect only when the feature is enabled.
- Session-model settings (issue #32).
  - `oidc.session_idle_ttl_secs`: the session IDLE timeout, alongside `session_ttl_secs`
    (now documented as the ABSOLUTE hard cap). Validated to be at least 1 second, at most
    `OIDC_MAX_SESSION_TTL_SECS`, and never larger than the absolute cap (an idle timeout
    beyond the cap could never fire, so accepting it would mislead an operator).
  - `oidc.session_partitioned_cookie`: off by default; ADDS the CHIPS `Partitioned`
    attribute for embedded-widget scenarios without dropping `SameSite` or breaking the
    `__Host-` prefix.
  - `oidc.session_peer_ip_binding` and `oidc.session_device_binding`: both off by default
    (the tunability principle), so a NAT or a mobile IP change never logs a user out
    unless an operator opts in.
  - `PEER_IP_HEADER`: the internal header on which the server stamps the POLICY-RESOLVED
    client IP for the peer-IP binding. It lives here, in the crate both the server and the
    OIDC provider depend on, so the two agree on the name without the server taking a
    dependency on the OIDC crate.

- Add a conformance cert-config confinement test (issue #37):
  `tests/conformance_cert_config.rs` loads both `deploy/ironauth.toml` and
  `deploy/conformance/ironauth.toml` through the strict loader and asserts the
  cert config turns the legacy/downgrade OP-profile toggles on while the shipped
  default keeps every one off. This proves the cert config parses under the
  strict schema and that the security downgrades cannot leak into the default
  posture. No library change; a test only.
  - `oidc.registration_mode = "open"` (anonymous, unauthenticated DCR) is now in
    the CONFINEMENT set, not only asserted on the cert side. It is one of the
    downgrades the cert config turns on, so nothing previously checked that it
    stayed OUT of the shipped default: open DCR could have leaked into the
    default posture with no test going red.
- Add the device-authorization knobs (issue #24, RFC 8628):
  - `oidc.device_code_ttl_secs` (default 600, validated to `1..=OIDC_MAX_DEVICE_CODE_TTL_SECS`
    = 1800): the short lifetime a device code and its user code are valid for.
  - `oidc.device_poll_interval_secs` (default 5, validated to
    `1..=OIDC_MAX_DEVICE_POLL_INTERVAL_SECS` = 300): the advertised minimum poll interval.
  - `oidc.device_slow_down_increment_secs` (default 5, may be 0, bounded by the same
    ceiling): how much a `slow_down` grows the enforced interval per too-fast poll.
  - `oidc.device_user_code_max_attempts` (default 5, at least 1): the number of failed
    user-code matches after which a flow is invalidated.
  - `oidc.device_verification_rate_limit` (default 10; 0 disables) and
    `oidc.device_verification_rate_window_secs` (default 60, validated to
    `1..=OIDC_MAX_LIFETIME_SECS`): the per-source fixed-window rate limit on user-code
    entry. The regenerated `docs/config-schema.json` and `docs/CONFIG.md` document them.
- Add the DCR abuse-control knobs (issue #31):
  - `oidc.registration_mode` (`closed` / `token_gated` / `open`, default
    `token_gated`): the per-environment exposure switch for Dynamic Client
    Registration. The safe default requires an initial access token; `open` (anonymous
    self-service registration) is an explicit opt-in. Takes effect only when
    `oidc.registration_enabled` mounts the endpoint.
  - `oidc.registration_max_clients` (default 100): the per-environment cap on
    dynamically registered clients.
  - `oidc.registration_rate_limit` (default 20) and `oidc.registration_rate_window_secs`
    (default 60, validated to `1..=OIDC_MAX_LIFETIME_SECS`): the endpoint's
    fixed-window rate limit; a limit of 0 disables it.
- Add `oidc.client_credentials_default_audience` (issue #23): the default audience a
  client-credentials access token carries when the request targets no resource
  server. A snake_case enum (`ClientCredentialsAudience`) with two members:
  `client_id` (the default; the token's `aud` is the OAuth client id, preserving the
  existing no-resource behavior) and `issuer` (the token's `aud` is the
  per-environment issuer). When a request targets a registered resource server (the
  RFC 8707 `resource` parameter, issue #28), that resource server's audience wins and
  this default does not apply. The regenerated `docs/config-schema.json` and
  `docs/CONFIG.md` document it.

- Add the refresh-token rotation and consent knobs (issue #21):
  - `oidc.issue_refresh_tokens` (default `true`): whether a code exchange issues a
    refresh token at all.
  - `oidc.refresh_idle_ttl_secs` / `oidc.refresh_max_lifetime_secs` (defaults 14 /
    30 days) and `oidc.offline_idle_ttl_secs` / `oidc.offline_max_lifetime_secs`
    (defaults 30 / 90 days): the idle timeout and family hard cap for a
    session-bound and an `offline_access` family respectively. Each idle timeout has
    a one-second floor and its own ceiling (`OIDC_MAX_REFRESH_IDLE_TTL_SECS`,
    `OIDC_MAX_REFRESH_MAX_LIFETIME_SECS`), and a hard cap must be at least its idle
    timeout.
  - `oidc.refresh_rotation_grace_secs` (default `10`): the window within which a
    duplicate presentation of a rotated token is a benign concurrent refresh rather
    than a reuse; `0` treats every superseded-token presentation as reuse.
  - `oidc.refresh_rotation_threshold_percent` (default `70`, bounded 0..=100): the
    fraction of idle TTL past which a confidential/bound client rotates.
  - `oidc.offline_access_requires_consent` (default `true`): whether a web client
    must consent to `offline_access` (OIDC Core 11), subject to the trusted
    first-party carve-out.
  - `oidc.remembered_consent_ttl_secs` (default 30 days, ceiling
    `OIDC_MAX_REMEMBERED_CONSENT_TTL_SECS`): how long a `remembered`-mode consent is
    honored before re-prompting.
- Add `oidc.registration_enabled` (issue #30), a plain default-off flag gating the
  Dynamic Client Registration endpoint (`/connect/register`). Off keeps the
  endpoint unmounted and undiscoverable, the safe posture; the real abuse gating
  (quotas, quarantine, initial-access-token policy) is owned by issue #31.
- Add the pushed-authorization-request settings (PAR, RFC 9126, issue #27):
  - `oidc.require_pushed_authorization_requests` (default `false`), the
    environment-wide switch that requires every client to use PAR; when `true` the
    authorization endpoint rejects a plain request with `invalid_request` and
    discovery advertises the requirement.
  - `oidc.par_ttl_secs` (default 60), the pushed `request_uri` lifetime in
    seconds, validated to stay between 1 and `OIDC_MAX_PAR_TTL_SECS` (600) so a
    misconfiguration cannot mint a long-lived reference.

- Add the JWT client-assertion authentication knobs (issue #25), shared with the
  JWT bearer grant (#26):
  - `oidc.client_assertion_audience`, a `ClientAssertionAudience` enum selecting
    which `aud` values a client assertion may carry. The default
    (`token_endpoint_or_issuer`) accepts either the token-endpoint URL (the
    RFC 7523 recommendation) or the issuer identifier, so a client that targets
    either is interoperable out of the box; `issuer_only` is the strict posture
    that accepts the issuer identifier alone. A promotable per-environment
    setting.
  - `oidc.client_assertion_max_skew_secs` (default `60`), the clock-skew
    allowance applied to a client assertion's `exp` through the verify core's
    skew parameter, bounded above by `OIDC_MAX_CLIENT_ASSERTION_SKEW_SECS` (300).
  - The generated `docs/config-schema.json` and `docs/CONFIG.md` are regenerated.
- Add `oidc.default_access_token_format` (issue #29), a `TokenFormat` enum
  (`at_jwt` or `opaque`) selecting the access-token format an environment mints
  when no resource server is targeted. The spec-conform default (`at_jwt`) mints a
  self-contained RFC 9068 signed JWT whose audience is the client id, so `UserInfo`
  and offline verification keep working; `opaque` mints a random, digest-only
  reference token. A promotable per-environment setting; a registered resource
  server overrides it per audience. The generated `docs/config-schema.json` and
  `docs/CONFIG.md` are regenerated.

- Add the legacy response-type toggles (issue #17, all default `false`):
  `oidc.enable_response_type_id_token`, `oidc.enable_response_type_code_id_token`,
  `oidc.enable_response_type_none`, and `oidc.enable_response_mode_form_post`. Each
  is an independent per-environment switch that opts a certification-run
  environment into a legacy response type or the `form_post` mode; the `code`
  response type and `query` mode are always available. Regenerates
  `docs/config-schema.json` and `docs/CONFIG.md`.
- Add `oidc.require_pkce_for_confidential_clients` (issue #13, default `true`):
  the per-environment PKCE policy for confidential clients. Public clients always
  require PKCE regardless. Regenerates `docs/config-schema.json` and
  `docs/CONFIG.md`.
- Add the `[oidc]` section (issue #12): `enabled` (opt-in mount, default off),
  `authorization_code_ttl_secs` (default 60), and `access_token_ttl_secs`
  (default 300). Lifetimes are validated non-zero and bounded by
  `OIDC_MAX_LIFETIME_SECS`. Regenerates `docs/config-schema.json` and
  `docs/CONFIG.md`.
- Initial strict configuration layer: fail-fast TOML parsing (unknown keys
  abort with file, line, column, and the expected-field list), `Secret`
  indirection (literal, file, env forms) with redacted Debug/Display/serialize,
  `Dsn` connection strings with password redaction, the feature maturity
  ladder (`FeatureRegistry`, experimental version acknowledgment gate), and
  the published JSON Schema contract (`Config::json_schema`,
  scripts/config-schema.sh regenerates docs/config-schema.json and
  docs/CONFIG.md).
