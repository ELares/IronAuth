# ironauth changelog

All notable changes to the `ironauth` binary. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- **The boot path starts the outbox RETENTION sweeper (issue #104, PR 3).**
  `spawn_retention_sweeper` takes the store, the scopes and the observer as ARGUMENTS, for
  the reason `spawn_consumer_pools` does: it is what lets a test drive the real seam against
  a real database instead of asserting about a copy.

  - WHEN IT ACTUALLY RUNS, stated exactly, because an earlier draft of this entry said
    "unconditionally" and that was measured false. `serve` starts it independently of
    `backchannel_worker_inputs` and shuts it down alongside the logout pools, but THREE
    things stop it: `outbox.reap_enabled = false` (a deliberate operator choice, logged at
    warn); no control-plane DSN, which is the DEFAULT deployment, because
    `admin.control_database_url` is unset and `dev_mode` is off (logged at error); and a
    deployment whose consumers never run, where the sweeper starts and correctly removes
    nothing, because only a consumer makes a message reapable.
  - It does NOT share the consumer pools' gate. Those are the switches of ONE consumer of a
    generic queue; the next consumer to register will run behind a different one, and
    retention must not have to be re-wired per consumer.
    `retention_is_not_gated_on_the_back_channel_logout_switch` is what turns red if such a
    gate is added, and `tests/serve_retention_boot.rs` boots the real binary to pin that the
    `serve` call site exists at all: replacing it with a no-op used to leave the whole suite
    green.
  - `outbox_retention_settings` resolves the inverted sentinel at ONE seam:
    `dead_letter_retention_secs = 0` becomes `None` (never), not `Duration::ZERO` (always).
    All four config-to-settings mappings are now pinned at distinct values, because swapping
    the completed window with the interval, and replacing the batch with `i64::MAX`, were
    both undetected.
  - `TracingRetentionObserver` logs a SATURATED pass at warn, naming the two knobs that fix
    it; a failed pass at warn, naming the missing 0102 grant as the likely cause; and an
    IDLE pass at debug, so a healthy reaper with nothing to do and a dead one are not the
    same silence.
  - OPERATOR OBLIGATION: retention deletes as `ironauth_control`, the only role migration
    0102 grants DELETE on `outbox_messages`. With NO control-plane DSN there is NO REAPING
    AT ALL: the boot logs an error saying so, and `outbox_messages` grows without bound,
    because every ended session enqueues one message plus one per participating relying
    party and nothing else removes any of them. Set `admin.control_database_url` (or run in
    dev mode). `outbox.reap_enabled = false` disables the sweeper deliberately and logs a
    warning saying the same thing. See `docs/design/RETENTION.md` for what this reaper does
    and does not bound.

- **The boot path spawns the outbox consumer pools (issue #104, PR 2).** Back-channel logout
  delivery is no longer a hand-rolled worker: `spawn_backchannel_logout_pools` registers the
  two logout consumers, and `spawn_consumer_pools` turns that registry into one running
  worker pool each, all sweeping one `ControlPlaneScopes` and reporting to one
  `TracingOutboxObserver`. `outbox_worker_settings` is the single place the `[outbox]`
  section becomes a `WorkerSettings`.

  - **The FAN-OUT consumer gets an effectively unbounded attempts budget, and the delivery
    consumer keeps the shared cap.** Both pools were first given `outbox.max_attempts`, and
    that loses logouts. A `session_ended` message is an ENTIRE session's fan-out, held at a
    moment when no per-relying-party message exists yet, so dead-lettering it leaves every
    RP of that session permanently un-notified with nothing anywhere to replay from. Its
    handler makes no outbound call, so the only failure it can classify as retryable is a
    DATABASE fault, and at the shipped defaults five attempts on a ten second base is about
    150 seconds of database trouble to discard a session's logout forever. The bound cannot
    be doing the other job a bound does either: every input this handler cannot process is
    already `permanent` and dead-letters on its first attempt regardless. This also restores
    what the deleted worker did, which was to let the lease lapse and re-claim, forever;
    moving onto a generic substrate is what introduced a terminal state here. It is safe
    HERE specifically because a `session_ended` message's ordering key is the ended session
    id, so its group is a singleton and there is nothing behind it to block; a consumer
    whose producers share ordering keys must keep the finite bound.
  - **The pools' outcomes are LOGGED.** The migration deleted two `tracing::warn!` calls and
    replaced them with nothing, and the new pool loop discarded its results, so a
    dead-lettered logout, a drain pass failing on a persistence fault, and a scope sweep
    that never returned a scope were all silent. `TracingOutboxObserver` reports a
    dead-lettering pass at ERROR (naming the consumer, the scope and the count), and a
    failed pass or a failed sweep at WARN. A healthy pass is deliberately not logged: one
    line per pool per scope per poll interval would bury the three that matter.
  - **The wiring is MEASURED, in `src/outbox_wiring_tests.rs`.** PR 1 shipped a framework
    with zero call sites; the same defect one layer up is a wiring that runs and that nothing
    observes. Measured with `.take(1)` on the pool loop, so the binary spawns the fan-out
    pool and never the delivery pool: with this suite SKIPPED, all 17 remaining tests of the
    crate pass and `cargo clippy --workspace --all-targets --all-features -- -D warnings` is
    clean, so nothing but this suite can see it. The suite
    drives the REAL `spawn_consumer_pools` and `outbox_worker_settings` against a real
    database and asserts BEHAVIOUR: a message enqueued for every registered consumer must be
    handled, whichever subset a broken loop would have covered.

- **The `dev_mode` control-DSN fallback warning now names the consequence that actually
  bites** (issue #441). When `admin.control_database_url` is unset and `dev_mode` is on, the
  management plane connects on `database.url`. A development database is usually a
  full-privilege one, so a management route the least-privileged control role holds no
  privilege for answers perfectly there and fails on every deployment that sets the knob.
  That was measured rather than supposed: with the router on the owning role and the
  relevant grants reverted, all 143 published management operations pass. The warning listed
  the row-level-security backstop and the role separation and stopped there, which said
  nothing about a surface being invisibly dead.

- Inbound OIDC federation is now WIRED into the server boot path (issue #75, PR B,
  adversarial review MEDIUM-1). `build_oidc_router` reads the new `oidc.federation` config and,
  when `oidc.federation.enabled` is set, builds the `FederationRuntime` (its OWN SSRF-hardened
  outbound fetcher plus the configured discovery / JWKS cache TTLs) and installs it via
  `OidcState::with_federation`, so a stored connector's `/federation/*` login legs go live.
  OFF by default: with federation disabled the routes stay a uniform not-found, so an existing
  deployment is unaffected. A downstream resource server MUST key trust on the local token's
  `acr` (`urn:ironauth:acr:federated`), NOT on the passed-through `amr`, which reflects the
  UPSTREAM's own assertion.
- Guarded SMS OTP factor semantics hardening (issue #70, adversarial review): the SMS
  verify surface the server exposes now honors the no-silent-downgrade invariant on EVERY
  purpose. `POST .../otp/sms/verify` establishes a primary session only for `login`,
  `recovery`, and self-service `register` (each gated by the tenant downgrade opt-in on a
  passkey / TOTP-protected account); `mfa` and `verify_address` now return a possession
  proof (`{"verified":true,"purpose":...}`) with NO session cookie instead of a full
  authenticated `sms` session, closing a purpose-confusion factor-downgrade to account
  takeover. The SMS send surface stays uniform present-vs-absent even under hashing-pool
  back-pressure. No configuration or wiring change for the binary.
- Guarded SMS OTP (issue #70): the server binary now installs a `LoggingSmsSender` dev stub
  behind the SMS provider seam, so the guarded SMS-OTP factor delivers end to end without an
  SMS gateway (the code is emitted only at the `debug` trace level; a real provider adapter
  is a documented M11 seam a deployment installs in its place). SMS OTP stays off by default,
  so the stub is inert until a tenant explicitly enables SMS and configures a country
  allowlist.
- `ironauth credential-class-policy set|list|remove` CLI (issue #66, PR A): set, list, and
  remove the declarative per-scope minimum-credential-class ladder row for a subject
  (`--subject tenant|group|org`, `--subject-ref ID`, `--class any|mfa|passkey|attested_passkey`),
  each an audited write through the same acting repository the authentication path composes
  from with strictest-wins. Mirrors the `step-up-policy` CLI pattern; a hosted admin HTTP CRUD
  can layer on later.
- Magic-link cross-device UI reachability (issue #68, adversarial review): the served
  magic-link send acknowledgment page now renders a `short_code` entry form, so the
  cross-device fallback (open the link on one device, finish on the originating device that
  holds the binding cookie) is completable through the browser UI the binary serves, not
  only via a raw POST.
- Email OTP and scanner-safe magic links (issue #68): the server binary now installs a
  `LoggingVerificationSender` dev transport behind the #64 verification seam, so the email-
  OTP and magic-link factors deliver end to end without a mail server (the code / link are
  emitted only at the `debug` trace level; a real email provider is a documented M11 seam
  a deployment installs in its place).
- Breached-password screening and the NIST SP 800-63B-4 policy are wired at boot from the
  `[password_policy]` config (issue #63). The boot path resolves the policy (length floors,
  legacy composition/rotation overrides, fail-open/closed) and installs it on the OIDC data
  plane, and builds the screening provider: the online HIBP k-anonymity range provider over a
  fresh SSRF-hardened fetcher, or the offline corpus provider loaded from the operator
  dataset file. The shipped defaults are the modern 63B-4 posture with screening MANDATORY
  over the free HIBP provider (fail-open), so a default deployment screens passwords with no
  configuration. A provider whose input is unavailable (a fetcher-setup failure, an
  unreadable corpus) logs and leaves the state to apply the fail-open/closed policy.
- `step-up-policy set | list | remove` subcommands (RFC 9470 step-up, issue #72): set,
  list, and remove the declarative per-scope and per-client step-up authentication policy
  directly against the data-plane store, each an audited write through the SAME repositories
  the enforcement path reads, so an operator can enable a policy without hand-writing Rust or
  SQL. A short `--acr` alias (`pwd`/`mfa`/`phr`/`phrh`) is canonicalized to the value the
  enforcement path compares against. Closes the "declarative policy has no production
  reachability" gap; a hosted admin HTTP CRUD can layer on later.
- `ban` / `unban` / `bans` subcommands (issue #64): place, lift, and list durable
  credential-abuse bans directly against the data-plane store, each an audited write. An
  identifier subject is canonicalized through the login seam so a CLI ban matches the form
  the request path checks, and a `--path` scopes the ban to one authentication path
  (default `password`), so a CLI lockout never blocks the passkey or recovery path. The
  admin API offers the same operations over HTTP; both write through the SAME repository.
- Wire the Argon2id hashing pool (issue #62): when the OIDC provider is mounted, the boot
  path builds ONE `HashingPool` from `[password_hashing]` (worker count from
  `pool_threads`, or the host core count when 0; the configured Argon2id parameters and
  queue depth) sharing the SAME quota enforcer as the request path, so hashing admission
  is per-tenant fair-share, and installs it on the OIDC state. Adds the `ironauth
  hash-probe [--config PATH] [--json]` subcommand: a headless-install tuning helper that
  measures Argon2id on this host and recommends parameters meeting the configured latency
  target, printing projected logins/s per core (the same probe backs the in-admin tuning
  helper). Registers the pool metric descriptions. The probe's default per-hash memory
  budget now derives from TOTAL host RAM (Linux `MemTotal / 2`, or a 1 GiB fallback on
  hosts without a dependency-free total-RAM read) instead of the currently-configured
  memory cost, so the default probe can explore the full ladder and recommend stronger
  parameters than the host is presently configured for (issue #62 hardening); a new
  `--memory-budget KIB` flag overrides it explicitly.
- Wire the inbound lazy-migration hook (issue #56): when the OIDC provider is mounted and
  `[oidc.lazy_migration]` is enabled, the boot path builds ONE `LazyMigrationHook` (a
  dedicated SSRF-hardened fetcher with the configured per-call timeout, the resolved shared
  secret, and a circuit breaker on the env clock) and installs the SAME Arc on BOTH the OIDC
  data plane (arming the login path) and the management plane (so the migration-progress
  endpoint reports the node's breaker state). A disabled or misconfigured hook (unresolvable
  secret, TLS setup failure) is logged and simply not armed, leaving the login path
  unchanged.
- The management-plane control store is now built with the platform envelope master
  key attached (issue #52), so the admin user-management API can seal, blind-index,
  and open user PII (issue #48) exactly as the data plane does. Without the key those
  admin user paths fail closed (never plaintext); `resolve_master_key` logs when it
  is unset.
- The binary now dispatches the config-as-code subcommands `validate`, `plan`,
  `apply`, and `drift` (issue #51, CLI half) into the new `ironauth-apply` crate.
  They are a THIN client of the management API: `validate` checks a document
  against the snapshot format locally; `plan` and `apply --dry-run` render the
  server-computed promotion plan; `apply` applies transactionally (a re-apply of
  an unchanged target is a no-op, a target drifted from an expected revision
  exits nonzero and changes nothing); `drift` reports drift with CI-gate exit
  codes. Run `ironauth <subcommand> --help` for usage. The outbound HTTP the CLI
  needs lives entirely in `ironauth-apply`, so this binary crate stays free of an
  HTTP-client dependency (scripts/http-audit.sh). The Terraform-provider and
  dogfooding halves of issue #51 are deferred; the issue stays open.
- The boot path now spawns the OIDC Back-Channel Logout delivery worker (issue #34) when
  `oidc.enabled` AND `oidc.backchannel_logout_enabled` are set (off by default). The
  worker drains the durable session-ended outbox per scope, builds one signed Logout Token
  per participating relying party, and POSTs it through the SSRF-hardened outbound fetcher
  with bounded-backoff retries and a dead-letter state. Scope enumeration is a
  control-plane read (the data-plane role cannot see the non-RLS `environments` table), so
  the worker connects both a data-plane store (to drain and sign) and a control-plane store
  (to enumerate scopes); a missing control DSN or a connect/fetcher-setup failure is logged
  and the worker is simply not spawned, leaving the rest of the server unaffected (the
  queue is durable, so nothing is lost). Adds tokio's `time` feature to the binary.
- The boot path now runs the strict feature-maturity gate (issue #4/#36): it validates
  `[features]` against the built-in registry and REFUSES to boot on a violation (an
  unknown feature, or an enabled experimental feature without an exact-version ack), and
  it resolves the experimental Global Token Revocation receiver's mount from that ladder
  (feature enabled AND acked) rather than any plain `[oidc]` toggle, so the ack can never
  be bypassed. When enabled it mounts `POST /global-token-revocation` and logs the
  experimental-surface warning.
- Wire the OIDF conformance suite into CI as a merge gate (issue #37). New
  `deploy/conformance/` harness: a docker-compose stack pinned BY DIGEST via a
  committed `SUITE_VERSION` (the OIDF suite, MongoDB, an nginx TLS terminator
  fronting the OP as the `op` issuer host, and IronAuth), a
  certification-representative `ironauth.toml` that turns on the legacy/downgrade
  OP-profile toggles FOR THE CERT ENVIRONMENT ONLY (the shipped default stays
  hardened, proven by a config test), a reviewed `profile-matrix.yaml` (the four
  OP profiles on the merge gate, Implicit/Hybrid nightly, the four logout
  profiles deferred to #33/#34/#39 as explicitly not-yet-enabled), a strict
  results gate (`parse_results.py`) that fails on ANY non-PASS (finished-but-
  failed, unreviewed WARNING, REVIEW, SKIPPED, unfinished, or a vacuously empty
  run) with standard-library unit tests, and a one-command runner that FAILS
  CLOSED: it exits 0 only after actually driving at least one plan with every
  module passing, and exits non-zero on a missing OIDF runner, an empty profile
  selection, a crashed selector, or an unrenderable plan config. Each plan's
  runner config is GENERATED from the profile matrix (`gen-plan-config.py`), so
  the exact-string issuer the suite matches has exactly one definition (#194).
  The runner is bash 3.2 portable, so the one-command local reproduction works on
  stock macOS.

  CI gains an always-on static lane (`scripts/conformance-check.sh`, in the
  invariants job) which is what actually ENFORCES today: it is gated by no
  repository variable and it runs the results-gate unit tests, validates the
  matrix, renders every enabled profile's plan config, verifies every image
  reference anywhere under `deploy/conformance` is pinned by digest, asserts the
  harness cannot fail open, and re-checks downgrade confinement. The LIVE suite
  lane always runs but is explicitly ADVISORY and named so it cannot be mistaken
  for a gate: it has no job-level `if:`, because GitHub reports a skipped job to
  branch protection as SUCCESS, so a required check gated on a repository
  variable would turn silently green if that variable were unset or mistyped.
  While the suite is unprovisioned it prints a `NOT ENFORCING` banner rather than
  posing as a passing gate. Also a nightly full-matrix workflow with a
  least-privilege badge-publish job, which now FAILS THE RUN when the matrix does
  not pass (a failing nightly used to be a green run recorded only in a badge
  JSON, notifying nobody), and a secret-isolated track-suite-master workflow.

  Provisioning the OIDF runner, resolving the real image digests, validating the
  generated plan config against the live runner, demonstrating the seeded
  regression, and only then promoting the live check to required are owner
  actions; docs/conformance/RUNBOOK.md carries the complete list, and
  docs/conformance/README.md states plainly what enforces today versus what does
  not.
- Compose per-environment issuers, JWKS serving, and signing into the live data
  plane (issue #194). `build_oidc_router` now builds ONE store-backed
  `IssuerRegistry` (keys load lazily and RLS-scoped from the data-plane store on
  first use) and mounts all three surfaces on the public plane: the protocol
  router, discovery (both well-known forms), and the per-environment JWKS, all over
  that one registry. Discovery resolves each environment's signing policy from its
  loaded keys, so the advertised `id_token_signing_alg_values_supported`, the served
  JWKS, and the minted tokens cannot diverge, and an unprovisioned or cross-tenant
  scope returns 404 exactly like the JWKS surface. The JWKS/discovery
  `Cache-Control` max-age comes from `oidc.jwks_cache_max_age_secs`. The stale
  "mounted with NO signing keys" warning is gone; an environment without a
  provisioned key still fails closed (token endpoint `server_error`, JWKS/discovery
  404). Default boot is unchanged.
- Mount the OIDC provider (issue #12) on the PUBLIC plane when `oidc.enabled` is
  set, connecting the data-plane store with `database.url`. Per-environment
  signing-key provisioning is a later milestone: until an environment has a key,
  its token endpoint fails closed (a startup warning says so). Default boot is
  unchanged (unmounted, database-free).
- `ironauth serve [--config PATH]`: loads and strictly validates config,
  surfaces its warnings to the log, wires telemetry, and runs the dual-plane
  server until `SIGTERM`/`SIGINT`, draining within the configured grace period.
  The non-default `otlp` feature is forwarded to `ironauth-server`.
- Initial binary: `--version` and `--help` only. The server skeleton lands
  with the M1 server-skeleton issue.
