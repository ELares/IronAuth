# ironauth changelog

All notable changes to the `ironauth` binary. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- Email OTP and scanner-safe magic links (issue #68): the server binary now installs a
  `LoggingVerificationSender` dev transport behind the #64 verification seam, so the email-
  OTP and magic-link factors deliver end to end without a mail server (the code / link are
  emitted only at the `debug` trace level; a real email provider is a documented M11 seam
  a deployment installs in its place).
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
