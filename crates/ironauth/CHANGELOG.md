# ironauth changelog

All notable changes to the `ironauth` binary. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

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
  run) with 17 standard-library unit tests, and a one-command runner. CI gains
  an always-on static lane (`scripts/conformance-check.sh`, in the invariants
  job) plus an owner-gated live merge-gate job, a nightly full-matrix workflow
  with a least-privilege badge-publish job, and a secret-isolated track-suite-
  master workflow. Provisioning the runner and secrets, promoting the merge-gate
  check to required, and resolving the real image digests are owner actions;
  see docs/conformance.
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
