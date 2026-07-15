# Profile matrix and coverage

The version-controlled matrix is
[`deploy/conformance/profile-matrix.yaml`](../../deploy/conformance/profile-matrix.yaml).
It is reviewed like code: which OIDF test plans run on which trigger, and which
are deferred, is a reviewed change, not a runner flag.

## Profiles wired now vs deferred

| Profile | Plan | Trigger | Enabled | Depends on |
|---------|------|---------|---------|-----------|
| Basic OP | `oidcc-basic-certification-test-plan` | merge-gate + nightly | yes | shipped (M2) |
| Config OP | `oidcc-config-certification-test-plan` | merge-gate + nightly | yes | shipped (M2) |
| Dynamic OP | `oidcc-dynamic-certification-test-plan` | merge-gate + nightly | yes | shipped (M2, DCR) |
| Form Post OP | `oidcc-formpost-basic-certification-test-plan` | merge-gate + nightly | yes | shipped (M2) |
| Implicit OP | `oidcc-implicit-certification-test-plan` | nightly | yes | shipped (M2) |
| Hybrid OP | `oidcc-hybrid-certification-test-plan` | nightly | yes | shipped (M2) |
| RP-Initiated Logout | `oidcc-rp-initiated-logout-certification-test-plan` | nightly | no | #39 |
| Session Management | `oidcc-session-management-certification-test-plan` | nightly | no | #33, #34 |
| Front-Channel Logout | `oidcc-frontchannel-logout-certification-test-plan` | nightly | no | #33, #34 |
| Back-Channel Logout | `oidcc-backchannel-logout-certification-test-plan` | nightly | no | #33, #34 |

The merge-gate subset is the four fast, deterministic OP profiles that exercise
the authorization-code path the whole product depends on. Implicit and Hybrid
are implemented but slower and less central, so they run in the full nightly
matrix rather than on every PR. The response types and modes those two need are
the legacy toggles the cert config turns on (see the confinement note below).

### Deferred profiles are explicitly not-yet-enabled, never vacuously green

The four logout profiles are listed with `enabled: false` and a `blocked_by`
issue. This is deliberate: a profile that is not yet implemented must never be
silently reported as passing. The runner (`run-conformance.sh`) skips a disabled
profile and prints `not-yet-enabled: <plan> (blocked by <issue>)`; it never
feeds a fabricated result to the gate. The results gate itself
(`parse_results.py`) only ever sees the enabled profiles' real results and fails
on any non-PASS among them, and it treats a run with zero modules as a vacuous
failure. `gen-plan-config.py` refuses outright to render a runner config for a
disabled profile, and `scripts/conformance-check.sh` asserts that refusal on
every PR. So no unimplemented profile can count as green.

The narrower claim above is about DEFERRED PROFILES, and it is the only thing
this section claims. It is emphatically NOT a claim that the live conformance
lane is currently enforcing anything, because it is not: the OIDF runner is not
provisioned in this repo, so the live suite drives ZERO plans today (see
[README.md](README.md) for exactly what enforces now versus what is owner-gated,
and the RUNBOOK for the outstanding owner actions). An earlier version of this
document said "there is no path by which an unimplemented profile counts as
green" in a way that read as a guarantee about the gate as a whole. It was not
one, and the harness had three fail-open paths at the time. What now backs the
claim, mechanically:

- `run-conformance.sh` FAILS CLOSED. It exits 0 only after actually driving at
  least one plan through the live suite with every module passing. A missing
  OIDF runner, an empty profile selection, a crashed selector, or a plan config
  that cannot be rendered are each a non-zero exit, not a skip.
- The live CI lane is **not a gate and is named so it cannot be mistaken for
  one** (`OIDF conformance live suite (advisory until provisioned; NOT a gate)`).
  It always runs, and when the suite is not provisioned it prints a `NOT
  ENFORCING` banner instead of posing as a passing check. It has no job-level
  `if:`, because GitHub reports a SKIPPED job to branch protection as SUCCESS: a
  required check gated on a repository variable would turn silently green the
  moment that variable was unset or mistyped.
- The conformance checks that DO enforce today are the always-on static lane
  (`scripts/conformance-check.sh`, in the `invariants` job), which no repository
  variable gates. It runs the results-gate unit tests, validates the matrix,
  renders every enabled profile's runner config, verifies every image reference
  under `deploy/conformance` (compose images, `docker run`, and `Dockerfile`
  `FROM` bases) is digest-pinned, and re-checks downgrade confinement, on every
  PR. The one image outside that scope is the `ironauth-cert` service's own base,
  built from `deploy/Dockerfile`; pinning it is an owner/infra item tracked in
  the RUNBOOK.

When a logout dependency merges, flip that profile to `enabled: true` in the
SAME PR, so the gate starts holding it exactly when the surface becomes real.

## Downgrade confinement

The certified OP profiles require legacy/downgrade behaviors (implicit and
hybrid response types, `response_type=none`, form-post response mode, and open
dynamic client registration). Each is a security downgrade. They are turned on
ONLY in `deploy/conformance/ironauth.toml`; the shipped default
`deploy/ironauth.toml` keeps every one off. This is enforced two ways:

- `crates/ironauth-config/tests/conformance_cert_config.rs` loads both configs
  through the real strict loader and asserts the cert file turns each downgrade
  on while the default keeps it off. If a downgrade ever leaks into the default,
  this test goes red.
- `scripts/conformance-check.sh` re-asserts the same thing with a fast grep, so
  it is also caught in the always-on static lane without a compile.

The confinement set is: `enable_response_type_id_token`,
`enable_response_type_code_id_token`, `enable_response_type_none`,
`enable_response_mode_form_post`, `registration_enabled`, a disabled DCR rate
limit, and `registration_mode = "open"`. That last one is anonymous,
unauthenticated client registration, and it was previously asserted only on the
CERT side: nothing checked that it stayed OUT of the shipped default, so open DCR
could have leaked into the default posture with no test going red. It is now in
the confinement set on both sides, in the Rust test and in the shell complement.

## Coverage vs protocol surface

The gate is only as good as the path a regression would traverse. The four
merge-gate profiles collectively drive:

- discovery on both well-known forms and the exact issuer string (Config, and
  every profile bootstraps from discovery) -> the #194 discovery-divergence
  surface;
- the authorization-code grant end to end: `authorize`, PKCE, `code` exchange,
  ID token signature and claims, `nonce`, and `UserInfo` (Basic);
- dynamic client registration and metadata negotiation (Dynamic);
- the form-post response mode encoding (Form Post).

A regression in any of those lands in a covered path and blocks the merge gate.
Regressions outside this surface (for example a logout defect) are covered by
the nightly matrix as those profiles are enabled, and by the RFC 9700 BCP
harness (a separate issue) for BCP-specific checks. The matrix is the reviewed
record of exactly which protocol surface is continuously held.

## Seeded-regression mechanism

Issue #37 asks for a deliberately seeded protocol regression that fails the gate,
to prove the gate catches a real break. The full live demonstration needs the
provisioned runner; the MECHANISM is documented here so the seeded violation is
guaranteed to land in a covered path.

Seed a regression by flipping ONE cert-environment behavior that a covered
profile asserts, then observe the gate. Three worked examples, each mapped to
the profile and assertion that catches it:

1. Issuer trailing-slash drift (the #194 surface). Append a trailing slash to
   `public_url` in `deploy/conformance/ironauth.toml` (`https://op/`). The
   advertised issuer becomes `https://op//t/cert/e/cert`, which no longer
   exact-string-matches what the suite fetched. Caught by: Config and Basic,
   during discovery bootstrap (the suite refuses to start a plan whose issuer
   does not match). Revert -> green.

2. ID token claim regression. Set `conform_id_token_claims = true` in the cert
   config (or otherwise place a scope-derived claim where the profile does not
   expect it). Caught by: Basic, in the ID token claim checks. Revert -> green.

3. PKCE downgrade. Set `require_pkce_for_confidential_clients = false` AND have a
   client omit the challenge. Caught by: the code-exchange checks in Basic.
   Revert -> green.

Each seed is a single reviewed line in the cert config, lands in a path the
merge-gate subset drives, and is reverted to return the gate to green. This is
the mechanism the acceptance criterion's "seeded regression fails the gate,
reverting it goes green" is demonstrated with once the runner is provisioned. It
is NOT claimed to have been run against the live suite here; the runner is
owner-provisioned (see the RUNBOOK).
