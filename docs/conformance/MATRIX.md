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
failure. So there is no path by which an unimplemented profile counts as green.

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
