# deploy/conformance

The OIDF conformance harness: a pinned stack, a certification-representative
IronAuth config, a reviewed profile matrix, a strict results gate, and a
one-command runner. Design and operations docs are in
[`docs/conformance/`](../../docs/conformance).

## One-command local reproduction

Run any profile against a local server (needs Docker and the resolved suite
digests; see the RUNBOOK for provisioning):

```
./run-conformance.sh --profile oidcc-basic-certification-test-plan --up
```

`--up` generates the OP self-signed cert, brings up the pinned stack, and seeds
the deterministic user. Drop `--up` to reuse a running stack. Run a whole
trigger with `--trigger merge-gate` or `--trigger nightly`. Open the suite UI at
`https://localhost.emobix.co.uk:8443`.

It runs on stock macOS bash (3.2), which is an acceptance criterion of issue #37,
so the runner uses no bash 4 construct; `conformance-check.sh` enforces that.

**It fails closed.** It exits 0 only after actually driving at least one plan and
passing every module. If the OIDF runner is not on PATH, if the selection matches
no enabled profile, if the selector itself crashes, or if a plan config cannot be
rendered, it exits NON-ZERO. It never reports a suite it could not run as green.
Since the runner is not provisioned yet (see the RUNBOOK), the command above
currently exits 1 with a diagnostic; that is the correct behavior, not a bug. To
exercise the selection and orchestration logic without a runner, and get a loud
"nothing was verified" notice instead, add `--allow-missing-runner`. That flag is
for local dry runs only: it is refused when `CI=true`, and a static check fails
the build if any workflow passes it.

## What is here

| File | Role |
|------|------|
| `SUITE_VERSION` | Pinned image digests (also the compose env-file). |
| `docker-compose.yml` | The stack: postgres, ironauth-cert, the `op` TLS proxy, mongodb, the suite, its httpd. |
| `ironauth.toml` | Certification-representative config. Turns on the cert-only downgrades; the shipped default stays hardened. |
| `nginx-tls.conf` | TLS terminator that fronts the OP as the `op` issuer host. |
| `gen-certs.sh` | Generates the self-signed CA + OP cert (SAN `op`). Output is gitignored. |
| `seed.sql` / `seed.sh` | Deterministic operator/tenant/environment + login user. A seed script, not a migration. |
| `cert-user-password.phc` | The COMMITTED Argon2id hash of the throwaway cert password, so seeding pulls no image and touches no network. |
| `profile-matrix.yaml` | The reviewed profile matrix (which plans run on which trigger). |
| `gen-plan-config.py` | Renders the runner's plan config from the matrix, so the issuer has ONE definition. |
| `parse_results.py` | The results gate: fails on any non-PASS. |
| `test_parse_results.py` | Unit tests for the gate and the normalizer (standard library only). |
| `normalize_runner_export.py` | Adapts the OIDF runner output to the gate's input shape. |
| `requirements.txt` | The harness's Python deps, exact- and hash-pinned. |
| `warning-waivers.json` | Reviewed WARNING waivers (empty by default). |
| `fixtures/` | Sample runner outputs the unit tests grade. |

## Verify the harness without the live suite

```
python3 test_parse_results.py                                  # the results gate
../../scripts/conformance-check.sh                             # matrix, plan config, digest pins, fail-closed wiring, confinement
cargo test -p ironauth-config --test conformance_cert_config   # cert-config confinement
cargo test -p ironauth-oidc  --test conformance_seed           # the committed seed hash really verifies
```

## Determinism notes

- Issuer: `ironauth.toml` sets `public_url = https://op` with NO trailing slash,
  so the per-environment issuer is exactly `https://op/t/cert/e/cert` on both
  well-known forms (the #194 exact-match surface). The matrix records that exact
  string; `conformance-check.sh` rejects a trailing slash.
- Images: every image reference in this directory is pinned by sha256 digest,
  never a mutable tag. `conformance-check.sh` enforces that across EVERY file
  here, shell scripts included, not just `docker-compose.yml`.
- Python: exact- and hash-pinned in `requirements.txt`; CI installs with
  `--require-hashes` against a pinned CPython 3.12.
- Seed: one fixed operator/tenant/environment/user, so login and consent are
  scriptable and repeatable. Clients are registered by the suite via DCR. The
  user's Argon2id hash is COMMITTED (`cert-user-password.phc`), so seeding runs
  no container and fetches no package; `cargo test -p ironauth-oidc --test
  conformance_seed` proves that hash verifies the committed password using the
  product's own verifier.
- DCR throttle: the cert config disables the migration-0018 rate limit and
  raises the client cap FOR THE CERT ENVIRONMENT ONLY, so the suite's rapid
  registrations are not throttled. The shipped default keeps the conservative
  limits.
