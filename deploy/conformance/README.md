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

## What is here

| File | Role |
|------|------|
| `SUITE_VERSION` | Pinned image digests (also the compose env-file). |
| `docker-compose.yml` | The stack: postgres, ironauth-cert, the `op` TLS proxy, mongodb, the suite, its httpd. |
| `ironauth.toml` | Certification-representative config. Turns on the cert-only downgrades; the shipped default stays hardened. |
| `nginx-tls.conf` | TLS terminator that fronts the OP as the `op` issuer host. |
| `gen-certs.sh` | Generates the self-signed CA + OP cert (SAN `op`). Output is gitignored. |
| `seed.sql` / `seed.sh` | Deterministic operator/tenant/environment + login user. A seed script, not a migration. |
| `profile-matrix.yaml` | The reviewed profile matrix (which plans run on which trigger). |
| `parse_results.py` | The results gate: fails on any non-PASS. |
| `test_parse_results.py` | Unit tests for the gate and the normalizer (17 tests, standard library only). |
| `normalize_runner_export.py` | Adapts the OIDF runner output to the gate's input shape. |
| `warning-waivers.json` | Reviewed WARNING waivers (empty by default). |
| `fixtures/` | Sample runner outputs the unit tests grade. |

## Verify the harness without the live suite

```
python3 test_parse_results.py            # the results gate (17 tests)
../../scripts/conformance-check.sh        # matrix + compose + digest pins + confinement
cargo test -p ironauth-config --test conformance_cert_config   # cert-config confinement
```

## Determinism notes

- Issuer: `ironauth.toml` sets `public_url = https://op` with NO trailing slash,
  so the per-environment issuer is exactly `https://op/t/cert/e/cert` on both
  well-known forms (the #194 exact-match surface). The matrix records that exact
  string; `conformance-check.sh` rejects a trailing slash.
- Images: every service is pinned by sha256 digest via `SUITE_VERSION`, never a
  mutable tag.
- Seed: one fixed operator/tenant/environment/user, so login and consent are
  scriptable and repeatable. Clients are registered by the suite via DCR.
- DCR throttle: the cert config disables the migration-0018 rate limit and
  raises the client cap FOR THE CERT ENVIRONMENT ONLY, so the suite's rapid
  registrations are not throttled. The shipped default keeps the conservative
  limits.
