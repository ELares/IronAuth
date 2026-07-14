# OIDF conformance harness

The OpenID Foundation conformance suite, wired into CI as a merge gate (issue
#37). Certification is not a launch event: the payoff is keeping the profile
matrix green release over release, so the suite runs continuously, not once.

This directory is the documentation. The harness itself (the pinned stack, the
cert config, the profile matrix, the results gate, and the one-command runner)
lives in [`deploy/conformance/`](../../deploy/conformance).

## The three ways it runs

| Trigger | Where | What | Gate? |
|---------|-------|------|-------|
| Every PR, static | `ci.yml` `invariants` job -> `scripts/conformance-check.sh` | Results-gate unit tests, matrix + compose shape, digest pinning, downgrade confinement. No live suite. | Yes (runner-independent) |
| Every PR, live | `ci.yml` `conformance` job | Drives the merge-gate OP-profile subset against an ephemeral deployment; fails on any non-PASS. | Owner-gated (see below) |
| Nightly | `conformance-nightly.yml` | The full profile matrix; archives logs; publishes the status badge. | No (scheduled only) |
| Nightly | `conformance-track-master.yml` | Runs against the suite's untrusted master image as an early warning. | No, and secret-isolated |

## Documents

- [RUNBOOK.md](RUNBOOK.md): provision the runner, triage a suite failure, bump
  the pinned suite version, and the exact owner/infra actions still outstanding.
- [MATRIX.md](MATRIX.md): the profile matrix design (wired now vs deferred), the
  coverage-vs-protocol-surface argument, and the seeded-regression mechanism
  that proves the gate catches a real protocol regression.

## What is verified locally vs what needs the provisioned runner

Verified locally, on every PR, with no external suite:

- the results gate fails on any non-PASS (finished-but-failed, unreviewed
  WARNING, REVIEW, SKIPPED, unfinished, and a vacuously empty run) and passes
  only on a real PASS: `deploy/conformance/test_parse_results.py` (17 tests);
- the cert config parses under the strict schema and its downgrades are confined
  (the shipped default stays hardened):
  `crates/ironauth-config/tests/conformance_cert_config.rs` (4 tests);
- the profile matrix and compose file are well formed, every suite image is
  pinned by digest, and no downgrade has leaked into the default:
  `scripts/conformance-check.sh`.

Needs the provisioned runner (owner/infra, tracked in the RUNBOOK):

- the real suite image digests in `deploy/conformance/SUITE_VERSION`;
- the suite's trust of the OP self-signed CA;
- the OIDF Python runner on PATH;
- promoting the `conformance` merge-gate check to a required branch-protection
  check;
- the `contents:write` token the badge job needs (already scoped to that one
  job; nothing for an owner to add beyond enabling the workflow).
