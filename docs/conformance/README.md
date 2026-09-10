# OIDF conformance harness

The OpenID Foundation conformance suite, wired into CI as a merge gate (issue
#37). Certification is not a launch event: the payoff is keeping the profile
matrix green release over release, so the suite runs continuously, not once.

This directory is the documentation. The harness itself (the pinned stack, the
cert config, the profile matrix, the results gate, and the one-command runner)
lives in [`deploy/conformance/`](../../deploy/conformance).

## What enforces TODAY, and what does not

Read this table before trusting a green check. The live OIDF suite is **not
provisioned in this repo**: the runner is an owner/infra action. So the live lane
drives zero plans and **enforces nothing today**, and it is named and banner-ed so
it cannot be mistaken for a passing gate. The static lane is the conformance
enforcement that is real right now, and no repository variable gates it.

| Trigger | Where | What | Enforcing today? |
|---------|-------|------|------------------|
| Every PR, static | `ci.yml` `invariants` job -> `scripts/conformance-check.sh` | Results-gate unit tests, matrix + compose shape, plan-config rendering, digest pinning across every file under `deploy/conformance`, fail-closed wiring, downgrade confinement. No live suite. | **Yes.** Gated by no variable; a real required check. |
| Every PR, live | `ci.yml` `conformance-live` job | When provisioned: drives the merge-gate OP-profile subset against an ephemeral deployment and fails closed on any non-PASS. Today: prints `NOT ENFORCING` and drives nothing. | **No.** Advisory, and says so in its own name. Do NOT make it a required check until it is enabled. |
| Nightly | `conformance-nightly.yml` | The full profile matrix; archives logs; publishes the status badge; **fails the run** if the matrix did not pass. | No (scheduled only, never a gate). Inert until enabled. |
| Nightly | `conformance-track-master.yml` | Runs against the suite's untrusted master image as an early warning. | No, and secret-isolated. |

Two design points worth stating plainly, because both were fail-open bugs first:

- The live job has **no job-level `if:`**. GitHub reports a SKIPPED job to branch
  protection as SUCCESS, so a required check gated on a repository variable goes
  silently GREEN the moment that variable is unset or mistyped. A merge gate must
  never be skippable into a pass, so the job always runs and reports honestly.
- `run-conformance.sh` **fails closed**. A missing OIDF runner, an empty profile
  selection, a crashed selector, or an unrenderable plan config are each a
  non-zero exit. It exits 0 only after actually driving a plan and passing every
  module, so it can never be vacuously green.

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
  only on a real PASS: `deploy/conformance/test_parse_results.py`;
- the cert config parses under the strict schema and its downgrades (including
  anonymous `registration_mode = "open"`) are confined, so the shipped default
  stays hardened: `crates/ironauth-config/tests/conformance_cert_config.rs`;
- the committed Argon2id seed hash really does verify the committed cert
  password, through the product's own verifier:
  `crates/ironauth-oidc/tests/conformance_seed.rs`;
- the profile matrix and compose file are well formed, every enabled profile
  renders a valid runner plan config, every image reference under
  `deploy/conformance` (compose `image:` keys, `docker run` invocations, and
  `Dockerfile` `FROM` bases) is pinned by digest, the harness cannot fail open,
  and no downgrade has leaked into the default: `scripts/conformance-check.sh`.
  One image is outside that scope: the `ironauth-cert` service builds from
  `deploy/Dockerfile`, whose base tags (`rust`, `debian`) live outside
  `deploy/conformance`; pinning them is an owner/infra item on the RUNBOOK
  owner-action list, not something this check enforces.

Needs the provisioned runner (owner/infra; the complete list is in the RUNBOOK):

- the real suite image digests in `deploy/conformance/SUITE_VERSION` (they are
  all-zero placeholders today, which fail closed);
- the suite's trust of the OP self-signed CA;
- the OIDF Python runner (`run-test-plan.py`) on PATH;
- the repository variable `CONFORMANCE_ENABLED=true`;
- validating the generated plan config and the plan-spec variant syntax against
  the real runner on the first live run;
- only THEN promoting the live check to a required branch-protection check, and
  renaming it so it no longer says "advisory".

Until those are done, no live conformance result exists, and nothing in this
repo claims otherwise. In particular the seeded-regression demonstration in
[MATRIX.md](MATRIX.md) documents the MECHANISM; it has not been run against the
live suite here.

## MCP authorization

[`mcp.md`](mcp.md) is the MCP authorization conformance page (issue #129). It is
GENERATED from measured results by `scripts/gen-mcp-conformance.py`; run
`scripts/mcp-conformance.sh` to remeasure and regenerate it. It is linked from here
because `docs/llms.txt` excludes this whole directory as generated fixtures, so a page
nothing links to is a page nothing can find.

## Shared Signals: SETs judged by a second implementation

`scripts/ssf-set-external-validation.sh` is issue #143's third acceptance
criterion, and it is the one obligation this repository cannot meet with its own
code: emitted Security Event Tokens must "validate with an external, independent
JWT/SET library against the environment JWKS". Verifying an `ironauth-jose`
signature with `ironauth-jose` is one implementation agreeing with itself, and a
shared misreading of RFC 8417 or RFC 7515 passes in both directions.

Two steps. `crates/ironauth-oidc/tests/ssf_set_corpus.rs` mints one SET per
algorithm a provisioned environment holds (EdDSA, ES256, RS256 -- what
`DayOneSigningKeys` provisions) and writes each beside the JWKS that environment
publishes and an `expect.json` recording what the minting side believes it
produced. `scripts/validate-set-external.py` then judges that corpus with PyJWT,
hash-pinned in
[`requirements-set.txt`](../../deploy/conformance/requirements-set.txt). Every
expectation comes from the corpus rather than from constants the validator keeps
its own copy of: a validator holding its own expected issuer would keep passing
after the issuer stopped matching.

It is deliberately NOT stdlib-only, which is the opposite of the rule the other
gates follow. A stdlib-only second implementation would be a JOSE implementation
this repository wrote, which is the thing the criterion rules out.

The negative controls are the other half. A validator misconfigured into
accepting anything prints the same "all valid" a working one does, so five
mutations are applied to every token and each must be REJECTED: a flipped
signature bit, each other algorithm's key, a declared algorithm that is not the
one it was signed with, and a wrong audience. One accepted control fails the
run. (The first version flipped the last base64url CHARACTER of the signature
and that control passed for RS256, because a 256-byte signature ends in a
one-byte group whose final character carries four bits the decoder discards --
so the "tampered" token was the original. It flips a decoded byte now.)

This lane runs on every PR, in the `invariants` job. Unlike the OIDF profiles
above it needs no provisioned runner and no owner action.
