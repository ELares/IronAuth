# Conformance runbook

How to provision the runner, triage a suite failure, and bump the pinned suite
version. Aimed at the owner/operator; the day-to-day developer path is the
one-command local reproduction in
[`deploy/conformance/README.md`](../../deploy/conformance/README.md).

## Owner/infra actions still outstanding

This list is the honest, COMPLETE account of what is not done. Until every item
below is finished, the live conformance lane drives zero plans and enforces
nothing; it is advisory, it is named so, and it prints a `NOT ENFORCING` banner.
The runner-independent half (`scripts/conformance-check.sh` plus the Rust
confinement and seed tests) is verified on every PR and is what enforces today.

The items below need registry network access, a real suite runner, or repo
settings, so they are owner actions and are NOT done in the repo:

1. Resolve the real image digests. The digests in
   [`deploy/conformance/SUITE_VERSION`](../../deploy/conformance/SUITE_VERSION)
   are all-zero placeholders that fail closed. Resolve each against a
   certification-representative suite release:

   ```
   docker pull registry.gitlab.com/openid/conformance-suite/server:release-vX.Y.Z
   docker image inspect registry.gitlab.com/openid/conformance-suite/server:release-vX.Y.Z \
       --format '{{index .RepoDigests 0}}'
   ```

   Paste each `image@sha256:...` into the matching `*_IMAGE` line and record the
   tag in the matching `*_VERSION` line. Do the same for mongo, postgres, and
   nginx. `scripts/conformance-check.sh` verifies every compose image stays
   pinned by digest.

2. Wire the suite's trust of the OP CA. `gen-certs.sh` writes `tls/ca.crt`; the
   compose mounts it into the suite container's
   `/usr/local/share/ca-certificates`. Confirm the suite's Java truststore picks
   it up for the pinned image (some releases need `update-ca-certificates` in an
   entrypoint, or the CA added to the JVM truststore). This is the one step most
   likely to need a per-release tweak; validate it first.

3. Provide the OIDF Python runner. Vendor or install `run-test-plan.py` from the
   pinned suite release and put it on PATH, so `run-conformance.sh` can drive
   plans. Its Python dependencies are already exact- and hash-pinned in
   `deploy/conformance/requirements.txt`, and every workflow that drives the
   suite installs them with `pip install --require-hashes`, so there is nothing
   to pin by hand; only the runner script itself is missing.

   Until it is on PATH, `run-conformance.sh` exits 1 with a diagnostic. That is
   deliberate: it used to `continue` past a missing runner and exit 0, so a CI
   run that drove ZERO plans reported the conformance gate as GREEN. A harness
   that cannot run the suite must never report the suite as passing.

4. Validate the generated plan config against the real runner. `run-conformance.sh`
   generates each plan's config from `profile-matrix.yaml` via
   `gen-plan-config.py` (issuer, discovery URL, and browser-automation login all
   come from the matrix, so the exact-string issuer has one definition). The
   shape is asserted on every PR, but it has never been fed to the actual OIDF
   runner. On the first live run, confirm against the pinned release:
   - the config schema (`server.discoveryUrl`, the `browser` automation block,
     and the form field ids the login and consent pages actually render);
   - the plan-spec variant syntax `plan-id[k=v,...]` that the runner is invoked
     with, which is the other thing only a live runner can confirm.
   Expect this and the CA truststore (step 2) to be the two steps that need a
   per-release tweak.

5. Set the repository variable `CONFORMANCE_ENABLED=true`. Until then the
   `conformance-live` job still RUNS (it is never skipped, because a skipped job
   reports to branch protection as SUCCESS) but it drives nothing and prints a
   `NOT ENFORCING` banner. The nightly workflows are inert until it is set; they
   are scheduled-only and never required checks, so nothing there can be turned
   green by a skip.

6. Promote the live check to required, and rename it. Only after steps 1 to 5 are
   done and a live run is genuinely green: rename the `conformance-live` job (its
   name currently says `advisory until provisioned; NOT a gate`, which must stop
   being true before it becomes a gate) and add it to the default branch's
   protection rules. Adding it while it is advisory would make a required check
   out of a job that verifies nothing. This is a repo-settings decision and is
   intentionally not automatable from the repo.

7. Demonstrate the seeded regression. Run one of the three seeded regressions in
   [MATRIX.md](MATRIX.md) against the live suite, confirm the gate goes RED, and
   revert to green. The mechanism is documented and each seed is a single reviewed
   line, but the demonstration itself needs the runner, so the acceptance
   criterion is NOT yet satisfied.

8. Confirm the DCR posture end to end. The cert config uses
   `registration_mode = "open"` (the only anonymous mode) so the suite registers
   its own clients. A DCR-created client starts quarantined (consent shown,
   redirect set restricted to what it registered), which is compatible with the
   suite. If a profile needs a non-quarantined or token-gated client, either
   switch to `registration_mode = "token_gated"` and seed an initial access
   token, or auto-verify DCR clients in the cert environment. Validate on the
   first live run.

9. Pin the OP-under-test image's base tags. The `ironauth-cert` service builds
   from [`deploy/Dockerfile`](../../deploy/Dockerfile), whose bases are mutable
   tags (`FROM rust:1.97-bookworm` and `FROM debian:bookworm-slim`). That file is
   outside `deploy/conformance`, so the always-on digest scan in
   `scripts/conformance-check.sh` (which now also covers `Dockerfile` `FROM`
   bases inside the harness directory) does not reach it, yet the determinism
   rule (a rerun months later resolving the identical bits) applies to the whole
   cert stack. Pin each base by digest the same way as the suite images in step 1:

   ```
   docker pull debian:bookworm-slim
   docker image inspect debian:bookworm-slim --format '{{index .RepoDigests 0}}'
   ```

   Paste each `image@sha256:...` back into `deploy/Dockerfile`. This touches the
   product image, not just the conformance harness, so it carries build-lane risk
   and is deliberately kept as an owner/infra decision separate from the #37
   harness work.

The badge job's `contents:write` token is already scoped to that single job in
`conformance-nightly.yml`; there is nothing for an owner to add beyond enabling
the workflow. The PR pipeline never holds a write token.

## Triaging a suite failure

1. Read the gate output. `parse_results.py` prints one line per module; a
   `BLOCK` line names the module and why (FAILED, unreviewed WARNING, REVIEW,
   SKIPPED, or did-not-finish). The archived `results/` artifact has the full
   suite logs.
2. Reproduce locally against the single failing profile:

   ```
   cd deploy/conformance
   ./run-conformance.sh --profile <plan-id> --up
   ```

   Open the suite UI at `https://localhost.emobix.co.uk:8443` to step through the
   test module and read its detailed log.
3. Classify:
   - a real protocol regression -> fix the provider; the gate did its job;
   - a genuine, understood suite quirk (a WARNING) -> add a reviewed entry to
     `deploy/conformance/warning-waivers.json` with a written reason and an issue
     link. Only WARNING is waivable; REVIEW, FAILED, and SKIPPED never are. An
     entry with no reason waives nothing.
4. Never make the gate green by loosening `parse_results.py`. The only sanctioned
   ways to accept a non-PASS are: fix the provider, or add a reviewed WARNING
   waiver.

## Bumping the pinned suite version

1. The `conformance-track-master` nightly is the early warning: if it starts
   failing on a condition the pinned matrix passes, an upstream change is coming.
2. Resolve the new release's digests (step 1 above) into `SUITE_VERSION`.
3. Run the full matrix locally (`./run-conformance.sh --trigger nightly --up`)
   against the new pin and triage any new WARNING/FAILED as above.
4. Open a PR with the `SUITE_VERSION` change. The diff is reviewed like any
   other; the always-on static checks confirm the pins are still digests.

## Certification submission

The archived `results/` artifacts are the suite log exports in the format the
OIDF certification submission consumes, so wave-1 certification (a separate
issue) can submit CI outputs directly. Retention is 90 days for the nightly
matrix. Formal submission, membership, and fees are out of scope here.
