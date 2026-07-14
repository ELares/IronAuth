# Conformance runbook

How to provision the runner, triage a suite failure, and bump the pinned suite
version. Aimed at the owner/operator; the day-to-day developer path is the
one-command local reproduction in
[`deploy/conformance/README.md`](../../deploy/conformance/README.md).

## Owner/infra actions still outstanding

The harness is complete and its runner-independent half is verified on every PR.
The following require registry network access and repo settings, so they are
owner actions and are NOT done in the repo:

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
   pinned suite release so `run-conformance.sh` can drive plans. Pin the runner's
   Python deps from `deploy/conformance/requirements.txt`.

4. Set the repository variable `CONFORMANCE_ENABLED=true`. Until then both the
   merge-gate `conformance` job and the nightly workflows are skipped (never a
   false red).

5. Promote the merge-gate check to required. Add the `OIDF conformance
   (merge-gate subset)` check to the default branch's protection rules. This is a
   repo-settings decision and is intentionally not automatable from the repo.

6. Confirm the DCR posture end to end. The cert config uses
   `registration_mode = "open"` (the only anonymous mode) so the suite registers
   its own clients. A DCR-created client starts quarantined (consent shown,
   redirect set restricted to what it registered), which is compatible with the
   suite. If a profile needs a non-quarantined or token-gated client, either
   switch to `registration_mode = "token_gated"` and seed an initial access
   token, or auto-verify DCR clients in the cert environment. Validate on the
   first live run.

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
