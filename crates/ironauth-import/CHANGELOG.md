# ironauth-import changelog

All notable changes to the `ironauth-import` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- **Four import defects that left a run PERMANENTLY unable to complete** (issue #55, review
  fold). Each was measured end to end, and each is worse than it sounds, because in every
  case the identities were fine and only the accounting was wrong, so nothing an operator
  looked at said anything was amiss.

  - **Every unparseable line collapsed into ONE ledger row.** Each parse failure was keyed
    on the constant `"<unparsable record>"`, and the ingest dedups on the subject, so the
    second and every later malformed line was SILENTLY DISCARDED. MEASURED with two bad
    lines and one good against a declared `source_total` of 3: `imported=1 failed=1
    accounted=2`, one short forever. It also refuted the engine's own documented "nothing is
    silently dropped". An unparseable or undecodable line is now keyed on a truncated
    SHA-256 of its own BYTES: stable across attempts (so a repeated bad line still dedups on
    a resume), distinct per distinct line, and one-way, so the subject carries no PII out of
    the line it summarizes.
  - **The ledger key is now the LOGIN HANDLE.** It was the id, else the external id, else
    the handle, which is a property of the input only while the input does not change, and
    the documented recovery procedure is to post the source AGAIN. MEASURED: pass 1 delivers
    a record with no external id, pass 2 re-presents the same identity now carrying one, and
    `accounted` reaches 3 against a `source_total` of 2 with `remainder == -1`,
    unsatisfiable forever. The handle is the one required field, so it cannot appear or
    disappear between attempts. Pinned by `a_source_edited_between_attempts_still_reconciles`.
  - **A ledger ingest now reports what it WROTE, not what it was handed.**
    `import_into_run` and `import_lines_into_run` return `RunImportReport`, which carries the
    record tally plus `ledger_written` and `ledger_deduped`. Two SOURCE records sharing one
    login handle are one ledger subject by construction, so they account one row against a
    declared two and the count invariant is unsatisfiable; before this, a caller could not
    tell that from a truncated upload. On a resume a non-zero `ledger_deduped` is the resume
    mechanism working; on a first pass it is a duplicate key in the source.
  - **Invalid UTF-8 is a per-record failure rather than a silent rewrite.**
    `LineSource::next_line` yields the line's BYTES and the engine owns the decode, so a
    Latin-1 login handle fails its own record with a reason instead of creating an account
    carrying U+FFFD that nobody can log in to, counted as an import, with no error anywhere
    (MEASURED).

- **A failed record is accounted INCONSISTENT** (issue #55, review fold). Every outcome was
  written `consistent: true`, including failures, and the only surface that enumerates
  records pages `consistent = false` or `backfilled = false`. MEASURED: a run reported
  `failed=1` while both violation queries returned `{"items":[]}`. Issue #55 requires every
  failure be REPORTED with its record identity, and a durable row nothing can read is not a
  report; writing `true` also made the consistency invariant vacuous for every bulk import.
  `false` is what the store's own schema-migration ingest has always written for a failed
  record, so the two producers of that table now agree. A run holding a failed record is
  therefore BLOCKED on consistency until it is reconciled or abandoned, which is the honest
  reading of "this migration did not fully succeed".

- **The import applies the management edge's own input validation** (issue #55, review
  fold). `prepare_record` now runs the `require_non_empty` rule (which also TRIMS) on the
  identifier, the external id, and the password hash, exactly as `POST .../users` does.
  MEASURED before it: `identifier: ""` was a 400 on the live path and an IMPORT here, and
  `" a@x.test "` was stored verbatim here and trimmed there, so the two writers of one
  column disagreed about what a login handle is. (NUL bytes and replacement characters are
  accepted by both paths; that is pre-existing and untouched.)

- **The streaming memory bound is measured on the LOOP THAT SHIPS** (issue #55, review
  fold). `peak_held_outcomes_do_not_grow_with_the_record_count` drove `LedgerBatch` directly
  and substituted `held.clear()` for the shipped flush, so it never constructed a
  `LedgerSink` at all. MEASURED by mutation: rewriting `LedgerSink::record` so the sink NEVER
  flushed put production back to O(N) in the record count and left `cargo test -p
  ironauth-import --lib` at 24 passed, NOT KILLED. The flush decision now lives in one
  method, `LedgerBatch::accept`, and `LedgerSink` is generic over its flush destination, so
  the probe drives the SHIPPED sink over a flush that needs no database. Both mutants (the
  accumulator never flushing, and the sink bypassing the decision) are now killed by that
  test.

- **The migration-run adapter is STREAMING, not collect-then-ingest** (issue #55).
  `import_into_run` collected every translated outcome into a `Vec` before ingesting any of
  them, because the engine's observer was synchronous: the engine below it was bounded by one
  record and the adapter above it was O(n) in the record count, which is the opposite of the
  acceptance criterion's streaming memory profile. The observer is now awaited per record, and
  the adapter holds a bounded batch of 256 translated outcomes and flushes it into one audited
  ingest. MEASURED on the shipped accumulator across 256 / 1 000 / 25 000 / 200 000 records:
  the peak held-outcome count is 256 at every point, flat over a 781x range
  (`peak_held_outcomes_do_not_grow_with_the_record_count`).

- A 100k-record LOAD HARNESS (issue #55), `#[ignore]`d and run by hand:

  ```text
  scripts/with-test-db.sh cargo test -p ironauth-import --features testing \
      --test hundred_k_import -- --ignored --nocapture
  ```

  Every record carries an algorithm-tagged FOREIGN bcrypt hash, and after the run one of
  those hundred thousand imported users is driven through the whole verify-then-rehash
  landing. That conjunction is the point: M6's exit criterion reads "100k-user import WITH
  FOREIGN HASHES completes with verify-then-rehash working", and until now both halves were
  proven APART, this harness importing hashless records while `engine.rs` proved
  verify-then-rehash across five schemes at a scale of about thirty. A criterion stated as a
  conjunction is not met by proving its halves separately. The foreign hash is minted once
  and reused on every line, which costs the measurement nothing because import stores the
  tagged hash without verifying it; hashing a hundred thousand distinct bcrypt values would
  measure bcrypt rather than the importer.

  MEASURED on one hundred thousand identities into a real Postgres: 100 000 created,
  100 000 ledger rows WRITTEN and accounted with none deduped, the run completing through
  the gated transition, in 77.46 seconds, with the process's resident set moving from a
  12 336 KiB baseline to a 13 424 KiB peak. The middle record of the hundred thousand
  (`load-50000@example.test`) was then read back carrying its `bcrypt` tag, verified against
  the original password, rehashed to Argon2id, and re-read with the foreign hash RETIRED and
  the original password authenticating against Argon2id alone. A second run landed at 83.86
  seconds with a 12 384 KiB baseline and a 13 360 KiB peak. Just under one megabyte of growth across a
  hundred thousand records, which is the order the streaming claim predicts and roughly an
  order of magnitude below what the collected outcomes ALONE would have cost. Three
  independent runs of this harness landed between 77 and 93 seconds with the peak within
  100 KiB of that figure every time, so the wall clock is machine-dependent and the memory
  shape is not. Resident set is a coarse instrument and the harness says so; the exact
  bound is the accumulator measurement above.

- **A resumed import no longer double-counts the ledger** (issue #55). A CREATED record was
  accounted under its minted `usr_` id, which is not a property of the input: on a resume the
  same source record is refused by the scope's unique constraint, reported as a skip, and
  accounted under its RECORD KEY, a different blind index from the one the first pass stored.
  The ledger then held two rows for one source record, `accounted` overshot `source_total`, and
  the count invariant went from short to over, so the run could never complete. Every outcome
  is now accounted under the stable record key, which is what makes the ingest's
  `ON CONFLICT DO NOTHING` the resume mechanism. Proved by cancelling an import future
  mid-await at record 400 of 700 and resuming with the whole source
  (`a_killed_import_resumes_without_duplicating_or_losing_records`).

- `import_stream_lines` and `import_lines_into_run` (issue #55): the ASYNCHRONOUS pull form of
  the engine, for a caller whose input arrives frame by frame off a socket and cannot be an
  `Iterator` without buffering the whole body first. The line source, the outcome sink, and the
  record creator are TRAITS (`LineSource`, `OutcomeSink`, `RecordCreator`) rather than async
  closure bounds: a borrowing async closure's future has no general `Send` implementation, so
  an axum handler driving one is refused at the router with nine "implementation of `Send` is
  not general enough" errors naming types the handler never mentions (MEASURED). `IterLines`,
  `CollectOutcomes`, and `DiscardOutcomes` are the adapters; `import_stream` and
  `import_into_run` delegate to them.

  **These are BREAKING changes to `import_stream` and `import_into_run`**, and the diff's own
  rewrite of `crates/ironauth-importers/tests/login.rs` is the migration in miniature. There
  are four:

  1. the observer parameter is now an `OutcomeSink` rather than an `FnMut(RecordOutcome)`.
     Migration: pass `&mut CollectOutcomes::default()` and read its `.0`, or
     `DiscardOutcomes` when the per-record outcomes are not wanted;
  2. both return `Result<_, StoreError>` rather than the bare report, because a sink that
     persists can fail and an import that outruns its accounting is worse than one that
     stops. Migration: `.await?` or `.expect(...)`;
  3. `import_stream` adds an `I::IntoIter: Send` bound, which every `Vec<String>` and array
     already satisfies;
  4. `import_into_run` now returns `RunImportReport` (the record tally plus the ledger's
     written and deduped row counts) rather than `ImportReport`. Migration: `report.records`
     is the old value.

  `LineSource::next_line` also yields `Option<Vec<u8>>` rather than `Option<String>`; it is
  new in this release, so nothing outside the tree can be depending on it.

- An import into a scope that SERVES an active trait schema now VALIDATES the restored trait
  documents (issue #53, PR 1, review fold). The exit covenant needs validation skipped when
  the target scope has NO schema, so a full export re-imports losslessly into a fresh
  instance; the first cut generalized that into skipping validation unconditionally, which
  let a restore into a live scope write documents no live write could have produced, with the
  next cutover scan as the first place an operator would find out. `import_stream` resolves
  the active schema ONCE per run and a violating record is that record's failure through the
  existing per-record report, carrying an RFC 6901 pointer and never the offending value. A
  stored schema that does not compile is treated as no schema rather than failing every
  record, so a corrupt registry cannot turn a restore into a total loss.

- Second-factor restore on import (issue #58/#69, review): `ImportRecord` gains an
  optional `totp` list (`ImportTotp`: the Base32 seed, parameters, friendly name,
  status, and single-use step) and a `recovery_codes` list (`ImportRecoveryCode`: the
  one-way hash and consumed state), which `to_record_line` / `parse_record_line`
  round-trip. The engine decodes and bounds-checks each factor (Base32 seed, digits
  6..=8, period 15..=60, known algorithm/status, 1..=200 char name) and restores it
  through the store's `totp_credentials` / `recovery_codes` re-seal path, so a
  re-imported TOTP factor verifies against the original authenticator and a re-imported
  recovery code redeems. Adds an internal dependency on `ironauth-jose` for the Base32
  decode; no new external crate.
- Migration state-machine wrap (issue #59, exploratory): `import_into_run` drives
  `import_stream` and ingests every per-record outcome (`Created` / `Skipped` /
  `Failed`) into an `ironauth-store` migration run's accounting ledger, so a bulk import
  is wrapped in the invariant-checked state machine. The run's COUNT invariant then
  measures the ingested accounting against the caller's declared `source_total`, so an
  import that does not reconcile with its source cannot be declared complete, and the
  per-record failures stay visible in the operator view. Purely additive (a new `run`
  module); no change to the streaming engine or the record format.
- Credential-registry round-trip (issue #58, review): `ImportRecord` gains an optional
  `credentials` list (a new `ImportCredential`: factor kind, friendly name, optional
  last-used instant), so the full identity export carries every passkey / TOTP /
  recovery-code enrollment and the engine restores each one under the imported user
  (validated to the closed credential-type set and the 1-to-200-character name bound,
  per-record failure isolation preserved; a re-imported duplicate skips without
  re-enrolling). The record shape is additive, so the M7 credential-secret material
  rides the same list.
- Export side of the record format (issue #58): `ImportRecord` now also derives
  `Serialize`, and `to_record_line` writes exactly what `parse_record_line` reads, so
  the full identity export (in `ironauth-admin`) produces the same line-delimited
  format the import consumes and a round-trip is lossless by construction. The record
  gains optional `traits` and `traits_schema_version` fields; the engine restores
  traits VERBATIM through the extended `admin_create`, so an export re-import carries
  a user's identity traits, not only the credential.

- New crate: streaming bulk user import with foreign password-hash support (issue
  #55). IronAuth's migration on-ramp, published as its own semver-versioned crate
  (the passwap pattern): the hash-scheme layer earns outside review of exactly the
  code that most needs it, and the server consumes it as a normal dependency.
  - **`scheme`: the algorithm-tagged foreign-hash layer.** Parse, tag, bounds-check,
    and verify a foreign hash by dispatching on its scheme: bcrypt (all four
    `$2a$`/`$2b$`/`$2x$`/`$2y$` variants), scrypt (RFC 7914 PHC), PBKDF2 (RFC 8018
    PHC over HMAC-SHA256/512), the Argon2 family (RFC 9106 PHC), and Firebase's
    modified scrypt (scrypt key derivation + AES-256-CTR over the account signer
    key) in a canonical `$fbscrypt$` serialization. Known-answer tests per scheme,
    including the published Firebase cross-implementation vector.
  - **Denial-of-service bounds.** Documented maximum cost parameters per scheme
    (bcrypt cost, scrypt log2(N)/r/p, PBKDF2 iterations, Argon2 memory/passes/
    parallelism, Firebase mem_cost/rounds). An out-of-bounds hash is rejected AT
    IMPORT with a per-parameter error, never stored (the Kratos lesson: an
    attacker-supplied cost cannot turn a later login verification into a DoS).
  - **`engine`: the streaming import engine.** Consumes an iterator of
    newline-delimited JSON records ONE AT A TIME (bounded memory, never collecting
    the input) and creates each user through the audited, isolation-scoped
    `ActingUserRepo::admin_create` (issue #52), so imported users get lifecycle,
    tenant isolation, and PII encryption (issue #48) for free. Per-record failure
    isolation (a bad record is reported and skipped, the batch continues; nothing
    silently dropped), idempotent re-import (a duplicate id / external id / login
    handle is a skip, not a second row), and scope confinement (a cross-scope id is
    rejected, so an import into one tenant cannot touch another). Progress-observable
    through a per-record callback and an aggregate `ImportReport`.
  - **Verify-then-rehash.** The stored foreign hash is a one-way verifier; the login
    path (ironauth-oidc) verifies it and, on first success, rehashes the password to
    the native Argon2id verifier and retires the foreign hash, so migration is
    lossless and no plaintext password is ever stored.
  - **Determinism seam.** `created_at` reads from `env.clock()` and the rehash salt
    from `env.entropy()`; no raw `SystemTime` or RNG.
