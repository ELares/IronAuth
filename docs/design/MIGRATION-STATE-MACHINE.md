# Migrations as an invariant-checked state machine (issue #59)

Status: EXPLORATORY. This is a working prototype and a written recommendation, not
a stability commitment. The surface may change or be withdrawn per the feature
maturity ladder.

## Why

Migrations are where identity systems strand users: an import that half completed,
a schema change applied while thousands of identities still fail validation, a
tenant move that copied users but not credentials. Today's tools model a migration
as a fire and forget job, so nothing structurally prevents an operator from
declaring victory while inconsistent users still exist. This work tests whether
wrapping the existing building blocks (the streaming bulk import of issue #55 and
the schema migration jobs of issue #53) in an explicit, invariant checked state
machine measurably improves operator safety. The prior art reference is
SuperTokens v12's `migration_mode`, still in canary; no incumbent ships an
invariant gated completion.

## The state machine

A wrapped migration is a `migration_runs` row that walks a closed set of NAMED
states through GATED transitions:

```
defined ── validating ── running ── reconciling ──▶ complete
   │            │            │            │  ▲
   │            │            │            └──┘  (back edge: more work found)
   └────────────┴────────────┴────────────┴──▶ abandoned
```

| State         | Meaning                                                                    |
| ------------- | -------------------------------------------------------------------------- |
| `defined`     | The run is created; `source_total` and `backfill_expected` are recorded.   |
| `validating`  | The underlying job's pre-flight validation is in progress.                 |
| `running`     | The underlying job is executing; records are being touched.                |
| `reconciling` | Execution finished; invariants are evaluated and offending records triaged.|
| `complete`    | Terminal success. Reachable ONLY when every invariant re-evaluates satisfied.|
| `abandoned`   | Terminal, explicit, audited giving up so a stuck run is never forgotten.   |

Legality is enforced in two layers. `MigrationState::can_transition_to` allows only
the non gated forward edges (and the `reconciling -> running` back edge for work
discovered late); `ActingMigrationRunRepo::transition` refuses anything else with a
typed `IllegalMigrationTransition`. The two consequential edges have dedicated
methods so they cannot be taken by accident:

- `try_complete` is the ONLY path to `complete`. It locks the run row, re-evaluates
  every invariant in the same transaction, and takes the edge (writing the
  `migration_run.complete` audit row) only when all are satisfied. Otherwise it
  returns `CompletionOutcome::Blocked(violated)` and writes nothing: a blocked
  attempt leaves no state change and no audit trail, so a `complete` row always
  means the invariants were clean.
- `abandon` is the ONLY path to `abandoned`. It records an operator safe reason as
  the audit row's `detail`, so the reason a migration was given up is attributable.

Every transition routes through the store's single audited write path
(`write_audited`), so each carries actor attribution and a correlation id.

## The invariants (re-evaluated, never cached)

Three invariant families are evaluated by `evaluate_invariants_in_tx`, which runs a
single grouped `count(*) FILTER (...)` query over `migration_run_records` at check
time. The verdict is NEVER stored on the run row; it is recomputed from the ledger
on every completion attempt and every operator read. This is the property that
makes the machine correct across a process restart: re-opening the store and
calling `evaluate` reproduces the exact verdict from the persisted rows.

- **Count.** `source_total == imported + failed + skipped`, with no unaccounted
  remainder. `source_total` is the declared ground truth denominator; the accounted
  side is the live row count grouped by outcome. An injected off by N (a source
  total that does not match the accounted records) yields a non zero remainder and
  blocks completion.
- **Consistency.** ZERO records flagged `consistent = false` (a failed transform, a
  failed re-validation, missing credential material). Any inconsistent identity
  blocks completion; the offending records are enumerable.
- **Backfill sentinel.** Every touched record must be `backfilled = true`, and the
  marked population must reach `backfill_expected`. Any unmarked record blocks
  completion; the offending records are enumerable.

## Unblocking a blocked run (the `reconciling` back edge, made real)

`reconciling` is not a dead end: each invariant family has an in place, audited unblock
path, so a run blocked on a violation is triaged and completed WITHOUT abandoning it.
The verdict is never cached, so the next `try_complete` re evaluates live and the fixed
run completes.

- **Count.** RE-INGEST the missing (or previously miscounted) records with
  `ingest_outcomes`; the idempotent per run unique index means a resumed ingest never
  double counts, and the accounted total then reaches `source_total`.
- **Consistency.** RECONCILE the offending identities with
  `ActingMigrationRunRepo::reconcile_records`: an operator who triaged or repaired an
  identity flips its `consistent` flag back to true and clears its recorded reason. The
  call is audited (`migration_run.reconcile`), takes the run row lock, and is refused on
  a terminal run, so a completed or abandoned run's ledger cannot be quietly re-opened.
- **Backfill sentinel.** MARK the untouched records with `mark_backfill`.

All three are symmetric: a violation that is removed at the source unblocks its
invariant on the next completion attempt, satisfying the "removing the cause unblocks"
property for every invariant family, not just count and the sentinel.

## Abandonment and its cleanup story

`abandon` is the explicit, audited terminal giving up: it records an operator safe
reason (the `migration_run.abandon` audit row's `detail`), takes the run row lock, and
is refused on an already terminal run, so a stuck half applied migration can never be
silently forgotten. It marks the RUN row terminal; it deliberately does NOT itself
delete or roll back the half applied DATA, because a safe rollback is workload specific
(a bulk import may have created real users who have since logged in; a schema migration
may have re-stamped a subset of identities).

The documented cleanup semantics for an abandoned run's half applied data:

- **What state the data is left in.** Every record the run touched remains in the
  `migration_run_records` ledger with its final `outcome`, `consistent`, and
  `backfilled` flags, and every identity the underlying job created or mutated remains
  in `users` exactly as the job left it. The ledger is therefore the operator's
  authoritative worklist of what the abandoned run touched: the paginated violation view
  still enumerates the inconsistent and unmarked records (the ledger is readable in any
  non `defined` state, terminal included), each naming the opened subject.
- **The operator's cleanup path.** Using that worklist, the operator reconciles the
  half applied identities through the #52 admin user API: a partially created or
  mis-migrated user is corrected or removed with the standard admin user lifecycle
  (`user.update` / `user.delete`), each of which is itself audited, so the cleanup is
  attributable. A bulk import's created users are removed (or kept and repaired) one by
  one from the ledger's `imported` records; a schema migration's re-stamped identities
  are re-migrated or reverted via a fresh #53 job. EXECUTING the cleanup is out of scope
  for this exploratory prototype (no automatic compensating action is wired), but the
  SEMANTICS above are the contract: the abandoned run's touched set is preserved and
  enumerable precisely so an operator can action it, rather than a silent partial state.
- **A future minimal hook.** A cheap production hardening would emit, on abandon, a
  single audited snapshot of the touched-record subject set (or simply lean on the
  already-persisted ledger as that snapshot) so an external cleanup job can consume it;
  the ledger already retains everything such a hook would need.

## Persistence (migration 0043)

Two new tenant scoped tables, both with forced row level security, the
`(tenant, environment)` isolation policy, a nonempty scope CHECK, closed set CHECKs,
and column scoped least privilege grants (the #31 lesson). Only the DATA plane
(`ironauth_app`) mutates these tables (it creates runs, drives transitions, ingests and
reconciles records); the CONTROL plane (`ironauth_control`, the operator API) is granted
SELECT ALONE and never INSERT or UPDATE, because its three endpoints only read:

- `migration_runs`: the state pointer plus `source_total`, `backfill_expected`, a non
  PII `subject_ref` back to the wrapped job, and the `abandoned_reason`.
- `migration_run_records`: one row per touched source record, carrying its `outcome`,
  `consistent`, and `backfilled` flags. A record's natural subject can be end user
  PII (a bulk import key may be an email), so it is stored ONLY as a blind index
  (`subject_bidx`, for lookup and per run dedup) and an envelope sealed value
  (`subject_sealed`, opened only for an authorized operator view), never plaintext
  (issue #48). A partial unique index on `(run_id, subject_bidx)` makes ingest
  idempotent so a resumed run never double counts.

## Operator API surface

Three environment scoped, permission gated read endpoints in `ironauth-admin`
(the write transitions are audited store operations driven by the migration
machinery; an admin SPA visualization is M9, out of scope here):

- `GET .../migration-runs` lists a scope's runs (cursor paginated).
- `GET .../migration-runs/{run_id}` returns the current state, the per state record
  counts, and every invariant's LIVE evaluation with its current values, plus the
  list of blocking invariants.
- `GET .../migration-runs/{run_id}/violations?invariant=...` pages the specific
  records violating an invariant, each naming the offending identity (opened) and
  its reason.

## The two wired kinds, and the tenant move fit

The generic seam is `ingest_outcomes`: each kind translates its native per record
outcomes into the run's ledger, and the machine is workload agnostic thereafter.

- **Bulk import (#55).** `ironauth_import::import_into_run` drives `import_stream`
  and maps each `RecordOutcome` (`Created`/`Skipped`/`Failed`) into the ledger. A
  failed import LINE is an accounted failure (it created no half formed identity),
  so the COUNT invariant is the primary gate for an import.
- **Schema migration (#53).** `ironauth_store`'s `ingest_schema_migration_job` is the
  shipped adapter (the counterpart of `import_into_run`): it reconciles a completed
  trait migration job's per record FAILURE report into the ledger, ingesting each
  failed identity as failed + inconsistent with its RFC 6901 JSON Pointer reasons as
  the operator safe detail (never a trait value, so no PII), so the CONSISTENCY
  invariant refuses to complete the run while any migrated identity failed
  re-validation. The failed records are marked processed, so consistency is the sole
  gate; the operator triages each with `reconcile_records` (or re-runs the job) before
  completion. The #53 job report enumerates failures but not the migrated subjects, so
  a schema migration run's `source_total` accounts its failure population; a production
  adapter that also accounts the migrated successes for the COUNT invariant would stream
  per record outcomes the way the import path does (a documented follow-up, not a
  regression in the exploratory prototype).
- **Tenant move (M5, fit only).** A tenant move is the same shape: `source_total` is
  the source scope's identity count; each moved identity is a record whose
  consistency flag asserts that BOTH the profile and the credential material landed
  (the classic "copied users but not credentials" failure becomes a consistency
  violation), and the sentinel asserts every source row was touched. It fits the
  model without a new invariant family; only the ingest adapter (M5's to build) is
  missing.

## What the state machine CAUGHT in seeded-failure testing

Integration tests seed each failure class and assert the machine blocks completion
and names the fault. All pass against a real Postgres.

- An injected off by N (five declared, three accounted) is caught by the COUNT
  invariant; the current value names `remainder=2`; completion is blocked; and once
  the two missing records are accounted, completion succeeds.
- A seeded inconsistent identity is caught by the CONSISTENCY invariant; the
  paginated violation view names the exact offending subject; the run stays in
  `reconciling`. RECONCILING that record with `reconcile_records` then re-evaluates the
  invariant satisfied (live, from the flipped row) and completion SUCCEEDS: the
  consistency unblock is symmetric with count re-ingest and sentinel marking.
- A missing backfill sentinel is caught by the BACKFILL invariant; the violation view
  names the unmarked record; marking it unblocks completion.
- A real schema migration job with failed identities, wrapped through the shipped
  `ingest_schema_migration_job` adapter, is blocked by CONSISTENCY, and the violation
  view names EXACTLY the identities the job's failure report listed.
- A property style test drives every transition ordering it can (repeated completion
  attempts, the `reconciling -> running -> reconciling` round trip) against a run
  with a standing violation and asserts the run NEVER reaches `complete`; the only
  path to `complete` is to clear the violation. Illegal edges (completing outside
  `reconciling`, skipping a state, re-abandoning a terminal run) are refused.
- A restart chaos test builds a blocked run, drops the in memory handle, re-opens the
  store against the same database, and asserts the state survived (`reconciling`) and
  the invariant verdict RE-EVALUATED to the same violation (never a cached verdict);
  the fix and completion then work through the restarted handle.

## Overhead

The machine adds one `migration_runs` row per run and one `migration_run_records`
row per touched source record. The record row carries an AEAD sealed subject and a
blind index, so ingest costs one seal and one HMAC per record on top of the
underlying job. Evaluation is a single grouped aggregate query per check, so a
completion attempt is O(1) round trips regardless of record count. The sealed
subject roughly doubles the per record row width versus storing a plaintext key,
which is the deliberate price of never landing a migration key list in plaintext.
For a large import the dominant cost remains the underlying user creation; the
ledger is a thin, bounded overlay.

## Recommendation

PROMOTE to an OPT IN wrapper now; do NOT make it the mandatory default lifecycle for
every migration yet.

The invariant gated completion and the restart survivable, re-evaluated verdict are
exactly the safety property the market lacks, and the prototype delivers them with a
small, auditable surface. Making it opt in lets the bulk import and schema migration
paths adopt it immediately (both concrete adapters are shipped: `import_into_run` in
`ironauth-import` and `ingest_schema_migration_job` in `ironauth-store`) and lets
operators opt a run into
the gate without forcing every future migration author through it before the ergonomics
are proven.

Before promoting it to the DEFAULT for all long running mutations, two gaps should
close: (1) the ingest adapters are currently caller driven, so a migration author who
forgets to ingest a record silently under counts. The count invariant catches the
mismatch, but the machine should own the ingest so accounting cannot be skipped.
(2) The tenant move adapter (M5) should be built and its consistency predicate (profile
AND credentials landed) exercised against a real move before the machine is claimed as
the universal lifecycle. Until then, opt in captures the safety win without over
committing an exploratory surface.

The concurrent-ingest-versus-completion race is NOT an open gap: `ingest_outcomes`,
`reconcile_records`, and `try_complete` all take the run row's `FOR UPDATE` lock before
touching the ledger, and `source_total` is immutable, so an ingest committing while a
completion is evaluating is serialized behind the same lock rather than slipping a
violation past the gate. A completion verdict is therefore always consistent with the
ledger it was computed over.

Two production hardenings are worth noting as promotion gates (neither is a correctness
defect in the prototype):

- **Completion gating is application level, by construction.** The mutable
  `migration_runs.state` column necessarily sits inside the data plane's column scoped
  UPDATE grant, so a database CHECK cannot enforce transition legality (a CHECK cannot
  see the prior value in a way that distinguishes a legal edge from an illegal one).
  Legality is instead enforced by confining ALL SQL against these tables to the
  repository module (the query-audit rule keeps it there), so `complete` is reachable
  only through `try_complete`'s gated path. A mandatory default should treat that
  module confinement as the security boundary it is.
- **The violations endpoint opens sealed PII without a "PII viewed" audit row.** Reading
  the paginated violation view decrypts each offending record's sealed subject for the
  authorized operator, but emits no audit row recording that the subject was viewed. For
  a surface that opens end user identifiers this is a reasonable production hardening (a
  `migration_run.violations.view` read-audit), deferred here as the exploratory API is
  read only.
