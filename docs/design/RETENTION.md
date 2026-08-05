<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Data retention

Status: accepted for `outbox_messages` (issue #104, PR 3).

This is the record of which tables IronAuth reaps, which it does not, and, for
each one it covers, whether the absence of a reaper is an engineering problem
nobody has solved yet or a policy question that is not engineering's to answer.
It exists because "no retention" is the default state of every append-only table
in the schema and that state is invisible: a table with no reaper looks exactly
like a table with a reaper that has nothing to do, right up until an operator
runs out of disk.

## What this document is NOT

It is not a complete inventory. The schema declares 108 tables across 102
migrations; this document names about twenty. That is a real gap and it is
stated here rather than implied away, because an earlier draft of this file
claimed the opposite ("every other table is open and this document says why, per
table") and a reader would then have been entitled to take an omission as an
assertion. A table absent from this file has not been ruled on. Adding a reaper
obliges an entry here; adding a table does not yet.

The distinction the rest of this document turns on:

- an **engineering decision** is one this repository can make on its own, from
  properties of the code, and be right about. `outbox_messages` was one: a
  completed queue row is delivery evidence, we know what it costs to keep and
  what it costs to lose, and the answer does not depend on the deployment's
  jurisdiction or its auditor.
- an **owner policy decision** is one where the correct number depends on
  obligations the code cannot see, and where a default we invent becomes the
  answer for every deployment that never reads this file. For those, this
  document states the competing pressures and picks nothing. A number chosen
  here by an engineer would not be a conservative default; it would be a
  silent policy commitment made on an operator's behalf.

## What is reaped

Seven tables already pruned themselves before this work, all in the same shape:
the producer stamps a per-row `expires_at` at write time and a `DELETE ... WHERE
expires_at <= now` removes the expired ones. Six of the seven do it INLINE in
the writer, so the prune is a side effect of the next write and stops entirely
when writes stop.

| table | migration | pruned by |
|---|---|---|
| `client_assertion_jtis` | 0013 | inline in `record` |
| `client_auth_diagnostics` | 0013 | inline in `record` |
| `external_assertion_jtis` | 0020 | inline in `record` |
| `pow_challenges` | 0057 | `reclaim_expired`, a bounded standalone method |
| `policy_decision_traces` | 0073 | inline in `record` |
| `token_size_events` | 0073 | inline in `record` |
| `dpop_proof_replay` | 0083 | inline in `check_and_record` |
| `idempotency_keys` | 0003, retention added in 0109 | inline in `insert_idempotency` |

`pow_challenges` is the one 0102 cites as its model, specifically for its
bounded subselect (Postgres `DELETE` takes no `LIMIT`). 0109 follows the same
bounded subselect for `idempotency_keys`, and adds an ORDER BY so the drain is
oldest first: without it, WHICH expired rows a pass removes is unspecified.

`idempotency_keys` differs from every other row in this table in one way worth
naming. For the replay caches, a missing row means REJECT (an unknown `jti` was
never seen, so nothing is replayed). Here a missing row means EXECUTE: the
caller re-runs its mutation. That is the documented contract for a key older
than the window, but it is why the window is stamped per row and honoured by the
lookup rather than left to whenever the prune next runs.

### Still unpruned, measured 2026-08-04

Nine tables have no delete path anywhere in the workspace and grow without
bound: `acme_challenges`, `authorization_codes`, `device_codes`,
`environment_states`, `fedcm_assertion_nonces`, `federation_login_states`,
`pushed_authorization_requests`, `signup_quarantines` and
`webauthn_challenges`. They are NOT one batch of work. Each is a single-use
latch whose safe window is its own question, and for the consume-latch tables a
row that is deleted while still referencable changes an authorization decision,
so each needs its retention floor argued from that table's replay semantics
rather than from a shared default.

### `outbox_messages` (migration 0099, retention added in 0102)

The first table with a PERIODIC SWEEPER TASK and an operator-configurable
window, rather than a prune keyed on a producer-stamped expiry. That is the
difference worth naming: nothing about an outbox message says when it stops
being interesting, because the answer depends on how long the deployment wants
to be able to answer "was this delivered".

- **Completed messages** are removed `outbox.completed_retention_secs` after
  their `completed_at`. Default seven days, floor one hour, ceiling ninety days.
- **Dead-lettered messages** are removed `outbox.dead_letter_retention_secs`
  after their `dead_lettered_at`, and the default of `0` means NEVER. A dead
  letter is work that will never happen unless an operator replays it, and for
  the back-channel logout fan-out one of them can be an entire session's relying
  parties left un-notified. It is the only record that this happened, so keeping
  it is the safe default and deleting it on a schedule has to be something an
  operator typed.
- **Nothing else is ever removed.** A message with both terminal columns NULL is
  not stale however old it is; it is UNDELIVERED. `oidc.backchannel_logout_enabled`
  defaults off while the producer that enqueues `session_ended` runs regardless,
  so a deployment accumulates undrained messages BY DESIGN, and turning the
  switch on begins by draining that backlog. An age-based reaper would delete
  those pending logouts, and because the claim's head-of-group rule reads
  terminal state, deleting a group's non-terminal head would also unblock the
  rest of the group and deliver the survivors out of order.

The sweeper runs as `ironauth_control`, which is the only role 0102 grants
DELETE. The data plane holds the column-scoped UPDATE that writes
`dead_lettered_at`, so giving it DELETE would let one role give up on a message
and then erase the record of having given up.

#### What a completed row carries, which is two things and not one

The obvious one is delivery evidence. The second is its slot in the
`UNIQUE (tenant_id, environment_id, consumer, idempotency_key)` constraint 0099
created, which IS the queue's at-most-once ledger: it is what a producer's
re-enqueue of the same domain fact conflicts with. Reaping the row frees the
key. Measured: after one pass past the window, `enqueue_all` under the same key
inserts a row and that row is CLAIMABLE, so the work becomes deliverable twice,
and the downstream defence does not cover it either, because a re-explode mints
a fresh `jti` and the relying party sees a new token rather than a replay it can
deduplicate.

This is not reachable with today's consumers, because a producer can only
re-enqueue while its OWN driving message is still non-terminal, and that horizon
is bounded by `outbox.max_attempts` claims separated by the retry backoff or a
lapsed lease: about 200 seconds at the shipped defaults. It is a latent contract
rather than a live duplicate, which is why the floor on
`outbox.completed_retention_secs` is stated as

    max(evidence window, longest producer re-enqueue horizon)

and not as the evidence window alone. The floor's VALUE stays at one hour: at
the shipped defaults the evidence term is the larger of the two and the
re-enqueue term has eighteen times of headroom inside it, and a constant large
enough to cover an arbitrarily raised `max_attempts` would impose a policy on
every deployment to protect a configuration almost none of them have.

**Operator obligation:** raising `outbox.max_attempts`,
`outbox.retry_base_secs` or `outbox.visibility_timeout_secs` lengthens the
second term, and `completed_retention_secs` must stay above it. This is
documented rather than validated at load, because computing the horizon exactly
would mean re-implementing the store's backoff schedule inside the config crate,
and a second copy of that arithmetic could refuse configurations that are safe.

#### What this reaper does NOT solve

Stated plainly, because the argument that motivated the design does not survive
being followed to the end. The motivation was that growth is worst where the
back-channel logout switch is off. That is true. But in exactly that deployment
the consumer pools are the only thing that ever writes `completed_at` or
`dead_lettered_at`, and both reap predicates key on those columns (and must), so
the reaper removes ZERO rows there, on every pass, forever.

- What it DOES bound: the deployment where consumers run. That is the volume PR
  2 of issue #104 introduced, roughly `1 + N_relying_parties` rows per ended
  session, all of which becomes terminal, none of which anything removed before
  now.
- What it does NOT bound: a default deployment's undrained `session_ended`
  backlog. That is a PRODUCER-side question (whether to enqueue work no consumer
  will ever take, or to drain it to a no-op) and it is an **owner policy
  decision**, deferred and not answered here. Widening this reaper to
  non-terminal rows is not the answer and must not be done: those rows are
  precisely the backlog that turning the switch on begins by draining.

#### What an operator can actually see

- The sweeper's own reports, which is what leaves the process today. A SATURATED
  pass logs at warn and names the two knobs that fix it; a pass that removed
  rows logs at debug; a pass that removed NOTHING also logs at debug, so a
  healthy idle reaper and a dead one are distinguishable; and a failed pass logs
  at warn, naming the missing 0102 grant as the likely cause.
- `OutboxDepth::completed`, the reapable backlog, is the counter the depth gauge
  gained for this, and it now has two readers: the queues management API reads
  `depth` for one scope, and the metrics sampler reads it across scopes to set
  `ironauth_outbox_depth`. Neither reader lives inside the sweep, and that is
  still deliberate: `depth` is an unbounded `count(*)` over the scope, and a pass
  whose whole story is boundedness must not grow a second unbounded read. The
  sampler is a separate task on its own configurable interval
  (`outbox.metrics_sample_interval_secs`), so the reaper's cost stays a function
  of what it deletes rather than of how much it left behind.
- A deployment with no control-plane DSN gets NO reaping at all. That is logged
  at error on boot, and both halves of it are pinned by a suite that boots the
  real binary (`crates/ironauth/tests/serve_retention_boot.rs`). It is a real
  operator obligation rather than a degraded mode: nothing else in the process
  removes an outbox row.

#### Throughput, so an operator can size the knobs

One sweep removes at most `reap_batch` rows per (scope, consumer) per tail. At
the shipped defaults that is `1000 * (604800 / 3600) = 168,000` rows per week
per (scope, consumer). The delivery consumer is the binding one, because the
fan-out turns one session into roughly `1 + N_relying_parties` rows: 168,000 a
week covers about 33,600 sessions a week at five relying parties each. A scope
that has already accumulated millions of rows takes weeks to clear at those
defaults, and the only signal that this is happening is the SATURATED flag on
each pass. Raise `outbox.reap_batch` or shorten `outbox.reap_interval_secs`.

## What is NOT reaped, and why

### Owner policy decisions

For each of these the engineering work is straightforward and the NUMBER is not.
This repository deliberately picks none of them.

#### `audit_log` (migration 0002)

0002 already says it: "Retention and pruning are a later, explicit operation
performed by a different, privileged path, never by the application role." ADR
0002 makes the same split. The role separation is therefore already in place;
what is missing is a duration, and the pressures point opposite ways.

PCI DSS, SOC 2 and ISO 27001 evidence expectations all push toward keeping audit
records for a long, fixed period, and an auditor who finds a gap treats the gap
as the finding. GDPR Article 5(1)(e) pushes the other way: personal data must not
be kept in identifiable form longer than necessary for the purpose, and an audit
row names a subject. A deployment subject to both has to reconcile them for
itself, usually per record class and often per jurisdiction.

#### `risk_decisions` (migration 0054)

One row per scored login: the persisted record of an AUTOMATED DECISION ABOUT A
PERSON. 0054 says it exists so that "a sampled decision is fully
RECONSTRUCTABLE", and reconstructability is exactly what GDPR Article 22 contest
rights depend on: a subject challenging an automated block or challenge needs
the decision to still exist. Deleting these on a short schedule removes the
subject's ability to contest; keeping them forever retains a behavioural
profile.

0054 notes that the audit log carries a PII-free enumerated signal summary, so
a decision is partially reconstructable from the audit trail alone. That widens
the space of defensible answers; it does not choose one.

#### `risk_login_geo` and `risk_disavowal_tokens` (migration 0054)

The two OTHER tables 0054 creates, listed on their own because their growth
profiles are not the decision record's and an earlier draft of this file omitted
them entirely.

`risk_login_geo` holds exactly ONE row per `(tenant, environment, subject)`,
upserted on each login, so it does not grow with logins at all; it grows with
subjects. Its retention question is really "how long after a user is gone do we
keep their last-seen coarse location", which is a policy question about sealed
device PII rather than a disk-usage question.

`risk_disavowal_tokens` holds one single-use "this wasn't me" token per
new-device notification, and 0054 states that a CONSUMED token is itself the
durable "credentials flagged for review" marker for the subject. The consumed
ones are therefore load-bearing state rather than a log, and only the unconsumed
expired ones are obviously reapable. Separating those two populations is
engineering work nobody has done; the window on the consumed ones is policy.

#### `risk_signals` (migration 0064)

Third-party ingested signals, NOT a decision record, and a DIFFERENT migration
from the three above. 0064 already states its own position and this document
does not overrule it: "Signal FRESHNESS is config-driven, not a stored column:
the engine treats a signal older than the source's max_age_secs as inert (it
never counts as a policy input), so a stale row simply stops mattering rather
than being deleted. Row RETENTION and pruning of inert rows are a documented
follow-up (there is no expires_at column, no age index, and no DELETE grant or
sweep in this PR)."

So this one sits nearer to engineering-not-done than to policy: the shape of a
reaper is clear, because a row is inert once past every configured
`max_age_secs`, and what is missing is the column, the index and the grant. The
policy component is smaller but not zero, because a signal names a subject.

#### `signup_quarantines` (migration 0065)

A quarantine record is an abuse-control verdict about a registration attempt. It
is retained evidence for a fraud review that may not have happened yet, and it
names a would-be user who may never become one. How long an unreviewed abuse
verdict about a non-customer may be kept is a policy question.

#### `recovery_approvals` (migration 0066)

Trusted-contact approvals name a THIRD PARTY who is not the account holder and
may not be a user of the system at all. Retention here decides how long the
system holds a record of one person vouching for another, which is a policy
question about a data subject the deployment may have no relationship with.

### An UNSOLVED CORRECTNESS problem, not a policy question

`issued_tokens`, `opaque_access_tokens`, `refresh_tokens`, `refresh_families`,
`grants`, `sessions`, `client_sessions`.

These are not waiting on a number. They are waiting on a design nobody has
written, and it is worth being blunt about why, because they are the tables an
operator looking at disk usage will reach for first.

Their rows are LOAD-BEARING FOR REVOCATION AND INTROSPECTION. Migration 0004
states the rule for the first of them: "a token counts as active only while its
issued row exists AND its grant is not revoked". The row's existence is part of
the answer to "is this token valid", not a log of the fact that it was issued.

So a naive age-based reaper over any of these SILENTLY REVOKES LIVE TOKENS. A
refresh token with a long lifetime, a session inside its idle window, a grant
whose access tokens are still being introspected: delete the row and the
credential stops working, with no error anywhere that says retention did it. The
symptom is a user being logged out for no reason, and the cause is invisible.

The reason this is hard rather than merely undone is that "expired" is not a
property of one row. A grant is reachable from refresh families that are
reachable from refresh tokens; a session is referenced by client sessions and by
outbox messages that name it. A correct reaper has to establish that NOTHING can
still be presented that would need the row, across that whole graph, and it has
to do so under concurrent issuance. That is a real design, with a real
correctness argument, and it is a separate piece of work.

Until it exists, these tables grow. That is stated here so an operator plans for
it rather than discovering it, and so nobody adds a `DELETE ... WHERE
created_at < ...` to any of them believing it is housekeeping.

### Frozen tables whose answer is a DROP, not a reaper

`session_ended_events` (migration 0024) and `backchannel_logout_deliveries`
(migration 0025).

Both were superseded by `outbox_messages` and have ZERO writers in the tree
today: no SQL in `repository.rs` targets either name. A reaper for them would be
a reaper for a table nothing writes.

An earlier draft of this file put both at PR 2 of issue #104, and that is wrong
for the first of them. 0099 is a PR 1 migration and its header names BOTH tables
as the ones the new table is "their UNION with the two things neither needed", so
the SCHEMA superseded both there. The WRITERS stopped at different points:
`SessionEventOutboxRepo` became "a TYPED FACADE over the generic outbox" in PR 1,
so `session_ended_events` lost its last writer then, and
`backchannel_logout_deliveries` lost its own in PR 2, when the per-relying-party
fan-out became an outbox consumer. Neither has one now, which is what makes a
DROP the right answer rather than a reaper.

Their real answer is a CONTRACT-phase migration that DROPs them, and that
migration is gated on the drain obligation 0099 records: a deployment upgrading
with back-channel logout ON loses every row still `delivered_at IS NULL` when the
last old replica stops, so before retiring the last old replica an operator must
run

    SELECT count(*) FROM session_ended_events WHERE delivered_at IS NULL;

and require it to reach 0. A DROP that lands before every deployment has
satisfied that turns a recoverable tail into a lost one. That sequencing is a
separate PR from this one, and it is a migration-phase question rather than a
retention question.

## Adding a reaper to a table

If you are adding one, the shape `outbox_messages` uses is the one to copy:

1. a migration granting DELETE to the ONE role that should hold it, which must
   not be a role that can also write the column the delete erases evidence of;
2. a bounded repository method keyed on a TERMINAL column, never on a creation
   timestamp, with the bound expressed as a subselect because Postgres `DELETE`
   takes no `LIMIT`;
3. a periodic task whose gate is its OWN, not inherited from whichever feature
   happens to write the table today, so a second writer arriving later does not
   land outside the reaper's reach. Then say plainly which deployments it does
   and does not remove rows in, including the ones where the honest answer is
   "none";
4. a saturation signal, so "keeping up" and "falling behind forever" are
   distinguishable;
5. a skip for FENCED scopes, because a paused tenant is one an operator paused;
6. an enumeration of the table that does not scale with the backlog. The obvious
   `SELECT DISTINCT` over a scope is a sequential scan whose cost grows with
   exactly the rows the reaper has not cleared yet (measured on the outbox: 8.0
   ms and 781 buffers at 50,000 rows, 33.5 ms and 7,908 buffers at 500,000,
   against 0.07 ms and 0.09 ms at 15 buffers either way for the recursive index
   walk that replaced it);
7. a counter on whatever depth or status surface the table already has, so zero
   is measurable against a known non-zero, AND a reader for that counter. A
   counter with no exporter is not yet an operator surface, and this document
   should say which of the two it is;
8. a check on what ELSE the deleted row was holding. For the outbox it was a
   unique-constraint slot that doubles as an idempotency ledger; for another
   table it could be a foreign-key target, or a uniqueness guarantee something
   else depends on;
9. an entry in this document.
