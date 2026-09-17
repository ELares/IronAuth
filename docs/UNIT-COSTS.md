# Per-operation unit costs

Issue #152 criterion 4 asks for per-operation unit costs with the Argon2id parameters stated.
The tables below are GENERATED from `docs/unit-costs-measurement.json`, which is the benchmark's
own output. RE-MEASURE THEM AND REWRITE THIS PAGE WITH ONE COMMAND:

```
scripts/unit-costs-doc.sh --measure
```

That runs the unit-costs benchmark on this machine, writes the measurement, and regenerates the
region below from it. Commit both. `scripts/unit-costs-doc.sh --check` runs in CI and fails if
the region stops matching the measurement, so the figures cannot drift from their source the way
the hand-written ones did.

TO RUN THE BENCHMARK WITHOUT REWRITING ANYTHING, `PG_BIN=<postgresql bin dir> scripts/bench.sh`
runs every benchmark and archives each one's output under `target/bench/`; the release workflow
runs it per release. The unit-costs benchmark alone is
`cargo run --release -p ironauth-oidc --example unit_costs`, which needs no database.

RE-MEASURE, NOT REPRODUCE, and that distinction survives generation. These are single values from
one run on one machine, and running the command again will not return them exactly: the example
does not pin cores, so the figure it takes depends on which kind the scheduler handed it. What
generation fixes is the table drifting from the measurement, not the measurement being
repeatable. "What this does not yet cover" at the end records how far the hand-written table had
drifted, which is why this is generated now.

<!-- BEGIN GENERATED: unit costs -->

## Password hashing

| parameters | hash | verify |
|---|---|---|
| OWASP default (shipped): `m=19456 KiB, t=2, p=1` | 11.45 ms | 11.21 ms |
| config floor (the weakest config load accepts): `m=8192 KiB, t=1, p=1` | 2.30 ms | 2.23 ms |
| config floor at the default iterations: `m=8192 KiB, t=2, p=1` | 4.51 ms | 4.39 ms |
| double iterations: `m=19456 KiB, t=4, p=1` | 23.06 ms | 22.41 ms |

## Token mint

| algorithm | mint | versus one password verify |
|---|---|---|
| EdDSA | 7.5 us | about 1493x cheaper |
| RS256 (published day one) | 323.2 us | about 35x cheaper |

Apple M4 Pro, 14 cores, 10 performance + 4 efficiency cores, release build, 10 samples per hashing figure and 2000 per signature after 50 warm-up signatures.

These figures are GENERATED from `docs/unit-costs-measurement.json`, which is the benchmark's own output. Re-measure with `scripts/unit-costs-doc.sh --measure` and commit the result; `scripts/unit-costs-doc.sh --check` fails if this section was edited by hand.

**At the shipped parameters one core of this kind sustains at most 89 password logins per second (11.21 ms each).** Read the next two sections before quoting that.

<!-- END GENERATED: unit costs -->

## Which core, and why it matters more than the number

The measurement is unpinned on a heterogeneous CPU. An adversarial review ran the same binary
under background QoS, which schedules it onto efficiency cores, and measured 62 to 66 ms per
verify: 15 to 16 logins per second, a 5.7x spread against the figure above.

That matters because the obvious way to use a per-core number is to multiply it by the core
count, and `default_pool_threads()` is `available_parallelism()`, which on this machine is 14.
Four of those threads land on efficiency cores. Multiplying the generated per-core figure
(currently 89) by 14 overstates the real
aggregate substantially, and the host line says "14 cores" as though they were interchangeable.

The example now prints the performance and efficiency split and says plainly that it is not
pinned. A sizing exercise on a heterogeneous machine has to account for the mix; on a
homogeneous server class, which is what a deployment usually runs, the question does not arise.

## Why that number is a floor, not a capacity

It counts one Argon2id verify per login and nothing else: no user read, no token mint, no audit
write, one core, no contention. A deployment will do less. Quoting it as a capacity figure would
be the most flattering possible reading of a single measurement.

## Why the parameters are printed with the numbers

Argon2id cost is a configuration choice, not a property of the code. A unit cost quoted without
`m`, `t` and `p` is unreproducible, and worse, invites a reader to compare it against a
deployment tuned differently and conclude something about the software.

The table shows the shape of the tradeoff deliberately. The floor row is what config load
actually refuses to go below, which is NOT a recommendation: at `t=1` the hash costs a fifth of
the shipped default and carries a fifth of the work an attacker must repeat.

An earlier version of this table labelled `m=8192, t=2, p=1` as "the weakest config load
accepts", and it is not: the validator rejects only `iterations < 1`, so `t=1` loads and costs
2.2 ms rather than the 4.5 ms published as the floor. The document exists to stop somebody
weakening hashing by accident while reading it for capacity, and it was understating the cheap
end by half, hiding exactly the configuration most tempting to a reader chasing throughput. Both
rows are shown now.

## Why the mint is measured rather than dismissed

An earlier version of this document measured only password hashing and justified that by saying
the hash dominates "by roughly three orders of magnitude". That claim was the one figure never
taken, and a review took it: 3.1 orders for EdDSA, and **1.5 for RS256**.

RS256 is not hypothetical. Every fresh environment publishes an RS256 key from day one, so a
deployment whose signing policy selects it mints at about 3% of a password verify rather than
0.1%. That is a visible line item in a capacity model, not a row rounding to zero, and the old
sentence told an operator not to model it.

## What a hop costs, and what that settles

A sizing guide needs the cost of asking something else, not only the cost of doing the work,
because that is what decides whether a cache in front of an operation pays for itself.

| operation | measured |
|---|---|
| render the published JWKS, EdDSA only | 0.55 us |
| render the published JWKS, three keys (a fresh environment) | 1.97 to 1.98 us |
| parse and accept a cached JWKS on a hit, three keys | 1.36 to 1.38 us |
| **net saved by a JWKS cache hit, three keys** | **0.59 to 0.62 us** |

| asking the database, loopback TCP, same machine | measured |
|---|---|
| bare round trip (`SELECT 1`) | 20 us |
| one autocommit indexed lookup | 35 us |
| **one SCOPED read: `begin_scoped` plus a join, under RLS** | **166 us** |
| a scoped read shaped as `HotStateRepo::get` issues it | 145 us |

| a hit against an attached accelerator | measured |
|---|---|
| **one IronCache `GET` hit, 512-byte value, loopback TCP** | **32 to 33 us** |

All four are from ONE run of `scripts/bench.sh`, measured as a role that is neither superuser nor
table owner. That matters: connecting as a superuser bypasses row-level security outright, and
an earlier revision of this table did exactly that, so its "under RLS" rows had no policy to
evaluate. The script now asserts the policies bite, by checking that the same query returns no
rows with the scope unset and one row with it set, before it measures anything.

The four database rows are MEANS over one run by one client with no other load; a contended
database is slower and the gaps widen. The accelerator row is measured separately, by a
different instrument, and the section at the end of this page says what it does and does not
cover.

### The third row is the one to size an accelerator against

An earlier revision of this section published the middle row as what a cache would replace and
concluded that the seam could save only the 12 us between it and a bare round trip. That was
wrong, and wrong in the direction that suppresses the work.

NO READ IN IRONAUTH IS AN AUTOCOMMIT STATEMENT. Every scoped read goes through `begin_scoped`,
which issues `BEGIN`, `SET TRANSACTION ISOLATION LEVEL READ COMMITTED`, and two
`SELECT set_config(...)` calls binding the row-level-security scope, then the query, then
`COMMIT`. Six sequential round trips, around a query whose tables are under FORCE ROW LEVEL
SECURITY with policies that re-read those settings. It is 550 call sites against 16 direct-pool
reads, so the autocommit figure describes essentially nothing this codebase does.

A cache hit replaces that whole sequence with one round trip of its own. So the saving is the
third row minus a hop, about **146 us against a 20 us hop, roughly seven to one in favour of the
accelerator**, and more on a contended database.

### What the Postgres tier can and cannot buy, which is a wiring question

`HotStateRepo::get` goes through `begin_scoped` like every other scoped read. So a hit against
the Postgres-backed tier pays the same `BEGIN`, isolation level, two `set_config` calls and
`COMMIT` as the read it stands in front of; only the query inside differs. Measured, 145 us
against the 166 us scoped read: a 13 per cent saving, bought with a write on every miss and an
invalidation feed to keep correct.

SO WIRED ONE-FOR-ONE IN FRONT OF A SINGLE REPOSITORY CALL, THE POSTGRES TIER BUYS NOTHING. An
attached IronCache is a different matter, priced at the end of this section. An
earlier revision of this section stopped there and concluded the tier "cannot accelerate
anything, by construction". That is too strong, and the correction is the useful part: what a
hit replaces is however many scoped transactions the cached answer stands in front of, and that
is a wiring choice rather than a property of the tier.

Two of the declared uses front more than one:

- `TENANT_CONFIG` is declared as "a tenant's resolved configuration, as the request path reads
  it". The nearest such load, `load_issuer_entry`, is THREE scoped transactions: the signing-key
  list, the environment guardrails, and the installed locales. One 145 us hit against roughly
  500 us is a saving of about 70 per cent, on the Postgres tier alone.
- `INTROSPECTION` is declared as "the result of an introspection call", not one repository
  method. An opaque token's resolution is one scoped read behind the client authentication, so
  there it is the 13 per cent case. A JWT token is not: `verify_any_audience` re-reads the
  serving-state fence once PER CANDIDATE AUDIENCE, deliberately and uncached, so a multi-audience
  token pays several scoped reads that one hit could replace.

Note what a hit CANNOT replace, in either case: the client authentication has to happen before
any cached answer is served, for the same reason the JWKS fence does, so it is on both sides of
the comparison and cancels.

For the write-shaped uses -- a single-use marker, a rate counter -- the Postgres tier is not
merely no faster. It is a second scoped WRITE in the same request, so it costs more than not
having it, and the shared-state justification below does not apply to them either: the durable
record they need is the row they were already writing.

WHERE THE POSTGRES TIER IS STILL THE RIGHT ANSWER is as a SHARED-STATE mechanism rather than a
faster one: flow state that survives the loss of the node that created it is a real job, and it
is the one the covenant's "complete on PostgreSQL alone" needs done.

A tier that is genuinely a different store changes the per-hit figure, and that figure is now
measured. An IronCache `GET` hit costs **32 to 33 us** across four runs, against the 166 us
scoped read in the table above.

| standing in front of one scoped read (166 us) | hit costs | saves |
|---|---|---|
| the Postgres tier (`PgHotState`) | 145 us | 13 per cent |
| an attached IronCache | 32 to 33 us | **80 per cent** |

That is the number every wiring decision above turns on, and it says the seam is worth attaching
an accelerator to and worth very little without one. Standing in front of a resolved tenant
config, which is three scoped transactions, the same hit saves about 93 per cent.

WHAT THE FIGURE DOES NOT SAY, in three parts, because each one was got wrong at some point in
getting here.

It is measured by a DIFFERENT INSTRUMENT from the database rows: a hand-rolled Python client
against IronCache, where the Postgres figures come from `pgbench`, a compiled C client. A review
built a C client doing the identical loop and measured about 4 us less per iteration, so the
Python number OVERSTATES the hop and the saving above is conservative. The two instruments are
close enough for a comparison spanning 130 us, and not close enough to compare 32 us against the
20 us bare round trip, which an earlier revision of this section did.

It is a HIT. A miss costs this plus the read it failed to avoid plus the write-back, so what
attaching an accelerator is worth is a function of hit rate, which is a property of a deployment
rather than of this software.

It is a PROTOCOL round trip, not the `redis`-crate path's cost, which adds its own encoding and
connection handling on top. Nothing in a shipped binary takes that path today: `ironcache_addr`
declares an address that readiness probes, and installs no implementation.

### What that means, use by use

**Scoped reads are worth accelerating**, and by how much depends on how many of them one cached
answer stands in front of, which the previous section works through. Introspection resolves an
opaque access token through `resolve_opaque_access_token`, one six-round-trip sequence; a
resolved tenant config is three of them.

**The JWKS document is still not**, and for a reason that has nothing to do with the figures
above. `jwks_json` consults its hot state only AFTER `resolve_for_publication` has returned the
entry, deliberately, so that a fenced scope is refused and a stale entry never served. The entry
is already in hand by then, so a hit cannot save a read of any shape: it saves the render, and it
adds the validation parse a hit must pay. That is the first table, netting about 0.6 us against a
20 us hop. At a single published key it is negative, which the first table above no longer
shows, because that table publishes password hashing rather than the JWKS render: the render
figures live in the accelerator section below and came from the same example run.

**The rate counter is a different question entirely.** Sharing it across nodes buys fleet-wide
correctness that no local answer provides at any speed, so the hop is not being traded against
latency at all.

### The rule, restated

A cache hit costs a round trip, so it can only return what the operation costs ABOVE one round
trip. The question is never "is the alternative a database read" but "how much work does that
read do beyond a single hop". A six-round-trip scoped transaction does a great deal; a render off
an entry already resolved does almost none.

## What this does not yet cover

Criterion 4 also asks that the sizing guide be GENERATED from CI benchmark output and regenerate
on release. THE TABLES ABOVE NOW ARE: they are written by `scripts/unit-costs-doc.sh` from
`docs/unit-costs-measurement.json`, which is the benchmark's own output, and `--check` runs in CI
so a hand-edited figure fails. The release lane regenerates the document from its own run and
archives it.

What follows is the record of why that was worth doing, kept because the drift it describes is
what a hand-transcribed measurement does rather than a one-off.

READ THE "was published" COLUMN AS HISTORY. It is the hand-written table this change replaced,
and those figures appear nowhere above any more: the tables are regenerated from the measurement
now, so a reader hunting for them will not find them. That is the point of the record.

Re-running the harness on the hardware class that table named (Apple M4 Pro, 10 performance and 4
efficiency cores, release build) put six of its ten figures outside their own ranges:

| figure | was published | re-measured |
|---|---|---|
| OWASP default, verify | 10.4 to 10.6 ms | 11.3 ms |
| config floor, verify | 2.2 ms | 2.3 ms |
| config floor at the default iterations, verify | 4.3 ms | 4.4 ms |
| double iterations, hash | 21.1 to 22.0 ms | 23.3 ms |
| double iterations, verify | 21.0 to 21.8 ms | 22.9 ms |
| RS256 mint | 317 to 318 us | 323.5 us |

Of the four that landed inside their published range, three landed at the top of it. The derived
headline moved with them: the hand-written one said **94 to 96 logins per second per core**, and
re-measuring gave **87 to 88**. The generated headline above now carries whatever the committed
measurement says, which is the whole of the fix.

WHAT THIS DOES AND DOES NOT SHOW. Every gap above is a few percent: each re-measured figure sits
between 1.7 and 6.6 percent past the TOP of its published range, all in the same direction. That is NOT the unpinned-core effect the section above measures. An
efficiency core costs 62 to 66 ms per verify, a 5.7x spread, so a run that landed on one would be
off by a factor rather than by a percent. Whatever moved these figures, it was not the scheduler
handing the example a different kind of core.

A few percent in one direction is what an ordinarily busy machine looks like, which is the point:
these ranges are written to a precision that a developer machine does not hold still to, and the
document says as much two sections up, that a single value "implies a precision these do not
have". Two consecutive runs of the harness here reported 88 and 87 logins per second, at 11.3 and
11.5 ms, without changing anything between them.

So what this shows is narrow and worth stating exactly: the documented command does not return
the documented numbers, which is the property criterion 2 asks for, and the published ranges are
tighter than the measurement is repeatable. It does not show the code got slower, and the
login-rate comparison is the one to be most careful with, because the hand-written table claimed
one PERFORMANCE core while the harness reports whichever core it was given; those are not the
same quantity. The generated headline says "one core of this kind" for exactly that reason, so
the claim the old table made is one this page no longer makes.

What criterion 2 added is the half that can be mechanical: the example now RUNS on every release
rather than only being compiled, under one command, with its output archived. Criterion 4's
generation is built on that. The drift recorded below cannot recur IN THE GENERATED REGION,
which is the password-hashing and token-mint tables: they are written from the measurement rather
than beside it, and `--check` fails if they stop matching. The other tables on this page, and
every figure in the prose, are still written by hand and gated by nothing but review.

WHAT GENERATION DOES NOT FIX is which machine the numbers describe, and there are two parts to
that. The first is core pinning: the example does not pin, so a generated table reproduces the
same unrepeatable figure more confidently than a transcribed one did. The second is the hardware
itself. The release lane ARCHIVES its regenerated document rather than committing it, because a
shared CI runner is not an instance class this guide recommends, and publishing its numbers here
would trade a drifted figure for a confidently generated one measured on the wrong machine.

So what remains for criterion 4 is a PINNED run on a named instance class. The mechanism to turn
that run into this document exists now: `scripts/unit-costs-doc.sh --measure` on that machine,
and commit what it writes.

The hardware class above is a development machine. A published sizing guide should be measured on
the instance classes it recommends.
