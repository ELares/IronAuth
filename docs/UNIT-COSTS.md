# Per-operation unit costs

Issue #152 criterion 4 asks for per-operation unit costs with the Argon2id parameters stated.
These are measured. RE-MEASURE THEM WITH THE ONE COMMAND THAT RUNS THE WHOLE BENCHMARK HARNESS:

```
PG_BIN=<postgresql bin dir> scripts/bench.sh
```

It runs every benchmark and writes each one's output under `target/bench/`; the release workflow
runs it per release and archives the results. To re-measure only this document's numbers,
`cargo run --release -p ironauth-oidc --example unit_costs` is that benchmark on its own, and it
needs no database, so it needs no `PG_BIN`.

Re-measure, not reproduce. The ranges below were transcribed from two runs, and a single
invocation produces single values rather than a range. More to the point, running that command
today does not return these figures: see "what this does not yet cover" at the end, which records
the comparison and why the example cannot yet be pinned to a repeatable number.

## Password hashing

| parameters | hash | verify |
|---|---|---|
| **OWASP default (shipped)**: `m=19456 KiB, t=2, p=1` | 11.4 to 12.8 ms | 10.4 to 10.6 ms |
| config floor, the weakest config load accepts: `m=8192 KiB, t=1, p=1` | 2.3 ms | 2.2 ms |
| config floor at the default iterations: `m=8192 KiB, t=2, p=1` | 4.3 to 4.4 ms | 4.3 ms |
| double iterations: `m=19456 KiB, t=4, p=1` | 21.1 to 22.0 ms | 21.0 to 21.8 ms |

## Token mint

| algorithm | mint | versus one password verify |
|---|---|---|
| EdDSA | 7.3 to 7.4 us | about 1400x cheaper |
| RS256, published day one by every environment | 317 to 318 us | about 33x cheaper |

Apple M4 Pro, 10 performance + 4 efficiency cores, release build, 10 samples per hashing figure
and 2000 per signature after 50 warm-up signatures. Two runs, and the RANGE of both is printed
rather than a single value, because a single value implies a precision these do not have.

**At the shipped parameters one PERFORMANCE core sustains at most 94 to 96 password logins per
second.** Read the next two sections before quoting that.

## Which core, and why it matters more than the number

The measurement is unpinned on a heterogeneous CPU. An adversarial review ran the same binary
under background QoS, which schedules it onto efficiency cores, and measured 62 to 66 ms per
verify: 15 to 16 logins per second, a 5.7x spread against the figure above.

That matters because the obvious way to use a per-core number is to multiply it by the core
count, and `default_pool_threads()` is `available_parallelism()`, which on this machine is 14.
Four of those threads land on efficiency cores. Multiplying 95 by 14 overstates the real
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

| published keys | render | parse on a hit | net saved by a hit |
|---|---|---|---|
| EdDSA only | 0.55 us | 0.55 to 0.57 us | -0.02 to 0.00 us |
| EdDSA + ES256 + RS256 (a fresh environment) | 1.97 to 1.98 us | 1.36 to 1.38 us | 0.59 to 0.62 us |
| the same three, one rotation each (six published) | 3.51 to 3.70 us | 2.69 to 2.77 us | 0.74 to 1.01 us |

| asking another process, loopback TCP, same machine | measured |
|---|---|
| bare round trip (`SELECT 1`) | 21 us |
| one indexed single-row lookup by key | 29 us |
| **the query work alone** (the difference) | **8 us** |

Three algorithms is what a fresh environment publishes, not two: provisioning mints EdDSA,
ES256 and RS256 and publishes all three from the environment's creation instant. The six-key row
is one rotation of each, whose predecessors stay published for a window.

Both are MEANS over the run, not floors, and both include Postgres parsing, planning and
executing, so a bare socket exchange on this hardware is cheaper than either. Neither is a figure
for a Redis-shaped accelerator, which speaks a lighter protocol; nothing here measures one. They
are offered as a concrete example of what asking another process costs on the most favourable
topology there is, where that process is on the same machine.

The third row is the one that generalises. **A CACHE SAVES THE WORK, NEVER THE HOP**: a hit
still pays a round trip to the cache, so the most it can return is the difference between the
two. On this machine a single-row indexed read is 29 us, of which 21 us is the round trip and
8 us is the index descent and row fetch. An accelerator co-located with the application cannot
save the 21 us, because it costs its own.

So the seam pays when one of three things is true, and not otherwise: the WORK is large (a
complex query, a join, a scan, an Argon2 verification), the DATABASE IS FAR and the cache is
near, or the database is CONTENDED and the cache is not. A single-row lookup against a
co-located database is none of those, and putting a same-machine cache in front of one saves
at most 8 us against a 21 us hop.

**That settles an open question in issue #146.** `IssuerRegistry` holds an optional hot-state
accelerator for the published JWKS document, and no shipped binary installs one. The natural
reading is that the boot wiring was never finished. The measurement says otherwise.

`jwks_json` consults the accelerator only AFTER `resolve_for_publication` has returned the
entry, and deliberately: everything that decides WHETHER to publish has to run first, so a
fenced scope is refused and a stale entry is never served. The safety ordering is right. Its
consequence is that a hit cannot save a database read, because the read that produced the entry
has already happened.

What a hit saves is the render, and what it ADDS is the cost of accepting the bytes: a UTF-8
check and a full JSON validation parse that `issuer.rs` keeps deliberately, because without it
the endpoint served any UTF-8 bytes found under that key as the environment's JWK Set. A miss
never pays that. So the saving is the render minus the parse, which is the last column above,
and for a fresh environment it is about 0.6 us.

Against a 20 us round trip that is roughly thirty times the cost of the thing it replaces, on
the most favourable topology, with the database on the same machine. At one published key the
net saving is NEGATIVE: accepting a cache hit costs marginally more CPU than rendering from the
entry the caller is already holding, before any hop is paid for at all.

Wiring the accelerator at this call site would make the JWKS endpoint slower. "Not wired" is
the faster configuration rather than the unfinished one.

This does not say the hot-state seam is not worth having. It says this USE is not, and it
sharpens what an earlier version of this section offered as the rule. That rule was "a hop pays
when the alternative is a database read", which the third row above shows is too generous: the
alternative has to be a database read whose WORK exceeds a hop, and a single-row lookup on the
same machine is not one.

By that measure the remaining registry uses split cleanly. The ones keyed on a single indexed
read, such as a tenant config or an introspection result, save about 8 us on a co-located
deployment and are not worth a hop there, though they become worth one as soon as the database
is remote or contended. The rate counter is the different case, and the strongest: sharing it
across nodes buys fleet-wide correctness that no local answer provides at any speed, so the hop
is not being traded against latency at all.

## What this does not yet cover

Criterion 4 also asks that the sizing guide be GENERATED from CI benchmark output and regenerate
on release. It is not. This table is still hand-transcribed, and it has drifted.

Re-running the harness on the hardware class the table names (Apple M4 Pro, 10 performance and 4
efficiency cores, release build) put six of the ten figures in the password-hashing and
token-mint tables outside their own ranges:

| figure | published | re-measured |
|---|---|---|
| OWASP default, verify | 10.4 to 10.6 ms | 11.3 ms |
| config floor, verify | 2.2 ms | 2.3 ms |
| config floor at the default iterations, verify | 4.3 ms | 4.4 ms |
| double iterations, hash | 21.1 to 22.0 ms | 23.3 ms |
| double iterations, verify | 21.0 to 21.8 ms | 22.9 ms |
| RS256 mint | 317 to 318 us | 323.5 us |

Of the four that landed inside their published range, three landed at the top of it. The
derived headline above the tables moved with them: **94 to 96 logins per second per core
published, 87 to 88 re-measured**.

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
login-rate comparison is the one to be most careful with, because the table says one PERFORMANCE
core while the harness reports whichever core it was given; those are not the same quantity.

What criterion 2 added is the half that can be mechanical: the example now RUNS on every release
rather than only being compiled, under one command, with its output archived.

Generation needs two things this does not have. The first is core pinning, without which a
generated table would reproduce the same unrepeatable figure more confidently. The second is
hardware: a table generated from a shared CI runner would be reproducible and wrong for the
instance classes this guide recommends. Closing criterion 4 needs a pinned run on the named
instance classes, and the archived results from that run are what the table should be generated
from.

The hardware class above is a development machine. A published sizing guide should be measured on
the instance classes it recommends.
