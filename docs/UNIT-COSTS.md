# Per-operation unit costs

Issue #152 criterion 4 asks for per-operation unit costs with the Argon2id parameters stated.
Measured, reproduced by the one command that runs the whole benchmark harness:

```
PG_BIN=<postgresql bin dir> scripts/bench.sh
```

That runs every benchmark and writes each one's output under `target/bench/`; the release
workflow runs it per release and archives the results. To re-measure only this document's
numbers, `cargo run --release -p ironauth-oidc --example unit_costs` is that benchmark on its
own, and it needs no database.

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

## What this does not yet cover

Criterion 4 also asks that the sizing guide be GENERATED from CI benchmark output and regenerate
on release. It is not. This table is still hand-transcribed, and it has drifted.

Re-running the harness on the hardware class the table names (Apple M4 Pro, 10 performance and 4
efficiency cores, release build, 10 samples) put FIVE of the eight figures above outside their
own published ranges, and all five in the same direction: the published figure is the optimistic
one, and the machine is slower than the table says.

| figure | published | re-measured |
|---|---|---|
| OWASP default, verify | 10.4 to 10.6 ms | 11.3 ms |
| config floor, verify | 2.2 ms | 2.3 ms |
| config floor at the default iterations, verify | 4.3 ms | 4.4 ms |
| double iterations, hash | 21.1 to 22.0 ms | 23.3 ms |
| double iterations, verify | 21.0 to 21.8 ms | 22.9 ms |

A sizing guide that is optimistic in one direction is the bad direction to be wrong in: capacity
planned against it under-provisions.

The mechanism is in the example's own header: `NOT PINNED: a per-core figure below is whichever
kind the scheduler chose`. On a heterogeneous CPU the same command on the same machine measures
a performance core sometimes and an efficiency core other times, so a single-run figure is not
repeatable to the precision these ranges are written to. The table is not drifting away from a
stable truth; it was never pinned to one.

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
