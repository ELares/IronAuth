# Per-operation unit costs

Issue #152 criterion 4 asks for per-operation unit costs with the Argon2id parameters stated.
Measured, reproduced by one command:

```
cargo run --release -p ironauth-oidc --example unit_costs
```

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
on release. It is not: this table is hand-transcribed from the example's output, CI compiles the
example but never runs it, and no gate compares the two. A review re-ran it and found the
published figures off by 0.5 to 1.4 ms against a run-to-run spread of about 0.2 ms, which is how
a hand-transcribed table drifts. Closing that needs the release pipeline criterion 2 asks for.

The hardware class above is a development machine. A published sizing guide should be measured on
the instance classes it recommends.
