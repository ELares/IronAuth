# Measured startup and idle footprint

Issue #152 criterion 3 asks for RSS idle and startup time against the stated targets, with
methodology and hardware class stated. These are measured, not estimated, and reproduced by
the one command that runs the whole benchmark harness:

```
PG_BIN=<postgresql bin dir> scripts/bench.sh
```

That runs every benchmark and writes each one's output under `target/bench/`; the release
workflow runs it per release and archives the results. To re-measure only this document's
numbers, `scripts/startup-rss-bench.sh` is the startup and RSS benchmark on its own.

## Results

| measurement | value | target | |
|---|---|---|---|
| startup to ready | 236 ms median, 268 ms max | < 1000 ms | within |
| RSS idle | 13.3 MiB median, 13.4 MiB max | < 100 MiB | within |

Hardware class: Apple M4 Pro, 14 cores, 48 GiB, macOS 26.5.1. Release build, 5 runs, against a
database whose schema was applied first by `ironauth migrate`.

## The first published version of this table was wrong, and how

An earlier revision of this document reported a COLD startup of 1191 ms and called it a missed
target, with a whole section explaining that the first boot against a fresh database runs every
migration before answering ready. An adversarial review took that apart, and all three parts of
the story were false.

**The 1191 ms was macOS validating a freshly written binary.** The harness runs
`cargo build --release` first, which re-creates the binary at a new inode every invocation, and
macOS validates a binary on first exec from a given inode. That cost, about 0.85 s, was charged
to whichever `serve` ran first, which was the sample labelled COLD and published as the
headline. The review measured the mechanism: three consecutive no-op release builds produced
three different inodes, and the first `ironauth --version` after each cost 0.87, 0.81 and 0.83 s
at user 0.00 and sys 0.00, blocked in validation and burning no CPU, while the very next exec
cost 0.00 s. The harness now execs the binary once and throws that sample away.

It would also not have reproduced on the Linux runner criterion 2 wants CI to use, where there
is no such validation, which is its own warning about publishing a number whose cause was never
identified.

**No migration was running.** `ironauth serve` does not migrate; `migrate` is a separate
subcommand. The review queried the benchmarked database afterwards and found ZERO tables, and
with `log_statement=all` the entire session logged four statements, all from `createdb` and
`psql`, none from the server. Every figure described a server booted against an empty database,
which is a shape no deployment runs. The harness now provisions the three roles the schema
grants to and runs `ironauth migrate` before measuring.

**There is no cold-versus-warm split.** Once the first-exec cost is charged to a throwaway exec,
the samples are indistinguishable: 220, 268, 233, 263, 236 ms, with the first run the second
fastest. The split was an artifact of the measurement, so the table reports one population.

The old COLD row was also n=1 while this document claimed "a MEDIAN and a MAX over five runs",
and the verdict turned on that single unreplicated sample: three invocations of the unmodified
harness gave 1194, 1005 and 1068 ms, so one more draw would have flipped the published
conclusion with no change to the code being measured.

## What each number means, precisely

**startup to ready** is wall time from `exec()` to the FIRST `/readyz` that answers ready.

What that proves is narrower than an earlier version of this document claimed. It said readiness
came after "the first database round trip". It does not: `ReadinessProbe::probe` is a bare
`TcpStream::connect` to the configured Postgres address, and its own doc comment says "no bytes
are exchanged and no database protocol is spoken". The harness starts Postgres before the loop,
so that connect succeeds immediately and readiness fires when the management listener binds. The
review confirmed it live: `/readyz` answered `ready` against a database holding zero tables.

So this is process start to listener-up, with the Postgres address proven TCP-reachable. That is
a real number and it is NOT time-to-serving-traffic. An operator sizing a rollout on it should
know the pool has not yet spoken a byte of protocol.

**rss idle** is resident set size after readiness plus a settle period, with NO traffic. A number
taken under load is a different measurement wearing the same name.

Both are reported as a MEDIAN and a MAX over five runs, and the VERDICT is decided by the max. A
single sample on a shared machine is not a measurement, and a target judged on a median hides the
tail an operator actually experiences. The very first version of this harness judged the median
and printed "within both targets" on a run whose own max exceeded one of them.

## What this does not yet cover

Criterion 2 asks that CI run the harness per release, which needs a release pipeline. The
harness has never run on Linux, and the defect above is a direct warning about that: a platform
effect dominated the headline figure for an entire revision of this document.

The hardware class above is a development machine. A published sizing guide should be measured on
the instance classes it recommends, and these numbers should be read as a floor rather than as a
capacity statement.
