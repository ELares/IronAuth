# Measured startup and idle footprint

Issue #152 criterion 3 asks for RSS idle and startup time against the stated targets, with
methodology and hardware class stated. These are measured, not estimated, and reproduced by
one command:

```
PG_BIN=<postgresql bin dir> scripts/startup-rss-bench.sh
```

## Results

| measurement | value | target | |
|---|---|---|---|
| startup, COLD (fresh database, migrations run) | 1191 ms | < 1000 ms | **over** |
| startup, WARM (already migrated) | 257 ms median, 269 ms max | < 1000 ms | within |
| RSS idle | 13.4 MiB median, 13.5 MiB max | < 100 MiB | within |

Hardware class: Apple M4 Pro, 14 cores, 48 GiB, macOS 26.5.1. Release build, 5 runs.

## The cold number is over target, and that is the point of publishing it

The first boot against a fresh database runs every migration before it answers ready. A
deployment restarting an already-migrated database gets the warm number, which clears the
target by roughly four times.

An earlier version of the harness reported "within both targets" on this same data, because
it judged the median of all five runs and four of them were warm. The cold cost was in the
`max` column and the verdict walked past it. Cold and warm are different operations rather
than noise around one value, so they get separate rows and separate verdicts.

Whether a fresh install is in scope for "sub-second startup" is a product decision. Publishing
only the half that passes is not a decision.

## What each number means, precisely

**startup** is wall time from `exec()` to the FIRST `/readyz` that answers ready. Not to "the
process exists", which is microseconds and says nothing, and not to the first listening
socket, which precedes migrations and the first database round trip. Those two are the easy
numbers to publish and neither is what an operator waits for.

**rss idle** is resident set size after readiness plus a settle period, with NO traffic. A
number taken under load is a different measurement wearing the same name.

Both are reported as a MEDIAN and a MAX over five runs. A single sample on a shared machine is
not a measurement, and a target stated as a median hides the tail an operator actually
experiences.

## What this does not yet cover

Criterion 2 asks that CI run the harness per release, which needs a release pipeline. Criteria
4 and 5 ask for per-operation unit costs with Argon2id parameters stated, and for passkey and
OTP funnel metrics from synthetic flows; neither is produced here.

The hardware class above is a development machine. A published sizing guide should be measured
on the instance classes it recommends, and these numbers should be read as a floor rather than
as a capacity statement.
