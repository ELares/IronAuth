<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# There is no committed benchmark baseline right now, deliberately

`bench-baseline.json` was deleted by the change that made the dispatch load precompiled
artifacts (issue #114 criterion 4). This file exists so the next person to see the gate fail
knows that is expected and what to do about it.

## Why the old one could not be kept

It recorded `cold_p95_micros = 93849.515`, measured on the pinned runner. That number is a
**compile**: the dispatch used `HookEngine::load`, so a cache miss ran cranelift.

The dispatch now deserializes a precompiled artifact when the stored engine key matches the
build, so the same benchmark measures a different operation -- 110.8 microseconds on a developer
laptop against roughly 33 milliseconds for the compile it replaces. A baseline is the figure the
gate enforces against and the figure a release publishes; keeping one that describes an operation
the code no longer performs would make both of those statements false.

It could not be kept even mechanically: `hook-bench-gate.sh` refuses a baseline above the
criterion's own ceiling, on the reasoning that such a baseline "describes a run that would itself
have failed". With the cold gate back at the criterion's 1000 microseconds, 93,849 is exactly
that.

## What happens next, and why the failure is the design

`hook-bench-gate.sh` treats a missing baseline as a FAILURE rather than a skip -- "a regression
check with nothing to compare against cannot fail". So the first run of the benchmark job on the
pinned runner class after this change **will fail**, and it will print the run's own measurement
under:

    hook-bench-gate: commit this as crates/ironauth-hooks/bench-baseline.json to record this run:

Commit that JSON as `crates/ironauth-hooks/bench-baseline.json` and delete this file. The
absolute gates still hold in the meantime: the run is checked against the criterion's 1 ms and
100 microseconds before the baseline arm is reached, so a genuinely slow build fails on those
whether or not a baseline exists.

## Why this was not done by writing a number here

Only the pinned runner's measurement is a baseline. A number taken anywhere else records a
different machine, and the gate refuses one recorded on a machine other than the one running --
correctly, because a p95 is a property of the measurement and not only of the code. Writing a
laptop figure into that file would have produced a green-looking artifact that the gate would
reject anyway, and that a release would otherwise have published as what the code was held to.
