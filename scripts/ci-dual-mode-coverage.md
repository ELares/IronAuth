# Dual-mode CI coverage and outbox diagnostics

Issue #1453 restores usable check evidence without weakening runtime assertions.

## Cache-attached OIDC coverage

The foundation job retains the real IronCache seam, chaos, shared-rate checks and
server build. It also compiles the full original target/example roster. Four
jobs execute the explicit disjoint inventory in `oidc-dual-targets.json` with the
unchanged `testing,ironcache` features. The inventory records every Cargo target
and validates it against locked offline metadata before selecting commands.

There are 169 registered integration targets. The same features enable 167;
`flow_custom_factor` and `token_hook_at_issuance` require `wasm-hooks` and were
already excluded by the original command. Shards contain 42, 42, 42 and 41 enabled
targets. The library executes once, in shard 0; doctests execute once, in shard 3.
The four examples retain their original compile-only behavior. New target kinds,
feature-closure changes, missing or duplicated assignments and changed test flags
fail the inventory check. Cargo failures remain failures, while `--no-fail-fast`
collects the remaining selected binary outcomes. The aggregate requires both the
foundation and all four shards to pass. Every execution job retains 30 minutes.

## Outbox failure evidence

The outbox job binds its actual GitHub run, attempt, source head and job start to
a fresh API response. It converts the remaining 30-minute budget to the runner's
monotonic clock, conservatively subtracting request time and timestamp precision.
The boot ID fences clock reuse across runners. A missing or ambiguous job clock
fails closed before the real chaos invocation.

The watchdog executes the original cargo command exactly once, for at most ten
minutes and ending at least two minutes before the actual job deadline. It adds
no retry. Static, flushed test-only stage labels surround the existing broker,
database, enqueue, notify, delivery, degradation and shutdown operations. They do
not include URLs, environment values, credentials or message content. The labels
localize a stopped operation; they do not by themselves establish its cause. A
success additionally requires the assertion-complete and broker-drop labels, so
a missing-broker skip cannot qualify the lane.

Only on failure does CI upload the bounded log, stage ledger and observer result.
The observer caps stdout at 8 MiB and the stage ledger at 1 MiB. Cleanup records
Linux process start identities and observed parent chains, and refuses to signal
a group containing an unproven or reused process identity. An unreaped direct
Popen child can be stopped if the first census fails, but descendant cleanup is
then explicitly unconfirmed. A forced stop is a failing result, never a passing
test or proof of database cleanup. The disposable PostgreSQL service remains
owned and retired by that workflow job. No serving provider or shared database is
part of these checks.

The local focused checks cover target selection, malformed inventories, actual
subprocess exit/output/deadline handling, clock binding and process ownership
models. The actual Linux `/proc` test runs on the hosted runner; macOS reports that
one case as skipped. The full dual-mode corpus and unresolved real chaos outcome
remain unqualified until the resulting hosted jobs actually execute.
