#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Event-feed ordering registry (issue #945), in the shape of the idempotent-write registry:
# generate an inventory of every producer that puts a row on the events feed, classify each
# by the ordering it actually gets, diff the committed copy, and require the split to be a
# DECISION rather than an accident.
#
# THE DEFECT IT GUARDS. `OutboxRepo::append_event` takes a per-scope `pg_advisory_xact_lock`
# held to commit, which is what makes the feed's sequence order equal COMMIT order. Almost
# nothing calls it. Every other producer goes through `enqueue_domain_event`, which takes no
# lock, so its rows carry the divergence `events_cursor_ordering.rs::
# the_feed_orders_by_sequence_which_is_not_commit_order` measures: a sequence is allocated
# when the row is written, not when its transaction commits, so two overlapping transactions
# can commit in the opposite order to their sequences.
#
# That is not a bug to be fixed by routing everything through the appender. The lock is held
# to COMMIT, so putting session-ended and token metering behind it serialises sign-in per
# environment: `append_lock_key` hashes tenant and environment, and both `insert_session_row`
# and `meter_token_issued` sit on those paths. Trading a throughput cliff on the
# authentication path for a documentation sentence is the wrong trade.
#
# (An earlier version of this comment cited
# `events_cursor_ordering.rs::an_unrelated_open_transaction_stalls_the_whole_feed` as having
# measured what a held lock does to the feed. It does not: that test takes no advisory lock
# and measures the READ-side watermark, which applies to every producer regardless of class.
# Its own comment argues the other way, that the watermark's cost is why a commit-ordered
# appender is worth weighing rather than assuming. The citation was wrong; the conclusion
# does not rest on it.)
#
# So the split stands, and this makes it explicit. What the feed guarantees for EVERY producer
# is completeness and replay stability, both delivered by the visibility watermark in
# `events_after` rather than by any lock: a cursor never advances past an event that had not
# committed when it was read, and a cursor read twice returns the same events in the same
# order.
#
# The classes are named `takes-append-lock` and `unlocked` rather than `commit-ordered` and
# `sequence-ordered`, deliberately. `pg_advisory_xact_lock` excludes only other sessions
# requesting the SAME key, so a lock-taker's rows are serialised against other lock-takers and
# against nothing else. With one lock-taker in the tree, "commit-ordered" would have named a
# guarantee no consumer actually receives.
#
# WHY A REGISTRY AND NOT A LINT. A new producer joining the sequence-ordered set is a
# legitimate choice most of the time. What must not happen is joining it SILENTLY, which is
# how the current split arose: `append_event` was written for criterion 2, and then every
# producer added afterwards reached for the unlocked helper because it was the one in front
# of them. A diffable inventory makes the choice visible in review.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# shellcheck source=scripts/lib/generated-artifact.sh
. scripts/lib/generated-artifact.sh

INVENTORY="docs/design/event-ordering-sites.txt"
require_tracked "event-ordering-audit" "$INVENTORY"

python3 - "$INVENTORY" <<'PY'
import pathlib, re, subprocess, sys

inventory = pathlib.Path(sys.argv[1])

# TRACKED sources only. Note what that does and does not buy: an untracked `.rs` that is
# `mod`-declared IS compiled, because cargo reads the filesystem rather than the index, so
# this does not stop a producer hiding locally. What it buys is a stable census in CI, which
# checks out committed state, and a diff that cannot be perturbed by scratch files.
tracked = subprocess.run(
    ["git", "ls-files", "crates/*/src/*.rs", "crates/*/src/**/*.rs"],
    capture_output=True, text=True, check=True,
).stdout.split()

# Every spelling that writes an outbox row, keyed on the CALL rather than on a method name
# that merely suggests a producer. `enqueue_all` and the two unvalidated/conflict-tolerant
# helpers are included because each has its own INSERT and each is reachable.
PRODUCER = re.compile(
    r"\benqueue_domain_event\s*\(|"
    r"\benqueue_outbox_in_tx(?:_at|_at_unvalidated|_ignoring_conflict)?\s*\(|"
    r"\.append_event\s*\(|"
    r"\.enqueue(?:_all|_unvalidated_for_test)?\s*\("
)
# The class keys on the per-scope advisory lock, which is what actually serialises appenders,
# rather than on which helper was called: `publish_snapshot_inner` takes the lock itself.
LOCK = re.compile(r"\bappend_lock_key\s*\(")
APPEND = re.compile(r"\.append_event\s*\(")
FN = re.compile(r"^(\s*)(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)")
CFG_TEST = re.compile(r"#\[cfg\(\s*(?:all\(\s*)?test\b")

# Plumbing: the helpers themselves, and the wake machinery that rides beside them.
PLUMBING = {
    "append_event", "enqueue_domain_event", "enqueue_outbox_in_tx",
    "enqueue_outbox_in_tx_at", "enqueue_outbox_in_tx_at_inner",
    "enqueue_outbox_in_tx_at_unvalidated", "enqueue_outbox_in_tx_ignoring_conflict",
    "signal_wakes", "record_wake", "append_lock_key",
}
# Files this census must not walk.
#
# `hashing_pool::submit` calls an in-memory Argon2 job queue's own `enqueue` and matched the
# broad spelling above; it writes no outbox row.
NON_OUTBOX_FILES = {"crates/ironauth-oidc/src/hashing_pool.rs"}

# Test modules whose `#[cfg(all(test, feature = "testing"))]` sits on the `mod` DECLARATION in
# another file, so an in-file scan cannot see it. Discovered rather than hardcoded, so a new
# one joins the exclusion the moment it is declared, instead of quietly entering a PRODUCTION
# registry the way `outbox_wiring_tests` did.
def cfg_test_modules():
    excluded = set()
    for path in tracked:
        p = pathlib.Path(path)
        if not p.exists():
            continue
        lines = p.read_text(encoding="utf-8").splitlines()
        for n, line in enumerate(lines):
            if not CFG_TEST.search(line):
                continue
            for m in range(n + 1, min(n + 4, len(lines))):
                decl = re.match(r"\s*mod\s+([A-Za-z0-9_]+)\s*;", lines[m])
                if decl:
                    excluded.add(str(p.parent / f"{decl.group(1)}.rs"))
                    break
    return excluded

rows = []
EXCLUDED = NON_OUTBOX_FILES | cfg_test_modules()

for path in tracked:
    if path in EXCLUDED:
        continue
    p = pathlib.Path(path)
    if not p.exists():
        continue
    lines = p.read_text(encoding="utf-8").splitlines()
    # Line numbers of `#[cfg(test)]` modules, so an inline test producer does not enter a
    # PRODUCTION registry. The comment used to claim tests were skipped while nothing skipped
    # them, and a `#[cfg(all(test, ...))]` module in `src/` was in the census.
    test_spans = []
    for n, line in enumerate(lines):
        if CFG_TEST.search(line):
            indent = len(line) - len(line.lstrip())
            end_n = len(lines)
            for m in range(n + 1, len(lines)):
                stripped = lines[m].lstrip()
                if stripped.startswith("}") and (len(lines[m]) - len(stripped)) <= indent:
                    end_n = m
                    break
            test_spans.append((n, end_n))

    def in_test(index):
        return any(a <= index <= b for a, b in test_spans)

    for n, line in enumerate(lines):
        m = FN.match(line)
        if not m:
            continue
        name = m.group(2)
        if name in PLUMBING or in_test(n):
            continue
        # The function's OWN body, by brace counting from its opening brace.
        depth, started, body_lines = 0, False, []
        for index in range(n, len(lines)):
            body_lines.append(lines[index])
            for ch in lines[index]:
                if ch == "{":
                    depth += 1
                    started = True
                elif ch == "}":
                    depth -= 1
            if started and depth <= 0:
                break
        body = "\n".join(body_lines)
        if not PRODUCER.search(body):
            continue
        ordered = "takes-append-lock" if (LOCK.search(body) or APPEND.search(body)) else "unlocked"
        # The LINE is part of the key. Without it `sorted(set(...))` collapsed every
        # same-named function in a file into one row: repository.rs alone holds 22
        # `delete_with_event` and 16 `create_with_event`, so 140 producer bodies became 77
        # rows and a NEW producer reusing an existing name changed nothing. That is the
        # mutation this registry exists to catch, and it survived.
        rows.append(f"{path}:{n + 1}:{name}:{ordered}")

rows.sort()
header = [
    "# GENERATED by scripts/event-ordering-audit.sh. Do not edit by hand.",
    "#",
    "# One row per production function that writes a row to the events feed:",
    "#   <file>:<line>:<function>:<class>",
    "#",
    "# takes-append-lock : the body takes the per-scope advisory lock held to commit, so its",
    "#                     rows are serialised against OTHER lock-takers. It is not a promise",
    "#                     of commit order against unlocked producers, and with one lock-taker",
    "#                     in the tree it currently orders against nothing.",
    "# unlocked          : sequence-ordered. Complete and replay-stable like every producer,",
    "#                     and not ordered against concurrent writers.",
    "#",
    "# A producer joining the unlocked set is usually right. Joining it SILENTLY is not.",
]
inventory.write_text("\n".join(header + rows) + "\n", encoding="utf-8")

locked = sum(1 for r in rows if r.endswith(":takes-append-lock"))
MINIMUM_ROWS = 120
if len(rows) < MINIMUM_ROWS:
    print(
        f"event-ordering-audit: only {len(rows)} producers found, below the floor of "
        f"{MINIMUM_ROWS}. A helper was probably renamed out from under the regex, which "
        f"would empty this registry silently rather than fail it.",
        file=sys.stderr,
    )
    sys.exit(1)
print(f"event-ordering-audit: {len(rows)} producers ({locked} take the append lock, {len(rows) - locked} unlocked)")
PY

if ! git diff --exit-code "$INVENTORY"; then
    echo
    echo "event-ordering-audit: $INVENTORY is stale (an event producer was added, removed, or"
    echo "                      changed its ordering class)."
    echo "                      Review the diff above, decide DELIBERATELY which class the"
    echo "                      producer belongs in, and commit the regenerated inventory."
    echo
    echo "                      sequence-ordered is the right default for a producer on a hot"
    echo "                      path: the feed stays complete and replay-stable for it, and it"
    echo "                      pays no lock. Choose commit-ordered only when a consumer must"
    echo "                      see that producer's events in the order its transactions"
    echo "                      committed, and only where the scope lock's cost is acceptable."
    exit 1
fi

echo "event-ordering-audit: clean (the committed inventory matches the tree)"
