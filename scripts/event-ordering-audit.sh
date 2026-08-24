#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Event-feed ordering registry (issue #945), in the shape of the idempotent-write registry:
# generate an inventory of every producer that puts a row on the events feed, classify each
# by the ordering it actually gets, diff the committed copy, and require the split to be a
# DECISION rather than an accident.
#
# THE DEFECT IT GUARDS. `OutboxRepo::append_event` takes a per-scope `pg_advisory_xact_lock`
# held to commit, which is what makes the feed's sequence order equal COMMIT order. NOTHING
# calls it: `grep -rn '\.append_event(' crates/*/src/` finds zero call sites, and its only
# callers anywhere are three test files. This script now asserts that emptiness in both
# directions, so the day a production call appears it is a decision somebody made rather than
# a fact discovered later. (An earlier revision of this comment said "almost nothing calls
# it" and the registry it generated recorded one row as appender-ordered. Both were wrong in
# the same direction: the one function serialised against other lock-takers,
# `publish_snapshot_inner`, takes the advisory lock DIRECTLY and never goes through the
# appender.) Every producer goes through `enqueue_domain_event`, which takes no
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
# WHY THERE IS NO PER-PRODUCER ORDERING CLASS. The first version of this script recorded one,
# by scanning each function's body for the per-scope advisory lock. A review defeated that
# column in both directions, and neither defeat is fixable by tightening the pattern:
#
#   - FALSE POSITIVE. The scan matched raw text, so a COMMENT naming `append_lock_key(scope)`
#     classified a function as taking the lock. The real lock could be deleted and replaced
#     with a truthful changelog comment about deleting it, and the registry stayed green and
#     unchanged. (Comments and string literals are now blanked before anything is matched, so
#     that particular reading is fixed; the column is still gone, for the next reason.)
#   - FALSE NEGATIVE. A producer that takes the lock through a one-line helper reads as
#     unlocked, because the lock is not in ITS body. Five rows recorded `unlocked` in fact ran
#     under a commit-held lock taken by a caller. Classifying correctly needs reachability,
#     and reachability is not something a text scan has.
#
# A column that is wrong in both directions is worse than no column, because it gets quoted.
# So this records WHERE the feed is written and leaves the ordering domain to the place that
# can state it honestly for every producer at once: docs/EVENTS-VS-WEBHOOKS.md, backed by
# events_cursor_ordering.rs.
#
# The naming point that column was carrying is still worth keeping, because it is why nobody
# should reintroduce it casually: `pg_advisory_xact_lock` excludes only other sessions
# requesting the SAME key. A lock-taker's rows are serialised against other lock-takers and
# against nothing else, and with zero production lock-takers reached through the appender,
# "commit-ordered" would have named a guarantee no consumer actually receives.
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
#
# `-z` and a NUL split rather than whitespace: a tracked path may contain a space, and
# `.split()` would turn one such file into two nonexistent ones that the loop below skips in
# silence. There are none today; a census that quietly drops a file when someone adds one is
# not a census.
tracked = subprocess.run(
    ["git", "ls-files", "-z", "crates/*/src/*.rs", "crates/*/src/**/*.rs"],
    capture_output=True, text=True, check=True,
).stdout.split("\0")
tracked = [t for t in tracked if t]

# ---------------------------------------------------------------------------------------
# Reading Rust as TEXT, and the one thing that has to be got right first
#
# Everything below is a text scan. A text scan that reads comments and string literals cannot
# tell code from a sentence ABOUT code, and that is not a theoretical complaint: a review of
# the first version of this script defeated it four separate ways, all the same way. A comment
# mentioning a helper classified a function as calling it. A `}` inside a comment ended a
# function body early and hid every call after it. A doc comment containing the text
# `#[cfg(test)]` deleted a span of real producers from the census.
#
# So the first thing that happens to every file is that its comments and string literals are
# blanked, preserving line structure and length so that reported line numbers stay true. After
# this, a `{` is a brace, and a helper name is a call.
LINE_COMMENT, BLOCK_COMMENT, STRING, CHAR, RAW = range(5)

def blank_noncode(text, keep_strings=False):
    """Replace comment (and, unless `keep_strings`, literal) CONTENT with spaces, keeping
    every newline in place.

    `keep_strings` exists for ONE reason: a producer that writes the outbox row itself does so
    in SQL, and SQL lives inside a string literal. Blanking literals is what stops a comment
    from being read as code, and it is also what would make raw SQL invisible. So identifier
    spellings are matched against the fully blanked text and SQL is matched against the
    comments-only-blanked text, and neither can be satisfied by a sentence in a comment.
    """
    out = []
    i, n = 0, len(text)
    state = None
    raw_hashes = 0
    block_depth = 0
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state is None:
            if ch == "/" and nxt == "/":
                state = LINE_COMMENT; out.append("  "); i += 2; continue
            if ch == "/" and nxt == "*":
                state = BLOCK_COMMENT; block_depth = 1; out.append("  "); i += 2; continue
            # r"..." and r#"..."# -- a raw string ends only at its matching hash count.
            if ch == "r" and (nxt == '"' or nxt == "#"):
                j = i + 1
                hashes = 0
                while j < n and text[j] == "#":
                    hashes += 1; j += 1
                if j < n and text[j] == '"':
                    state = RAW; raw_hashes = hashes
                    out.append(" " * (j - i + 1)); i = j + 1; continue
            if ch == '"':
                if keep_strings:
                    out.append(ch); i += 1
                    # Copy the literal verbatim, still honouring escapes so a `\"` does not
                    # end it early.
                    while i < n:
                        c = text[i]
                        if c == "\\" and i + 1 < n:
                            out.append(text[i:i + 2]); i += 2; continue
                        out.append(c); i += 1
                        if c == '"':
                            break
                    continue
                state = STRING; out.append(" "); i += 1; continue
            if ch == "'":
                # A lifetime (`'a`) is not a char literal. A char literal is `'x'` or `'\n'`.
                j = i + 1
                if j < n and text[j] == "\\":
                    state = CHAR; out.append(" "); i += 1; continue
                if j + 1 < n and text[j + 1] == "'":
                    state = CHAR; out.append(" "); i += 1; continue
            out.append(ch); i += 1; continue
        if state == LINE_COMMENT:
            if ch == "\n":
                state = None; out.append("\n")
            else:
                out.append(" ")
            i += 1; continue
        if state == BLOCK_COMMENT:
            # Rust block comments NEST: `/* /* */ */` is one comment, and exiting on the
            # first `*/` would treat the remainder of the outer comment as code. That is the
            # same class of mistake as not blanking comments at all -- a sentence read as a
            # call -- so the depth is counted rather than assumed to be one.
            if ch == "/" and nxt == "*":
                block_depth += 1; out.append("  "); i += 2; continue
            if ch == "*" and nxt == "/":
                block_depth -= 1
                if block_depth == 0:
                    state = None
                out.append("  "); i += 2; continue
            out.append("\n" if ch == "\n" else " "); i += 1; continue
        if state == STRING:
            if ch == "\\":
                # A backslash-newline line continuation: emit the NEWLINE, or every line
                # number after it shifts. repository.rs writes almost every SQL statement
                # this way, so eating them desynchronised the blanked text from the raw text
                # by hundreds of lines.
                out.append(" " + ("\n" if nxt == "\n" else " ")); i += 2; continue
            if ch == '"':
                state = None; out.append(" "); i += 1; continue
            out.append("\n" if ch == "\n" else " "); i += 1; continue
        if state == CHAR:
            if ch == "\\":
                out.append(" " + ("\n" if nxt == "\n" else " ")); i += 2; continue
            if ch == "'":
                state = None; out.append(" "); i += 1; continue
            out.append(" "); i += 1; continue
        if state == RAW:
            if ch == '"':
                j = i + 1; seen = 0
                while j < n and text[j] == "#" and seen < raw_hashes:
                    seen += 1; j += 1
                if seen == raw_hashes:
                    state = None; out.append(" " * (j - i)); i = j; continue
            out.append("\n" if ch == "\n" else " "); i += 1; continue
    return "".join(out)

# Every spelling that writes an outbox row, keyed on the CALL rather than on a method name
# that merely suggests a producer.
# Every spelling that writes an outbox row, ONE PATTERN PER SPELLING so each can be counted
# on its own. A single alternation cannot tell "this helper was renamed and the regex now
# matches nothing through it" from "nobody happens to call it", and that is the failure the
# floor below is supposed to catch.
PRODUCER_SPELLINGS = {
    "enqueue_domain_event": re.compile(r"\benqueue_domain_event\s*\("),
    "enqueue_outbox_in_tx*": re.compile(
        r"\benqueue_outbox_in_tx(?:_at|_at_unvalidated|_ignoring_conflict)?\s*\("
    ),
    "append_event": re.compile(r"\.append_event\s*\("),
    "enqueue*": re.compile(r"\.enqueue(?:_all|_unvalidated_for_test)?\s*\("),
    # A producer that skips every helper and writes the row itself. Without this the census
    # is blind to exactly the newcomer least likely to have been reviewed.
    "raw INSERT": re.compile(r"INSERT\s+INTO\s+outbox_messages\b", re.IGNORECASE),
}
RAW_SQL = PRODUCER_SPELLINGS["raw INSERT"]
PRODUCER = re.compile(
    "|".join(f"(?:{r.pattern})" for name, r in PRODUCER_SPELLINGS.items()
             if name != "raw INSERT")
)
# Any declaration form, rather than the two modifiers that happened to be in front of the
# author. `pub(crate) async unsafe fn`, `const fn`, `extern "C" fn` and plain `fn` are all
# producers if their bodies emit, and enumerating modifiers is how a scan goes quietly blind
# to the next one somebody uses.
FN = re.compile(
    r"^(\s*)"
    r'(?:(?:pub(?:\([^)]*\))?|async|const|unsafe|extern(?:\s+"[^"]*")?)\s+)*'
    r"fn\s+([A-Za-z0-9_]+)"
)
CFG_TEST = re.compile(r"#\[cfg\(\s*(?:all\(\s*)?test\b")
# A `#[cfg(feature = "testing")]` item is compiled only for the test harness. The header calls
# this a registry of PRODUCTION functions, so such an item does not belong in it. (The feature
# name survives the literal blanking above because the attribute is matched before the value.)
CFG_TESTING_FEATURE = re.compile(r'#\[cfg\([^]]*feature\s*=\s*"testing"')

# Plumbing: the helpers themselves, and the wake machinery that rides beside them. Scoped to
# the FILE that defines each, because a bare name excludes that name everywhere -- a producer
# in another crate called `enqueue_all` would have been invisible, which is the exact
# name-collision defect the row key was already fixed for once.
PLUMBING = {
    ("crates/ironauth-store/src/repository.rs", "append_event"),
    ("crates/ironauth-store/src/repository.rs", "enqueue_domain_event"),
    ("crates/ironauth-store/src/repository.rs", "enqueue_outbox_in_tx"),
    ("crates/ironauth-store/src/repository.rs", "enqueue_outbox_in_tx_at"),
    ("crates/ironauth-store/src/repository.rs", "enqueue_outbox_in_tx_at_inner"),
    ("crates/ironauth-store/src/repository.rs", "enqueue_outbox_in_tx_at_unvalidated"),
    ("crates/ironauth-store/src/repository.rs", "enqueue_outbox_in_tx_ignoring_conflict"),
    ("crates/ironauth-store/src/repository.rs", "signal_wakes"),
    ("crates/ironauth-store/src/repository.rs", "record_wake"),
    ("crates/ironauth-store/src/repository.rs", "append_lock_key"),
}
# Call sites that match a producer spelling but write no outbox row, scoped to (file,
# function) rather than to a whole file. `hashing_pool::submit` calls an in-memory Argon2 job
# queue's own `enqueue`. Excluding its whole FILE on that one function's justification would
# have hidden a real producer added anywhere else in it.
NON_OUTBOX = {
    ("crates/ironauth-oidc/src/hashing_pool.rs", "submit"),
}

# Test modules whose `#[cfg(all(test, feature = "testing"))]` sits on the `mod` DECLARATION in
# another file, so an in-file scan cannot see it. Discovered rather than hardcoded, so a new
# one joins the exclusion the moment it is declared, instead of quietly entering a PRODUCTION
# registry the way `outbox_wiring_tests` did.
def cfg_test_modules(sources):
    excluded = set()
    for path, lines in sources.items():
        p = pathlib.Path(path)
        for n, line in enumerate(lines):
            if not CFG_TEST.search(line):
                continue
            for m in range(n + 1, min(n + 4, len(lines))):
                decl = re.match(r"\s*mod\s+([A-Za-z0-9_]+)\s*;", lines[m])
                if decl:
                    excluded.add(str(p.parent / f"{decl.group(1)}.rs"))
                    break
    return excluded

# Read every file ONCE, blanked. A path that does not exist is a census hole, not a file to
# skip quietly: `git ls-files` lists the index, so a listed-but-absent path means the working
# tree disagrees with it and the count below would be silently short.
sources = {}
raw_sources = {}
sql_visible = {}
missing = []
for path in tracked:
    p = pathlib.Path(path)
    if not p.exists():
        missing.append(path)
        continue
    text = p.read_text(encoding="utf-8")
    blanked = blank_noncode(text)
    sql_kept = blank_noncode(text, keep_strings=True)
    sql_visible[path] = sql_kept
    # The blanking is only safe if it is line-for-line. Everything below indexes the raw text
    # by a line number found in the blanked text, so a single swallowed newline points every
    # later lookup at the wrong line. This is not a hypothetical: the first version ate the
    # newline of every backslash-continued string literal, and repository.rs has hundreds.
    for label, view in (("blanked", blanked), ("sql-visible", sql_kept)):
        if view.count("\n") != text.count("\n"):
            print(
                f"event-ordering-audit: the {label} view of {path} changed its line count "
                f"({text.count(chr(10))} -> {view.count(chr(10))}); the two views are read "
                f"at the same line indices, so every lookup into that file would be wrong.",
                file=sys.stderr,
            )
            sys.exit(1)
    sources[path] = blanked.splitlines()
    # The RAW lines too. An attribute is selected ON a string literal
    # (`#[cfg(feature = "testing")]`), and the blanking above erases exactly that literal, so
    # an attribute check run against the blanked text cannot see which feature it names.
    raw_sources[path] = text.splitlines()
if missing:
    print(
        "event-ordering-audit: these tracked sources are missing from the working tree, so "
        "the census below would be short without saying so: " + ", ".join(sorted(missing)),
        file=sys.stderr,
    )
    sys.exit(1)

EXCLUDED = cfg_test_modules(sources)

# name -> how many producer bodies carry it, per file.
counts = {}

for path, lines in sources.items():
    if path in EXCLUDED:
        continue
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

    claimed = []  # (start, end) of bodies already attributed, so a nested fn is not a second row.
    for n, line in enumerate(lines):
        m = FN.match(line)
        if not m:
            continue
        name = m.group(2)
        if (path, name) in PLUMBING or (path, name) in NON_OUTBOX or in_test(n):
            continue
        if any(a <= n <= b for a, b in claimed):
            continue  # a nested fn inside a body already counted: one site, one row.
        # A `#[cfg(feature = "testing")]` item is compiled only for the test harness, and
        # this registry's header calls itself a census of PRODUCTION code. Read from the RAW
        # lines: `enqueue_unvalidated_for_test` sat in the registry under the header's own
        # word "production" precisely because the blanked text no longer says "testing".
        attrs = "\n".join(raw_sources[path][max(0, n - 6):n])
        if CFG_TESTING_FEATURE.search(attrs):
            continue
        depth, started, body_lines = 0, False, []
        end_index = n
        for index in range(n, len(lines)):
            body_lines.append(lines[index])
            for ch in lines[index]:
                if ch == "{":
                    depth += 1
                    started = True
                elif ch == "}":
                    depth -= 1
            end_index = index
            if started and depth <= 0:
                break
        if not started:
            # A `fn` with no body in this file (a trait method signature, or a truncated
            # scan). Not a producer, and not a reason to swallow the rest of the file.
            continue
        claimed.append((n, end_index))
        # The body twice: identifiers from the blanked view, SQL from the view that kept its
        # string literals. Both are line-aligned with each other and with the raw file.
        sql_body = "\n".join(sql_visible[path].splitlines()[n:end_index + 1])
        if not PRODUCER.search("\n".join(body_lines)) and not RAW_SQL.search(sql_body):
            continue
        counts[(path, name)] = counts.get((path, name), 0) + 1

# The row key is (file, function, COUNT), and the count is what makes it work.
#
# Keying on file:function alone collapsed every same-named function in a file into one row --
# repository.rs holds 22 `delete_with_event` and 16 `create_with_event`, so 140 producer
# bodies became 77 rows and a NEW producer reusing an existing name changed nothing. Keying on
# the LINE fixed that and broke something else: any edit that shifts line numbers rewrote 122
# of 140 rows, so the one row that changed CLASS was buried in churn and the diff stopped
# being reviewable, which is the only thing this registry is for.
#
# A count is unique where a bare name was not, and stable where a line number was not. A 23rd
# `delete_with_event` moves one character on one line.
rows = [f"{path}:{name}:{count}" for (path, name), count in counts.items()]
rows.sort()
total = sum(counts.values())

# TWO floors, because the blunt one cannot catch the failure it was written for.
#
# A total-count floor only fires if a rename takes out enough producers at once. Rename ONE of
# the five spellings and the census drops from 139 to perhaps 130: still comfortably over any
# floor, still silently blind to every producer that used it. So each SPELLING carries its own
# floor of one. A spelling that matches nowhere in the tree is either dead code that should be
# deleted from this list, or a helper that has been renamed out from under the regex, and both
# are things somebody has to look at.
# Two spellings are EXPECTED to match nothing, each for a recorded reason. The guard runs in
# both directions: an expected-present spelling that stops matching is a rename, and an
# expected-absent one that starts matching is a change to the feed's shape. Either way a
# person looks.
EXPECTED_ABSENT = {
    # `raw INSERT` is deliberately NOT here: the helper that writes the outbox row does so
    # with raw SQL, so the spelling legitimately matches inside the plumbing. What matters is
    # a raw INSERT in a body that is NOT plumbing, and that is caught the ordinary way -- it
    # becomes a census row, in a file where nobody expected one.
    "append_event": (
        "the commit-ordered appender has NO production caller. It was written for issue "
        "#104's criterion and every producer added afterwards reached for the unlocked "
        "helper instead. The one function that is serialised against other lock-takers, "
        "publish_snapshot_inner, takes the advisory lock directly rather than through this. "
        "If a production call appears, the feed has gained its first appender-ordered "
        "producer and that is a decision, not a refactor. NOTE the match is receiver-blind: "
        "`anything.append_event(...)` trips this, not only an OutboxRepo. Check the receiver "
        "before treating it as a feed change; a false alarm here costs one reading, and the "
        "alternative -- narrowing the pattern -- costs a silent miss."
    ),
}
SQL_SPELLINGS = {"raw INSERT"}

def corpus(name):
    """The text a spelling is matched against: SQL needs its string literals, identifiers
    must not have them."""
    if name in SQL_SPELLINGS:
        return sql_visible.values()
    return ("\n".join(lines) for lines in sources.values())

present = {
    name for name, pattern in PRODUCER_SPELLINGS.items()
    if any(pattern.search(text) for text in corpus(name))
}
vanished = sorted(n for n in PRODUCER_SPELLINGS if n not in present and n not in EXPECTED_ABSENT)
appeared = sorted(n for n in EXPECTED_ABSENT if n in present)
if vanished or appeared:
    if vanished:
        print(
            "event-ordering-audit: these producer spellings match nothing in the tree: "
            + ", ".join(vanished)
            + ". Either the helper was renamed (and every producer reached through it is "
            "now invisible to this census) or it is dead and belongs out of this list.",
            file=sys.stderr,
        )
    for name in appeared:
        print(
            f"event-ordering-audit: `{name}` was recorded as having no production call site, "
            f"and now has one. {EXPECTED_ABSENT[name]}",
            file=sys.stderr,
        )
    sys.exit(1)

MINIMUM_SITES = 120
if total < MINIMUM_SITES:
    # Fail BEFORE writing. A floor that writes the corrupted inventory first leaves the tree
    # dirty with exactly the file the next run diffs against.
    print(
        f"event-ordering-audit: only {total} producer bodies found, below the floor of "
        f"{MINIMUM_SITES}. Something removed producers wholesale rather than one at a time.",
        file=sys.stderr,
    )
    sys.exit(1)

header = [
    "# GENERATED by scripts/event-ordering-audit.sh. Do not edit by hand.",
    "#",
    "# A census of every place production code writes a row to the events feed:",
    "#   <file>:<function>:<how many bodies with that name in that file are producers>",
    "#",
    "# WHAT THIS DOES AND DOES NOT SAY.",
    "#",
    "# It says WHERE the feed is written, and it makes any change to that set show up in a",
    "# diff. That is its whole job: a producer joining the feed is usually a fine choice, and",
    "# joining it SILENTLY is not.",
    "#",
    "# It deliberately does NOT record an ordering class per producer. An earlier version did,",
    "# by scanning each function's body for the per-scope advisory lock. That cannot be made",
    "# sound by a text scan: a producer that takes the lock through a one-line helper reads as",
    "# unlocked, a producer one call away from the emit site is not seen at all, and five rows",
    "# recorded `unlocked` in fact ran under a commit-held lock taken by a caller. A column",
    "# that is wrong in both directions is worse than no column, because it is quoted.",
    "#",
    "# WHAT IT CAN MISS. This is a text scan, not a reachability analysis. It sees a call to",
    "# one of the known emit helpers, or a raw INSERT into outbox_messages, in a function's",
    "# OWN body. A producer that reaches the feed through a wrapper of its own is recorded at",
    "# the wrapper and not at its callers, so this census answers \"where is the feed",
    "# written\" and not \"which request paths can reach it\".",
    "#",
    "# The ordering domain itself is documented in docs/EVENTS-VS-WEBHOOKS.md and measured by",
    "# crates/ironauth-store/tests/events_cursor_ordering.rs. What every producer gets is",
    "# completeness and replay stability, delivered by the visibility watermark in",
    "# `events_after` rather than by any lock.",
]
inventory.write_text("\n".join(header + rows) + "\n", encoding="utf-8")
print(
    f"event-ordering-audit: {total} producer bodies across {len(rows)} (file, function) "
    f"pairs"
)
PY

if ! git diff --exit-code "$INVENTORY"; then
    echo
    echo "event-ordering-audit: $INVENTORY is stale. The set of places production code writes"
    echo "                      to the events feed has changed: a producer was added, removed,"
    echo "                      or one name now covers a different number of them."
    echo
    echo "                      Read the diff above and decide DELIBERATELY that the new"
    echo "                      producer belongs on the feed, then commit the regenerated"
    echo "                      inventory. Adding one is usually the right call; adding one"
    echo "                      without anybody looking is what this exists to stop."
    echo
    echo "                      What the feed guarantees for every producer is completeness"
    echo "                      and replay stability, from the visibility watermark in"
    echo "                      events_after. It does NOT guarantee that sequence order equals"
    echo "                      commit order, so a consumer that needs commit order needs more"
    echo "                      than a place on this list. See docs/EVENTS-VS-WEBHOOKS.md."
    exit 1
fi

echo "event-ordering-audit: clean (the committed inventory matches the tree)"
