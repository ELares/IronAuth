#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Every management write handler emits a registered event type (issue #108, criterion 6).

Criterion 6 originally read "the registry counts at least 100 registered event types". The
owner replaced it with this check, because a COUNT is the wrong measure: it is satisfied by
registering types nothing emits, which is the exact fiction the registry's own rule already
forbids -- a consumer would subscribe to such a type and wait forever. Coverage measures the
property the count was a proxy for, and it cannot be inflated by adding rows to a table.

THE DENOMINATOR IS THE ROUTER. A management write handler is one mounted on a write method
(`post`/`put`/`patch`/`delete`) in the admin router's flat route list. That list is the
deployment's own statement of what its management surface is, so a new endpoint enters this
check the moment it becomes reachable, and an internal helper that happens to write never
inflates it.

THE NUMERATOR is whether the handler's frame BUILDS A DOMAIN EVENT, not whether it calls a
method with a particular suffix.

That distinction was a measured bug in the first version of this script, and it is worth
stating because the obvious rule looks right. Matching `_with_event(` seemed safe -- the
delegating-wrapper convention means `create` delegates to `create_with_event(..., None)`. But
the store's event-accepting methods have EIGHT distinct spellings, and three of them carry no
suffix at all: `admin_create_emitting`, `delete`, `update_claims`. So `users::create_user`,
`users::delete_user` and `users::update_user` were all reported as announcing nothing while
they each emit a registered type.

A check defeated by a SPELLING rather than by a decision is not a rule. Every producer must
construct the event before handing it over, so the construction is the invariant: a
`DomainEvent` value, or one of the `*_event(` builders the handlers use. That is stable
whatever the store method is called.

A TRAP THIS DELIBERATELY DOES NOT FALL INTO. The obvious refinement -- narrow the denominator
to handlers containing an audited write (`.acting(`) -- is WRONG, and measurably so. It would
drop 20 handlers, but `brand_assets::set_brand_logo` (a 179-byte frame) and
`organizations::disable_organization` (347 bytes) are thin delegators that write through a
shared helper and contain no `.acting(` of their own. Auto-exempting on that signal would
silently excuse real writes, which is the failure this check exists to prevent. So the
denominator stays the full mounted write surface, and anything genuinely non-mutating is
named in `EXEMPT` with a reason a reviewer can check.

THE BASELINE IS A RATCHET, and it deliberately states no coverage figure. It was introduced
while most handlers were uncovered, because a check that fails from its first commit gets
disabled rather than fixed; the uncovered handlers went into
`producer-coverage-baseline.txt` so the check could pass on day one and tighten from there.
The live figure is PRINTED by this script on every run, which is the only place it cannot go
stale. This fails on:

  * a handler that is uncovered and NOT in the baseline -- a NEW management write that
    announces nothing, which is the regression worth blocking; and
  * a baseline entry that is now covered or no longer exists -- so the file shrinks as
    producers land and cannot rot into a permanent excuse.

An EMPTY baseline is the strongest state this can be in and not a reason to delete it: with
no entries left, the first rule alone means every management write handler must reach a
producer, and any new one that does not fails on the pull request that adds it.

Issue #108 closes when the baseline is EMPTY. The file's length is the remaining work, stated
in the repository rather than in a status report.

Usage:
    producer-coverage.py [--update-baseline]
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(
    subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True
    ).stdout.strip()
)
ADMIN = ROOT / "crates" / "ironauth-admin" / "src"
ROUTER = ADMIN / "lib.rs"
BASELINE = ROOT / "scripts" / "producer-coverage-baseline.txt"

# `post(tenants::create_tenant)` -> ("post", "tenants", "create_tenant")
ROUTE = re.compile(r"\b(post|put|patch|delete)\(\s*([a-z0-9_]+)::([a-z0-9_]+)\s*[,)]")

# The frame builds an event: a `DomainEvent` value, a call to one of the `*_event`
# builders, or a direct `event_catalog::envelope(...)`. Keyed on CONSTRUCTION rather than
# on the store method's name, because the event-accepting methods are spelled eight
# different ways and three carry no suffix (`admin_create_emitting`, `delete`,
# `update_claims`).
#
# `envelope(` is the third shape and it was missing. A producer that rides a domain write
# hands the store a `DomainEvent`; a producer with NO domain write to ride -- a scheduled
# job, an operator-triggered publish -- builds the envelope itself and appends it. That
# second shape is documented on `OutboxRepo::append_event` as the supported path, so it is
# what every future producer of its kind will look like, and this scan reported the first
# one that arrived as announcing nothing. An EXEMPT entry would have been a false
# statement: that handler both mutates and announces.
#
# Deliberately not tightened to `event_catalog::envelope`, and NOT because every call site
# is that qualified form: 80 are, and four are `crate::events::envelope(` (`users.rs` three
# times, `organizations.rs` once). The "76" here was stale for several changes before anyone
# counted; both numbers are hand written beside a thing that moves, so re-measure them rather
# than trusting them. An earlier version of this comment asserted the stronger
# thing, which was false and would have made the tightening look free. Measured, tightening
# still passes (137/137 at the time of writing), because those four producers are detected
# through the `*_event(`
# shape instead. The reason to keep the loose pattern is the tradeoff below: the looser
# pattern's only risk is a false PASS on some future unrelated `envelope(`. That is the
# wrong direction to guard against
# here -- a false FAILURE on a correct handler would push the next author toward an
# EXEMPT entry, and a wrong EXEMPT entry is permanent while a wrong regex is not.
EMITS = re.compile(r"DomainEvent|\b[a-z0-9_]+_event\s*\(|\benvelope\s*\(")

# Mounted on a write method, but mutates NOTHING: a query whose input does not fit in a URL.
# Each was read and confirmed to contain no write call and no audited write. An event here
# would announce that somebody asked a question, which is not a fact about the tenant.
EXEMPT = {
    "authzen::authzen_evaluation": "AuthZEN evaluation: answers a permit/deny question, writes nothing",
    "authzen::authzen_evaluations": "AuthZEN batch evaluation: as above, many questions per call",
    "diagnostics::post_flow_dry_run": "flow dry run: evaluates a flow WITHOUT committing it",
    "password_hashing::probe_password_hashing": "hashing probe: measures cost parameters, stores nothing",
    "promotion::plan_config_promotion": "promotion PLAN: computes the diff; applying it is a separate route",
    "migration::verify_credential": "credential verification: checks a secret, changes no state",
}


def handler_body(module: str, name: str) -> str | None:
    """The source of one handler function, brace-balanced from its signature."""
    path = ADMIN / f"{module}.rs"
    if not path.is_file():
        return None
    text = path.read_text()
    signature = re.search(rf"(?:pub\s+)?(?:async\s+)?fn\s+{re.escape(name)}\s*[(<]", text)
    if not signature:
        return None
    start = text.index("{", signature.start())
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return None


def emits(module: str, name: str, depth: int = 2, seen: set[str] | None = None) -> bool | None:
    """Does this handler build a domain event, directly or through a helper it calls?

    Delegation has to be followed or the check reports false gaps. `brand_assets::
    delete_brand_logo` is a 179-byte wrapper around `delete_asset`, which is where the
    event is built and `delete_with_event` is called; judged on its own frame it looks
    like a management write that announces nothing.

    Only module-local helpers, and only two levels. Both limits are deliberate: a handler
    whose emit is three hops away through another module is not legible as a producer
    anyway, and an unbounded walk would eventually reach the store and call everything
    covered. `None` means the body could not be read.
    """
    seen = seen if seen is not None else set()
    key = f"{module}::{name}"
    if key in seen:
        return False
    seen.add(key)
    body = handler_body(module, name)
    if body is None:
        return None
    if EMITS.search(body):
        return True
    if depth <= 0:
        return False
    # Every module-local call this frame makes, tried in turn.
    for callee in sorted(set(re.findall(r"\b([a-z][a-z0-9_]{2,})\s*\(", body))):
        if callee == name or handler_body(module, callee) is None:
            continue
        if emits(module, callee, depth - 1, seen):
            return True
    return False


def measure() -> tuple[list[str], list[str], list[str]]:
    """(covered, uncovered, unreadable), each a sorted list of `module::handler`."""
    router = ROUTER.read_text()
    # De-duplicated: one handler can be mounted under several paths, and it is covered or
    # not regardless of how many routes reach it.
    handlers = sorted({(module, name) for _, module, name in ROUTE.findall(router)})
    covered, uncovered, unreadable = [], [], []
    for module, name in handlers:
        label = f"{module}::{name}"
        if label in EXEMPT:
            continue
        verdict = emits(module, name)
        if verdict is None:
            unreadable.append(label)
        elif verdict:
            covered.append(label)
        else:
            uncovered.append(label)
    return covered, uncovered, unreadable


def main() -> int:
    if not ROUTER.is_file():
        print(f"producer-coverage: {ROUTER.relative_to(ROOT)} is missing.", file=sys.stderr)
        return 1

    covered, uncovered, unreadable = measure()
    if not covered and not uncovered:
        # An empty denominator agrees with any repository. The route syntax changed, or this
        # is pointed at the wrong file.
        print("producer-coverage: no write handlers found in the router.", file=sys.stderr)
        print("  The denominator is empty, so this check would pass for any tree.", file=sys.stderr)
        return 1

    if unreadable:
        # Neither a pass nor a silent skip: a handler this cannot read is one it cannot
        # judge, and counting it as covered is how a check quietly stops measuring.
        print("producer-coverage: could not read these handler bodies:", file=sys.stderr)
        for entry in unreadable:
            print(f"  - {entry}", file=sys.stderr)
        return 1

    if "--update-baseline" in sys.argv:
        BASELINE.write_text(
            "# Management write handlers that emit no event yet (issue #108, criterion 6).\n"
            "# SHRINK-ONLY: producer-coverage.py fails if an entry here is already covered or\n"
            "# gone, and fails if an uncovered handler is missing from this list. #108 closes\n"
            "# when this file is empty. Regenerate with: scripts/producer-coverage.py"
            " --update-baseline\n" + "".join(f"{entry}\n" for entry in uncovered)
        )
        print(f"producer-coverage: baseline rewritten with {len(uncovered)} entries")
        return 0

    baseline = set()
    if BASELINE.is_file():
        baseline = {
            line.strip()
            for line in BASELINE.read_text().splitlines()
            if line.strip() and not line.startswith("#")
        }

    total = len(covered) + len(uncovered)
    regressions = sorted(set(uncovered) - baseline)
    stale = sorted(baseline - set(uncovered))

    if regressions:
        print(
            "producer-coverage: these management write handlers announce NOTHING:",
            file=sys.stderr,
        )
        for entry in regressions:
            print(f"  - {entry}", file=sys.stderr)
        print(file=sys.stderr)
        print(
            "  A management write that emits no event is invisible to every integrator\n"
            "  watching the event stream. Emit a registered type through the matching\n"
            "  `*_with_event` store method, or -- if it truly mutates nothing -- add it to\n"
            "  EXEMPT in this script WITH a reason.",
            file=sys.stderr,
        )
        return 1

    if stale:
        print(
            "producer-coverage: these baseline entries are covered or gone; the baseline"
            " must shrink:",
            file=sys.stderr,
        )
        for entry in stale:
            print(f"  - {entry}", file=sys.stderr)
        print(file=sys.stderr)
        print("  Run: scripts/producer-coverage.py --update-baseline", file=sys.stderr)
        return 1

    print(
        f"producer-coverage: {len(covered)}/{total} management write handlers emit an event; "
        f"{len(uncovered)} remaining in the baseline, {len(EXEMPT)} exempt"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
