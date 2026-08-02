#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Idempotent-write registry (issue #247), in the shape of the session-mint and
# user-token-mint registries: generate an inventory from source, diff the committed
# copy, then require every entry the inventory FLAGS to carry a written verdict in
# docs/design/IDEMPOTENT-WRITE-SITES.md.
#
# THE DEFECT IT GUARDS. An admin handler that requires an `Idempotency-Key` and then
# performs TWO un-joined store writes has a hole no reviewer sees from the diff: the
# idempotency record commits with ONE of them, so a failure between the two leaves a
# partial state the replay store cannot see, and a retry under the same key either
# re-executes against rows that already exist or replays a response for work that never
# finished. Issue #247 found this at two live sites:
#
#   - `invitations::create_invitation` provisioned the pending user in one transaction
#     and wrote the invitation (with the Idempotency-Key record) in a second, so a
#     failure of the second wedged the invited identifier behind a ghost account and the
#     retry answered 409 forever;
#   - `recovery_approvals::decide` committed the decision AND the Idempotency-Key record
#     and then completed the recovery in a second transaction whose result it discarded,
#     so a failed completion stranded the flow and the retry replayed the stored 200
#     without ever re-attempting it.
#
# Both are joined now. This is the count that makes the third one impossible to add
# QUIETLY.
#
# WHAT IT COUNTS, and why that spelling. A mutating store repository is reachable only
# through `ScopedStore::acting`, so `.acting(` is the entry point to every audited write.
# Counting it naively is defeatable, and each spelling below is closed because a rule
# defeated by a SPELLING rather than by a decision is not a rule (the same argument
# invariant-lints.sh makes for the mint registries):
#
#   - binding the handle (`let acting = ...acting(...);`) and then calling it twice would
#     count once, so every USE of such a binding is counted. `recovery_approvals::decide`
#     is written exactly that way TODAY;
#   - the two-phase form that writes the idempotency row itself
#     (`.management().idempotency().record(...)`) is not an `.acting(` chain at all, so
#     `.idempotency()` is counted too. `signing_algorithm` is written exactly that way
#     TODAY, and its data write is on the OTHER database role, which is why it cannot be
#     joined without a grant change;
#   - `pub(crate) async fn` and a bare `async fn` are matched as well as `pub async fn`,
#     so a handler cannot leave the walk by narrowing its visibility. Before this was
#     widened, a two-write handler spelled `pub(crate) async fn` produced NO inventory row
#     at all and the scan reported clean (MEASURED);
#   - the source glob is RECURSIVE, so a handler in a subdirectory of the crate is opened
#     too. Before this, a two-write handler moved into `src/sub/` was never read and the
#     scan reported clean (MEASURED).
#
# THE COUNT IS INTRA-FRAME, and that is a stated limit rather than an oversight. A write
# performed by a HELPER the handler calls belongs to the helper's frame, not the
# handler's, so it does not raise the handler's number. Summing helper frames into every
# caller was considered and rejected on a measurement: `sudo.rs:require_fresh_privilege`
# holds one `.acting(...)` write on its refusal path and most of the handlers below call
# it, so summing would flag them all with one identical verdict and bury the rows that say
# something. Instead, EVERY same-crate `async fn` a listed handler calls is inventoried as
# a row of its own. A helper that gains a second write is flagged on its own row, and a
# handler that starts calling a new helper changes the inventory and must regenerate it.
# What this does NOT flag on its own is a handler with exactly one write in its frame and
# exactly one more in a helper: that shows as an inventory DIFF (a new or changed helper
# row) rather than as a flag, and the diff is what forces the author to look.
#
# It is a COUNT, not a proof, exactly like the mint registries. Two mutually exclusive
# arms (approve XOR reject) count as two and are not a defect; that is what the prose doc
# is for. What the count guarantees is that a handler cannot GAIN a second store write
# without its author regenerating the inventory and writing down why.
#
# MEASURED against the pre-fix tree (fde74fc): the walk found 33 handlers and flagged
# THREE of them. Two were exactly the defects issue #247 fixed. The third,
# `signing_algorithm::set_client_signing_algorithm`, is flagged before AND after and
# carries a standing verdict: it is structurally split across two database roles and
# cannot be joined without a grant change. No false positive, and no site this scan judged
# clean was one issue #247 judged broken.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# `require_tracked`: an untracked generated artifact makes the freshness diff below
# compare against nothing and report clean for any content at all.
# shellcheck source=scripts/lib/generated-artifact.sh
. scripts/lib/generated-artifact.sh

inventory='docs/design/idempotent-write-sites.txt'
doc='docs/design/IDEMPOTENT-WRITE-SITES.md'
fail=0

for path in "$doc"; do
  if [ ! -f "$path" ]; then
    echo "idempotent-write-audit: expected $path to exist"
    exit 1
  fi
done

python3 - "$inventory" <<'PY'
import glob
import re
import sys

out = sys.argv[1]

# The floor. Raise it when an idempotent handler (or a helper one calls) is legitimately
# added; LOWER it only in the same change that deliberately removes one, and say so. Its
# job is to make a silent SHRINK of the walk impossible, which is the failure mode the
# test-registration script had in its own first version.
MINIMUM_ROWS = 46

# A top-level `async fn`, matched at column zero so a nested closure or an `impl` method
# indented inside something else cannot be mistaken for one. Every visibility a free
# function can carry is matched (`pub`, `pub(crate)`, `pub(super)`, `pub(in path)`, and
# none at all), because narrowing a handler's visibility must not remove it from the walk.
SIGNATURE = re.compile(r"^(?:pub(?:\([^)]*\))? )?async fn (\w+)\(", re.MULTILINE)
# `let <name> = <chain>.acting(`: a BOUND acting handle. Non-greedy up to the first `;`
# so the match cannot run past the statement.
BINDING = re.compile(r"\blet (\w+) = (?:[^;]*?)\.acting\(", re.S)


def body_of(text, start):
    """The braced body that follows `start`, by brace matching."""
    open_at = text.index("{", start)
    depth = 0
    for index in range(open_at, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[open_at : index + 1]
    raise SystemExit("idempotent-write-audit: unbalanced braces while scanning a handler")


def store_writes(body):
    """How many store WRITE entry points this frame reaches, IN ITS OWN FRAME."""
    # Every inline `...acting(...)` chain.
    count = body.count(".acting(")
    # Plus every EXTRA use of a bound acting handle (the binding itself is already one).
    for name in BINDING.findall(body):
        uses = len(re.findall(rf"\b{name}\s*\n?\s*\.", body))
        if uses >= 1:
            count += uses - 1
    # Plus the two-phase form, which writes the idempotency row on the control plane
    # without an acting chain at all.
    count += body.count(".idempotency()")
    return count


# Every `async fn` in the crate, recursively: the handlers are a subset, and the rest are
# the pool the helper rows are drawn from.
functions = []
for path in sorted(glob.glob("crates/ironauth-admin/src/**/*.rs", recursive=True)):
    text = open(path, encoding="utf-8").read()
    for match in SIGNATURE.finditer(text):
        functions.append((path, match.group(1), body_of(text, match.end())))

# Only handlers that REQUIRE an Idempotency-Key are in scope: those are the ones whose
# partial state a replay is supposed to hide.
handlers = [
    (path, name, body) for path, name, body in functions if "idempotency::required_key(" in body
]
handler_keys = {(path, name) for path, name, _ in handlers}

# One level of call resolution: every same-crate `async fn` a handler NAMES. Resolution is
# by name across the whole crate, so an ambiguous name contributes every definition that
# bears it; that over-includes rather than under-includes, which is the safe direction for
# a registry.
called = set()
for _path, _name, body in handlers:
    for path, name, _helper_body in functions:
        if (path, name) in handler_keys:
            continue
        if re.search(rf"\b{re.escape(name)}\s*\(", body):
            called.add((path, name))

rows = [(path, name, store_writes(body)) for path, name, body in handlers]
rows += [
    (path, name, store_writes(body)) for path, name, body in functions if (path, name) in called
]

if len(rows) < MINIMUM_ROWS:
    sys.stderr.write(
        f"idempotent-write-audit: found {len(rows)} inventory rows, below the floor of "
        f"{MINIMUM_ROWS}. The walk has SHRUNK: either a handler or a helper was "
        "deliberately removed (lower the floor here and say so) or the scan stopped "
        "seeing them.\n"
    )
    sys.exit(1)

header = (
    "# Idempotent-write registry (generated)\n"
    "#\n"
    "# Generated by scripts/idempotent-write-audit.sh from every admin handler that\n"
    "# calls `idempotency::required_key(`, plus every same-crate `async fn` those\n"
    "# handlers call; do not edit by hand. The number is how many store WRITE entry\n"
    "# points that ONE FRAME reaches (inline `.acting(` chains, extra uses of a bound\n"
    "# acting handle, and the two-phase `.idempotency()` record). A write inside a\n"
    "# helper counts on the HELPER's row, never on its caller's.\n"
    "#\n"
    "# A row with more than ONE must be named, with a verdict, in\n"
    "# docs/design/IDEMPOTENT-WRITE-SITES.md, and every name that document's verdict\n"
    "# table carries must be a row that is flagged here. Two un-joined writes behind one\n"
    "# Idempotency-Key is issue #247's defect: a failure between them leaves a partial\n"
    "# state the replay store cannot see.\n"
)
lines = sorted({f"{path}:{name}:{count}" for path, name, count in rows})
open(out, "w", encoding="utf-8").write(header + "\n".join(lines) + "\n")
PY

require_tracked "idempotent-write-audit" "$inventory" || fail=1
if ! git diff --exit-code "$inventory" >/dev/null 2>&1; then
  echo "idempotent-write-audit: $inventory is stale (an idempotent handler changed)."
  echo "                        Regenerated; review and commit it, and give any row"
  echo "                        with more than one store write a verdict in $doc."
  git --no-pager diff -- "$inventory" || true
  fail=1
fi

# The verdict contract, BOTH directions. Neither half is a substring search over the whole
# document: deleting the verdict table and leaving two bare backticked mentions passed the
# first version of this check, and so did appending a verdict for a handler that never
# existed. Stale verdicts rotting unnoticed is the exact failure this registry exists to
# stop, so a verdict must be a TABLE ROW that states a judgement, and every verdict must
# answer to a row the inventory currently flags.
if ! python3 - "$inventory" "$doc"; then
  fail=1
fi <<'PY'
import re
import sys

inventory, doc = sys.argv[1], sys.argv[2]

ROW = re.compile(r"^\s*\|")
NEEDLE = re.compile(r"`([\w.]+\.rs):(\w+)`")
VERDICT = re.compile(r"\*\*[A-Z][A-Z ]{3,}")

flagged = {}
for line in open(inventory, encoding="utf-8"):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    path, name, count = line.rsplit(":", 2)
    if int(count) > 1:
        flagged[(path.rsplit("/", 1)[-1], name)] = int(count)

judged = set()
for line in open(doc, encoding="utf-8"):
    if not ROW.match(line) or not VERDICT.search(line):
        continue
    judged.update(NEEDLE.findall(line))

failures = 0
for (basename, name), count in sorted(flagged.items()):
    if (basename, name) in judged:
        continue
    print(
        f"idempotent-write-audit: '{basename}:{name}' reaches {count} store writes behind one"
    )
    print(f"                        Idempotency-Key and carries no verdict row in {doc}.")
    print("                        A verdict is a TABLE ROW naming it and stating a bold,")
    print("                        shouted judgement, not a passing mention.")
    failures += 1

for basename, name in sorted(judged):
    if (basename, name) in flagged:
        continue
    print(f"idempotent-write-audit: {doc} carries a verdict for '{basename}:{name}', which is")
    print("                        not a flagged row in the inventory. Either the site is gone,")
    print("                        or it was joined and the verdict is now stale: delete the")
    print("                        row, or correct the name it uses.")
    failures += 1

sys.exit(1 if failures else 0)
PY

if [ "$fail" -ne 0 ]; then
  exit 1
fi

entries=$(grep -cv '^#' "$inventory" || true)
echo "idempotent-write-audit: clean (${entries} inventory rows)"
