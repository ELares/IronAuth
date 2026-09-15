#!/usr/bin/env python3
"""Check the exported metrics against the documented contract (issue #152 criterion 1).

Fails on drift in EITHER direction:

  * a metric emitted by the code and absent from `docs/METRICS.md`, so an operator
    building a dashboard cannot know it exists;
  * a metric documented and no longer emitted, so a dashboard or an alert silently
    stops firing while the doc still promises it.

The second direction is the one that gets skipped, and it is the one that hurts during
an incident: an alert on a metric nothing emits never fires and looks exactly like an
alert whose condition is not met.

# The contract is the DOC, not the code

`docs/METRICS.md` is the source of truth and this script asserts the code matches it.
The initial contract was seeded from the code as a snapshot, which is stated plainly in
the doc itself; from that point on, changing either side without the other fails here.
Generating the doc from the code on every run would make this a check whose expected
value comes from the thing it checks, which cannot fail for any value.

# What it can and cannot see

It parses `metrics::{counter,gauge,histogram}!` invocations, resolving a name given as
a string literal or as a `const`. It cannot see a metric emitted through a helper it
does not recognise, and a gate that silently covers nothing is worse than none, so the
completeness check below refuses any `ironauth_`-prefixed string literal that is neither
extracted nor listed as a known non-metric.
"""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CONTRACT = ROOT / "docs" / "METRICS.md"
MACROS = ("counter", "gauge", "histogram")

# `ironauth_`-prefixed literals that are deliberately not metrics. Each is a Postgres
# role, schema or object name. A new entry here is a claim that something is not a
# metric, which is exactly the sort of claim review should see in a diff.
NOT_METRICS = {
    "ironauth_app",
    "ironauth_audit_retention",
    "ironauth_control",
    "ironauth_super",
    "ironauth_test_",
}


def rust_sources():
    for path in sorted(ROOT.glob("crates/**/*.rs")):
        if "/tests/" in str(path):
            continue
        yield path


def string_consts():
    pattern = re.compile(r'const\s+([A-Z][A-Z0-9_]*)\s*:\s*&\s*(?:\'\w+\s+)?str\s*=\s*"([^"]+)"')
    out = {}
    for path in rust_sources():
        for match in pattern.finditer(path.read_text(errors="ignore")):
            out[match.group(1)] = match.group(2)
    return out


def extract():
    """Every metric the code emits, with the union of labels across its call sites."""
    consts = string_consts()
    call = re.compile(r"metrics::(" + "|".join(MACROS) + r")!\s*\(")
    found = {}
    for path in rust_sources():
        text = path.read_text(errors="ignore")
        for match in call.finditer(text):
            start = match.end() - 1
            depth = 0
            body = None
            for index in range(start, min(start + 4000, len(text))):
                if text[index] == "(":
                    depth += 1
                elif text[index] == ")":
                    depth -= 1
                    if depth == 0:
                        body = text[start + 1 : index]
                        break
            if body is None:
                continue
            raw = body.split(",")[0].strip()
            literal = re.fullmatch(r'"([^"]+)"', raw)
            name = literal.group(1) if literal else consts.get(raw.split("::")[-1])
            if not name or not name.startswith("ironauth_"):
                continue
            labels = set(re.findall(r'"([a-z_][a-z0-9_]*)"\s*=>', body))
            entry = found.setdefault(name, {"kind": match.group(1), "labels": set()})
            entry["labels"].update(labels)
    return {name: {"kind": v["kind"], "labels": sorted(v["labels"])} for name, v in sorted(found.items())}


def documented():
    """The contract table, as `{name: {kind, labels}}`."""
    if not CONTRACT.exists():
        print(f"metric-contract: {CONTRACT} is missing", file=sys.stderr)
        sys.exit(1)
    rows = {}
    row = re.compile(r"^\|\s*`(ironauth_[a-z0-9_]+)`\s*\|\s*(\w+)\s*\|(.*)\|\s*$")
    for line in CONTRACT.read_text().splitlines():
        match = row.match(line.strip())
        if not match:
            continue
        labels = sorted(set(re.findall(r"`([a-z_][a-z0-9_]*)`", match.group(3))))
        rows[match.group(1)] = {"kind": match.group(2), "labels": labels}
    return rows


def completeness(extracted):
    """Refuse a metric-shaped literal the extractor cannot see."""
    literals = set()
    for path in rust_sources():
        literals.update(re.findall(r'"(ironauth_[a-z0-9_]+)"', path.read_text(errors="ignore")))
    unseen = sorted(literals - set(extracted) - NOT_METRICS)
    if unseen:
        print(
            "metric-contract: these look like metric names but this scan cannot see them "
            "being emitted, so it would cover them silently:",
            file=sys.stderr,
        )
        for name in unseen:
            print(f"  {name}", file=sys.stderr)
        print(
            "  Either they are emitted through a form this script does not parse (fix the "
            "script), or they are not metrics (add them to NOT_METRICS with a reason).",
            file=sys.stderr,
        )
        return False
    return True


def main():
    extracted = extract()
    contract = documented()
    ok = completeness(extracted)

    undocumented = sorted(set(extracted) - set(contract))
    if undocumented:
        ok = False
        print("metric-contract: emitted but NOT documented:", file=sys.stderr)
        for name in undocumented:
            info = extracted[name]
            labels = ", ".join(f"`{label}`" for label in info["labels"]) or "none"
            print(f"  | `{name}` | {info['kind']} | {labels} |", file=sys.stderr)
        print("  Add the rows above to docs/METRICS.md.", file=sys.stderr)

    stale = sorted(set(contract) - set(extracted))
    if stale:
        ok = False
        print("metric-contract: documented but NOT emitted:", file=sys.stderr)
        for name in stale:
            print(f"  {name}", file=sys.stderr)
        print(
            "  A dashboard or alert on one of these never fires, which looks exactly like "
            "a condition that is not met. Remove the row, or restore the metric.",
            file=sys.stderr,
        )

    for name in sorted(set(extracted) & set(contract)):
        got, want = extracted[name], contract[name]
        if got["kind"] != want["kind"]:
            ok = False
            print(
                f"metric-contract: {name} is a {got['kind']} in code and a {want['kind']} "
                "in the contract",
                file=sys.stderr,
            )
        if got["labels"] != want["labels"]:
            ok = False
            print(f"metric-contract: {name} label drift", file=sys.stderr)
            print(f"  code:     {got['labels']}", file=sys.stderr)
            print(f"  contract: {want['labels']}", file=sys.stderr)

    if not ok:
        sys.exit(1)
    print(f"metric-contract: clean ({len(extracted)} metrics, labels match the contract)")


if __name__ == "__main__":
    main()
