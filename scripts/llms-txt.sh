#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The agent-facing documentation index and corpus are FRESH and COVER the published set
# (issue #123 criterion 2).
#
# > llms-full.txt regenerates automatically on docs releases and COVERS THE PUBLISHED
# > DOCUMENTATION SET.
#
# Two claims, and the second is the one a freshness check alone would miss. A generator that
# started skipping half the corpus would still produce a byte-identical result on the next run,
# so `git diff --exit-code` would pass over a corpus that had quietly halved.
#
# So this checks both:
#
#   1. FRESHNESS -- regenerate and diff, the same shape every generated artifact in this
#      repository uses; and
#   2. COVERAGE -- every published document appears in BOTH files, computed here from an
#      independent walk rather than from the generator's own list. A denominator taken from the
#      thing being measured is not a denominator.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# shellcheck source=scripts/lib/generated-artifact.sh
. scripts/lib/generated-artifact.sh

require_tracked "llms-txt" docs/llms.txt
require_tracked "llms-txt" docs/llms-full.txt

python3 scripts/gen-llms-txt.py >/dev/null
echo "llms-txt: docs/llms.txt and docs/llms-full.txt regenerated"

if ! git diff --exit-code docs/llms.txt docs/llms-full.txt; then
  echo
  echo "llms-txt: the committed agent-facing docs drifted from the documentation set."
  echo "Review the diff above and commit the update."
  exit 1
fi

python3 - <<'PYCHECK'
import pathlib, re, sys

index = pathlib.Path("docs/llms.txt").read_text(encoding="utf-8")
corpus = pathlib.Path("docs/llms-full.txt").read_text(encoding="utf-8")

# An INDEPENDENT walk. The generator excludes `docs/design` and the generated-artifact
# directories; this repeats that rule rather than importing it, so a generator that silently
# widened its exclusions is caught by the two disagreeing.
EXCLUDED = {
    "design", "openapi", "events", "conformance",
    "journey-transcripts", "snapshot", "well-known", "adr",
}
expected = []
for name in ("README.md", "SECURITY.md", "CONTRIBUTING.md"):
    if pathlib.Path(name).is_file():
        expected.append(name)
for path in sorted(pathlib.Path("docs").rglob("*.md")):
    parts = path.parts
    if len(parts) > 2 and parts[1] in EXCLUDED:
        continue
    expected.append(str(path))

if len(expected) < 10:
    print(f"llms-txt: the coverage walk found only {len(expected)} documents; it is broken", file=sys.stderr)
    raise SystemExit(1)

missing_index = [p for p in expected if f"]({p})" not in index]
missing_corpus = [p for p in expected if f"Source: {p}\n" not in corpus]

if missing_index or missing_corpus:
    print("llms-txt: the published set is not covered", file=sys.stderr)
    for path in missing_index:
        print(f"  missing from llms.txt:      {path}", file=sys.stderr)
    for path in missing_corpus:
        print(f"  missing from llms-full.txt: {path}", file=sys.stderr)
    raise SystemExit(1)

# AND THE OTHER DIRECTION: the corpus must not carry a document the walk does not publish, which
# is how an excluded internal decision record would reach an agent.
published = {f"Source: {p}" for p in expected}
carried = set(re.findall(r"^Source: (.+)$", corpus, re.M))
extra = sorted({f"Source: {p}" for p in carried} - published)
if extra:
    print("llms-txt: the corpus carries documents the published set excludes:", file=sys.stderr)
    for line in extra:
        print(f"  {line}", file=sys.stderr)
    raise SystemExit(1)

print(f"llms-txt: clean ({len(expected)} published documents, all present in both files)")
PYCHECK
