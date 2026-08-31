#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Generate the agent-facing documentation index and corpus (issue #123 criterion 2).

    llms.txt       an index: every published document, with its title and a one-line summary
    llms-full.txt  the corpus: every published document, concatenated, in the index's order

Both are written from ONE walk of the published set, so the index cannot list a document the
corpus omits. That is the failure the `llms.txt` convention is most prone to -- an index is
cheap to hand-maintain and quietly stops matching what is actually served.

# What "the published documentation set" means here

Every `.md` under `docs/`, plus the root documents a reader is expected to start from. It is a
DENY-list rather than an allow-list: a document added to `docs/` is published unless something
excludes it, so the failure mode is "a new page appears in llms-full.txt before anyone wrote a
summary" rather than "a new page is invisible to every agent and nobody notices".

The exclusions are narrow and each says why. `docs/design/` is excluded as a directory: those are
decision records written for maintainers, they assume the codebase, and an agent integrating
IronAuth that reads them will produce confident advice about internals it cannot see.

# Determinism

Sorted by path, no timestamps, no counts embedded in prose. The output must be byte-identical
across runs or the freshness gate becomes a permanent false alarm, which is worse than no gate
because a real change then hides in the noise.
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

# The root documents an integrator starts from. Listed rather than globbed: the repository root
# holds files that are not documentation for a reader of the product.
ROOT_DOCS = ["README.md", "SECURITY.md", "CONTRIBUTING.md"]

# Directories under docs/ that are NOT the published set, each with its reason.
EXCLUDED_DIRS = {
    # Decision records for maintainers. They assume the codebase, so an agent integrating
    # IronAuth that reads them produces confident advice about internals it cannot see.
    "design": "internal decision records, written for maintainers rather than integrators",
    # Generated machine artifacts, not prose: the OpenAPI document, event catalogue, journey
    # transcripts and conformance fixtures. An agent should read the contract, not a copy of it
    # pasted into a text file.
    "openapi": "the published contract itself, which agents should fetch rather than read pasted",
    "events": "a generated machine catalogue rather than prose",
    "conformance": "generated conformance fixtures",
    "journey-transcripts": "generated transcripts",
    "snapshot": "generated snapshot fixtures",
    "well-known": "generated protocol metadata",
    "adr": "architecture decision records, written for maintainers",
}


def published() -> list[pathlib.Path]:
    """Every published document, sorted, as paths relative to the repository root."""
    found: list[pathlib.Path] = []
    for name in ROOT_DOCS:
        path = ROOT / name
        if path.is_file():
            found.append(path.relative_to(ROOT))
    for path in sorted((ROOT / "docs").rglob("*.md")):
        relative = path.relative_to(ROOT)
        # Only the FIRST segment under docs/ is consulted, so an exclusion covers a directory
        # and everything below it rather than one level.
        parts = relative.parts
        if len(parts) > 2 and parts[1] in EXCLUDED_DIRS:
            continue
        found.append(relative)
    return sorted(set(found), key=lambda p: str(p))


def title_and_summary(path: pathlib.Path) -> tuple[str, str]:
    """The document's H1 and its first prose paragraph."""
    text = (ROOT / path).read_text(encoding="utf-8")
    title = path.stem
    summary = ""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.startswith("# "):
            title = line[2:].strip()
            # The first non-empty, non-heading, non-fence line after the title.
            for candidate in lines[index + 1 :]:
                stripped = candidate.strip()
                if not stripped or stripped.startswith(("#", "```", "|", "<!--", "-", "*", ">")):
                    continue
                # BADGE ROWS ARE NOT PROSE. A README commonly opens with a line of shields, and
                # taking it as the summary gives every agent a paragraph of image URLs where a
                # sentence about the product belongs. Measured on this repository's own README,
                # which is why the check exists rather than being imagined.
                if stripped.startswith(("[!", "![")):
                    continue
                summary = re.sub(r"\s+", " ", stripped)
                break
            break
    if len(summary) > 200:
        summary = summary[:197].rstrip() + "..."
    return title, summary


def main() -> int:
    documents = published()
    if len(documents) < 10:
        # A walk that matched almost nothing would write an empty corpus and pass a freshness
        # gate against it, which is the one failure a generated artifact cannot report itself.
        print(f"gen-llms-txt: found only {len(documents)} documents; the walk is broken", file=sys.stderr)
        return 1

    index = [
        "# IronAuth",
        "",
        "A standards-first OpenID Connect identity platform. This file is the agent-facing index;",
        "`llms-full.txt` beside it carries the full text of every document listed here.",
        "",
        "Generated by `scripts/gen-llms-txt.py`. Do not edit: `scripts/llms-txt.sh` regenerates",
        "both files and fails if either drifts.",
        "",
        "## Documentation",
        "",
    ]
    corpus = [
        "# IronAuth documentation",
        "",
        "The full text of every published IronAuth document, in the order `llms.txt` lists them.",
        "Generated by `scripts/gen-llms-txt.py`.",
        "",
    ]
    for path in documents:
        title, summary = title_and_summary(path)
        index.append(f"- [{title}]({path}): {summary}" if summary else f"- [{title}]({path})")
        corpus.extend(
            [
                "",
                "---",
                "",
                f"# {title}",
                "",
                f"Source: {path}",
                "",
                (ROOT / path).read_text(encoding="utf-8").rstrip(),
            ]
        )

    (ROOT / "docs" / "llms.txt").write_text("\n".join(index) + "\n", encoding="utf-8")
    (ROOT / "docs" / "llms-full.txt").write_text("\n".join(corpus) + "\n", encoding="utf-8")
    print(f"gen-llms-txt: wrote {len(documents)} documents to docs/llms.txt and docs/llms-full.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
