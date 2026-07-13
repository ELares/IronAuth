#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Prose rule: no em dashes (U+2014) and no en dashes (U+2013) anywhere in repo
# text. Plain hyphens are fine. Runs over every tracked file; binary files are
# skipped by the text heuristic in the scanner.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

git ls-files -z | python3 -c '
import sys

failed = False
for path in sys.stdin.buffer.read().split(b"\x00"):
    if not path:
        continue
    name = path.decode("utf-8", "replace")
    try:
        with open(name, "rb") as fh:
            data = fh.read()
    except (IsADirectoryError, FileNotFoundError):
        continue
    if b"\x00" in data[:8192]:
        continue  # binary
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        continue
    em, en = "\u2014", "\u2013"
    for lineno, line in enumerate(text.splitlines(), 1):
        if em in line or en in line:
            print(f"{name}:{lineno}: em or en dash found")
            failed = True
sys.exit(1 if failed else 0)
'
echo "dash-scan: clean"
