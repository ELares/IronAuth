#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# GENERATE THE SIZING GUIDE'S TABLES FROM A MEASUREMENT (issue #152 criterion 4).
#
#     scripts/unit-costs-doc.sh            # rewrite the tables from the committed measurement
#     scripts/unit-costs-doc.sh --check    # fail if the document does not match it
#     scripts/unit-costs-doc.sh --measure  # re-measure on THIS machine, then rewrite
#
# Criterion 4 asks that the sizing guide be GENERATED from benchmark output rather than written.
# It was hand-transcribed, and re-running the example found SIX of its ten published figures
# outside their own ranges: the table had drifted from the thing it described, which is what a
# hand-transcribed measurement does.
#
# # Why the numbers come from a committed file rather than a fresh run
#
# A gate that re-measured and compared would fail on every machine that is not the one the guide
# was written on, and the repair anyone reaches for is widening the tolerance until the check
# means nothing. So the document is generated from `docs/unit-costs-measurement.json`, which IS
# the benchmark's output, committed. Regeneration is then deterministic: `--check` regenerates
# and diffs, so a hand-edited table fails and a re-measured one is a deliberate commit of a new
# measurement.
#
# `--measure` is how that new measurement is taken. The release lane runs it and archives the
# result rather than committing it, because a shared CI runner is not the hardware class this
# guide recommends, and publishing its numbers as the guide's would be trading a drifted figure
# for a confidently generated one measured on the wrong machine.
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel)" || {
    echo "::error::unit-costs-doc: not inside a git repository" >&2
    exit 1
}
cd "$ROOT" || exit 1

DOC="docs/UNIT-COSTS.md"
MEASUREMENT="docs/unit-costs-measurement.json"
MODE="${1:-write}"

if [ "$MODE" = "--measure" ]; then
    echo "unit-costs-doc: measuring on this machine"
    UNIT_COSTS_JSON="$ROOT/$MEASUREMENT" \
        cargo run --release -q -p ironauth-oidc --example unit_costs || {
        echo "::error::unit-costs-doc: the measurement failed" >&2
        exit 1
    }
    MODE=write
fi

if [ ! -f "$MEASUREMENT" ]; then
    echo "::error::unit-costs-doc: $MEASUREMENT is missing; run with --measure" >&2
    exit 1
fi

python3 - "$DOC" "$MEASUREMENT" "$MODE" <<'PY'
import json
import pathlib
import sys

doc_path, measurement_path, mode = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
measurement = json.loads(measurement_path.read_text(encoding="utf-8"))

BEGIN = "<!-- BEGIN GENERATED: unit costs -->"
END = "<!-- END GENERATED: unit costs -->"


def table() -> str:
    host = measurement["host"]
    lines = [
        BEGIN,
        "",
        "## Password hashing",
        "",
        "| parameters | hash | verify |",
        "|---|---|---|",
    ]
    for row in measurement["password_hashing"]:
        lines.append(
            f"| {row['label']}: `m={row['m_kib']} KiB, t={row['t']}, p={row['p']}` "
            f"| {row['hash_ms']:.2f} ms | {row['verify_ms']:.2f} ms |"
        )
    lines += ["", "## Token mint", "", "| algorithm | mint | versus one password verify |", "|---|---|---|"]
    for row in measurement["token_mint"]:
        lines.append(
            f"| {row['algorithm']} | {row['mint_us']:.1f} us | about {row['vs_verify']:.0f}x cheaper |"
        )
    mix = f", {host['core_mix']} cores" if host["core_mix"] else ""
    lines += [
        "",
        f"{host['cpu']}, {host['cores']} cores{mix}, release build, {host['samples']} samples per "
        f"hashing figure and {host['sign_samples']} per signature after {host['sign_warmup']} "
        "warm-up signatures.",
        "",
        # THE PROVENANCE IS PART OF THE GENERATED REGION, so a reader cannot take the numbers
        # without the sentence that says where they came from and how to reproduce them.
        "These figures are GENERATED from `docs/unit-costs-measurement.json`, which is the "
        "benchmark's own output. Re-measure with `scripts/unit-costs-doc.sh --measure` and commit "
        "the result; `scripts/unit-costs-doc.sh --check` fails if this section was edited by hand.",
    ]
    shipped = measurement.get("shipped_verify_ms", 0.0)
    if shipped > 0:
        lines += [
            "",
            f"**At the shipped parameters one core of this kind sustains at most "
            f"{1000.0 / shipped:.0f} password logins per second ({shipped:.2f} ms each).** "
            "Read the next two sections before quoting that.",
        ]
    lines += ["", END]
    return "\n".join(lines)


text = doc_path.read_text(encoding="utf-8")
if BEGIN not in text or END not in text:
    print(f"::error::unit-costs-doc: {doc_path} has no generated region markers", file=sys.stderr)
    raise SystemExit(1)

head, rest = text.split(BEGIN, 1)
_, tail = rest.split(END, 1)
regenerated = head + table() + tail

if mode == "--check":
    if regenerated != text:
        print(
            "::error::unit-costs-doc: the generated region does not match the measurement.\n"
            "  Either it was edited by hand, or the measurement changed without regenerating.\n"
            "  Run scripts/unit-costs-doc.sh and commit the result.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    print("unit-costs-doc: clean (the sizing guide matches its measurement)")
    raise SystemExit(0)

doc_path.write_text(regenerated, encoding="utf-8")
print(f"unit-costs-doc: regenerated the tables in {doc_path} from {measurement_path}")
PY
