#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Regenerate the cross-language JWT verification conformance corpus (issue #118) from
# `packages/ironauth-sdk/scripts/generate-vectors.mjs`.
#
#   packages/ironauth-sdk/vectors/verify-vectors.json
#
# Issue #118 ships six independent verifiers (Cloudflare Workers, Fastly Compute in Rust,
# Lambda@Edge, plain WebCrypto, and official Java and .NET artifacts). All six are judged
# against THIS one corpus, which is the only way "they all agree" is measured rather than
# hoped. The corpus is therefore a contract, not a fixture.
#
# The generator is deterministic (fixed keys, a fixed evaluation instant, fixed claims), so
# regenerating produces byte-identical output and a drift here is always a real change.
#
# WHY THIS GATE EXISTS. A conformance corpus is exactly the artifact someone weakens under
# deadline: delete the `alg_none` vector and every verifier goes green. Committing the corpus
# WITHOUT this check would make that edit invisible, because the file would simply be whatever
# was last committed. With it, the corpus can only change by changing the generator, in a diff
# a reviewer reads.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# shellcheck source=scripts/lib/generated-artifact.sh
. scripts/lib/generated-artifact.sh

CORPUS="packages/ironauth-sdk/vectors/verify-vectors.json"

node packages/ironauth-sdk/scripts/generate-vectors.mjs >/dev/null

echo "verify-vectors: ${CORPUS} regenerated"
require_tracked "verify-vectors" "${CORPUS}" || exit 1
if ! git diff --exit-code "${CORPUS}" >/dev/null 2>&1; then
    echo "verify-vectors: the committed corpus is STALE."
    echo "  Review the diff carefully. A REMOVED or WEAKENED vector is the change this gate"
    echo "  exists to surface: dropping a refusal case makes every verifier in issue #118 go"
    echo "  green on a token it should refuse."
    git --no-pager diff -- "${CORPUS}" || true
    exit 1
fi
# The COUNTS this corpus's prose states, checked against the corpus itself.
#
# `docs/edge-verification.md` names the vector, refusal and accepted counts in words, and
# `bench-verify.mjs` names the accepted and algorithm counts in a comment. Both had drifted:
# sixteen and twelve, four and two, while the corpus carried nineteen and fourteen, five and
# three. Nothing noticed, because a sentence beside a generated artifact is not regenerated
# with it.
#
# ANCHORED, and comparing the captured word. An earlier revision of this check asked only
# whether the right spelled number appeared ANYWHERE in the file, which is not the same
# question: a page whose only claim about the corpus was false passed it as long as the correct
# word occurred in some unrelated sentence. It was also inert by accident, because "four" is a
# substring of "fourteen": with the corpus at four algorithms the check was satisfied by the
# refusal count. Measured both ways before this rewrite.
python3 - "${CORPUS}" docs/edge-verification.md packages/ironauth-sdk/scripts/bench-verify.mjs <<'PYCHECK'
import base64, json, re, sys

corpus_path, doc_path, bench_path = sys.argv[1], sys.argv[2], sys.argv[3]
corpus = json.load(open(corpus_path))
cases = corpus["cases"]
total = len(cases)
accepts = sum(1 for case in cases if case["expect"] == "accept")
refusals = total - accepts


def accepted_algorithm(case):
    """The `alg` an accepted vector's own header names."""
    header = case["token"].split(".")[0]
    padded = header + "=" * (-len(header) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))["alg"]


# The algorithms the ACCEPTED VECTORS SPAN, which is what the sentences claim, and NOT
# `corpus["algorithms"]`, which is the issuer's published allow-list. Those are different
# quantities that happen to be equal today, and an earlier revision of this check compared the
# sentences against the allow-list. Both directions were measured and both were wrong: turning
# one accepted vector into a refusal left the allow-list at three, so the guard passed a page
# claiming three spanned algorithms when two were spanned; and adding an algorithm to the
# allow-list with no accepted vector failed a page whose count was correct, and its message
# told the author to write a false number.
algorithms = len({accepted_algorithm(case) for case in cases if case["expect"] == "accept"})

WORDS = {
    2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight",
    9: "nine", 10: "ten", 11: "eleven", 12: "twelve", 13: "thirteen", 14: "fourteen",
    15: "fifteen", 16: "sixteen", 17: "seventeen", 18: "eighteen", 19: "nineteen",
    20: "twenty", 21: "twenty-one", 22: "twenty-two", 23: "twenty-three",
    24: "twenty-four", 25: "twenty-five",
}

doc = open(doc_path).read()
bench = open(bench_path).read()
problems = []


def spelled(value, label):
    """The spelled form, or a recorded problem when the table does not reach that far."""
    word = WORDS.get(value)
    if word is None:
        problems.append(f"no spelled form for {label}={value}; extend WORDS in this check")
    return word


# The capture class admits a HYPHEN, because the spellings above do past twenty. `(\w+)` cannot
# match "twenty-one", and the hyphen breaks the surrounding literal too, so the pattern misses
# entirely and reports a MISSING sentence for a page whose sentence is present and correct.
# Measured before this widening: a correct page failed at every count from 21 to 25, with no
# spelling that could pass, two corpus growths away from where the corpus already is.


def check(text, where, pattern, expectations):
    """Require the SENTENCE to exist, and each captured word to be the corpus's own.

    A missing sentence is a failure rather than a pass. Anchoring is the whole point: a
    substring search over the file answers "does this word appear", and the question is
    "does the claim say the right thing".
    """
    match = re.search(pattern, text, re.S)
    if match is None:
        problems.append(f"{where}: no sentence matching {pattern!r}; the guard cannot check it")
        return
    for index, (value, label) in enumerate(expectations, start=1):
        word = spelled(value, label)
        if word is None:
            continue
        found = match.group(index)
        if found != word:
            problems.append(f"{where}: says {found!r} for {label}, corpus has {value} ({word})")


check(
    doc,
    "docs/edge-verification.md corpus sentence",
    r"verify-vectors\.json`:\s+([\w-]+) vectors,\s+([\w-]+) of them\s+refusals",
    [(total, "total vectors"), (refusals, "refusals")],
)
check(
    doc,
    "docs/edge-verification.md agreement sentence",
    r"agree on all ([\w-]+) are",
    [(total, "total vectors")],
)
check(
    doc,
    "docs/edge-verification.md accepted-vector bullet",
    r"corpus holds ([\w-]+) accepted vectors across\s+([\w-]+)\s+distinct algorithms",
    [(accepts, "accepted vectors"), (algorithms, "algorithms")],
)
check(
    bench,
    "bench-verify.mjs subjects() comment",
    r"corpus holds ([\w-]+) accepted vectors across\s+\*?\s*([\w-]+) distinct algorithms",
    [(accepts, "accepted vectors"), (algorithms, "algorithms")],
)

if problems:
    print("verify-vectors: the corpus counts and the prose disagree:")
    for problem in problems:
        print(f"  {problem}")
    print(
        f"  corpus: {total} vectors, {accepts} accepts, {refusals} refusals, "
        f"{algorithms} algorithms"
    )
    raise SystemExit(1)
PYCHECK

echo "verify-vectors: clean"
