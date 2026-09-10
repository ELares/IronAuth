#!/usr/bin/env bash
# CAEP Interoperability Profile traceability (issue #144 criterion 6).
#
# Criterion 6 asks for the profile checklist "encoded as CI tests, each requirement
# traceable". A markdown table naming test functions is traceable only while somebody keeps
# it in step by hand, and the failure is silent in both directions:
#
#   - a row naming a test that was renamed or deleted reads as covered and measures
#     nothing;
#   - a test that exists and is named by no row is coverage nobody can find from the
#     requirement, which is what "traceable" is supposed to prevent.
#
# So this checks BOTH directions, the way scripts/rfc9700-scan.sh does for endpoints:
# every test named in the checklist must exist in the suite, and every test in the suite
# must be named by the checklist.
#
# It deliberately does NOT check that the tests pass; `cargo test` does that. A gate that
# tried would be a slower, worse copy of the test runner.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

DOC="docs/conformance/caep-interop-checklist.md"
SUITE="crates/ironauth-oidc/tests/caep_interop_profile.rs"

for path in "$DOC" "$SUITE"; do
    if [ ! -f "$path" ]; then
        echo "caep-interop-scan: $path is missing" >&2
        exit 1
    fi
done

# The tests the suite actually defines.
#
# ONLY functions carrying #[tokio::test]. Taking every `async fn` swept in the file's
# helpers, and the first run of this gate duly demanded a checklist row for
# `transmitter_metadata`. A gate that asks for documentation of a helper teaches its
# reader to add noise rows, which is how a traceability table stops being read.
defined="$(awk '/^#\[tokio::test\]/ { want = 1; next }
                want && /^async fn / { sub(/^async fn /, ""); sub(/\(.*/, ""); print; want = 0 }' \
    "$SUITE" | sort -u)"

# The tests the checklist claims, taken from the backticked cells of the mapping table.
# Restricted to names that look like the suite's, so prose mentioning a helper in
# backticks is not mistaken for a claim.
claimed="$(grep -oE '`section_[a-z0-9_]+`' "$DOC" | tr -d '`' | sort -u)"

if [ -z "$defined" ]; then
    echo "caep-interop-scan: $SUITE defines no tests" >&2
    exit 1
fi
if [ -z "$claimed" ]; then
    echo "caep-interop-scan: $DOC claims no tests" >&2
    exit 1
fi

status=0

missing="$(comm -13 <(echo "$defined") <(echo "$claimed") || true)"
if [ -n "$missing" ]; then
    status=1
    echo "caep-interop-scan: the checklist names tests that do not exist in $SUITE:" >&2
    echo "$missing" | sed 's/^/    /' >&2
    echo "" >&2
    echo "    A requirement row pointing at a missing test reads as covered and measures" >&2
    echo "    nothing. Restore the test, or move the row to the deployment-properties" >&2
    echo "    table with the reason it cannot be tested here." >&2
fi

unclaimed="$(comm -23 <(echo "$defined") <(echo "$claimed") || true)"
if [ -n "$unclaimed" ]; then
    status=1
    echo "caep-interop-scan: $SUITE defines tests the checklist does not name:" >&2
    echo "$unclaimed" | sed 's/^/    /' >&2
    echo "" >&2
    echo "    A profile test nobody can reach from the requirement is not traceable," >&2
    echo "    which is the property issue #144 criterion 6 asks for. Add the row." >&2
fi

if [ "$status" -eq 0 ]; then
    echo "caep-interop-scan: OK ($(echo "$defined" | wc -l | tr -d ' ') requirements traceable)"
fi
exit "$status"
