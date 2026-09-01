#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The MCP authorization conformance bundle against a REAL IronAuth (issue #129).
#
# Every checklist item the published page claims is measured HERE, against the emulator and
# two sample resource servers, and the page is generated from what this writes. The argument
# for a live lane is the one the BFF's makes: a fake is written by the same person as the
# code, from the same understanding, so it agrees with the code's mistakes. The two defects
# that made a real login impossible in the BFF passed every test that package had.
#
# The cross-server replay item is the reason two servers run rather than one. A token minted
# for server A verifies against B on every check except the audience: same issuer, same
# signing key, same type, unexpired. Only the audience separates them, and a bundle that ran
# one server could not tell whether that check existed at all.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# The clock for the "zero to a secured MCP server" budget. Started BEFORE anything is built
# or launched, because that is what the claim means: a reader following this path starts with
# a checkout and nothing running.
STARTED_AT=$(date +%s)

BIND="127.0.0.1:${IRONAUTH_MCP_PORT:-18241}"
WORK="$(mktemp -d -t ironauth-mcp-XXXXXX)"
LOG="${WORK}/emulator.log"

cleanup() {
    if [ -f "${WORK}/emulator.pid" ]; then
        kill "$(cat "${WORK}/emulator.pid")" 2>/dev/null || true
    fi
    rm -rf "${WORK}"
}
trap cleanup EXIT

echo "mcp-conformance: building the sample server"
(cd packages/mcp-sample && npm install --silent >/dev/null 2>&1 && npm run build >/dev/null)

echo "mcp-conformance: starting the emulator on ${BIND}"
cargo run --quiet -p ironauth --bin ironauth -- dev --bind "${BIND}" --seed 1 > "${LOG}" 2>&1 &
echo $! > "${WORK}/emulator.pid"

# Waiting for the banner is NOT enough: it prints while the listener is still coming up. The
# loop asks DISCOVERY to answer, which is true only once the server is serving, and checks the
# emulator is still alive each time so a failed start is its own error immediately.
ISSUER=""
for _ in $(seq 1 900); do
    if ! kill -0 "$(cat "${WORK}/emulator.pid")" 2>/dev/null; then
        echo "mcp-conformance: the emulator exited before serving; its log:" >&2
        tail -20 "${LOG}" >&2
        exit 1
    fi
    # `|| true` because of `pipefail`: until the banner is written the grep finds nothing and
    # exits 1, which under `set -e` aborts the loop whose whole purpose is to wait.
    ISSUER=$(grep -o 'issuer http://[^ ]*' "${LOG}" 2>/dev/null | head -1 | sed 's/issuer //' || true)
    if [ -n "${ISSUER}" ] && curl -sf -o /dev/null "${ISSUER}/.well-known/openid-configuration"; then
        break
    fi
    sleep 0.2
done

OPERATOR=$(grep -o 'operator token [^ ]*' "${LOG}" | head -1 | sed 's/operator token //' || true)
MANAGEMENT=$(grep -o 'management http://[^ ]*' "${LOG}" | head -1 | sed 's/management //' || true)
if [ -z "${ISSUER}" ] || [ -z "${OPERATOR}" ] || [ -z "${MANAGEMENT}" ]; then
    echo "mcp-conformance: the emulator never reported an issuer, operator token, and management base" >&2
    tail -20 "${LOG}" >&2
    exit 1
fi

# The two MCP servers must be REGISTERED resource servers, or their RFC 9728 documents do
# not exist and a client following the 401 pointer finds a 404. `apply` is the path that
# registers one: the management API exposes resource servers read-only.
TENANT=$(echo "${ISSUER}" | sed 's#.*/t/##; s#/e/.*##')
ENVIRONMENT=$(echo "${ISSUER}" | sed 's#.*/e/##')
cat > "${WORK}/resources.json" <<JSON
{
  "schema_version": "ironauth.config-snapshot/v1",
  "resources": {
    "resource_server": [
      { "audience": "${ISSUER}/mcp-a", "token_format": "at_jwt" },
      { "audience": "${ISSUER}/mcp-b", "token_format": "at_jwt" }
    ]
  }
}
JSON
echo "mcp-conformance: registering the two MCP resource servers"
cargo run --quiet -p ironauth --bin ironauth -- apply "${WORK}/resources.json"     --target "${TENANT}/${ENVIRONMENT}" --api-url "${MANAGEMENT}" --token "${OPERATOR}"

USER=$(grep -o 'ironauth dev: user [^ ]*' "${LOG}" | head -1 | sed 's/.*user //' || true)
PASSWORD=$(grep -oE 'ironauth dev: user [^ ]+ / [^ ]+' "${LOG}" | head -1 | sed 's#.* / ##' || true)
REDIRECT=$(grep -oE 'redirect [^)]*' "${LOG}" | head -1 | sed 's/redirect //' || true)
if [ -z "${USER}" ] || [ -z "${PASSWORD}" ] || [ -z "${REDIRECT}" ]; then
    echo "mcp-conformance: the emulator never reported a seeded user and redirect" >&2
    tail -20 "${LOG}" >&2
    exit 1
fi

echo "mcp-conformance: driving the checklist against ${ISSUER}"
node packages/mcp-sample/dist/conformance.js \
    "${ISSUER}" "${OPERATOR}" "${MANAGEMENT}" "${REDIRECT}" "${USER}" "${PASSWORD}"

# The 5-minute budget, MEASURED rather than asserted in prose. Recorded as an item so it
# appears on the page beside everything else: a documented time budget that nobody times is
# the same shape as a conformance claim nobody tests.
ELAPSED=$(( $(date +%s) - STARTED_AT ))
echo "mcp-conformance: zero to a secured MCP server in ${ELAPSED}s"
python3 - "${ELAPSED}" <<'PYEOF'
import json
import pathlib
import sys

elapsed = int(sys.argv[1])
budget = 300
path = pathlib.Path("docs/conformance/mcp-results.json")
data = json.loads(path.read_text())
data["items"].append(
    {
        "id": "MCP-QUICKSTART-BUDGET",
        "title": "Zero to a secured MCP server inside the documented budget",
        "requirement": "IronAuth MCP quickstart: 5 minutes",
        "outcome": "pass" if elapsed <= budget else "fail",
        # The measured seconds are deliberately NOT in the evidence: they differ per machine
        # and would make the committed page drift on every run. What is claimed is that the
        # scripted path finished inside the budget, which is what the criterion asks.
        "evidence": f"scripted run completed within the {budget}s budget",
    }
)
path.write_text(json.dumps(data, indent=2) + "\n")
if elapsed > budget:
    print(f"mcp-conformance: took {elapsed}s, over the {budget}s budget", file=sys.stderr)
    sys.exit(1)
PYEOF

echo "mcp-conformance: regenerating the published page"
python3 scripts/gen-mcp-conformance.py

# The page is GENERATED, so a drift here means someone edited it by hand and their edit is
# about to be lost, or the results changed and the page was not regenerated with them.
if ! git diff --exit-code docs/conformance/mcp.md; then
    echo >&2
    echo "mcp-conformance: docs/conformance/mcp.md drifted from the measured results." >&2
    echo "Commit the regenerated page rather than editing it." >&2
    exit 1
fi

echo "mcp-conformance: clean"
