#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Every MUTATING admin MCP tool drives a handler that records the entry path (issue #123
# criterion 5).
#
# > Every admin MCP mutation appears in the audit stream attributed to the machine identity with
# > the MCP entry path marked.
#
# "Every" is a claim about a SET, and the set is declared in TypeScript while the handlers are
# Rust. Nothing else in the tree can compare them, which is why this exists rather than a test in
# either language:
#
#   1. read the tool declarations, and take the mutating ones (anything but GET);
#   2. resolve each tool's method+path to an operationId through the PUBLISHED contract, which is
#      also what proves the tool drives a real operation at all;
#   3. find the Rust handler carrying that operationId;
#   4. require it to name `DeclaredEntryPath` in its signature.
#
# Step 4 is a text scan and its ceiling is worth stating: it proves the handler ACCEPTS the entry
# path, not that it passes it to the store. `crates/ironauth-admin/tests/audit_entry_path.rs` is
# what proves the value reaches an audit row, over HTTP, for real. This gate is the denominator
# -- it fails when a tool is added whose handler was never wired -- and that test is the witness.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

python3 - <<'PYCHECK'
import json, pathlib, re, sys

tools_src = pathlib.Path("packages/ironauth-mcp/src/tools.ts").read_text(encoding="utf-8")
contract = json.loads(pathlib.Path("docs/openapi/management.json").read_text(encoding="utf-8"))
admin = pathlib.Path("crates/ironauth-admin/src")

# Each tool is an object literal; pull the three fields this needs.
tools = []
for block in re.findall(r"\{\s*\n\s*name:\s*'([^']+)',(.*?)\n  \},", tools_src, re.S):
    name, body = block
    method = re.search(r"method:\s*'([A-Z]+)'", body)
    path = re.search(r"path:\s*'([^']+)'", body)
    if not method or not path:
        print(f"mcp-entry-path: tool {name} declares no method or path", file=sys.stderr)
        raise SystemExit(1)
    tools.append((name, method.group(1), path.group(1)))

if len(tools) < 5:
    # A parse that silently matched nothing would pass this gate over an empty set, which is the
    # failure a coverage check is least able to notice about itself.
    print(f"mcp-entry-path: parsed only {len(tools)} tools; the parser is broken", file=sys.stderr)
    raise SystemExit(1)

sources = {p: p.read_text(encoding="utf-8") for p in admin.rglob("*.rs")}
failures = []
checked = 0

for name, method, path in tools:
    operations = contract["paths"].get(path)
    if not operations or method.lower() not in operations:
        failures.append(f"{name}: the contract publishes no {method} {path}")
        continue
    if method == "GET":
        continue
    operation_id = operations[method.lower()].get("operationId")
    # Find the `#[utoipa::path(...)]` block carrying this operationId and read the `pub async fn`
    # that follows it.
    handler = None
    for source in sources.values():
        marker = f'operation_id = "{operation_id}"'
        at = source.find(marker)
        if at == -1:
            continue
        signature = re.search(r"pub async fn (\w+)\(((?:.*\n)*?)\)\s*->", source[at:])
        if signature:
            handler = signature.group(1), signature.group(2)
            break
    if handler is None:
        failures.append(f"{name}: no handler found for operation {operation_id}")
        continue
    checked += 1
    fn_name, params = handler
    if "DeclaredEntryPath" not in params:
        failures.append(
            f"{name} ({method} {path}) drives `{fn_name}`, which does not take DeclaredEntryPath, "
            f"so an agent-driven {operation_id} lands in the audit stream unmarked"
        )

if failures:
    print("mcp-entry-path: FAILED", file=sys.stderr)
    for failure in failures:
        print(f"  {failure}", file=sys.stderr)
    raise SystemExit(1)

if checked == 0:
    print("mcp-entry-path: no mutating tools were checked; the surface or the parser is wrong", file=sys.stderr)
    raise SystemExit(1)

print(f"mcp-entry-path: clean ({len(tools)} tools, {checked} mutating, every handler records the entry path)")
PYCHECK
