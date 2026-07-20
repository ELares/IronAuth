#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Route audit (issue #85 acceptance criterion: "a CI check verifies every
# network call from the pages app targets a documented public flow or session
# endpoint"). The standalone reference app in packages/reference-app is a PURE
# CLIENT of the public flow API; this lint is the structural guarantee that it
# can never be forked into hitting a private or management endpoint.
#
# It enforces three properties over the app's TypeScript sources:
#
#   1. The single funnel: ONLY src/api.ts may perform a network call
#      (fetch/XMLHttpRequest/WebSocket/EventSource/sendBeacon), and ONLY
#      src/endpoints.ts may contain a server path or absolute URL literal. Every
#      other module is network free, so there is one audited choke point.
#
#   2. Public only: every server path literal declared in src/endpoints.ts must
#      be a member of the PUBLIC endpoint inventory, assembled from the Rust
#      FLOW_*_PATH constants (the one source of truth for the flow routes) plus a
#      small allowlist of documented public session endpoints. A path that is not
#      public fails the audit, so a fork that adds a private endpoint is caught.
#
#   3. No external hosts: an absolute http(s):// URL literal anywhere in the app
#      fails the audit (the issuer base is runtime config, never a literal), so
#      the app cannot be hardcoded to call an external host.
#
# The audit reads the Rust path constants directly, so it cannot drift from the
# server, exactly like scripts/discovery-scan.sh and scripts/rfc9700-scan.sh.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

python3 - <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(".")
transport = root / "crates" / "ironauth-oidc" / "src" / "flow" / "transport.rs"
inventory_doc = root / "docs" / "conformance" / "rfc9700-endpoints.txt"
app_src = root / "packages" / "reference-app" / "src"
endpoints_file = app_src / "endpoints.ts"
api_file = app_src / "api.ts"

fail = False


def problem(msg):
    global fail
    print(f"route-audit: {msg}")
    fail = True


# ---- 1. Build the PUBLIC endpoint inventory --------------------------------

# The flow routes come straight from the Rust FLOW_*_PATH constants (the source
# of truth). The constant value may wrap onto the next line, so match across it.
rust = transport.read_text(encoding="utf-8")
flow_paths = set(
    re.findall(
        r'pub const FLOW_\w+_PATH\s*:\s*&str\s*=\s*"((?:[^"\\]|\\.)*)"',
        rust,
    )
)
if not flow_paths:
    problem(f"found no FLOW_*_PATH constants in {transport} (source of truth moved?)")

# The documented public session endpoints the reference app is permitted to use.
# Each MUST appear in the generated public endpoint inventory, so this allowlist
# can never name a path that is not actually a mounted public endpoint.
session_endpoints = {"/userinfo", "/end_session"}

documented = set(
    line.strip()
    for line in inventory_doc.read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.startswith("#")
)
for path in sorted(flow_paths | session_endpoints):
    if path not in documented:
        problem(
            f"public inventory entry {path!r} is not in the documented endpoint "
            f"inventory {inventory_doc} (not a mounted public endpoint)"
        )

public_inventory = flow_paths | session_endpoints

# ---- 2 + 3. Scan the app sources -------------------------------------------

# A network call sink: any of these in CODE (not a comment, not a string) outside
# src/api.ts is a violation.
network_sinks = re.compile(
    r"\b(fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon)\s*\("
)


def tokenize(text):
    """Split a TypeScript source into (code, strings) with comments removed.

    A comment-aware, string-aware pass so that the word ``fetch(`` inside a
    comment is not mistaken for a call and a URL inside a comment is not mistaken
    for a literal. Returns (code_without_strings_or_comments, [string_literals]).
    A ``/`` that does not begin ``//`` or ``/*`` is treated as an ordinary code
    character (division or a regex delimiter), which is correct for this app and
    keeps a stray ``"`` inside a regex from opening a phantom string. An
    unterminated string or block comment is reported by the caller.
    """
    code = []
    strings = []
    i, n = 0, len(text)
    unterminated = False
    while i < n:
        c = text[i]
        two = text[i : i + 2]
        if two == "//":
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif two == "/*":
            j = text.find("*/", i + 2)
            if j < 0:
                unterminated = True
                break
            i = j + 2
        elif c in "\"'`":
            quote = c
            j = i + 1
            buf = []
            closed = False
            while j < n:
                cj = text[j]
                if cj == "\\" and quote != "`":
                    buf.append(text[j : j + 2])
                    j += 2
                    continue
                if cj == quote:
                    closed = True
                    j += 1
                    break
                buf.append(cj)
                j += 1
            if not closed:
                unterminated = True
                break
            strings.append("".join(buf))
            i = j
        else:
            code.append(c)
            i += 1
    return "".join(code), strings, unterminated


ts_files = sorted(p for p in app_src.rglob("*.ts"))
if not ts_files:
    problem(f"no TypeScript sources found under {app_src}")

declared_paths = set()

for path in ts_files:
    text = path.read_text(encoding="utf-8")
    rel = path.relative_to(root)
    code, strings, unterminated = tokenize(text)
    if unterminated:
        problem(f"{rel}: unterminated string or comment (the audit could not parse it)")

    # Property 1a: network sinks only in api.ts (scanned over CODE, so a mention
    # in a comment or a string does not count).
    if path != api_file:
        for match in network_sinks.finditer(code):
            problem(
                f"{rel}: network call {match.group(1)!r} outside the single audited "
                f"client (src/api.ts)"
            )

    # Properties 1b, 2, 3: server path and URL literals only in endpoints.ts.
    for literal in strings:
        is_abs_url = bool(re.match(r"^https?://", literal))
        is_server_path = literal.startswith("/") and len(literal) > 1 and not literal.startswith("//")
        if is_abs_url:
            problem(
                f"{rel}: absolute URL literal {literal!r} (the issuer base is runtime "
                f"config, never a literal; no external hosts)"
            )
        if is_server_path:
            if path != endpoints_file:
                problem(
                    f"{rel}: server path literal {literal!r} outside src/endpoints.ts "
                    f"(all endpoints must be declared in the one audited module)"
                )
            else:
                declared_paths.add(literal)

# ---- 2. Every declared endpoint must be public -----------------------------

for literal in sorted(declared_paths):
    if literal not in public_inventory:
        problem(
            f"endpoints.ts declares {literal!r}, which is NOT a documented public "
            f"endpoint (flow FLOW_*_PATH constants + session {sorted(session_endpoints)})"
        )

if not declared_paths:
    problem("src/endpoints.ts declares no endpoints (expected the public flow routes)")

if fail:
    sys.exit(1)

print("route-audit: clean")
print(f"  public inventory: {len(public_inventory)} endpoints")
print(f"  app declares:     {sorted(declared_paths)}")
PY
