#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Route audit for the admin console SPA (issue #90), mirroring
# scripts/route-audit.sh for the reference app. The console is a PURE CLIENT of
# the PUBLIC management API: it must reach the server ONLY through the one
# generated, typed client (packages/admin-spa/src/api/client.ts). This static
# lint is the structural guarantee that it can never be wired to hit an
# undocumented or private endpoint.
#
# It enforces these properties over the app's HAND WRITTEN TypeScript sources
# (the generated management.gen.ts is the contract itself and is excluded):
#
#   1. The single funnel. Only src/api/client.ts may perform a network call
#      (fetch/XMLHttpRequest/WebSocket/EventSource/sendBeacon or openapi-fetch's
#      createClient) or import the openapi-fetch network library. Every other
#      module is network free, so there is one audited choke point.
#
#   2. Documented paths only. Any management API path literal (a string starting
#      with /v1/ or /.well-known/, or one of the allowlisted OIDC public
#      endpoints) must be a path the committed docs/openapi/management.json
#      documents, or a member of the small OIDC public allowlist below. An
#      undocumented API path fails the audit.
#
#   3. No external hosts. An absolute http(s):// URL literal anywhere in the app
#      fails the audit (the issuer and management bases are runtime <meta> config,
#      never a literal), so the app cannot be hardcoded to call an external host.
#
# In PR1 the console is a static shell, so it reaches no endpoint yet; the SCRIPT
# and its wiring are the deliverable, and the OIDC allowlist is declared now for
# the PR2 login module to draw on.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

python3 - <<'PY'
import json
import pathlib
import re
import sys

root = pathlib.Path(".")
spec_file = root / "docs" / "openapi" / "management.json"
app_src = root / "packages" / "admin-spa" / "src"
client_file = app_src / "api" / "client.ts"
generated_file = app_src / "api" / "management.gen.ts"

fail = False


def problem(msg):
    global fail
    print(f"admin-spa-route-audit: {msg}")
    fail = True


# ---- 1. The documented + allowlisted path inventory ------------------------

spec = json.loads(spec_file.read_text(encoding="utf-8"))
documented_paths = set(spec.get("paths", {}).keys())
if not documented_paths:
    problem(f"found no paths in {spec_file} (source of truth moved?)")

# The OIDC PUBLIC endpoints the PR2 login module is permitted to reach directly
# (authorize, token, discovery, end_session). These are NOT management API paths,
# so they are allowlisted here explicitly. PR2 wires them; PR1 only declares them.
oidc_public_allowlist = {
    "/authorize",
    "/token",
    "/.well-known/openid-configuration",
    "/end_session",
}

allowed_paths = documented_paths | oidc_public_allowlist

# A literal is treated as a server API path (and therefore must be documented or
# allowlisted) when it names the management API or an OIDC public endpoint. App
# route literals (for example "/" or "/tenants" used as in browser routes) do not
# match and are left alone; the funnel rule already forbids a network call
# outside the one client.
def is_api_path(literal):
    return (
        literal.startswith("/v1/")
        or literal.startswith("/.well-known/")
        or literal in oidc_public_allowlist
    )


# ---- 2. Scan the hand written sources --------------------------------------

network_sinks = re.compile(
    r"\b(fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon|createClient)\s*\("
)


def tokenize(text):
    """Split a TypeScript/TSX source into (code, strings) with comments removed.

    Comment and string aware so that a sink name inside a comment is not a call
    and a path inside a comment is not a literal. A ``/`` that does not begin
    ``//`` or ``/*`` is an ordinary code character (division or a regex
    delimiter), which is correct here and keeps a ``"`` inside a regex from
    opening a phantom string. Returns (code_without_strings, [string_literals],
    unterminated_flag).
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


sources = sorted(
    p
    for p in list(app_src.rglob("*.ts")) + list(app_src.rglob("*.tsx"))
    if p != generated_file and not p.name.endswith(".d.ts")
)
if not sources:
    problem(f"no hand written TypeScript sources found under {app_src}")

declared_api_paths = set()

for path in sources:
    rel = path.relative_to(root)
    code, strings, unterminated = tokenize(path.read_text(encoding="utf-8"))
    if unterminated:
        problem(f"{rel}: unterminated string or comment (the audit could not parse it)")

    # Property 1: network sinks only in the one client.
    if path != client_file:
        for match in network_sinks.finditer(code):
            problem(
                f"{rel}: network call {match.group(1)!r} outside the single audited "
                f"client (src/api/client.ts)"
            )

    for literal in strings:
        # Property 1: the openapi-fetch network library is imported only in the
        # one client.
        if literal == "openapi-fetch" and path != client_file:
            problem(
                f"{rel}: imports the openapi-fetch network library outside the single "
                f"audited client (src/api/client.ts)"
            )
        # Property 3: no absolute URL literal anywhere.
        if re.match(r"^https?://", literal):
            problem(
                f"{rel}: absolute URL literal {literal!r} (the issuer and management "
                f"bases are runtime <meta> config, never a literal; no external hosts)"
            )
        # Property 2: collect API path literals for the documented check.
        if is_api_path(literal):
            declared_api_paths.add(literal)

# ---- 3. Every API path literal must be documented or allowlisted -----------

for literal in sorted(declared_api_paths):
    if literal not in allowed_paths:
        problem(
            f"the app names API path {literal!r}, which is NOT documented in "
            f"{spec_file} and is not an allowlisted OIDC public endpoint"
        )

if fail:
    sys.exit(1)

print("admin-spa-route-audit: clean")
print(f"  documented management paths: {len(documented_paths)}")
print(f"  oidc public allowlist:       {len(oidc_public_allowlist)}")
print(f"  app names API paths:         {sorted(declared_api_paths)}")
PY
