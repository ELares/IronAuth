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
#   4. No backdoor credential (issue #90, PR 2). No source literal may carry an
#      operator token or a management key: the SPA's ONLY credential is the in
#      memory at+jwt from the OIDC login, attached from a variable, never a
#      literal. A literal that names the operator/management-key credential class
#      (a `mak_` id, an operator token key) fails the audit. This is the
#      structural no-backdoor check: the browser can hold no service credential.
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

# Property 4: substrings that only ever appear in a service-credential literal.
# A `mak_` is a management-key id prefix; the operator-token config key names the
# operator credential. The console's only credential is the runtime at+jwt, so
# none of these belongs in any source literal. Matched case-insensitively.
FORBIDDEN_CREDENTIAL_SUBSTRINGS = (
    "mak_",
    "bootstrap_operator_token",
    "bootstrap-operator-token",
    "operator_token",
    "operator-token",
)

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
    r"\b(fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon|createClient|import)\s*\("
)

# URL bearing attribute / property / CSS sinks that fetch a resource without
# going through the one typed client: a form "action", an "src"/"srcset"
# assignment or JSX attribute, and a CSS "url(...)". A browser route "href" is
# deliberately NOT here (client side navigation under the /admin mount is not a
# server call). Any of these outside the single client is a funnel violation.
url_bearing_sinks = re.compile(
    r"(?:\b(?:form)?[Aa]ction\s*=)|(?:\.src\b)|(?:\bsrc(?:set)?\s*=)|(?:\burl\s*\()"
)

# The same shapes but as they appear INSIDE a string literal (a raw HTML string:
# a "<form action=..." or "src=..." or a CSS "url(..." held in a template). The
# "=" must be followed by a quote or a slash so an ordinary prose "action = 5"
# does not match; a legitimate Preact app writes JSX, never HTML in a string.
html_url_sinks = re.compile(
    r"""(?:\b(?:form)?[Aa]ction\s*=\s*["'/])"""
    r"""|(?:\bsrc(?:set)?\s*=\s*["'/])"""
    r"""|(?:\burl\s*\()"""
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
        for match in url_bearing_sinks.finditer(code):
            problem(
                f"{rel}: URL bearing sink {match.group(0)!r} outside the single "
                f"audited client (src/api/client.ts); a form action, src, or CSS "
                f"url fetches outside the one typed client"
            )

    for literal in strings:
        # Property 1: the openapi-fetch network library is imported only in the
        # one client.
        if literal == "openapi-fetch" and path != client_file:
            problem(
                f"{rel}: imports the openapi-fetch network library outside the single "
                f"audited client (src/api/client.ts)"
            )
        # Property 3: no authority bearing URL literal anywhere. A "//" in a
        # literal names a host authority: a scheme relative "//host", a full
        # "scheme://host", or a "//host" buried in a "url(...)" or an attribute
        # value. A legitimate server path is single slash ("/v1/..."); an app
        # route is single slash ("/tenants"); the issuer and management bases are
        # runtime <meta> config, never a literal. So any "//" is an external or
        # protocol relative host and fails the audit (the "no external host"
        # guarantee, airtight against protocol relative and embedded forms).
        if "//" in literal:
            problem(
                f"{rel}: authority bearing URL literal {literal!r} (a scheme or "
                f"protocol relative host; the issuer and management bases are "
                f"runtime <meta> config, never a literal; no external hosts)"
            )
        # A raw HTML string that carries a URL sink (a form action, an src, or a
        # CSS url) is a network sink smuggled inside a string, outside the funnel.
        if path != client_file and html_url_sinks.search(literal):
            problem(
                f"{rel}: URL bearing sink inside a string literal {literal!r} "
                f"outside the single audited client (src/api/client.ts); raw HTML "
                f"in a string fetches outside the one typed client"
            )
        # Property 4: no backdoor credential literal. A `mak_` names a management
        # key; the operator-token config keys name the operator credential. The
        # console holds NEITHER; its only credential is the runtime at+jwt.
        lowered = literal.lower()
        for forbidden in FORBIDDEN_CREDENTIAL_SUBSTRINGS:
            if forbidden in lowered:
                problem(
                    f"{rel}: source literal {literal!r} names a service credential "
                    f"(matched {forbidden!r}); the console holds NO operator token or "
                    f"management key, only the in memory at+jwt from the OIDC login "
                    f"(no backdoor)"
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
