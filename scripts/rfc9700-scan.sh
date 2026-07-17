#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# RFC 9700 conformance freshness lint (issue #38). The RFC 9700 checklist is
# encoded as executable CI invariants in crates/ironauth-oidc/tests/rfc9700.rs and
# mapped to each requirement in docs/conformance/rfc9700-checklist.md. This lint
# binds every mounted OAuth endpoint to that coverage, so a future BCP-relevant
# endpoint cannot ship while the checklist still reads complete:
#
#   1. tests/rfc9700.rs is a registered [[test]] (autotests=false, so an
#      unregistered test file is dead and never runs).
#   2. The endpoint inventory is GENERATED from EVERY router in the crate (the
#      protocol router, the discovery router, and the issuer/JWKS router; scanning
#      only one of them would leave a whole router's endpoints invisible to this
#      lint) and diffed against the committed copy, exactly like
#      scripts/compat-matrix.sh: a new .route() anywhere under
#      crates/ironauth-oidc/src makes the committed inventory stale and fails CI
#      until it is regenerated and committed.
#   3. Every generated endpoint is named in the checklist doc (a new endpoint must
#      be mapped to a covering test or an explicit not-applicable reason).
#   4. Every rfc9700_* test the checklist claims actually exists as a function, and
#      every rfc9700_* test that exists is claimed by the checklist (no drift in
#      either direction), exactly like scripts/discovery-scan.sh asserts a single
#      source of truth.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

src="crates/ironauth-oidc/src"
doc="docs/conformance/rfc9700-checklist.md"
cargo="crates/ironauth-oidc/Cargo.toml"
tests_dir="crates/ironauth-oidc/tests"
inventory="docs/conformance/rfc9700-endpoints.txt"

fail=0

# 1. The conformance suite is a registered test target, else it is dead.
if ! grep -q '^name = "rfc9700"$' "$cargo" || ! grep -q '^path = "tests/rfc9700.rs"$' "$cargo"; then
  echo "rfc9700-scan: tests/rfc9700.rs is not a registered [[test]] in $cargo (autotests=false)"
  fail=1
fi

# 2. Regenerate the endpoint inventory from EVERY router in the crate and diff it.
#    The inventory is every .route() mount under crates/ironauth-oidc/src, so it is
#    bound to the whole mounted surface (oidc_router, discovery_router, and the
#    issuer/JWKS router) rather than to one function that a new router could bypass.
#    A .route() path is resolved whether it is a string LITERAL or a `const NAME: &str`
#    PATH CONST (the one shape the string-only scan used to miss); a non-literal path
#    that resolves to no known const FAILS the scan, so a const/computed route can never
#    silently evade the inventory.
python3 - "$src" "$inventory" <<'PY'
import pathlib, re, sys
src, out = pathlib.Path(sys.argv[1]), sys.argv[2]
files = sorted(src.rglob("*.rs"))

# Map every `const NAME: &str = "literal";` path const, so a `.route()` mounted at a
# CONST path can be RESOLVED to its literal rather than silently evade the inventory (a
# const path is the one shape the old string-only scan could not capture, so a new
# const/computed route could ship uncovered while the scan still printed "clean").
const_re = re.compile(r"const\s+([A-Z][A-Z0-9_]*)\s*:\s*&\s*(?:'static\s+)?str\s*=\s*\"([^\"]+)\"")
consts = {}
for path in files:
    for name, value in const_re.findall(path.read_text(encoding="utf-8")):
        consts[name] = value

# Resolve the FIRST argument of EVERY `.route(...)` mount: a string literal is taken
# verbatim; a bare/pathed SCREAMING_SNAKE const is resolved through the const map above.
# Anything else (a computed or unknown path, or a const we cannot resolve) is UNRESOLVED
# and FAILS the scan with its file:line, so a const/computed route can never again evade
# this inventory (the systemic hardening: the scan cannot silently miss a mounted route).
ident_re = re.compile(r"(?:[A-Za-z_]\w*::)*([A-Z][A-Z0-9_]*)")
routes = set()
unresolved = []
for path in files:
    text = path.read_text(encoding="utf-8")
    for m in re.finditer(r"\.route\(", text):
        i, n = m.end(), len(text)
        while i < n and text[i] in " \t\r\n":
            i += 1
        if i >= n or text[i] == ")":
            # `.route()` with no argument is a doc/comment reference, not a real mount.
            continue
        if text[i] == '"':
            j = text.find('"', i + 1)
            if j != -1:
                routes.add(text[i + 1 : j])
            continue
        im = ident_re.match(text, i)
        if im and im.group(1) in consts:
            routes.add(consts[im.group(1)])
            continue
        line = text.count("\n", 0, m.start()) + 1
        snippet = text[i : i + 48].splitlines()[0]
        unresolved.append(
            f"{path}:{line}: .route() path `{snippet}` is not a string literal or a "
            "resolvable path const"
        )

if unresolved:
    sys.stderr.write(
        "rfc9700-scan: a .route() mounts a non-literal, unresolvable path (a const or "
        "computed route path must be a string literal or a resolvable `const NAME: &str` "
        "path const, so it cannot silently evade the endpoint inventory):\n"
    )
    for item in unresolved:
        sys.stderr.write("  " + item + "\n")
    sys.exit(1)

header = (
    "# RFC 9700 endpoint inventory (generated)\n"
    "#\n"
    "# Generated by scripts/rfc9700-scan.sh from EVERY .route() mounted under\n"
    "# crates/ironauth-oidc/src (the protocol router, the discovery router, and the\n"
    "# issuer/JWKS router); do not edit by hand. Every path here MUST be mapped to a\n"
    "# covering test (or an explicit not-applicable reason) in\n"
    "# docs/conformance/rfc9700-checklist.md, so a new OAuth endpoint cannot ship\n"
    "# uncovered while the checklist reads complete.\n"
)
open(out, "w", encoding="utf-8").write(header + "\n".join(sorted(routes)) + "\n")
PY
if ! git diff --exit-code "$inventory" >/dev/null 2>&1; then
  echo "rfc9700-scan: $inventory is stale (a route changed). Regenerated; review and commit it,"
  echo "              and map any new endpoint in $doc."
  git --no-pager diff -- "$inventory" || true
  fail=1
fi

# 3. Every generated endpoint is named in the checklist doc.
while IFS= read -r path; do
  case "$path" in ''|'#'*) continue ;; esac
  if ! grep -qF -- "$path" "$doc"; then
    echo "rfc9700-scan: endpoint '$path' is not mapped in $doc (uncovered endpoint)"
    fail=1
  fi
done < "$inventory"

# 4. The checklist and the suite reference the SAME set of rfc9700_* tests.
#    (a) every rfc9700_* test the doc claims exists as a function;
#    (b) every rfc9700_* test defined in the suite is claimed by the doc.
doc_tests=$(grep -oE 'rfc9700_[a-z0-9_]+' "$doc" | sort -u || true)
src_tests=$(grep -oE 'fn (rfc9700_[a-z0-9_]+)' "$tests_dir"/rfc9700.rs | sed 's/^fn //' | sort -u || true)

for name in $doc_tests; do
  if ! grep -rqE "fn ${name}\b" "$tests_dir"; then
    echo "rfc9700-scan: checklist references test '${name}', which no test defines"
    fail=1
  fi
done

for name in $src_tests; do
  if ! grep -qF -- "$name" "$doc"; then
    echo "rfc9700-scan: test '${name}' exists but is not traced in $doc"
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "rfc9700-scan: clean (every mounted endpoint is mapped; checklist and suite agree)"
