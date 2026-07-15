#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The resource-model classification lint (issue #41).
#
# Every first-class resource type MUST carry an explicit promotable / runtime /
# environment-identity classification, so the config snapshot (5.3) and the
# promotion engine (5.4) never have to reverse-engineer "does this travel in a
# snapshot?" (the PingOne AIC failure mode). The classification lives in
# crates/ironauth-store/src/classification.rs as a closed ResourceType enum, an
# exhaustive classify() match, and a ResourceType::ALL registry.
#
# The compiler already forces classify() to cover every variant (an exhaustive
# match). This lint is the independent belt to that suspenders, and it also
# guards the two things the compiler does NOT: that ResourceType::ALL lists every
# variant (a fixed-size array silently drops a new one), and that all THREE
# classes are actually used. CI fails here if a new resource type lands
# unclassified or unlisted.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

SRC="crates/ironauth-store/src/classification.rs"
if [ ! -f "${SRC}" ]; then
  echo "classification-lint: ${SRC} not found" >&2
  exit 1
fi

fail=0

# 1. The variants of the ResourceType enum: the identifiers between
#    `pub enum ResourceType {` and its closing brace, one per line.
variants=$(awk '
  /pub enum ResourceType \{/ { inblock = 1; next }
  inblock && /^\}/           { inblock = 0 }
  inblock && /^[[:space:]]+[A-Z][A-Za-z0-9]*,[[:space:]]*$/ {
    gsub(/[[:space:],]/, "");
    print
  }
' "${SRC}")

if [ -z "${variants}" ]; then
  echo "classification-lint: could not extract any ResourceType variants from ${SRC}" >&2
  exit 1
fi

# 2. The body of classify() and the ResourceType::ALL registry, so each variant
#    can be checked for membership in both.
classify_body=$(awk '
  /pub fn classify\(/ { inblock = 1 }
  inblock             { print }
  inblock && /^\}/    { inblock = 0 }
' "${SRC}")
all_body=$(awk '
  /pub const ALL: \[ResourceType;/ { inblock = 1 }
  inblock                          { print }
  inblock && /\];/                 { inblock = 0 }
' "${SRC}")

for variant in ${variants}; do
  if ! printf '%s\n' "${classify_body}" | grep -q "ResourceType::${variant}\b"; then
    echo "classification-lint: ResourceType::${variant} is not classified in classify()"
    fail=1
  fi
  if ! printf '%s\n' "${all_body}" | grep -q "ResourceType::${variant}\b"; then
    echo "classification-lint: ResourceType::${variant} is missing from ResourceType::ALL"
    fail=1
  fi
done

# 3. All three classes must appear as wire strings, so the taxonomy is never
#    silently collapsed to one or two.
for class in promotable runtime environment-identity; do
  if ! grep -q "\"${class}\"" "${SRC}"; then
    echo "classification-lint: the '${class}' class has no wire string in ${SRC}"
    fail=1
  fi
done

if [ "${fail}" -ne 0 ]; then
  echo
  echo "classification-lint: every ResourceType must be classified in classify() AND listed"
  echo "in ResourceType::ALL, and all three classes must be used. See ${SRC}."
  exit 1
fi

count=$(printf '%s\n' "${variants}" | grep -c .)
echo "classification-lint: clean (${count} resource types, all classified and listed)"
