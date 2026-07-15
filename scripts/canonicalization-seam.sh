#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The identifier canonicalization seam lint (issue #54).
#
# Canonicalization drift is a recurring CVE generator (Authelia CVE-2026-47203 /
# CVE-2025-24806 / CVE-2026-48794, Zitadel CVE-2025-31124): when a login handle is
# normalized per-endpoint, one endpoint's view of an identifier differs from
# another's and the gap is the vulnerability. The fix is a SINGLE canonicalization
# function applied ONCE at the boundary, with every comparison, uniqueness check,
# and lockout / access decision operating only on the canonical form.
#
# THE ONE ALLOWED ENTRY POINT is:
#
#     ironauth_store::identifier::canonicalize_identifier
#
# It is the only function that produces a `CanonicalIdentifier`, and the store's
# flexible-identifier blind index, uniqueness constraint, and resolution API accept
# only a `&CanonicalIdentifier`. Because `CanonicalIdentifier`'s fields are private,
# the Rust type system ALREADY makes "route every identifier comparison through the
# seam" impossible to bypass across crates. This lint is the belt-and-suspenders
# backstop the repository convention calls for (the same class of grep-based
# structural lint as scripts/invariant-lints.sh and scripts/query-audit.sh): it
# fails the build if a second canonicalizer appears, or if a `CanonicalIdentifier`
# is fabricated outside the seam module, either of which would reopen the drift gap.
#
# An exceptional line may carry the marker "seam-allow: <reason>" together with a
# written justification; use sparingly.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

SEAM_FILE="crates/ironauth-store/src/identifier.rs"
fail=0

# Rule single-seam: exactly one definition of the canonicalization entry point. A
# second `fn canonicalize_identifier` anywhere is a competing normalizer, which is
# precisely the per-endpoint drift the seam exists to prevent.
defs=$(grep -rn --include='*.rs' -E 'fn[[:space:]]+canonicalize_identifier[[:space:]]*\(' crates || true)
def_count=$(printf '%s' "$defs" | grep -c . || true)
if [ "$def_count" -ne 1 ]; then
  echo "canonicalization-seam: rule 'single-seam' violated: expected exactly one"
  echo "  definition of canonicalize_identifier, found ${def_count}:"
  echo "$defs"
  fail=1
elif ! printf '%s' "$defs" | grep -q "^${SEAM_FILE}:"; then
  echo "canonicalization-seam: rule 'single-seam' violated: canonicalize_identifier"
  echo "  must be defined in ${SEAM_FILE}, found:"
  echo "$defs"
  fail=1
fi

# Rule no-bypass: a `CanonicalIdentifier` is constructed ONLY inside the seam module.
# Constructing one elsewhere (struct-literal `CanonicalIdentifier { ... }`) would
# mint a "canonical" value that never passed the seam, defeating the type-level
# guarantee. The private field already blocks this across modules; the lint keeps a
# future refactor inside the crate honest and makes the invariant self-documenting.
bypass=$(grep -rn --include='*.rs' -E 'CanonicalIdentifier[[:space:]]*\{' crates \
  | grep -v "^${SEAM_FILE}:" \
  | grep -v 'seam-allow:' || true)
if [ -n "$bypass" ]; then
  echo "canonicalization-seam: rule 'no-bypass' violated: a CanonicalIdentifier is"
  echo "  constructed outside the seam module (${SEAM_FILE}); route the value through"
  echo "  canonicalize_identifier instead:"
  echo "$bypass"
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo
  echo "Canonicalize every identifier exactly once through"
  echo "ironauth_store::identifier::canonicalize_identifier, and compare only the"
  echo "resulting CanonicalIdentifier. See crates/ironauth-store/src/identifier.rs."
  exit 1
fi
echo "canonicalization-seam: clean (one seam, no bypass)"
