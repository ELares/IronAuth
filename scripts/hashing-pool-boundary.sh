#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The password-hashing pool-boundary lint (issue #62).
#
# Password hashing is the hottest and most denial-of-service-prone operation an
# identity provider performs: an OWASP-strength Argon2id costs tens of ms of CPU
# and tens of MiB of memory per hash. If a request-path handler calls the RAW
# hasher directly, that Argon2 runs INLINE on a tokio protocol-I/O worker with NO
# per-tenant admission and NO fair-share accounting, so flooding that one endpoint
# stalls the whole instance for every tenant, the exact cross-tenant DoS issue #62
# exists to prevent (this bit device-flow verify and invitation-accept before the
# fix). Every request-path hash MUST route through the admission-controlled pool
# (`OidcState::hash_password` / `verify_password` / `verify_absent`, which enqueue
# onto the dedicated worker pool behind per-tenant fair-share admission).
#
# THE ONLY functions this lint governs are the raw hashers in the `password`
# module:
#
#     crate::password::hash_password
#     crate::password::verify_password
#     crate::password::verify_absent
#
# They may be called ONLY from the pool-boundary modules that own the seam:
#
#     crates/ironauth-oidc/src/password.rs       (the definitions themselves)
#     crates/ironauth-oidc/src/hashing_pool.rs   (the worker that runs the hash)
#     crates/ironauth-oidc/src/state.rs          (the OidcState pool + bounded fallback)
#
# Anywhere else, route through `OidcState::{hash_password,verify_password,verify_absent}`
# so the pool and its admission apply. The parameterized minter
# `password::hash_password_with` (used by the pool worker and the tuning probe) is
# deliberately NOT governed; it is the minting primitive, not a request-path call.
#
# The raw hashers are ALSO re-exported from the crate root
# (`ironauth_oidc::{hash_password,verify_password,verify_absent}`, see
# ironauth-oidc/src/lib.rs), so a DIFFERENT crate can reach them WITHOUT ever naming
# the `password::` module. This lint therefore scans EVERY crate's production source
# (not just ironauth-oidc) and catches the re-export call form as well, so an inline
# cross-crate hash cannot slip past the boundary (issue #62 LOW). Integration-test
# trees (`crates/*/tests/`) are excluded: test scaffolding legitimately mints and
# verifies hashes directly (seeding fixtures, asserting the primitive's behavior).
#
# This is the same class of grep-based structural backstop as
# scripts/canonicalization-seam.sh and scripts/invariant-lints.sh. An exceptional
# line may carry the marker "pool-boundary-allow: <reason>" with a written
# justification; use sparingly.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# The pool-boundary modules that legitimately reference the raw hashers.
ALLOW_RE='crates/ironauth-oidc/src/(password|hashing_pool|state)\.rs'
# Integration-test trees, where minting/verifying hashes directly is legitimate test
# scaffolding rather than a request-path call.
TESTS_RE='/tests/'
fail=0

# Rule qualified-path: no `password::{hash_password,verify_password,verify_absent}`
# path reference (a call OR a `use` import) anywhere outside the boundary modules.
# The trailing `[^[:alnum:]_]` class keeps `password::hash_password_with` (the
# minting primitive) out of scope while still catching an import line ending in
# `;`, `,`, or `}`.
qualified=$(grep -rn --include='*.rs' -E \
  'password::(hash_password|verify_password|verify_absent)[^[:alnum:]_]' crates \
  | grep -Ev "^${ALLOW_RE}:" \
  | grep -Ev "$TESTS_RE" \
  | grep -v 'pool-boundary-allow:' || true)
if [ -n "$qualified" ]; then
  echo "hashing-pool-boundary: rule 'qualified-path' violated: a raw password hasher"
  echo "  is referenced outside the pool-boundary modules. Route it through"
  echo "  OidcState::{hash_password,verify_password,verify_absent} (the admission-"
  echo "  controlled pool) instead:"
  echo "$qualified"
  fail=1
fi

# Rule reexport-call: no CALL through the crate-root RE-EXPORT
# (`ironauth_oidc::{hash_password,verify_password,verify_absent}(...)`) anywhere in
# production source. This is the cross-crate hole the qualified-path rule misses,
# because the caller never names the `password::` module. Matches only the call form
# (name then `(`), so a rustdoc link or a `use` import line does not trip it (a bare
# call reached via a `use` import is caught by rule bare-call below). The re-exported
# minter `hash_password_with` is excluded because `_` follows the name, not `(`.
reexport=$(grep -rn --include='*.rs' -E \
  'ironauth_oidc::(hash_password|verify_password|verify_absent)[[:space:]]*\(' crates \
  | grep -Ev "$TESTS_RE" \
  | grep -v 'pool-boundary-allow:' || true)
if [ -n "$reexport" ]; then
  echo "hashing-pool-boundary: rule 'reexport-call' violated: a raw password hasher is"
  echo "  called cross-crate through the ironauth_oidc re-export, bypassing the pool."
  echo "  Route it through OidcState::{hash_password,verify_password,verify_absent}"
  echo "  (or, for a justified exception, mark the line pool-boundary-allow: <reason>):"
  echo "$reexport"
  fail=1
fi

# Rule bare-call: no BARE call to one of the raw hashers (e.g. after
# `use crate::password::verify_password;` or `use ironauth_oidc::verify_absent;`)
# anywhere in production source outside the boundary modules. A method call
# (`state.verify_password(...)`, `argon2.hash_password(...)`) is preceded by `.` and
# is NOT matched, and `hash_password_with(` is excluded because `(` never immediately
# follows the name.
bare=$(grep -rn --include='*.rs' -E \
  '(^|[^._[:alnum:]])(hash_password|verify_password|verify_absent)[[:space:]]*\(' \
  crates \
  | grep -Ev "^${ALLOW_RE}:" \
  | grep -Ev "$TESTS_RE" \
  | grep -v 'pool-boundary-allow:' || true)
if [ -n "$bare" ]; then
  echo "hashing-pool-boundary: rule 'bare-call' violated: a raw password hasher is"
  echo "  called (bare) outside the pool-boundary modules. Route it through"
  echo "  OidcState::{hash_password,verify_password,verify_absent} instead:"
  echo "$bare"
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo
  echo "Every request-path password hash must run on the dedicated, admission-"
  echo "controlled pool so one tenant's hashing storm degrades ONLY that tenant."
  echo "See crates/ironauth-oidc/src/hashing_pool.rs and OidcState's hash methods."
  exit 1
fi
echo "hashing-pool-boundary: clean (raw hashers confined to the pool boundary)"
