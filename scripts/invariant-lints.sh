#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Structural invariants that ordinary compiler lints cannot express, enforced
# as grep rules over the workspace. Each rule names the invariant it guards.
# An exceptional call site may carry the marker "invariant-allow: <rule>" on
# the same line together with a written reason; use sparingly.
#
# SCOPE: `scan` walks every Rust tree in the repository, crates/ and the
#   top-level fuzz/, minus crates/ironauth-env/ (which IS the seam the time and
#   entropy rules funnel everything through, so it is the one place the raw calls
#   belong). fuzz/ is walked because it is Rust that links the same crates, not
#   because it violates anything today; a rule that stopped at crates/ would be
#   one `cargo fuzz add` away from a blind spot. packages/ is deliberately out:
#   it is the TypeScript SPA and none of these rules can apply to it. A NEW Rust
#   tree must be added to the walk here at the same time it is added to the
#   workspace.
#
# Rule time-via-env: all wall-clock and monotonic time flows through
#   crates/ironauth-env (Clock trait). No raw SystemTime::now or Instant::now
#   anywhere else, so protocol logic stays deterministic under test.
# Rule entropy-via-env: all randomness flows through crates/ironauth-env
#   (Entropy trait). No direct getrandom or rand usage anywhere else, so
#   identifier and nonce generation stays deterministic under test.
# Rule typ-via-declaration: a token's JOSE `typ` media type is stamped from the
#   ironauth-jose TokenTyp declaration (EmissionOptions::with_token_typ), never
#   from a bare string at the mint site. TokenTyp is the SAME declaration the
#   verifier's ExpectedTyp reads, so a profile cannot be minted under one
#   spelling and required under another, and a typo cannot mint a token that
#   nothing will ever accept. Foreign media types (a peer's dictated header) and
#   tests that mint a deliberately wrong typ carry the allow marker and a reason.
#   Both spellings of the call are caught, the method form `.with_typ(` and the
#   UFCS form `EmissionOptions::with_typ(`: the same function reached the second
#   way is the same hole, and a rule that only knew the first would be defeated by
#   a spelling rather than by a decision.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

fail=0

scan() {
  local rule="$1" pattern="$2"
  local hits
  hits=$(grep -rn --include='*.rs' -E "$pattern" crates fuzz \
    | grep -v '^crates/ironauth-env/' \
    | grep -v "invariant-allow: ${rule}" || true)
  if [ -n "$hits" ]; then
    echo "invariant-lints: rule '${rule}' violated:"
    echo "$hits"
    fail=1
  fi
}

scan time-via-env 'SystemTime::now|Instant::now'
# The `rand::` guard requires a non-identifier char (or start of line) before `rand`
# so a real `rand` crate path is caught while an identifier that merely ENDS in "rand"
# (for example a `Brand::` associated call) is not a false positive.
scan entropy-via-env 'getrandom::|(^|[^A-Za-z0-9_])rand::|rand_core::'
scan typ-via-declaration '(\.|::)\s*with_typ\s*\('

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "invariant-lints: clean"
