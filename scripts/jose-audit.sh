#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# JOSE audit: ironauth-jose is the ONE crate allowed to verify a JWS/JWT and the
# ONE crate allowed to touch a JOSE verification primitive. The hardened verifier
# only closes the JOSE CVE classes structurally if it is the sole verification
# path, so no other workspace crate may build a second verifier (directly or by
# pulling a high-level JOSE/JWT crate that carries those very CVE classes). This
# lint enforces that, mirroring scripts/http-audit.sh.
#
# Primary net (authoritative): no crate other than ironauth-jose may declare a
# DIRECT dependency on a JOSE/JWT crate or on `ring`. This is the real guarantee,
# because Rust code cannot `use` a crate it does not directly depend on: without
# the dependency there is no way to construct a second verifier. `ring` is named
# so a crate cannot hand-roll signature verification over the same backend and
# evade the net; ring enters the tree only transitively (via rustls), never as a
# direct dependency outside ironauth-jose.
#
# Secondary net (best-effort, documented): no crate other than ironauth-jose may
# name a JOSE verification primitive in its source (ring's signature/HMAC API, or
# a JOSE/JWT crate namespace). This is grep-based and catches an accidental use
# of a transitively available API. A justified exception carries the marker
# "jose-audit-allow: <reason>" on the same line.
#
# Tests are exempt (they legitimately sign and craft tokens with ring inside the
# jose crate, and stand up fixtures elsewhere).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# The one crate allowed a JOSE verification path.
JOSE_CRATE='ironauth-jose'

# JOSE/JWT crates and the crypto backend. A direct dependency on any of these,
# outside ironauth-jose, is a second verifier. The names are anchored at the
# start of a manifest key so prose in comments does not match.
JOSE_DEPS='jsonwebtoken|josekit|jose|jwt|jwt-simple|jwt_compact|jwtk|jwts|frank_jwt|biscuit|biscuit-auth|ring'

# JOSE verification / signature primitives in source. ring's signature and HMAC
# entry points are named so a hand-rolled verifier is caught; ironauth-jose's own
# use of them is exempt (the crate is excluded below).
JOSE_SYMBOLS='ring::signature|ring::hmac|UnparsedPublicKey|RsaPublicKeyComponents|jsonwebtoken::|josekit::|biscuit::'

fail=0

# Primary net: scan every crate manifest except ironauth-jose's for a direct
# dependency declaration (name at the start of a key) on a banned crate.
for manifest in crates/*/Cargo.toml; do
  case "$manifest" in
    crates/${JOSE_CRATE}/Cargo.toml) continue ;;
  esac
  hits=$(grep -nE "^[[:space:]]*(${JOSE_DEPS})[[:space:]]*(=|\.)" "$manifest" \
    | grep -v 'jose-audit-allow' \
    || true)
  if [ -n "$hits" ]; then
    echo "jose-audit: JOSE/JWT or ring dependency outside ${JOSE_CRATE} in ${manifest}:"
    echo "$hits"
    fail=1
  fi
done

# Secondary net: scan crate sources (not tests, not ironauth-jose) for a JOSE
# verification or signature primitive.
src_hits=$(grep -rnE "${JOSE_SYMBOLS}" --include='*.rs' crates \
  | grep -v "^crates/${JOSE_CRATE}/" \
  | grep -vE '/tests/' \
  | grep -v 'jose-audit-allow' \
  || true)
if [ -n "$src_hits" ]; then
  echo "jose-audit: JOSE verification primitive used outside ${JOSE_CRATE}:"
  echo "$src_hits"
  echo
  echo "Route every JWS/JWT verification through ${JOSE_CRATE}::verify, or add"
  echo "'jose-audit-allow: <reason>' on the line if it is a genuine false positive."
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "jose-audit: clean (ironauth-jose is the only JOSE verification path)"
