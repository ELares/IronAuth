#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# HTTP audit: ironauth-fetch is the ONE crate allowed to perform outbound HTTP.
# The SSRF-hardened fetcher only closes the SSRF class structurally if it is the
# sole outbound path, so no other workspace crate may build an HTTP client or a
# client TLS stream. This lint enforces that.
#
# Primary net (authoritative): no crate other than ironauth-fetch may declare a
# DIRECT dependency on an HTTP-client or client-TLS-stream crate. This is the
# real guarantee, because Rust code cannot `use` a crate it does not directly
# depend on: without the dependency there is no way to construct a second client.
#
# Secondary net (best-effort, documented): no crate other than ironauth-fetch may
# name an HTTP-client or TLS-client constructor in its source. This is grep-based
# and catches an accidental use of a transitively available API. A justified
# exception carries the marker "http-audit-allow: <reason>" on the same line.
#
# Deliberately NOT flagged: a bare TcpStream::connect. Non-HTTP TCP reachability
# probes are legitimate (for example the readiness check dials the configured
# database), and hand-rolling HTTP over a raw socket still needs no HTTP-client
# crate to be caught by the primary net plus code review. Tests are exempt (they
# stand up loopback servers and clients).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# The one crate allowed an outbound HTTP path.
FETCH_CRATE='ironauth-fetch'

# HTTP-client and client-TLS-stream crates. A direct dependency on any of these,
# outside ironauth-fetch, is a second outbound path. Bare `rustls` is included so
# a crate cannot hand-roll an HTTPS client over a raw TcpStream and evade the
# net; the anchored key match does not catch `rustls-native-certs`, `tokio-rustls`
# and friends (they start with a different token), which are ironauth-fetch's own
# excluded deps anyway.
CLIENT_DEPS='reqwest|isahc|ureq|surf|attohttpc|curl|hyper|hyper-util|tokio-rustls|native-tls|rustls'

# HTTP-client / TLS-client constructors in source. The rustls client entry points
# are named too, so a hand-rolled TLS client is caught; ironauth-fetch's own use
# of tokio_rustls::rustls::ClientConfig is exempt (the fetch crate is excluded).
CLIENT_SYMBOLS='reqwest::|isahc::|ureq::|surf::|attohttpc::|hyper::client|hyper_util::client|client::conn::|TlsConnector|rustls::(ClientConfig|ClientConnection|ClientConnectionData)'

fail=0

# Primary net: scan every crate manifest except ironauth-fetch's for a direct
# dependency declaration (name at the start of a key, so prose in comments does
# not match) on a banned crate.
for manifest in crates/*/Cargo.toml; do
  case "$manifest" in
    crates/${FETCH_CRATE}/Cargo.toml) continue ;;
  esac
  hits=$(grep -nE "^[[:space:]]*(${CLIENT_DEPS})[[:space:]]*(=|\.)" "$manifest" \
    | grep -v 'http-audit-allow' \
    || true)
  if [ -n "$hits" ]; then
    echo "http-audit: HTTP-client dependency outside ${FETCH_CRATE} in ${manifest}:"
    echo "$hits"
    fail=1
  fi
done

# Secondary net: scan crate sources (not tests, not ironauth-fetch) for an
# HTTP-client or TLS-client constructor.
src_hits=$(grep -rnE "${CLIENT_SYMBOLS}" --include='*.rs' crates \
  | grep -v "^crates/${FETCH_CRATE}/" \
  | grep -vE '/tests/' \
  | grep -v 'http-audit-allow' \
  || true)
if [ -n "$src_hits" ]; then
  echo "http-audit: HTTP/TLS client construction outside ${FETCH_CRATE}:"
  echo "$src_hits"
  echo
  echo "Route every outbound HTTP request through ${FETCH_CRATE}, or add"
  echo "'http-audit-allow: <reason>' on the line if it is a genuine false positive."
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "http-audit: clean (ironauth-fetch is the only outbound HTTP path)"
