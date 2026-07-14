#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Generate the self-signed CA and OP server certificate the conformance stack
# uses. Determinism note: TLS keys carry fresh randomness by construction, so the
# BYTES are not reproducible; what is deterministic and load-bearing is the
# SUBJECT and the SAN. The server cert is issued for exactly the issuer host
# "op" (SAN DNS:op), so it matches https://op, the value ironauth.toml pins as
# public_url. The CA is what the suite must trust (mounted into its truststore;
# see docs/conformance/RUNBOOK.md).
#
# Output goes to ./tls/, which is gitignored: private keys are NEVER committed.
# Re-run any time; it overwrites in place.
set -euo pipefail
cd "$(dirname "$0")"

out="tls"
mkdir -p "$out"

# The issuer host. Must equal the host in ironauth.toml's public_url.
op_host="op"

echo "==> CA"
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$out/ca.key" -out "$out/ca.crt" \
    -days 825 -sha256 \
    -subj "/CN=IronAuth Conformance Cert CA" >/dev/null 2>&1

echo "==> OP server key + CSR (CN=$op_host)"
openssl req -newkey rsa:2048 -nodes \
    -keyout "$out/op.key" -out "$out/op.csr" \
    -subj "/CN=$op_host" >/dev/null 2>&1

echo "==> OP server cert (SAN DNS:$op_host), signed by the CA"
openssl x509 -req -in "$out/op.csr" \
    -CA "$out/ca.crt" -CAkey "$out/ca.key" -CAcreateserial \
    -days 825 -sha256 \
    -extfile <(printf 'subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\n' "$op_host") \
    -out "$out/op.crt" >/dev/null 2>&1

rm -f "$out/op.csr" "$out/ca.srl"
echo "gen-certs: wrote $out/ca.crt, $out/op.crt, $out/op.key (op host: $op_host)"
echo "gen-certs: mount tls/ca.crt into the suite truststore so it trusts https://$op_host"
