#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Seed the conformance deployment with the deterministic operator, tenant,
# environment, and login user the OIDF suite needs (seed.sql). This is a seed
# SCRIPT, not a schema migration.
#
# It computes an Argon2id PHC hash for the committed cert password, renders it
# into seed.sql, and applies the result to the running postgres container as the
# superuser (which bypasses row-level security so scoped rows insert directly).
#
# Argon2id is computed with the `argon2` CLI if present, else via a pinned
# throwaway container. A verifier reads the parameters from the PHC string, so
# any valid Argon2id hash of the cert password verifies regardless of the params
# used to create it.
#
# Usage (from this directory, with the stack up):
#     ./seed.sh
set -euo pipefail
cd "$(dirname "$0")"

# Throwaway cert-only credential. Committed on purpose: the whole cert
# environment is disposable and never reachable outside the conformance run.
CERT_USER_PASSWORD="${CERT_USER_PASSWORD:-conformance-cert-password}"
COMPOSE=(docker compose --env-file SUITE_VERSION -f docker-compose.yml)

hash_argon2id() {
    local password="$1" salt="conformanceseed"
    if command -v argon2 >/dev/null 2>&1; then
        printf '%s' "$password" | argon2 "$salt" -id -e
    else
        # No local argon2 CLI: use a pinned throwaway container that ships it.
        # Alpine's argon2 package provides the same CLI.
        docker run --rm --entrypoint sh alpine:3.20 -c \
            "apk add --no-cache argon2 >/dev/null 2>&1 && printf '%s' '$password' | argon2 '$salt' -id -e"
    fi
}

echo "==> computing Argon2id hash for the cert login user"
user_hash="$(hash_argon2id "$CERT_USER_PASSWORD")"
if [ -z "$user_hash" ]; then
    echo "seed: failed to compute an Argon2id hash (install the 'argon2' CLI or Docker)" >&2
    exit 1
fi

echo "==> rendering seed.sql"
# Use a safe delimiter: PHC strings contain '$' and '/', so substitute with awk
# rather than sed to avoid delimiter and escape hazards.
awk -v h="$user_hash" '{ gsub(/__USER_PASSWORD_HASH__/, h); print }' \
    seed.sql > seed.rendered.sql

echo "==> applying seed to postgres"
"${COMPOSE[@]}" exec -T postgres \
    psql -v ON_ERROR_STOP=1 -U ironauth -d ironauth < seed.rendered.sql

echo "seed: done"
echo "seed:   login user  = alice@conformance.test"
echo "seed:   password     = $CERT_USER_PASSWORD"
echo "seed:   issuer       = https://op/t/cert/e/cert"
