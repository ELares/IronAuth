#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Seed the conformance deployment with the deterministic operator, tenant,
# environment, and login user the OIDF suite needs (seed.sql). This is a seed
# SCRIPT, not a schema migration.
#
# THE PASSWORD HASH IS COMMITTED, NOT COMPUTED AT RUN TIME.
# cert-user-password.phc holds a reviewed Argon2id PHC string for the committed
# cert password, produced by the product's own hasher
# (crates/ironauth-oidc/src/password.rs, at the OWASP parameters). Committing it
# means the default seed path pulls NO image and reaches NO network: there is no
# mutable tag to drift and no package installed at run time. The committed hash
# is not taken on trust either: crates/ironauth-oidc/tests/conformance_seed.rs
# re-verifies it against the committed password with the real verifier on every
# PR, so a wrong or corrupt hash is a red test, not a mystery login failure.
#
# Overriding CERT_USER_PASSWORD makes the committed hash no longer match, so a
# hash must then be computed, which needs the `argon2` CLI. If it is absent we
# FAIL CLOSED rather than seed a user whose password nobody can reproduce.
#
# Usage (from this directory, with the stack up):
#     ./seed.sh
set -euo pipefail
cd "$(dirname "$0")"

# Throwaway cert-only credential. Committed on purpose: the whole cert
# environment is disposable and never reachable outside the conformance run.
DEFAULT_CERT_USER_PASSWORD="conformance-cert-password"
CERT_USER_PASSWORD="${CERT_USER_PASSWORD:-$DEFAULT_CERT_USER_PASSWORD}"
COMPOSE=(docker compose --env-file SUITE_VERSION -f docker-compose.yml)

if [ "$CERT_USER_PASSWORD" = "$DEFAULT_CERT_USER_PASSWORD" ]; then
    echo "==> using the committed Argon2id hash (cert-user-password.phc)"
    user_hash="$(cat cert-user-password.phc)"
else
    echo "==> CERT_USER_PASSWORD is overridden: computing an Argon2id hash"
    if ! command -v argon2 >/dev/null 2>&1; then
        echo "seed: CERT_USER_PASSWORD is overridden but the 'argon2' CLI is not" >&2
        echo "seed: installed, so no hash can be computed. Install argon2, or unset" >&2
        echo "seed: CERT_USER_PASSWORD to use the committed default credential." >&2
        exit 1
    fi
    # The password reaches argon2 on STDIN. It is never interpolated into a
    # command string, so a quote, a backtick, or a '$' in it can neither break
    # the command nor inject into it.
    user_hash="$(printf '%s' "$CERT_USER_PASSWORD" | argon2 "conformanceseed" -id -e)"
fi

# Fail closed on anything that is not an Argon2id PHC string: seeding a garbage
# hash would fail at login time, far from the cause.
case "$user_hash" in
    '$argon2id$'*) ;;
    *) echo "seed: not a valid Argon2id PHC string; refusing to seed" >&2; exit 1 ;;
esac

echo "==> rendering seed.sql"
# Use a safe delimiter: PHC strings contain '$' and '/', so substitute with awk
# rather than sed to avoid delimiter and escape hazards. The hash arrives as an
# awk VARIABLE, never spliced into the program text.
awk -v h="$user_hash" '{ gsub(/__USER_PASSWORD_HASH__/, h); print }' \
    seed.sql > seed.rendered.sql

echo "==> applying seed to postgres"
"${COMPOSE[@]}" exec -T postgres \
    psql -v ON_ERROR_STOP=1 -U ironauth -d ironauth < seed.rendered.sql

echo "seed: done"
echo "seed:   login user  = alice@conformance.test"
echo "seed:   issuer      = https://op/t/cert/e/cert"
