#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# PII-column encryption classification (issue #48).
#
# Per-tenant envelope encryption is only a guarantee if EVERY classified PII
# column and stored secret actually lands on an encrypted column. This lint fails
# the build when a schema column whose NAME matches the PII taxonomy is declared
# in plaintext without an encryption declaration, so a new sensitive column cannot
# ship in the clear by omission.
#
# The rule is grep-based (the same class of structural lint as query-audit.sh):
# a column-definition line (a `CREATE TABLE` column or an `ALTER TABLE ADD COLUMN`)
# whose column name is in the taxonomy below is COMPLIANT only when one of:
#
#   1. it is a `bytea` column (the sealed envelope ciphertext or a blind index,
#      stored via the ironauth-jose AEAD substrate);
#   2. it carries the marker `pii-encryption-allow: <reason>` on the same line
#      with a written justification (a genuine false positive);
#   3. the column is DROPPED by some migration (an expand-contract: the plaintext
#      column existed in an earlier migration and a later one removes it, so it is
#      absent from the final schema and from any database dump).
#
# Anything else is a plaintext PII column in the live schema and fails. The
# drop-aware rule (3) is what lets `users.identifier` / `users.claims` ship
# plaintext in their original 0006/0009 migrations and then be converted to sealed
# columns (dropped and replaced) in 0027, while a NEWLY added plaintext PII column
# that is never dropped and never sealed still fails.
#
# The taxonomy covers direct personal identifiers, the login handle, the JSON
# standard-claim document (an aggregate column that carries PII values), and secret
# material. Deliberately specific names (never bare `name`, which would collide
# with legitimate non-PII columns like display_name), so a new column trips the
# lint only when it is unmistakably sensitive.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

MIGRATIONS="crates/ironauth-store/migrations"

# The PII / stored-secret taxonomy: direct personal identifiers, the login handle,
# the aggregate standard-claim JSON payload, and secret material.
TAXON='email|phone_number|phone|ssn|social_security_number|first_name|last_name|given_name|family_name|full_name|date_of_birth|birthdate|home_address|street_address|postal_code|credit_card|card_number|passport_number|national_id|totp_seed|totp_secret|mfa_secret|api_secret|identifier|claims'

# SQL column types a definition line ends its name with.
TYPES='text|bytea|varchar|character|integer|int|bigint|boolean|timestamptz|jsonb|json|uuid|numeric'

# Pass A: collect every column name a migration DROPs (`DROP COLUMN [IF EXISTS]
# <name>`), across all migrations. A plaintext PII column that is dropped somewhere
# is absent from the final schema, so it is compliant by the expand-contract rule.
# Column names in the taxonomy are table-specific enough that a name-only drop set
# is sound for this schema.
DROPPED=$(grep -rhoiE 'DROP COLUMN[[:space:]]+(IF EXISTS[[:space:]]+)?"?[a-z_][a-z0-9_]*"?' "${MIGRATIONS}"/*.sql \
  | sed -E 's/.*DROP COLUMN[[:space:]]+(IF EXISTS[[:space:]]+)?"?([a-z_][a-z0-9_]*)"?/\2/I' \
  | sort -u || true)

is_dropped() {
  # Exact-line match against the dropped-column set.
  printf '%s\n' "${DROPPED}" | grep -qxF "$1"
}

fail=0

for f in "${MIGRATIONS}"/*.sql; do
  # Match column-definition lines: a leading-indented `<name> <type>` column, or
  # an `ADD COLUMN <name> ...` form. Skip comment-only lines (a PII word in prose).
  hits=$(grep -nEi \
    "(^[[:space:]]*(${TAXON})[[:space:]]+(${TYPES})|ADD COLUMN[[:space:]]+\"?(${TAXON})\"?[[:space:]])" \
    "$f" \
    | grep -vE '^[0-9]+:[[:space:]]*--' \
    || true)
  [ -z "$hits" ] && continue
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    # Compliant if the column is sealed as bytea, or carries the allow marker.
    if printf '%s' "$line" | grep -qiE 'bytea|pii-encryption-allow'; then
      continue
    fi
    # Compliant if the column is dropped by some migration (expand-contract): pull
    # the column name out of the line and check the dropped set.
    col=$(printf '%s' "$line" \
      | sed -E "s/^[0-9]+:[[:space:]]*(ADD COLUMN[[:space:]]+)?\"?(${TAXON})\"?.*/\2/I")
    if [ -n "$col" ] && is_dropped "$col"; then
      continue
    fi
    if [ "$fail" -eq 0 ]; then
      echo "pii-encryption: a PII/secret column is declared in plaintext without envelope encryption:"
    fi
    echo "  ${f}:${line}"
    fail=1
  done <<< "$hits"
done

if [ "$fail" -ne 0 ]; then
  echo
  echo "Store classified PII and secrets as an envelope ciphertext (a bytea column"
  echo "sealed through the ironauth-store envelope repository, issue #48), or drop the"
  echo "plaintext column in a later migration (expand-contract), or add"
  echo "'pii-encryption-allow: <reason>' on the definition line if it is a false positive."
  exit 1
fi

echo "pii-encryption: clean (every classified PII/secret column is encrypted or dropped)"
