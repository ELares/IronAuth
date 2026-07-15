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

# The scan tracks TABLE context so the expand-contract drop-exemption is keyed on
# the exact (table, column), not the column name alone. A name-only drop set would
# permanently exempt a name once ANY table dropped it: because 0027 drops
# users.identifier and users.claims, a brand-new plaintext `identifier` or `claims`
# column in a DIFFERENT future table would otherwise pass as clean. Keying on
# (table, column) closes that: a column is exempt only when the SAME table drops it.
#
# Migrations declare a table header on its own line (`CREATE TABLE t (` or
# `ALTER TABLE t`) followed by indented column lines (`<name> <type>` inside a
# CREATE, or `ADD COLUMN <name> ...` / `DROP COLUMN <name>` inside an ALTER), so the
# current table is the last header seen. A declared PII column is COMPLIANT when it
# is bytea, carries `pii-encryption-allow: <reason>`, or its (table, column) is
# dropped by some migration. Files are passed in lexical (== migration) order.
if awk -v taxon="${TAXON}" -v types="${TYPES}" '
  function strip_name(s) { gsub(/"/, "", s); sub(/[^a-z0-9_].*$/, "", s); return s }
  { low = tolower($0) }
  # A comment line never sets context or declares a column (a PII word in prose).
  low ~ /^[[:space:]]*--/ { next }
  # Table context: the last CREATE TABLE / ALTER TABLE header seen.
  low ~ /(create|alter)[[:space:]]+table[[:space:]]/ {
    t = low
    sub(/.*[[:space:]]table[[:space:]]+/, "", t)
    sub(/^if[[:space:]]+not[[:space:]]+exists[[:space:]]+/, "", t)
    sub(/^if[[:space:]]+exists[[:space:]]+/, "", t)
    t = strip_name(t)
    if (t != "") curtable = t
  }
  # DROP COLUMN <name>: record (table, column) as dropped (expand-contract contract).
  low ~ /drop[[:space:]]+column[[:space:]]/ {
    d = low
    sub(/.*drop[[:space:]]+column[[:space:]]+/, "", d)
    sub(/^if[[:space:]]+exists[[:space:]]+/, "", d)
    d = strip_name(d)
    if (d != "" && curtable != "") dropped[curtable SUBSEP d] = 1
  }
  # A column declaration: an ADD COLUMN <name>, or an indented `<name> <type>` inside
  # a CREATE TABLE. Extract the name and, for the indented form, require a type token
  # so a bare keyword line is not misread as a column.
  {
    col = ""
    if (low ~ /add[[:space:]]+column[[:space:]]/) {
      c = low; sub(/.*add[[:space:]]+column[[:space:]]+/, "", c); col = strip_name(c)
    } else if ($0 ~ /^[[:space:]]+[A-Za-z"]/) {
      c = low; sub(/^[[:space:]]+/, "", c)
      name = strip_name(c)
      rest = c; sub(/^[^[:space:]]+[[:space:]]+/, "", rest); sub(/[[:space:]].*$/, "", rest)
      if (rest ~ ("^(" types ")$")) col = name
    }
    if (col != "" && col ~ ("^(" taxon ")$")) {
      # Exempt on the line: sealed bytea or an explicit allow marker.
      if (low ~ /bytea/ || low ~ /pii-encryption-allow/) next
      key = curtable SUBSEP col
      if (!(key in declared)) declared[key] = FILENAME ":" FNR ": " $0
    }
  }
  END {
    fail = 0
    for (k in declared) {
      if (!(k in dropped)) {
        if (!fail) print "pii-encryption: a PII/secret column is declared in plaintext without envelope encryption:"
        print "  " declared[k]
        fail = 1
      }
    }
    exit fail
  }
' "${MIGRATIONS}"/*.sql; then
  echo "pii-encryption: clean (every classified PII/secret column is encrypted or dropped)"
else
  echo
  echo "Store classified PII and secrets as an envelope ciphertext (a bytea column"
  echo "sealed through the ironauth-store envelope repository, issue #48), or drop the"
  echo "plaintext column in the SAME table in a later migration (expand-contract), or"
  echo "add 'pii-encryption-allow: <reason>' on the definition line if it is a false"
  echo "positive."
  exit 1
fi
