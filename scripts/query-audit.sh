#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Query audit: no SQL against a tenant-scoped table may live outside the scoped
# repository module. Tenant and environment isolation is enforced by the
# repository layer (which applies the (tenant, environment) scope to every
# query) and by Postgres row-level security beneath it. A raw query against a
# scoped table from anywhere else would bypass the repository's scope filter, so
# this lint fails the build if it finds one.
#
# The rule is grep-based (acceptable per issue #6): it flags a scoped-table name
# used as a SQL object (after FROM / INTO / UPDATE / JOIN / TRUNCATE / TABLE) in
# any crate source file other than the repository module. A justified exception
# may carry the marker "query-audit-allow" on the same line with a written
# reason; use it only for a genuinely non-SQL occurrence.
#
# Migrations (*.sql) are exempt: they legitimately create the tables. Test files
# (tests/**) are exempt: the RLS test deliberately issues raw adversarial SQL to
# prove row-level security holds when the app-layer filter is bypassed.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# The tenant-scoped tables (mandatory tenant_id + environment_id + row-level
# security). Keep in sync with crates/ironauth-store/migrations and the design
# doc docs/design/TENANCY.md. CHECKLIST: any migration that adds a new
# tenant-scoped table MUST (a) set up ENABLE + FORCE row-level security, the
# (tenant, environment) isolation policy, and the nonempty-scope CHECK in the
# same migration, and (b) add the table name here. `audit_log` (the
# same-transaction audit log, issue #7) is scoped exactly like `clients`.
SCOPED_TABLES='clients|organizations|audit_log'

# The one module allowed to name a scoped table in SQL.
REPO_MODULE='crates/ironauth-store/src/repository.rs'

# SQL object positions where a table name can appear.
KEYWORDS='FROM|INTO|UPDATE|JOIN|TRUNCATE|TABLE'

hits=$(grep -rniE "(${KEYWORDS})[[:space:]]+\"?(${SCOPED_TABLES})\b" \
  --include='*.rs' crates \
  | grep -v "^${REPO_MODULE}:" \
  | grep -vE '/tests/' \
  | grep -v 'query-audit-allow' \
  || true)

if [ -n "$hits" ]; then
  echo "query-audit: scoped-table SQL found outside ${REPO_MODULE}:"
  echo "$hits"
  echo
  echo "Route all queries against ${SCOPED_TABLES//|/, } through a scoped repository,"
  echo "or add 'query-audit-allow: <reason>' on the line if it is a false positive."
  exit 1
fi

echo "query-audit: clean (no scoped-table SQL outside the repository module)"
