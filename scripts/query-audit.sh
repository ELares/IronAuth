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

# The tables whose SQL must live only in the repository module. Keep in sync
# with crates/ironauth-store/migrations and the design doc docs/design/TENANCY.md.
#
# Most are TENANT-SCOPED (mandatory tenant_id + environment_id + forced row-level
# security): clients, organizations, audit_log (#7), and management_credentials
# (#11). CHECKLIST for a new tenant-scoped table: the migration MUST (a) ENABLE +
# FORCE row-level security, add the (tenant, environment) isolation policy, and
# add the nonempty-scope CHECK in the same migration, and (b) add the name here.
#
# idempotency_keys (#11) is the one exception: it is CREDENTIAL-scoped, not
# tenant-row-level-security scoped, because an operator-plane POST is looked up
# for a replay before any tenant exists (see 0003_management_api.sql). It is
# still confined to the repository module and reachable only by ironauth_control,
# so it is listed here to keep its SQL out of every other file.
#
# grants, authorization_codes, and issued_tokens (#12) are the OIDC
# authorization-code grant tables: all three are TENANT-SCOPED with forced
# row-level security, so their SQL stays in the repository module too.
#
# users, sessions, and consents (#20) are the bootstrap login/consent/session
# tables: all three are TENANT-SCOPED with forced row-level security, so their SQL
# stays in the repository module too.
#
# signing_keys (#19) is the per-environment signing-key table: TENANT-SCOPED with
# forced row-level security, so its SQL stays in the repository module too.
#
# resource_servers and opaque_access_tokens (#29) are the access-token-format
# tables: the audience-to-format registry and the digest-only opaque-token store.
# Both are TENANT-SCOPED with forced row-level security, so their SQL stays in the
# repository module too.
#
# client_assertion_jtis and client_auth_diagnostics (#25) are the JWT-assertion
# client-authentication tables: the cross-node single-use jti replay cache and the
# out-of-band client-authentication diagnostics sink. Both are TENANT-SCOPED with
# forced row-level security, so their SQL stays in the repository module too.
#
# pushed_authorization_requests (#27) is the PAR store (RFC 9126): the single-use
# request_uri table the authorization endpoint consumes. TENANT-SCOPED with forced
# row-level security, so its SQL stays in the repository module too.
#
# refresh_families and refresh_tokens (#21) are the refresh-token rotation tables:
# the revocation spine and the digest-only generation store. Both are TENANT-SCOPED
# with forced row-level security, so their SQL stays in the repository module too.
SCOPED_TABLES='clients|organizations|audit_log|management_credentials|idempotency_keys|grants|authorization_codes|issued_tokens|signing_keys|users|sessions|consents|resource_servers|opaque_access_tokens|client_assertion_jtis|client_auth_diagnostics|pushed_authorization_requests|refresh_families|refresh_tokens'

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
