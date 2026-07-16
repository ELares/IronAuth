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
#
# service_accounts (#23) is the client-credentials service-account principal table:
# the (client -> stable machine-`sub`) mapping. TENANT-SCOPED with forced row-level
# security, so its SQL stays in the repository module too.
#
# dcr_policies, dcr_initial_access_tokens, and dcr_rate_counters (#31) are the
# Dynamic Client Registration abuse-control tables: the reusable named policy
# objects, the SHA-256-hashed initial-access-token store, and the endpoint-local
# rate counters. All three are TENANT-SCOPED with forced row-level security, so
# their SQL stays in the repository module too.
#
# external_assertion_issuers, external_assertion_subject_mappings, and
# external_assertion_jtis (#26) are the JWT bearer assertion grant tables: the
# registered external trust anchors, the explicit subject-mapping rules, and the
# external-issuer single-use jti replay cache (distinct from client_assertion_jtis
# so an external jti cannot collide with a client-assertion jti). All three are
# TENANT-SCOPED with forced row-level security, so their SQL stays in the
# repository module too.
#
# device_codes (#24) is the RFC 8628 device-authorization grant table: the digest-
# only device-code and hashed user-code store a constrained device polls and a
# human approves. TENANT-SCOPED with forced row-level security, so its SQL stays in
# the repository module too. Its per-source verification rate limiting reuses the
# generic dcr_rate_counters fixed-window counter (a device_verify: key namespace).
#
# client_sessions (#32) is the per-client tier of the two-tier session model: the
# per-(client, session) sid store, keyed to one SSO session. TENANT-SCOPED with
# forced row-level security, so its SQL stays in the repository module too. The SSO
# tier reuses the expanded sessions table above.
#
# session_ended_events (#35) is the durable session-ended fan-out outbox: one row
# enqueued in the SAME transaction as every terminal session end, drained by the
# back-channel logout worker. TENANT-SCOPED with forced row-level security, so its SQL
# stays in the repository module too.
#
# tenant_keks, tenant_deks, and encrypted_secrets (#48) are the per-tenant envelope
# encryption tables: the wrapped key-encryption keys, the wrapped data-encryption
# keys, and the transparent encrypted-secret store. All three are TENANT-SCOPED with
# forced row-level security, so their SQL stays in the repository module too. They
# store only wrapped keys and ciphertext, never a plaintext key or payload; the AEAD
# primitive lives in ironauth-jose (the one crate allowed a direct ring dependency).
#
# environment_states (#46) records each (tenant, environment)'s data-plane serving
# status ('active' or 'suspended') so the data plane can fence a suspended scope
# without reading the control-plane level tables. TENANT-SCOPED with forced
# row-level security, so its SQL stays in the repository module too.
#
# tenant_byok_bindings (#49) records the per-(tenant, environment) bring-your-own-key
# binding: which KMS driver holds the customer root, an opaque external key REFERENCE
# (never key material), and the binding's lifecycle status. TENANT-SCOPED with forced
# row-level security, so its SQL stays in the repository module too; the terminal
# offboarding stage severs it in the same audited transaction that crypto-shreds the
# platform KEK.
#
# custom_domains and acme_challenges (#47) are the per-environment custom-domain
# registry and the ACME challenge lifecycle rows. Both are TENANT-SCOPED with forced
# row-level security, so their SQL stays in the repository module too. A cert private
# key is never stored on these tables (it lives sealed in encrypted_secrets, #48);
# cross-tenant verified-domain exclusivity is a global partial unique index the
# storage engine enforces across every row irrespective of row-level security.
#
# environment_guardrails (#42) is the scope-forced guardrail PROJECTION VIEW the
# data plane reads to enforce the redirect guardrail (an http loopback is rejected
# in a prod environment). It is not a base table (it is a definer view over the
# environments level table whose WHERE clause pins the bound scope), but its SQL is
# kept in the repository module for the same reason: no other file may name it, so
# the scoped read stays in one place.
#
# environment_variables and environment_secrets (#45) are the per-environment
# config store: non-secret promotable variables (name -> value) and write-only
# secrets (name -> value sealed under the scope's envelope DEK, ciphertext only, no
# plaintext column). Both are TENANT-SCOPED with forced row-level security, so their
# SQL stays in the repository module too.
#
# account_credentials (#61) is the self-service credential registry: one row per
# enrolled credential (passkey, TOTP, recovery-code set) bound to its subject, with
# the user-authored friendly name sealed under the scope's envelope DEK (ciphertext
# only, no plaintext PII column). TENANT-SCOPED with forced row-level security, and
# every read/write additionally subject-bound, so its SQL stays in the repository
# module too.
#
# webauthn_credentials / webauthn_challenges (#65) are the passkey factor tables:
# one row per registered passkey (its COSE public key, sign counter, AAGUID,
# transports, BE/BS flags, and sealed nickname) and the short-lived single-use
# ceremony challenge store. Both TENANT-SCOPED with forced row-level security, and
# the credential reads/writes additionally subject-bound, so their SQL stays in the
# repository module too.
#
# abuse_bans (#64) is the durable credential-abuse ban registry: one row per active
# ban over a regulated dimension (IP / account / canonical identifier, sealed and
# blind-indexed, no plaintext subject) and one authentication path. TENANT-SCOPED
# with forced row-level security, so its SQL stays in the repository module too. Its
# high-frequency LAYERED failure counters reuse the generic dcr_rate_counters
# fixed-window counter (an abuse: key namespace), exactly like device_verify.
#
# totp_credentials / recovery_codes (#69) are the TOTP second-factor tables: one row
# per enrolled authenticator (its RFC 6238 SEED sealed under the scope DEK, the
# parameters, the enrollment status, the single-use last-consumed time-step, and the
# resync offset) and the per-user one-time recovery codes (each stored as an Argon2id
# hash, single-use). Both TENANT-SCOPED with forced row-level security, and every
# read/write additionally subject-bound, so their SQL stays in the repository module too.
#
# scope_step_up_policies (#72) is the per-scope step-up policy table: one row per
# OAuth scope token that carries an elevated authentication requirement (an acr floor
# and a max auth age). TENANT-SCOPED with forced row-level security, so its SQL stays
# in the repository module too.
#
# email_otp_codes / magic_link_tokens (#68) are the email-OTP and scanner-safe
# magic-link factor tables: one active numeric code per (user, purpose) stored as an
# Argon2id hash, and one active single-use magic link per (user, purpose) stored as a
# SHA-256 token digest plus an Argon2id short-code hash and a same-device binding digest.
# Both TENANT-SCOPED with forced row-level security and subject-bound, and both seal the
# recipient email under the scope DEK, so their SQL stays in the repository module too.
#
# sms_otp_codes / sms_config / sms_country_allowlist / sms_route_stats (#70) are the
# guarded SMS-OTP factor tables: one active numeric code per (user, purpose) stored as an
# Argon2id hash with a sealed + blind-indexed recipient PHONE, the per-tenant enablement +
# factor-downgrade opt-in, the per-tenant country ALLOWLIST, and the per-route
# send-to-verify conversion counters + auto-throttle state. All TENANT-SCOPED with forced
# row-level security, so their SQL stays in the repository module too.
#
# credential_class_policies / attestation_config (#66) are the credential-policy tables:
# the per-scope minimum-credential-class ladder (one row per policy subject: the tenant,
# a group, or an org) the authentication path composes with strictest-wins, and the
# per-scope attestation conveyance mode the passkey registration path requests. Both
# TENANT-SCOPED with forced row-level security, so their SQL stays in the repository
# module too. Neither stores PII (a class token, a subject discriminator, a mode).
#
# mds3_blob_cache / aaguid_rules (#66, PR B) are the passkey-attestation evaluation
# tables: the per-scope SINGLETON verified FIDO MDS3 metadata BLOB cache (the extracted,
# trusted authenticator entries the 'direct' attestation path evaluates against) and the
# per-scope AAGUID allow / deny list (one disposition per pinned authenticator model).
# Both TENANT-SCOPED with forced row-level security, so their SQL stays in the repository
# module too. Neither stores PII (public authenticator metadata and a 16-byte AAGUID).
#
# admin_sudo_elevations (#73) is the admin session-privilege (sudo) ledger: one
# append-only row per recorded re-authentication elevation (the acting principal, the
# achieved acr, the elevation instant, and the window expiry) the admin mutation guard
# reads the latest of to evaluate freshness. TENANT-SCOPED with forced row-level
# security, so its SQL stays in the repository module too. It stores no PII (a service
# actor id, a public acr string, two timestamps).
SCOPED_TABLES='clients|organizations|audit_log|management_credentials|idempotency_keys|grants|authorization_codes|issued_tokens|signing_keys|users|sessions|consents|resource_servers|opaque_access_tokens|client_assertion_jtis|client_auth_diagnostics|pushed_authorization_requests|refresh_families|refresh_tokens|service_accounts|dcr_policies|dcr_initial_access_tokens|dcr_rate_counters|external_assertion_issuers|external_assertion_subject_mappings|external_assertion_jtis|device_codes|client_sessions|session_ended_events|backchannel_logout_deliveries|tenant_keks|tenant_deks|encrypted_secrets|environment_states|tenant_byok_bindings|environment_guardrails|custom_domains|acme_challenges|environment_variables|environment_secrets|account_credentials|trait_schemas|trait_migration_jobs|user_invitations|user_identifiers|migration_runs|migration_run_records|webauthn_credentials|webauthn_challenges|abuse_bans|totp_credentials|recovery_codes|scope_step_up_policies|email_otp_codes|magic_link_tokens|credential_class_policies|attestation_config|sms_otp_codes|sms_config|sms_country_allowlist|sms_route_stats|mds3_blob_cache|aaguid_rules|admin_sudo_elevations'

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
