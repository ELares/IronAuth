<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# The IronAuth exit guide

One of IronAuth's three named covenants is **no unexportable data**: you can
always leave. Everything IronAuth holds about your users, including their
password hashes with the algorithm tags and full parameters needed to keep
verifying them, exports self-serve through the management API in documented
formats. There is no support ticket, no operator intervention, and no private
knowledge required: the round-trip in this guide uses only what is written here.

This is a deliberate contrast with the incumbents. Cognito cannot export password
hashes at all, which forces a password reset on the entire user base of anyone who
leaves. Auth0 gates hash export behind a support ticket. Firebase is the honorable
exception. IronAuth makes the covenant mechanically true, in both directions: the
same lazy-migration mechanism that lets a tenant migrate ONTO IronAuth without
re-prompting a password also points outward, so a successor system can migrate a
user base AWAY from IronAuth exactly as easily.

This guide covers the export API, the record format, the per-scheme hash formats,
and the outbound verification contract. It pairs with the streaming bulk import
(the inbound direction); the export produces exactly what the import consumes.

## The export API

```
GET /v1/tenants/{tenant_id}/environments/{environment_id}/export
Authorization: Bearer <management token>
```

The response is `application/x-ndjson`: newline-delimited JSON, **one user per
line**, one JSON object per user. It is the exact format the streaming bulk import
consumes, so an export re-imports into a fresh IronAuth instance losslessly, with
every user's login intact, INCLUDING users still on an imported foreign hash that
they have not yet re-verified.

Properties of the endpoint:

- **Self-serve and permission-gated.** The export is a single authorized management
  call. The operator plane, or the environment's OWN management key, may export it;
  a management key scoped to a different environment is refused. No operator
  intervention beyond the API call is required.
- **Audited.** Every export writes one `user.export` audit row attributed to the
  acting principal. Password hashes are sensitive material, so the export is
  observable, not obstructed: the audit row records who exported and how many
  identities, never any exported value.
- **Streaming.** The export drains the environment one bounded page at a time, so an
  export of 100k+ users streams without loading the whole set into memory.

### What a record contains

Each line is a JSON object with these fields. Every field except `identifier` is
optional and omitted when empty.

| Field | Meaning |
| --- | --- |
| `identifier` | The login handle (required). |
| `external_id` | The correlation id from your own systems, if linked. |
| `state` | The lifecycle state (`blocked`, `disabled`, `pending_verification`). Omitted for an ordinary active account. |
| `claims` | The OIDC standard-claim document (a JSON object), if any. |
| `traits` | The identity-traits document (a JSON object), if any. |
| `traits_schema_version` | The trait-schema version the traits last validated against, preserved verbatim. |
| `password_hash` | The password verifier as an algorithm-tagged string (see below), if the account has a credential. |
| `credentials` | The account's enrolled MFA / login credential registry (see below), if any: each passkey, TOTP, or recovery-code enrollment. |
| `totp` | The account's enrolled TOTP authenticators (issue #69), if any, each with its OPENED seed (see below), so the second factor round-trips. |
| `recovery_codes` | The account's one-time recovery codes (issue #69), if any, each as its one-way hash plus its consumed state. |

Example line (formatting added for readability; a real line is one physical line):

```json
{
  "identifier": "bob@example.com",
  "external_id": "crm-77",
  "claims": { "email": "bob@example.com" },
  "traits": { "department": "engineering" },
  "traits_schema_version": 3,
  "password_hash": "$2b$06$Q9s...<bcrypt digest>",
  "credentials": [
    { "credential_type": "passkey", "friendly_name": "my laptop" },
    { "credential_type": "totp", "friendly_name": "authenticator app", "last_used_at": 1710000000000000 }
  ],
  "totp": [
    {
      "friendly_name": "authenticator app",
      "seed_base32": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      "algorithm": "SHA1", "digits": 6, "period_secs": 30,
      "status": "active", "last_consumed_step": 56789012
    }
  ],
  "recovery_codes": [
    { "code_hash": "$argon2id$v=19$...<digest>", "consumed": false }
  ]
}
```

### The credential registry

The `credentials` array carries the account's enrolled MFA / login credentials from
the credential registry, one object per enrollment, so the export carries the
registry and not merely the primary password. Each object holds the non-secret
metadata that the credential registry stores today:

| Field | Meaning |
| --- | --- |
| `credential_type` | The factor kind: `passkey`, `totp`, or `recovery_code`. |
| `friendly_name` | The user-authored label ("my laptop"). Sealed at rest; opened for export and re-sealed at the destination. |
| `last_used_at` | When the factor was last used to authenticate, in microseconds since the Unix epoch, if ever. |

On import each enrollment is re-created under the destination user with a fresh
credential id, its friendly name re-sealed under the destination environment's key,
and `usable_for_login` re-derived from the factor kind.

### The TOTP second factor and recovery codes (issue #69)

A TOTP seed is a long-lived shared secret, exactly the class the exit covenant says
to export (like a password hash): it is sealed at rest under the tenant DEK and
OPENED only for the gated, audited export. Each object in the `totp` array carries
the opened `seed_base32` plus the RFC 6238 parameters (`algorithm`, `digits`,
`period_secs`), the enrollment `status`, and the single-use `last_consumed_step`, so
a destination instance re-seals the seed and the authenticator keeps working. Each
`recovery_codes` object carries the one-way Argon2id `code_hash` (never a plaintext
code, exactly like a password verifier) and whether it was already `consumed`. A
registered WebAuthn passkey is deliberately NOT portable (see below); a TOTP seed is,
so it round-trips. The field-coverage test enumerates every column of
`totp_credentials` and `recovery_codes`, so no second-factor column can silently
escape export coverage.

### What is NOT in a record, and why

The export omits fields that are re-created at the destination rather than carried:

- The internal `usr_` identifier is NOT exported. It embeds the SOURCE
  environment's scope, so it cannot be reused in a fresh instance (a different
  tenant and environment). The portable identity keys are the login handle and the
  external id; the destination mints a fresh internal id and keys de-duplication on
  the login handle (unique per environment), so a re-import stays idempotent.
- Timestamps, blind-index lookup columns, and the encryption key versions that seal
  PII at rest are re-derived and re-sealed against the destination instance.
- Soft-deleted (offboarded) users are excluded: a tombstone is not exported.
- The account's enrolled MFA / login credential REGISTRY (passkey, TOTP, and
  recovery-code enrollments) IS exported today, in the `credentials` array above: the
  factor kind, the friendly name, and the last-used instant round-trip. The TOTP
  SEED and the recovery-code hashes ARE exported too (issue #69), in the `totp` and
  `recovery_codes` arrays above: a TOTP seed is a portable shared secret the covenant
  carries, sealed at rest and opened for the audited export. The field-coverage test
  fails the build the moment a credential-registry (or user, or `totp_credentials`,
  or `recovery_codes`) column is added without export coverage, so nothing can
  silently escape. The test enumerates the FULL identity model, not one table.
- A registered WebAuthn passkey (the `webauthn_credentials` table, issue #65) is NOT
  in a record. Unlike a password hash, a passkey is DEVICE-BOUND and not portable
  across IdP instances: the private key never leaves the authenticator, and the
  stored COSE public key is scoped to this deployment's Relying Party ID, so an
  authenticator refuses to sign for a different RP ID. Re-homing the public key to
  another provider would produce a credential that can never authenticate. A user
  therefore re-enrolls their passkeys on the destination instance (a fresh ceremony
  binds a new credential to the new RP ID). The whole passkey credential material is
  classified as OPERATIONAL device state in the field-coverage test, with only the
  scope/structural columns marked DERIVED, so the guard still fails the build if the
  table grows an unclassified column. The portable identity (the user and its
  password hash) round-trips as before; the non-portable device keys are documented
  here as the honest exception.
- The federation org binding (the `users.org_connection_id` stamp, issue #77) is NOT
  carried in a record. It is instance-local routing state: it references an org
  connection whose id embeds the source scope, and the enterprise routing config (the
  org connections and routing rules) is exported and imported separately as promotable
  configuration, where the ids are re-minted for the target scope. The binding
  self-heals on the destination: a returning federated login re-routes through the
  imported config and re-stamps the user. It is classified as OPERATIONAL in the
  field-coverage test, so the guard still fails the build if the users table grows an
  unclassified column. The portable identity round-trips as before.

## Password hash formats

A password hash is a **one-way verifier**, not a personal identifier and not a
recoverable secret: there is no code path anywhere in IronAuth that recovers a
plaintext password from it. Exporting it is the whole point of the covenant, and it
is why the export is permission-gated and audited.

Every exported `password_hash` is a self-describing, algorithm-tagged string. A
successor system detects the scheme from the leading marker and verifies against it
directly. The native IronAuth verifier is Argon2id; a user imported from another
provider who has not yet logged in carries that provider's foreign hash verbatim.

| Scheme | Marker | Reference |
| --- | --- | --- |
| Argon2 (i / d / id) | `$argon2id$`, `$argon2i$`, `$argon2d$` | RFC 9106, PHC string format |
| scrypt | `$scrypt$` | RFC 7914, PHC string format |
| PBKDF2 (HMAC-SHA256 / SHA512) | `$pbkdf2-sha256$`, `$pbkdf2-sha512$` | RFC 8018 (PKCS#5 v2.1) |
| bcrypt | `$2a$`, `$2b$`, `$2x$`, `$2y$` | the classic bcrypt format |
| Firebase modified scrypt | `$fbscrypt$` | a self-contained serialization (see below) |

### The PHC string format (informative)

Argon2, scrypt, and PBKDF2 hashes are in the [PHC string
format](https://github.com/P-H-C/phc-string-format): `$<id>$<params>$<salt>$<hash>`,
where `<params>` carries the cost parameters as comma-separated `key=value` pairs
and `<salt>` / `<hash>` are base64 (no padding). The parameters that govern
verification travel inside the string, so a verifier needs nothing beyond the string
itself:

- **Argon2** (RFC 9106): `m` (memory in KiB), `t` (passes / iterations), `p`
  (parallelism), plus the version `v`. Example:
  `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`.
- **scrypt** (RFC 7914): `ln` (log2 of the CPU/memory cost N), `r` (block size), `p`
  (parallelism). Example: `$scrypt$ln=16,r=8,p=1$<salt>$<hash>`.
- **PBKDF2** (RFC 8018): `i` (iteration count), over HMAC-SHA256 or HMAC-SHA512 as
  the marker names. Example: `$pbkdf2-sha256$i=600000$<salt>$<hash>`.

### bcrypt

bcrypt is not PHC; its own format `$2b$<cost>$<22-char-salt><31-char-digest>`
carries the cost (a work factor of `2^cost`) inline. All four version prefixes
(`$2a$`, `$2b$`, `$2x$`, `$2y$`) share one verify path.

### Firebase modified scrypt

Firebase's modified scrypt is not self-describing in the wild (its account-wide
signer key, salt separator, and cost live outside the per-user hash), so IronAuth
serializes it into a canonical, self-contained string that round-trips:

```
$fbscrypt$n=<mem_cost>,r=<rounds>,p=1$<salt_sep_b64>$<signer_key_b64>$<salt_b64>$<hash_b64>
```

Verification derives a 64-byte key with scrypt over `salt || salt_separator`, then
AES-256-CTR encrypts the signer key under the first 32 bytes and compares against the
stored hash in constant time.

## The outbound verification contract

The mirror image of IronAuth's inbound lazy-migration hook. When a successor system
is migrating a user base away from IronAuth, it verifies each user's password
against IronAuth on that user's next login, then rehashes the credential into its
own store, so the whole base migrates with no forced password reset.

```
POST /v1/tenants/{tenant_id}/environments/{environment_id}/migration/verify-credential
Authorization: Bearer <outbound verification token>
Content-Type: application/json

{ "identifier": "bob@example.com", "password": "<candidate>" }
```

Response:

```json
{
  "verified": true,
  "subject": "usr_...",
  "profile": {
    "claims": { "email": "bob@example.com" },
    "traits": { "department": "engineering" }
  }
}
```

On success the response carries the stable subject and the user's profile (claims
and traits) so the successor seeds its own record. A wrong password, an unknown
account, and a fenced account (blocked, disabled, pending verification) all return
`{ "verified": false }` with no distinguishing oracle and no profile. Verification
covers both the native Argon2id verifier and any foreign hash, through the same
dispatch as login; it never mutates IronAuth state.

### Enablement (disabled by default)

Exposing a live credential oracle to a third party is an explicit, per-deployment
opt-in, so this endpoint is **disabled by default**. It is enabled through
environment-scoped configuration in `ironauth-config`:

```toml
[admin]
outbound_verification_enabled = true
# The shared bearer token a successor system presents. A distinct credential from
# the operator token and every management key; it authorizes ONLY this endpoint.
outbound_verification_token = { env = "IRONAUTH_OUTBOUND_VERIFICATION_TOKEN" }
# The ONE (tenant, environment) this endpoint is authorized for. The shared token
# can only ever verify credentials in this one environment; a request to any other
# tenant or environment is a uniform not-found, so the token never crosses tenants.
outbound_verification_tenant = "ten_..."
outbound_verification_environment = "env_..."
```

When disabled, the endpoint is a uniform not-found. When enabled without a token, it
authorizes nobody (fail closed). When enabled without a configured
`(tenant, environment)` scope, it matches no request (fail closed). A request whose
path scope does not match the configured scope is a uniform not-found REGARDLESS of
the token, so the endpoint is invisible and inert outside its one authorized
environment. A request missing a bearer against a DISABLED endpoint is itself a
uniform not-found (the enablement gate is evaluated before the bearer check), so a
disabled endpoint is indistinguishable from an absent route.

## The round-trip guarantee

The acceptance bar for the covenant is a round-trip, exercised in CI: a full export
of a populated instance imports into a FRESH instance, and every exported user logs
in with their original password, including a user still on an imported foreign hash.
Because the export serializes the same record format the import consumes and both
sides share one algorithm-tagged hash layer, the round-trip is lossless by
construction. You can always leave.
