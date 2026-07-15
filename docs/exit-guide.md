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

Example line (formatting added for readability; a real line is one physical line):

```json
{
  "identifier": "bob@example.com",
  "external_id": "crm-77",
  "claims": { "email": "bob@example.com" },
  "traits": { "department": "engineering" },
  "traits_schema_version": 3,
  "password_hash": "$2b$06$Q9s...<bcrypt digest>"
}
```

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
- MFA enrollments (TOTP secrets, recovery-code state) are NOT in the current export
  because the MFA data model does not exist yet in this release. When it lands, it
  joins the export; a field-coverage test fails the build if any user field is added
  without being covered by the export, so nothing can silently escape.

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
```

When disabled, the endpoint is a uniform not-found. When enabled without a token, it
authorizes nobody (fail closed). A request missing a bearer is unauthorized exactly
as the rest of the management API is.

## The round-trip guarantee

The acceptance bar for the covenant is a round-trip, exercised in CI: a full export
of a populated instance imports into a FRESH instance, and every exported user logs
in with their original password, including a user still on an imported foreign hash.
Because the export serializes the same record format the import consumes and both
sides share one algorithm-tagged hash layer, the round-trip is lossless by
construction. You can always leave.
