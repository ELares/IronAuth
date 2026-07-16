# ironauth-importers changelog

All notable changes to the `ironauth-importers` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- New crate: first-party migration importers for Keycloak, Auth0, Firebase, and a
  generic SCIM/LDAP escape hatch (issue #57). Migration is a product, not a doc
  page: each importer is a FRONT-END over the #55 streaming bulk-import engine. It
  parses a documented vendor export format and emits the engine's line-delimited
  record format (`ironauth_import::ImportRecord`), so every source inherits the
  streaming job's resumability, progress, denial-of-service bounds, and per-record
  error reporting. The importers never reimplement the job, never touch the store,
  and never verify or rehash a password.
  - **Keycloak realm export.** Maps `username`, `id`, email/name claims, the enabled
    flag, and custom attributes (to traits), and re-encodes the PBKDF2-SHA256/512
    credential into the canonical PHC string the scheme layer verifies (a length
    parameter is always emitted, so the re-encoding is correct regardless of the
    source derived-key size). Realm/client roles, groups, required actions,
    federated identities, non-password factors, and a legacy HMAC-SHA1 PBKDF2
    credential are reported per record.
  - **Auth0 bulk export.** Parses the profile export (JSON array or NDJSON) joined
    by email to the separately obtained password-hash export (bcrypt); maps
    identities, `app_metadata` / `user_metadata` (to traits), and the blocked flag.
    Social identities, missing hash rows, and enrolled MFA are reported per record.
  - **Firebase auth:export.** Re-encodes each user's modified-scrypt hash with the
    project-level parameters (signer key, salt separator, rounds, memory cost)
    supplied through `FirebaseHashParams` (built directly or parsed from a
    `hash_config`), so verification works against the fixture project parameters.
    Maps providers and phone identifiers; social providers and phone-only users are
    reported per record.
  - **Generic SCIM/LDAP escape hatch.** Consumes SCIM 2.0 core user resources (RFC
    7643; a single resource, an array, or a `ListResponse`) offline (NOT a SCIM
    protocol server), and an LDAP directory JSON projection whose `userPassword`
    LDAP scheme is re-encoded: `{PBKDF2-SHA256}` / `{PBKDF2-SHA512}` become
    verifiable PHC strings, `{CRYPT}` / `{ARGON2}` and bare modular-crypt hashes are
    unwrapped, and the weak `{SSHA}` / `{SHA}` / HMAC-SHA1 `{PBKDF2}` schemes are
    reported so the user is forced to reset.
  - **Gap reporting and the validation-only pass.** Every importer returns a
    `Mapping`: a per-user list of outcomes where nothing is silently dropped. A
    construct with no representable IronAuth target is recorded as a `Gap` naming
    WHAT was skipped and WHY. `Mapping::gap_report()` is the validation-only pass (it
    creates no user); `Mapping::record_lines()` feeds the #55 engine on commit.
    Gap-report snapshot tests keep the mapping honest over time.
  - **Verification.** Fixture-based integration tests per source (committed
    sanitized real-shape exports), an end-to-end login-and-rehash test per source
    proving credential intactness and the rehash to Argon2id, the Firebase
    modified-scrypt verification against fixture project parameters, per-record gap
    reporting with field-level detail, and a cargo-fuzz target per export parser.
  - **Scope.** One-shot correctness over a static export. Scheduled or continuous
    sync is a documented later extension, not part of this crate.
