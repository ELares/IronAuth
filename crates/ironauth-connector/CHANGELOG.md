# ironauth-connector changelog

All notable changes to the `ironauth-connector` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- New crate: declarative federation connector definitions and the capability
  matrix (issue #75, PR A). A pure, I/O-free crate that parses and strictly
  validates an OIDC-shaped upstream connector as DATA, so adding a provider is a
  definition rather than in-tree code.
  - **No raw fetch by construction.** The crate has NO `ironauth-fetch` and NO
    HTTP-client dependency, so a connector definition (which carries
    attacker-influenced issuer / `jwks_uri` / endpoint URLs) cannot even name a
    raw outbound fetch. Every federation fetch rides the SSRF-hardened
    `ironauth-fetch` path in a later slice; `scripts/http-audit.sh` enforces the
    fetch-free property.
  - **Two-phase strict validation.** Phase one is serde with
    `#[serde(deny_unknown_fields)]` on every nested struct, so an unknown key
    fails the parse; the `endpoints` field is a hand-validated one-of that NAMES
    the two accepted forms (discovery issuer XOR explicit set) in its error,
    mirroring `ironauth_config`'s `SecretVisitor`. Phase two is
    `ConnectorDefinition::validate`, returning `ValidationError`s that carry RFC
    6901 JSON POINTERS to the offending node (the `openid` scope must be present;
    every endpoint URL must be an absolute `https` URL; an issuer must have no
    query or fragment). The URL check is SYNTACTIC only; the SSRF network check is
    the fetch-time concern.
  - **Zero new dependencies.** Reuses `ironauth-config`'s `Secret`, serde with
    `deny_unknown_fields`, and `schemars`; the URL syntactic check is inline (no
    `url` crate) and the validator is hand-written (no `jsonschema` crate).
  - **Capability matrix with conservative defaults.** `CapabilityMatrix` carries
    `refresh` / `groups` / `logout_propagation` (all `false` by default) and
    `email_verified_trust`, which defaults to `Untrusted`: a connector's assertion
    that an email is verified is not believed unless the definition explicitly
    raises the trust.
  - **Quirks and claim mapping as data.** `Quirks` (first-auth-only profile
    delivery, email source, `UserInfo` required) and `ClaimMapping` (the parsed,
    stored declarative shape) are DATA; a new provider idiosyncrasy is a new field
    value, never a new code branch. The claim-mapping EVALUATOR is a later slice.
  - **Published schema.** `connector_definition_schema` and
    `capability_matrix_schema` emit the JSON Schemas
    `scripts/connector-schema.sh` writes to `docs/connector-schema.json` and
    `docs/capability-matrix.schema.json`, CI-freshness-checked like the config
    schema. A cargo-fuzz target drives arbitrary bytes at the deserializer and
    validator (never a panic).
  - **Userinfo rejected in URLs (review INFO 5).** The syntactic URL check now
    rejects a credential-bearing authority (`user:pass@host`) in the issuer and
    every explicit endpoint with an RFC 6901 pointer error; a userinfo authority
    is a host-confusion vector (mirrors the redirect userinfo-reject). The
    network SSRF block remains the fetch-time concern.
  - **`enabled` toggle on the definition (review LOW 4).** A new
    `enabled: bool` field (default `true`) lets the management API disable a
    connector without deleting it; the store already carried the column.
  - **`secret_free_json` propagates its error (review LOW 3).** The secret-free
    projection returns `Result<Value, serde_json::Error>` instead of swallowing a
    serialize failure to `null`, so a corrupt projection can never be persisted
    silently.
