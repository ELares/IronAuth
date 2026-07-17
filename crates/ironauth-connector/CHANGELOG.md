# ironauth-connector changelog

All notable changes to the `ironauth-connector` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- Connector-definition validation hardening (issue #75, PR C follow-up): three write-time
  guards so an operator gets an actionable config error instead of a silent per-login trap.
  - **A custom `subject` rule is rejected.** A federated identity is ALWAYS keyed on the
    verified, issuer-namespaced upstream `sub`, never the mapped subject, so a custom subject
    rule can only FAIL a login (a missing or wrong-typed mapped claim) for zero benefit.
    `ConnectorDefinition::validate` now rejects anything other than the canonical default
    (`sub`, required) at `/claim_mapping/subject`; an absent or explicit-default `subject` is
    accepted and the evaluator still keys on the verified `sub`.
  - **A UserInfo-requiring connector is rejected until issue #74 lands.** The federation
    callback passes `userinfo: None` (the UserInfo fetch is deferred to #74), so a connector
    that sources a claim from UserInfo would fail EVERY login (and be misclassified as an
    upstream fault). `validate` now rejects `quirks.userinfo_required = true` (at
    `/quirks/userinfo_required`) and `quirks.email_source = "userinfo"` (at
    `/quirks/email_source`); `fallback_order` (ID token first) and `id_token` are accepted.
  - **The mapped `email` trait is NFKC-normalized in the evaluator, regardless of claim
    path.** `claim_mapping::evaluate` now NFKC-normalizes a resolved `email` string BEFORE the
    trait-schema type check, so an email mapped from a nested path (for example `emails.0`) is
    canonicalized the same as a top-level `email` and the type-checked and provisioned values
    are byte-identical. Adds a pure, table-only `unicode-normalization` dependency (already in
    the workspace tree via ironauth-screening); the crate stays fetch-free and store-free.
- Declarative claim-mapping EVALUATOR (issue #75, PR C), still pure and I/O-free (the crate
  stays fetch-free and now also store-free): the new `claim_mapping` module turns the stored
  `ClaimMapping` SHAPE into a transform.
  - **`claim_mapping::evaluate`.** Resolves the subject and each trait field's ordered
    claim-path fallback (a dotted path like `address.locality` or `emails.0`, the first that
    resolves to a non-null value winning) against the verified `{ id_token, optional userinfo }`
    claims (`ClaimSources`), assembles a `TraitDocument`, TYPE-CHECKS it against the scope's
    active trait schema, and returns `Result<TraitDocument, ClaimMappingError>`. Declarative
    ONLY: no transforms or programmable logic (the pre-token hook and claims engine are M11).
    The `email` field's source order is governed by the connector's `email_source` quirk (data,
    never a code branch).
  - **Fail-closed.** On ANY failure (a missing required claim, a malformed subject, or a
    trait-schema type-check failure) it returns `Err` and NO document, so the federation
    callback aborts before any user row is written: a mapping failure never provisions a partial
    identity. The document is assembled and type-checked in full first.
  - **Two error classes.** `ClaimMappingError::MappingInvalid` (folds to `ConnectorError::Config`):
    a resolved value fails the trait schema's type check, a rule targets a trait the schema does
    not declare, or the scope has no active schema for the mapped traits (the mapping definition
    is wrong). `ClaimMappingError::UpstreamClaim` (folds to `ConnectorError::UpstreamProtocol`):
    a required claim is absent or a claim is malformed (the upstream misbehaved). Every error
    carries RFC 6901 pointers and operator-safe messages, never a claim value.
  - **`TraitSchemaView`.** The minimal, store-free seam the evaluator type-checks through
    (implemented in `ironauth-oidc` over `ironauth_store::TraitSchema`), so the crate takes no
    store dependency.
  - **`ConnectorRuntimeConfig`** gained `claim_mapping` and `quirks` (both `#[serde(default)]`),
    the fields the federation callback reads back from the stored `definition_json` to evaluate.
  - A second fuzz target (`claim_mapping`): arbitrary claims through a mapping never panic,
    always return a typed result (never a partial document), and any Ok document is fully
    type-valid.
- Federation login wiring (issue #75, PR B, follow-on): the secret-free `ConnectorRuntimeConfig`
  read projection (endpoints, scopes, client id, PKCE policy) the federation login path
  deserializes from the STORED `definition_json` (which strips the client secret, so it
  cannot round-trip into the strict `ConnectorDefinition`); it ignores unknown fields (a
  forward-compatible read view, not the exhaustive write-time parse). The discovery parser
  now forbids a transport DOWNGRADE: an https issuer's endpoints must be https (no plaintext
  downgrade), while an http issuer (only reachable through the fetcher's explicit plaintext
  opt-in, a loopback test upstream) may carry http endpoints.
- Upstream discovery-document parsing and the federation error taxonomy (issue #75, PR B),
  both still I/O-free (the crate remains fetch-free by construction):
  - **`discovery` module.** Parses a REMOTE provider's OIDC discovery metadata from bytes the
    federation slice fetches through the hardened path, enforcing the MIX-UP defence (the
    document's own `issuer` must byte-for-byte equal the configured issuer) and returning a
    `ResolvedEndpoints` with the upstream authorize / token / userinfo URLs, `jwks_uri`, and the
    advertised signing-algorithm and PKCE-method lists. It lives HERE (not in `ironauth-oidc`) so
    the crate that reads the hostile upstream metadata is structurally incapable of fetching it,
    and so the exposed struct field names never collide with the self-discovery lint's reserved
    served-document keys. A malformed document or an issuer mismatch is an `UpstreamProtocol`
    fault, never trusted.
  - **`ConnectorError` taxonomy.** The stable `#[non_exhaustive]` three-way classification issue
    #76 consumes: `Config` (the definition or mapping is wrong; not retryable), `UpstreamProtocol`
    (the upstream spoke incorrectly, e.g. a bad ID token or a mismatched discovery issuer; not
    retryable), and `UpstreamUnavailable` (the exchange could not complete, e.g. a blocked SSRF
    target, a timeout, a non-2xx, or an empty JWKS; transient). Carries only a non-sensitive
    description, plus a bounded `kind()` metric label and an `is_retryable()` predicate.
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
