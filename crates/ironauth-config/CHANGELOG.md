# ironauth-config changelog

All notable changes to the `ironauth-config` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- Add `oidc.registration_enabled` (issue #30), a plain default-off flag gating the
  Dynamic Client Registration endpoint (`/connect/register`). Off keeps the
  endpoint unmounted and undiscoverable, the safe posture; the real abuse gating
  (quotas, quarantine, initial-access-token policy) is owned by issue #31.
- Add the pushed-authorization-request settings (PAR, RFC 9126, issue #27):
  - `oidc.require_pushed_authorization_requests` (default `false`), the
    environment-wide switch that requires every client to use PAR; when `true` the
    authorization endpoint rejects a plain request with `invalid_request` and
    discovery advertises the requirement.
  - `oidc.par_ttl_secs` (default 60), the pushed `request_uri` lifetime in
    seconds, validated to stay between 1 and `OIDC_MAX_PAR_TTL_SECS` (600) so a
    misconfiguration cannot mint a long-lived reference.

- Add the JWT client-assertion authentication knobs (issue #25), shared with the
  JWT bearer grant (#26):
  - `oidc.client_assertion_audience`, a `ClientAssertionAudience` enum selecting
    which `aud` values a client assertion may carry. The default
    (`token_endpoint_or_issuer`) accepts either the token-endpoint URL (the
    RFC 7523 recommendation) or the issuer identifier, so a client that targets
    either is interoperable out of the box; `issuer_only` is the strict posture
    that accepts the issuer identifier alone. A promotable per-environment
    setting.
  - `oidc.client_assertion_max_skew_secs` (default `60`), the clock-skew
    allowance applied to a client assertion's `exp` through the verify core's
    skew parameter, bounded above by `OIDC_MAX_CLIENT_ASSERTION_SKEW_SECS` (300).
  - The generated `docs/config-schema.json` and `docs/CONFIG.md` are regenerated.
- Add `oidc.default_access_token_format` (issue #29), a `TokenFormat` enum
  (`at_jwt` or `opaque`) selecting the access-token format an environment mints
  when no resource server is targeted. The spec-conform default (`at_jwt`) mints a
  self-contained RFC 9068 signed JWT whose audience is the client id, so `UserInfo`
  and offline verification keep working; `opaque` mints a random, digest-only
  reference token. A promotable per-environment setting; a registered resource
  server overrides it per audience. The generated `docs/config-schema.json` and
  `docs/CONFIG.md` are regenerated.

- Add the legacy response-type toggles (issue #17, all default `false`):
  `oidc.enable_response_type_id_token`, `oidc.enable_response_type_code_id_token`,
  `oidc.enable_response_type_none`, and `oidc.enable_response_mode_form_post`. Each
  is an independent per-environment switch that opts a certification-run
  environment into a legacy response type or the `form_post` mode; the `code`
  response type and `query` mode are always available. Regenerates
  `docs/config-schema.json` and `docs/CONFIG.md`.
- Add `oidc.require_pkce_for_confidential_clients` (issue #13, default `true`):
  the per-environment PKCE policy for confidential clients. Public clients always
  require PKCE regardless. Regenerates `docs/config-schema.json` and
  `docs/CONFIG.md`.
- Add the `[oidc]` section (issue #12): `enabled` (opt-in mount, default off),
  `authorization_code_ttl_secs` (default 60), and `access_token_ttl_secs`
  (default 300). Lifetimes are validated non-zero and bounded by
  `OIDC_MAX_LIFETIME_SECS`. Regenerates `docs/config-schema.json` and
  `docs/CONFIG.md`.
- Initial strict configuration layer: fail-fast TOML parsing (unknown keys
  abort with file, line, column, and the expected-field list), `Secret`
  indirection (literal, file, env forms) with redacted Debug/Display/serialize,
  `Dsn` connection strings with password redaction, the feature maturity
  ladder (`FeatureRegistry`, experimental version acknowledgment gate), and
  the published JSON Schema contract (`Config::json_schema`,
  scripts/config-schema.sh regenerates docs/config-schema.json and
  docs/CONFIG.md).
