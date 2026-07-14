# ironauth-config changelog

All notable changes to the `ironauth-config` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- Add a conformance cert-config confinement test (issue #37):
  `tests/conformance_cert_config.rs` loads both `deploy/ironauth.toml` and
  `deploy/conformance/ironauth.toml` through the strict loader and asserts the
  cert config turns the legacy/downgrade OP-profile toggles on while the shipped
  default keeps every one off. This proves the cert config parses under the
  strict schema and that the security downgrades cannot leak into the default
  posture. No library change; a test only.
  - `oidc.registration_mode = "open"` (anonymous, unauthenticated DCR) is now in
    the CONFINEMENT set, not only asserted on the cert side. It is one of the
    downgrades the cert config turns on, so nothing previously checked that it
    stayed OUT of the shipped default: open DCR could have leaked into the
    default posture with no test going red.
- Add the device-authorization knobs (issue #24, RFC 8628):
  - `oidc.device_code_ttl_secs` (default 600, validated to `1..=OIDC_MAX_DEVICE_CODE_TTL_SECS`
    = 1800): the short lifetime a device code and its user code are valid for.
  - `oidc.device_poll_interval_secs` (default 5, validated to
    `1..=OIDC_MAX_DEVICE_POLL_INTERVAL_SECS` = 300): the advertised minimum poll interval.
  - `oidc.device_slow_down_increment_secs` (default 5, may be 0, bounded by the same
    ceiling): how much a `slow_down` grows the enforced interval per too-fast poll.
  - `oidc.device_user_code_max_attempts` (default 5, at least 1): the number of failed
    user-code matches after which a flow is invalidated.
  - `oidc.device_verification_rate_limit` (default 10; 0 disables) and
    `oidc.device_verification_rate_window_secs` (default 60, validated to
    `1..=OIDC_MAX_LIFETIME_SECS`): the per-source fixed-window rate limit on user-code
    entry. The regenerated `docs/config-schema.json` and `docs/CONFIG.md` document them.
- Add the DCR abuse-control knobs (issue #31):
  - `oidc.registration_mode` (`closed` / `token_gated` / `open`, default
    `token_gated`): the per-environment exposure switch for Dynamic Client
    Registration. The safe default requires an initial access token; `open` (anonymous
    self-service registration) is an explicit opt-in. Takes effect only when
    `oidc.registration_enabled` mounts the endpoint.
  - `oidc.registration_max_clients` (default 100): the per-environment cap on
    dynamically registered clients.
  - `oidc.registration_rate_limit` (default 20) and `oidc.registration_rate_window_secs`
    (default 60, validated to `1..=OIDC_MAX_LIFETIME_SECS`): the endpoint's
    fixed-window rate limit; a limit of 0 disables it.
- Add `oidc.client_credentials_default_audience` (issue #23): the default audience a
  client-credentials access token carries when the request targets no resource
  server. A snake_case enum (`ClientCredentialsAudience`) with two members:
  `client_id` (the default; the token's `aud` is the OAuth client id, preserving the
  existing no-resource behavior) and `issuer` (the token's `aud` is the
  per-environment issuer). When a request targets a registered resource server (the
  RFC 8707 `resource` parameter, issue #28), that resource server's audience wins and
  this default does not apply. The regenerated `docs/config-schema.json` and
  `docs/CONFIG.md` document it.

- Add the refresh-token rotation and consent knobs (issue #21):
  - `oidc.issue_refresh_tokens` (default `true`): whether a code exchange issues a
    refresh token at all.
  - `oidc.refresh_idle_ttl_secs` / `oidc.refresh_max_lifetime_secs` (defaults 14 /
    30 days) and `oidc.offline_idle_ttl_secs` / `oidc.offline_max_lifetime_secs`
    (defaults 30 / 90 days): the idle timeout and family hard cap for a
    session-bound and an `offline_access` family respectively. Each idle timeout has
    a one-second floor and its own ceiling (`OIDC_MAX_REFRESH_IDLE_TTL_SECS`,
    `OIDC_MAX_REFRESH_MAX_LIFETIME_SECS`), and a hard cap must be at least its idle
    timeout.
  - `oidc.refresh_rotation_grace_secs` (default `10`): the window within which a
    duplicate presentation of a rotated token is a benign concurrent refresh rather
    than a reuse; `0` treats every superseded-token presentation as reuse.
  - `oidc.refresh_rotation_threshold_percent` (default `70`, bounded 0..=100): the
    fraction of idle TTL past which a confidential/bound client rotates.
  - `oidc.offline_access_requires_consent` (default `true`): whether a web client
    must consent to `offline_access` (OIDC Core 11), subject to the trusted
    first-party carve-out.
  - `oidc.remembered_consent_ttl_secs` (default 30 days, ceiling
    `OIDC_MAX_REMEMBERED_CONSENT_TTL_SECS`): how long a `remembered`-mode consent is
    honored before re-prompting.
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
