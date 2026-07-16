# ironauth-config changelog

All notable changes to the `ironauth-config` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- Reject a single-label WebAuthn RP ID at startup (issue #65 review hardening): a bare
  label such as a public suffix (`com`) is no longer accepted, since it passed the
  registrable-suffix check against a host like `auth.example.com` yet the browser
  rejects it at ceremony time. A registrable RP ID must contain a dot; `localhost`
  stays the single-label dev exception. It is a boot-time `ConfigError::Invalid`.
- WebAuthn passkey settings on `[oidc]` (issue #65): `webauthn_enabled` (default on),
  `webauthn_rp_id` (the per-environment Relying Party ID; when unset it is derived
  from the serving origin's host), `webauthn_challenge_ttl_secs` (default 300),
  `webauthn_require_user_verification` (default on), and
  `webauthn_clone_detection_block` (default off, warn). The RP ID is validated at
  STARTUP against the serving origin: when set, `server.public_url` must be
  configured and the RP ID must be the origin host or a parent (registrable-suffix)
  domain of it, so a misconfiguration is a boot-time `ConfigError::Invalid` rather
  than a per-ceremony runtime surprise.

- `[oidc.lazy_migration]` inbound lazy-migration hook settings (issue #56): a new nested
  config table arming the login-time verification of an unknown identifier against a legacy
  store. `enabled` (default false) gates it; `endpoint` (an https URL, required and https
  when enabled, validated at config load) is the verification webhook; `secret` is the
  shared bearer, through the existing Secret indirection and covered by the literal-secret
  lint; `timeout_secs` (default 5, bounded by `OIDC_MAX_LAZY_MIGRATION_TIMEOUT_SECS = 30`)
  is the per-call timeout; and `breaker_failure_threshold` / `breaker_window_secs` /
  `breaker_cooldown_secs` (defaults 5 / 30 / 30) tune the circuit breaker. Config over a new
  DB table, promotable per environment in spirit like the other OIDC toggles.
- Lazy-migration endpoint validation tightened (issue #56, adversarial review): the
  `endpoint` is now parsed as a well-formed absolute https URL with a non-empty host and no
  userinfo at config LOAD, instead of the prior bare `starts_with("https://")` check. A
  malformed-but-https endpoint (`https://` with no host, an embedded space, an unterminated
  `[` host, or smuggled `user:pass@`) is now a clear load error rather than silently failing
  every unknown-identifier login and tripping the breaker at runtime (criterion 6). Adds a
  dependency on the `http` crate purely for this syntactic URL parse.
- `[admin]` outbound verification SCOPE binding (issue #58, review):
  `admin.outbound_verification_tenant` and `admin.outbound_verification_environment`
  (both unset by default) pin the outbound credential-verification endpoint to exactly
  one `(tenant, environment)`. A request whose path scope does not match is a uniform
  not-found regardless of the token, so the shared token can never verify credentials
  across tenants. Unset either half fails closed (matches nothing).
- `[admin]` outbound lazy-migration verification settings (issue #58), DISABLED BY
  DEFAULT. `admin.outbound_verification_enabled` (default false) leaves the outbound
  credential-verification endpoint a uniform not-found; `admin.outbound_verification_token`
  (unset by default, via the `file`/`env` secret indirection) is the shared bearer a
  successor system presents, a credential distinct from the operator token and every
  management key that authorizes ONLY that endpoint. Exposing a live credential oracle
  to a third party is an explicit per-deployment opt-in.
- `[identifiers]`: flexible-identifier settings (issue #54). `identifiers.uniqueness`
  selects the per-environment login-identifier uniqueness policy: `environment_wide`
  (the safe default, one canonical identifier per tenant-environment), `org_scoped`
  (unique within an org, falling back to the environment scope for a membership-free
  user once M10 org membership ships), or `non_unique` (multiple accounts may share
  one identifier; identifier-first login still resolves deterministically). Changing
  the mode on a populated environment requires a validation pass that reports
  post-canonicalization collisions before it applies. New public
  `IdentifiersConfig` and `IdentifierUniqueness` types.
- `[byok]`: bring-your-own-key customer-managed encryption settings (issue #49),
  EXPERIMENTAL and DEFAULT-OFF. `byok.enabled` (default false) leaves every BYOK
  path unreachable; `byok.provider` (default `local`) selects the key-management
  driver; `byok.endpoint` is the external KMS URL for an external provider,
  outbound through the SSRF-hardened fetcher and owner/infra-gated.
- Registered the `custom-domains-acme` EXPERIMENTAL feature flag (issue #47,
  EXPLORATORY): per-environment custom domains with built-in ACME. Off by default
  and ack-gated on `CUSTOM_DOMAINS_ACME_VERSION` (a live issuance needs a
  provisioned CA account and a reachable domain, which is infra/owner-gated), so an
  operator enabling it acknowledges the exact implemented revision. New public
  `CUSTOM_DOMAINS_ACME_FEATURE` and `CUSTOM_DOMAINS_ACME_VERSION` constants.
- `admin.allowed_regions`: the operator's configured data-residency region set
  (issue #46). A tenant's `home_region` and a per-environment `region` pin must be
  one of these; empty (the default) leaves residency pinning unavailable and refuses
  any residency pin on a create.
- `admin.offboarding_retention_secs`: the tenant-offboarding retention window in
  seconds (issue #46), the grace period a soft-deleted tenant can be restored
  within before the terminal hard deletion. Tunable, safe default 30 days.
- Per-tenant and per-environment quota fairness settings (issue #50), on a new
  `[quota]` section consumed by the `ironauth-quota` engine.
  - `[quota.tenant]` and `[quota.environment]`: the two nested tiers, each with a
    sustained rate and burst capacity per dimension (`requests_per_second` /
    `requests_burst`, `token_issuance_per_second` / `token_issuance_burst`,
    `hook_seconds_per_second` / `hook_seconds_burst`). Safe defaults; the
    per-tenant envelope is larger than the per-environment share. A `*_burst` of
    0 is the documented unlimited form for a single-tenant self-hoster.
  - `quota.usage_thresholds_percent` (default `[80, 100]`): the utilization
    percentages at which a saturation webhook fires per dimension. Validated to
    be at most `QUOTA_MAX_USAGE_THRESHOLDS` entries, each 1..=100, with no
    duplicates; an empty list disables saturation webhooks.
  - `quota.idle_bucket_ttl_secs` (default `3600`): how long an idle per-tenant or
    per-environment token bucket is retained before the reaper evicts it, bounding
    the in-memory footprint under legitimate scope churn. `0` disables the reaper
    (buckets live for the process lifetime); the key space is still bounded by real
    tenancy, because only a verified, existing scope ever allocates a bucket.
- Session Management 1.0 and Front-Channel Logout 1.0, behind default-off flags for
  certification completeness (issue #39).
  - `oidc.session_management_enabled` (default `false`): when set, the OP serves the
    `check_session_iframe`, discovery advertises `check_session_iframe`, and every
    authorization response carries `session_state`. Off by default because these iframe
    mechanisms are degraded under third-party-cookie partitioning (Session Management
    1.0 section 5.1); enabling still requires a per-client opt-in.
  - `oidc.frontchannel_logout_enabled` (default `false`): when set, the `end_session`
    flow renders a hidden iframe per participating RP that registered a
    `frontchannel_logout_uri`, passing `iss` and the RP's own `sid` when it registered
    `frontchannel_logout_session_required`. Best-effort only; it never blocks or
    reorders the authoritative back-channel logout path. Off by default; enabling still
    requires the per-client registration.
- Back-Channel Logout delivery worker settings (issue #34), all on `[oidc]`:
  - `backchannel_logout_enabled` (default `false`): whether the delivery worker runs. Off
    by default (the covenant: no mandatory background infrastructure). Discovery advertises
    `backchannel_logout_supported` regardless; this switch governs only the worker.
  - `backchannel_logout_max_attempts` (default `5`, at least 1): the attempts cap after
    which a per-RP delivery is dead-lettered.
  - `backchannel_logout_retry_base_secs` (default `10`): the base delay for the worker's
    exponential backoff between retries.
  - `backchannel_logout_poll_interval_secs` (default `5`): how often the worker polls the
    queue for due work.
  - `backchannel_logout_request_timeout_secs` (default `10`): the per-delivery time budget
    the SSRF-hardened fetcher enforces, so a slow RP cannot wedge the worker.
  - The three second-valued knobs are validated to be at least 1 and at most
    `OIDC_MAX_LIFETIME_SECS`; the attempts cap must be at least 1.
- Global Token Revocation, an EXPERIMENTAL receiver (issue #36).
  - The `global-token-revocation` feature is registered on the maturity ladder as
    Experimental: off by default, and enabling it requires an `ack` equal to the exact
    implemented draft revision (`GLOBAL_TOKEN_REVOCATION_DRAFT`,
    `draft-parecki-oauth-global-token-revocation-01`). A future draft that changes the
    wire shape bumps that version and invalidates the old ack. The implemented draft
    revision is surfaced in `docs/CONFIG.md` (the feature ladder table) so an interop
    mismatch with another implementer is diagnosable.
  - `oidc.global_token_revocation_hard_kill`: whether a global revoke ALSO revokes the
    subject's `offline_access` families (not only the session-bound ones). Off by default
    (offline grants survive, matching the platform-wide revoke-everything semantic); set
    it for an account-takeover posture. Effect only when the feature is enabled.
- Session-model settings (issue #32).
  - `oidc.session_idle_ttl_secs`: the session IDLE timeout, alongside `session_ttl_secs`
    (now documented as the ABSOLUTE hard cap). Validated to be at least 1 second, at most
    `OIDC_MAX_SESSION_TTL_SECS`, and never larger than the absolute cap (an idle timeout
    beyond the cap could never fire, so accepting it would mislead an operator).
  - `oidc.session_partitioned_cookie`: off by default; ADDS the CHIPS `Partitioned`
    attribute for embedded-widget scenarios without dropping `SameSite` or breaking the
    `__Host-` prefix.
  - `oidc.session_peer_ip_binding` and `oidc.session_device_binding`: both off by default
    (the tunability principle), so a NAT or a mobile IP change never logs a user out
    unless an operator opts in.
  - `PEER_IP_HEADER`: the internal header on which the server stamps the POLICY-RESOLVED
    client IP for the peer-IP binding. It lives here, in the crate both the server and the
    OIDC provider depend on, so the two agree on the name without the server taking a
    dependency on the OIDC crate.

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
