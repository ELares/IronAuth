# ironauth-config changelog

All notable changes to the `ironauth-config` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

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
