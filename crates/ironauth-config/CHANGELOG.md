# ironauth-config changelog

All notable changes to the `ironauth-config` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- Initial strict configuration layer: fail-fast TOML parsing (unknown keys
  abort with file, line, column, and the expected-field list), `Secret`
  indirection (literal, file, env forms) with redacted Debug/Display/serialize,
  `Dsn` connection strings with password redaction, the feature maturity
  ladder (`FeatureRegistry`, experimental version acknowledgment gate), and
  the published JSON Schema contract (`Config::json_schema`,
  scripts/config-schema.sh regenerates docs/config-schema.json and
  docs/CONFIG.md).
