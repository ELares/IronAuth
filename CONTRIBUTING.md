# Contributing to IronAuth

Thank you for contributing. IronAuth is pre-1.0 and moving fast along a
public plan (16 milestones in the issue tracker); the fastest way to help is
to pick an open issue in the current milestone and say so on the issue.

## Ground rules

- **One issue per PR.** Reference it with "Closes #N". PRs that drift beyond
  their issue get split.
- **Green gate before review.** Run `scripts/gate.sh` locally; it runs the
  same fmt, clippy pedantic, test, invariant-lint, dash-scan, and
  compatibility checks CI enforces. Changes to the management API additionally
  run `scripts/openapi-check.sh` (the served-versus-committed OpenAPI drift
  check).
- **Prose rule.** No em dashes and no en dashes anywhere in repo text
  (code, comments, docs, commit messages). CI enforces this.
- **Determinism seam.** All time and randomness flows through
  `crates/ironauth-env`. The invariant lints will fail your PR otherwise;
  if you believe you need a raw source, the escape marker requires a written
  reason on the same line.
- **Changelogs.** User-visible changes update the owning artifact's
  `CHANGELOG.md` (Unreleased section) in the same PR.

## The management-api-first rule (mandatory)

Every admin capability is a documented public API before any UI exposes it. The
management API (`crates/ironauth-admin`, served on the management plane) is the
single source of truth for administration; the admin SPA (M9), the CLI, the TUI,
Terraform, and the MCP server (M12/M13) are all THIN CLIENTS of it. This is what
prevents console-only features and secret private endpoints, and it is the
substrate the generated SDKs are diffed against.

Concretely, a PR that adds an admin capability must:

- add or extend the endpoint in `ironauth-admin` with an accurate
  `#[utoipa::path]` annotation (a stable `operation_id`, typed request and
  response schemas, and typed errors), so it lands in the OpenAPI spec;
- inherit the cross-cutting discipline: cursor pagination on every list (opaque
  cursors, a config-capped page size, never offset), Idempotency-Key on every
  POST, RateLimit headers on every response, and a same-transaction audit row on
  every mutation;
- regenerate the committed spec with `scripts/openapi-check.sh` (CI fails the
  build if the served API drifts from `docs/openapi/management.json`).

A UI or client that needs a capability the API does not yet expose is a signal to
add the API first, not to reach past it.

## The threat-model rule (mandatory)

Every PR that ships a **new surface** (a network-facing endpoint family, a
new parser over untrusted input, or a new privileged plane) must extend
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) with that surface's STRIDE
section **in the same PR**. Reviewers block merges that add a surface without
its threat-model section. If you are unsure whether your change is a new
surface, ask on the issue before opening the PR.

## Security

Never open a public issue for a suspected vulnerability; see
[SECURITY.md](SECURITY.md) for private reporting and the safe-harbor
commitment.

## Licensing

Dual-licensed MIT or Apache-2.0. Unless you explicitly state otherwise, any
contribution intentionally submitted for inclusion is dual-licensed as
described in [LICENSE](LICENSE), without any additional terms.
