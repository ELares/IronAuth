# ADR 0005: OpenAPI-first management API

Status: accepted (M1, management-API skeleton issue #11)

## Context

A management API that later needs replacing is a documented multi-year tax:
Keycloak is rewriting its inconsistent Admin API as v2, and Zitadel's
Connect-only gRPC v2 fragmented its tooling and docs. The commercial reference
points (Auth0, Clerk, Stytch, WorkOS, Logto) all converged on OpenAPI-first REST
with accurate generated types, and on the discipline half: every admin
capability is a documented public API before any UI exposes it. This issue
establishes the contract once, so the fifteen later milestones (the admin SPA,
CLI, Terraform, generated SDKs, the MCP server) inherit it instead of
relitigating it. The persistence isolation substrate (#6) and the
same-transaction audit log (#7) are the layers this API builds on.

## Decision

The management API is REST, OpenAPI 3.1, and served on the management plane. Six
properties are fixed from the first endpoint.

- **OpenAPI 3.1 is the source of truth.** The spec is derived from the
  `#[utoipa::path]` annotations on the axum handlers with `utoipa` (MIT OR
  Apache-2.0, MSRV 1.75, pure Rust). Each handler is listed once in the
  `#[derive(OpenApi)]` `paths(...)` and wired to the same path string in the
  router; a contract test (`documented_paths_are_the_expected_set`) pins the exact
  documented (method, path) set, so the hand-wired router and the spec cannot
  silently diverge. The generated document is committed to
  `docs/openapi/management.json` and `scripts/openapi-check.sh` regenerates and
  `git diff --exit-code`s it, so a handler change not reflected in the spec (or
  the reverse) fails the build. The spec is also served at `GET /openapi.json`.

  The `utoipa-axum` route-binder, which would fuse the router and the spec into a
  single builder (removing even the need for the pin test), is deliberately NOT
  used: it depends on the unmaintained `paste` crate (RUSTSEC-2024-0436), which
  `cargo deny` rejects. Wiring the twelve routes by hand and pinning the set with
  a test keeps the dependency graph advisory-clean at the cost of one small test,
  which is the better trade for a foundational crate. If `utoipa-axum` later drops
  `paste`, adopting it is a mechanical change behind an unchanged wire contract.

- **Cursor pagination on every list endpoint.** Opaque cursors are the base64 of
  a stable `(created_at, id)` sort key; the next page selects rows strictly after
  it, so insertions and deletions between pages never skip or duplicate a row.
  The page size is capped by config (`admin.max_page_size`, safe default), and a
  default (`admin.default_page_size`) applies when the caller omits `limit`.
  There is no offset pagination anywhere.

- **Idempotency-Key on every POST** (draft-ietf-httpapi-idempotency-key). The key
  is scoped to the acting credential and stored WITH the original response in the
  SAME transaction as the mutation, so a replay returns the original response
  verbatim without re-executing the mutation, and therefore writes no second
  audit row. A key reused with a different request (a different fingerprint of
  method, path, and body) is a 422.

- **RateLimit headers on every response.** The structured `RateLimit` and
  `RateLimit-Policy` fields (draft-ietf-httpapi-ratelimit-headers) plus the
  legacy `X-RateLimit-*` triplet are stamped by a middleware wired to a
  PLACEHOLDER limiter. The real layered, per-tenant limiter is later ops work;
  fixing the header shape now lets clients and SDKs depend on it before the
  limiter lands.

- **Environment-scoped credentials, control-plane and data-plane separated.**
  Management API keys (`mak_`) are bound to `(tenant, environment)` through the
  typed-ID substrate. The presented token is `<mak_id>.<secret>`: the id half
  declares the scope in the clear (safe to log) and the secret half is 128 bits
  of entropy; only the SHA-256 of the whole token is stored. A config bootstrap
  operator token authorizes the operator plane (tenant CRUD) in M1; the full
  operator-plane credential class lands in M5.

- **Audit on every mutation.** Every management mutation writes its audit row in
  the same transaction, through the store's single audited-write primitive.

## Control-plane database role

Management mutations touch the operator, tenant, and environment LEVEL tables
that the data-plane role (`ironauth_app`) deliberately cannot see. Rather than
widen the data-plane role, migration 3 grants a SECOND low-privilege role,
`ironauth_control`, exactly those rights (plus append-only audit and the new
management tables), and nothing on the data-plane scoped tables (`clients`,
`organizations`). It is a peer of `ironauth_app`, never a superset: still never a
superuser and never a table owner, so forced row-level security applies to it
too. Like the data-plane role, the migration GRANTs to it but never creates it or
ships a password; it is provisioned out of band in production and race-safely by
the test harness. The management repositories connect as (or are handed a pool
authenticated as) `ironauth_control`, and the two pools are kept entirely
separate. This makes "control-plane credentials are a distinct class from
data-plane keys" real at the database layer.

## Operator-plane audit scoping (the wrinkle)

The audit log (#7) is `(tenant, environment)`-scoped with foreign keys, so an
operator-plane "create tenant" has no pre-existing scope to key its audit row on.
It is resolved by creating the tenant AND its first environment in the SAME
transaction, then writing the audit row scoped to that fresh
`(new_tenant, new_first_environment)` pair: both rows exist by the time the audit
insert runs, so its foreign keys and the row-level-security check are satisfied.
Environment CRUD under an existing tenant scopes the audit to `(tenant, the
environment)`. Tenant deactivation scopes to `(tenant, its oldest environment)`,
which is retained (see soft delete below), so the audit foreign key holds. The
well-known bootstrap operator ROW is ensured idempotently inside the create
transaction; that is platform self-bootstrap (like a migration), not a
caller-visible mutation, so it is the one control-plane write that is not itself
audited. No audited management mutation is genuinely unscopable.

The idempotency store is the one deliberate exception to `(tenant, environment)`
row-level-security scoping: an operator-plane POST is looked up for a replay
BEFORE any tenant exists, so it cannot key on a not-yet-created scope. Isolation
there is by the acting CREDENTIAL (which, for a management key, itself embeds the
scope), enforced by the query and reachable only by `ironauth_control`. It is
still confined to the repository module by `scripts/query-audit.sh`.

## Soft delete, and idempotent methods (RFC 9110)

DELETE is idempotent per RFC 9110. Tenants, environments, and management keys are
DEACTIVATED (a `deleted_at` timestamp) rather than hard-deleted: the row is
retained so the append-only audit log's foreign key to it stays satisfiable
forever (an audit row can never be removed, so a hard delete of an audited
resource is structurally impossible). Reads filter `deleted_at IS NULL`, so a
deactivated resource returns not-found; repeating the delete has the same effect.

## Two wrong-scope behaviors

Both are required and both are tested:

- a resource-ID probe under a VALID scope for a resource in ANOTHER scope is a
  UNIFORM not-found, identical to an absent resource (the anti-oracle rule from
  the persistence layer); the management resolve-by-id probes are registered with
  the #6 IDOR harness and run in CI;
- a credential presented against the WRONG environment or the WRONG plane fails
  LOUD with a structured error naming the expected and actual scope.

## Consequences

- The spec is authoritative from the first endpoint, so the WorkOS-style
  spec-driven SDK generation with diff-enumerated changelogs works, and drift is
  a build failure rather than a review lapse.
- The admin SPA, CLI, TUI, Terraform, and MCP server are thin clients; there are
  no console-only features or secret private endpoints (the management-api-first
  rule, in CONTRIBUTING.md).
- The header and credential contracts (pagination, idempotency, rate limits,
  environment-scoped keys) are fixed before the endpoint count grows, so later
  milestones extend the surface without renegotiating the cross-cutting shape.
- The placeholder rate limiter and the M1 bootstrap operator token are explicit
  seams: the real limiter and the full operator-plane credential class (M5) land
  behind an unchanged wire contract.
