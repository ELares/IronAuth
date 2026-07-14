# ironauth-admin changelog

All notable changes to the `ironauth-admin` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- DCR abuse-control management surface (issue #31). Five operator-plane endpoints,
  all honoring the crate's contract (Idempotency-Key, same-transaction audit,
  RateLimit headers, cursor pagination, OpenAPI as source of truth):
  - `POST` / `GET` `.../dcr/policies`: author a named, reusable policy (its primitives
    validated at create time against the OIDC policy engine, one source of truth for
    the shape; a duplicate name is a 409) and list policies (cursor paginated).
  - `POST .../dcr/initial-access-tokens`: mint an initial access token attaching a
    policy chain by name (resolved to a primitive snapshot so a later policy edit
    never changes an already-minted token). The plaintext token is returned exactly
    ONCE (HTTP 201); an idempotent replay omits it (HTTP 200). Only its SHA-256 is
    stored.
  - `GET` / `POST .../clients/{client_id}` (+`/verify`): read a dynamically registered
    client's quarantine state, and verify it (lifting the quarantine) idempotently. A
    not-found is a uniform anti-oracle 404.
  - The DCR resources are DATA-plane scoped, so these control-plane endpoints route
    through the control role's narrow grants (mint/verify), never a second data-plane
    store. New `ApiError::Conflict` (409). Now depends on `ironauth-oidc` for the
    shared policy-primitive type.

- Initial OpenAPI-first management API skeleton (issue #11). Establishes the
  management API contract and discipline once, so the later admin SPA, CLI,
  Terraform, and MCP surfaces inherit it as thin clients.
  - **OpenAPI 3.1 as source of truth.** The spec is derived from the
    `#[utoipa::path]` annotations on the axum handlers with `utoipa` (MIT OR
    Apache-2.0, MSRV 1.75); the handlers are listed once in `#[derive(OpenApi)]`
    `paths(...)` and wired to the same paths in the router, a contract test pins
    the documented (method, path) set, and `scripts/openapi-check.sh` regenerates
    the committed `docs/openapi/management.json` and `git diff --exit-code`s so
    drift fails the build. Served at `GET /openapi.json`. The utoipa-axum
    route-binder is deliberately not used: it pulls the unmaintained `paste` crate
    (RUSTSEC-2024-0436) that `cargo deny` rejects, so the router is wired by hand
    and no new advisory enters the graph.
  - **Cursor pagination on every list endpoint.** Opaque base64 cursors over a
    stable `(created_at, id)` key, a config-capped page size
    (`admin.max_page_size`, `admin.default_page_size`), and no offset pagination
    anywhere.
  - **Idempotency-Key on every POST** (draft-ietf-httpapi-idempotency-key). Keys
    are scoped to the acting credential and stored with the original response in
    the SAME transaction as the mutation, so a replay returns the original result
    and writes no second audit row. A key reused with a different request is a
    422.
  - **RateLimit headers on every response.** Structured `RateLimit` and
    `RateLimit-Policy` (draft-ietf-httpapi-ratelimit-headers) plus the legacy
    `X-RateLimit-*` triplet, wired to a placeholder limiter so the header
    contract is fixed before the real limiter lands.
  - **Environment-scoped credentials, two wrong-scope behaviors.** Management API
    keys (`mak_`) are bound to `(tenant, environment)` via the typed-ID
    substrate; the presented token is `<mak_id>.<secret>` and only the token hash
    is stored. A config bootstrap operator token authorizes the operator plane
    (tenant CRUD) in M1; the full operator-plane credential class lands in M5.
    Cross-scope resource probes are a uniform not-found (registered with the #6
    IDOR harness); a credential against the wrong environment or plane fails LOUD
    with an error naming expected and actual scope.
  - **Audit on every mutation.** Every management mutation writes its audit row in
    the same transaction, through the store's audited-write primitive, connecting
    as the distinct `ironauth_control` role.
  - First resource endpoints proving the discipline end to end: tenants CRUD
    (operator plane), environments CRUD (under a tenant), and management-key CRUD
    (under an environment). Idempotent PUT/DELETE semantics (RFC 9110): DELETE is
    a soft deactivation that is idempotent and keeps the append-only audit log's
    foreign keys satisfiable.
