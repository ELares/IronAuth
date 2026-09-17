# Integrating applications and automation

Use IronAuth's public protocols for application sign-in and its management
API for administration. Choose the integration path that fits your runtime;
the repository supplies working examples and helpers rather than requiring
a particular SDK.

## Quickstarts

| Application | Starting point | What it demonstrates |
| --- | --- | --- |
| React SPA | [React quickstart](quickstart-react.md) | A React frontend with a BFF that holds tokens server-side. |
| Next.js App Router | [Next.js quickstart](quickstart-nextjs.md) | Login/callback routes and an opaque browser session backed by `@ironauth/bff`. |
| Go backend | [Go quickstart](quickstart-go.md) | User authentication and token verification against a local issuer. |
| Python backend | [Python quickstart](quickstart-python.md) | User authentication and verification without requiring a bespoke sign-in SDK. |
| iOS / Android | [AppAuth guide](mobile-appauth.md) and [mobile samples](../clients/mobile/) | System-browser sign-in with PKCE; review the documented per-client DPoP exemption for AppAuth. |

Quickstarts use the [local emulator](EMULATOR.md). Their marked shell blocks
are executed by `scripts/quickstart.sh`; read the runner's prerequisites
before running a quickstart as an automated check. The TypeScript helpers
are currently built and packed from the repository, rather than installed
from a published npm release.

For a persistent deployment, register a client in the correct tenant and
environment, use its scoped issuer, and configure exact redirect URIs.
Public clients use PKCE and are subject to the issuer's DPoP policy. Client
secrets belong in confidential server components.

## Browser applications

The recommended integration holds access and refresh tokens on your server
and gives the browser an opaque session cookie. The
[BFF guide](bff.md) explains the browser architecture choices and the
[BFF package](../packages/ironauth-bff/README.md) documents the handlers.

`@ironauth/bff` provides login, callback, logout, userinfo, and API proxy
handlers; adapters for Fetch and Node-style request/response runtimes;
discovery and DPoP helpers; and RFC 9470 step-up challenges and redirects.
State-changing requests require `X-IronAuth-BFF`. Its development
`MemorySessionStore` loses sessions on restart and does not share them
between replicas; implement `SessionStore` using durable shared storage
for a persistent multi-instance application.

The React and Next.js guides use these handlers. There is no separate
published React hook library or Next.js SDK in the current tree.

## Hosted and custom authentication pages

The server renders its own hosted sign-in, registration, recovery, consent,
MFA, passkey, device, logout, and organization pages. Branding and locale
configuration are managed per environment.

For custom pages, fork [the reference app](../packages/reference-app/README.md)
and consume the [headless flow contract](FLOWS.md). The server owns the
authentication decisions and validates every submission. A custom renderer
must serve its own restrictive security headers; the built-in pages' headers
do not automatically protect a separately hosted frontend.

## APIs and token verification

Use discovery at `{issuer}/.well-known/openid-configuration` and the
advertised JWKS. Validate signatures, exact issuer, audience, allowed
algorithm, and token lifetime. An access token and an ID token serve
different purposes; do not treat decoding a JWT as verification.

| Runtime / task | Repository support |
| --- | --- |
| TypeScript / WebCrypto | [SDK modules](../packages/ironauth-sdk/README.md) for verification, JWKS caching, OAuth/PKCE, DPoP, protected-resource metadata and challenges, authorization checks, and diagnostics. |
| Edge platforms | [Runtime support and evidence](edge-verification.md), WebCrypto snippets, and a Rust Fastly Compute snippet. Some runtime claims are explicitly inferred rather than measured on a hosted platform. |
| Java | [Dependency-free verification implementation and samples](../sdks/java/README.md); verification only. |
| .NET | [Verification implementation and samples](../sdks/dotnet/README.md); verification only. |
| Session-derived JWTs | [Session tokenizer](session-tokenizer.md), using a configured audience, TTL, claim rules, and template-specific keys. |

Self-contained signature verification does not learn about revocation
immediately. Tokens remain verifiable until expiration; use introspection
when a resource server needs current server-side grant state. Tokenized
sessions have the same TTL tradeoff. See the [agent revocation contract](agents.md)
and [session tokenizer](session-tokenizer.md).

## Authorization

The TypeScript SDK's `check()` has three configured resolvers: permissions
in an already verified access token, IronAuth's AuthZEN endpoint, or a
customer's compatible PDP. Failure returns deny. See the
[SDK guide](../packages/ironauth-sdk/README.md).

Permissions, organization membership, and grants are separate from the act
of signing in. Register resource-server scopes and permission mappings in
the intended environment. The [capability guide](CAPABILITIES.md) describes
the current AuthZEN, organization, and experimental agent-policy limits.

## Management and automation

The [committed OpenAPI specification](openapi/management.json) describes
administrative operations. The server serves it at `GET /openapi.json`
on the management plane when that API is mounted. Use a credential with
the minimum required permissions and keep management access restricted.

| Client | Current coverage and use |
| --- | --- |
| [Admin console](ADMIN-CONSOLE.md) | Selected administration workflows over the public management API, with browser OIDC login mapped to operator subjects. It is not a UI for every API operation. |
| Go (`sdks/go`) and Python (`sdks/python`) | Generated management clients, checked against the public specification. They are administration clients, not a replacement for application OAuth/OIDC verification. |
| `ironauth validate/plan/apply/drift` | Configuration-as-code workflows. Snapshot export is broader than apply support; check the [capability guide](CAPABILITIES.md) before planning a promotion. |
| [Terraform provider](../terraform-provider-ironauth/) | Tenant resource only at present. Its provider-coverage check is a ratchet, not evidence of complete API coverage. Configure credentials through `IRONAUTH_ENDPOINT` and `IRONAUTH_TOKEN` or provider arguments. |
| [Admin MCP](../packages/ironauth-mcp/README.md) | Advertises declared tools only when the scoped key has their permissions. Destructive calls require `confirm: true`, and mutations carry the MCP audit entry path. This is a library implementation, not a complete MCP transport deployment. |
| [Docs MCP](../packages/ironauth-docs-mcp/README.md) | Read-only `search_docs` / `read_doc` over [the generated documentation corpus](llms-full.txt), with no management credential. |

List operations use opaque cursor pagination. Preserve the returned cursor
and honor the configured page limit. Supply an `Idempotency-Key` when the
operation requires one and handle typed errors and rate limits. The
[SDK contract](SDK-CONTRACT.md) defines which wire values clients can rely on.

## Provisioning and migration

IronAuth implements inbound SCIM provisioning and outbound SCIM push,
LDAP synchronization, bulk import, and migration workflows. Configure the
connection, scope, credentials, mapping, and worker requirements described
in [capabilities](CAPABILITIES.md) and [operations](OPERATIONS.md). A stored
connection alone does not establish that every worker is enabled.

Follow the [exit guide](exit-guide.md) for portable exports and the
[migration skill](skills/migrate-to-ironauth.md) for migration planning.
Previously stored password hashes use the bounded supported verification
schemes in the [hash-scheme guide](../crates/ironauth-hash-scheme/README.md).

## Agents and MCP resources

[Agent principals](agents.md) carry an organization, linked human, and
declared tool scopes. Issuance enforces the declared scopes, and revocation
affects the agent's grants. Workload federation and ordinary service
accounts have different identity contracts; use the
[capability guide](CAPABILITIES.md) to choose between them.

The [MCP sample resource server](../packages/mcp-sample/) demonstrates
protected-resource metadata, OAuth challenges, and token verification;
the [conformance page](conformance/mcp.md) states what its recorded tests
actually measure. The separate admin MCP package drives management tools.

Draft agent and transaction protocols are opt-in prototypes. Read their
[individual guides](README.md#experimental-protocols) and versioned
configuration acknowledgements before adopting them.
