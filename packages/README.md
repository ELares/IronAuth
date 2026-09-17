# TypeScript packages

These packages provide browser interfaces, application helpers, and MCP
implementations around IronAuth's public contracts. They are present in the
repository today; the development packages have private manifests and are
not a promise of registry publication.

| Package | Purpose | Contract and guide |
| --- | --- | --- |
| [admin-spa](admin-spa/README.md) | Preact/TypeScript administration console. Its production build is embedded under `/admin` in the Rust binary; standalone hosting has additional origin and callback requirements. | Management OpenAPI; [console guide](../docs/ADMIN-CONSOLE.md). |
| [reference-app](reference-app/README.md) | Forkable hosted-page renderer for fully custom sign-in pages, deployed separately from the built-in Rust-rendered pages. | Public headless [flow contract](../docs/FLOWS.md). |
| [ironauth-sdk](ironauth-sdk/README.md) | WebCrypto token verification, OAuth/PKCE/DPoP helpers, protected-resource metadata/challenges, session-token refresh, authorization checks, and diagnostic/snippet utilities. | [Integration guide](../docs/INTEGRATIONS.md) and [SDK contract](../docs/SDK-CONTRACT.md). |
| [ironauth-bff](ironauth-bff/README.md) | Framework-agnostic login/callback/logout/userinfo/proxy handlers with tokens held server-side, hardened session cookies, DPoP, and step-up helpers. | [BFF guidance](../docs/bff.md), [React](../docs/quickstart-react.md), and [Next.js](../docs/quickstart-nextjs.md) quickstarts. |
| [ironauth-mcp](ironauth-mcp/README.md) | Administration tools filtered to the permissions of a scoped management key; destructive calls require explicit confirmation. | Public management API and audit entry-path contract. |
| [ironauth-docs-mcp](ironauth-docs-mcp/README.md) | Read-only search and retrieval over the generated documentation corpus. | [Published docs index](../docs/llms.txt). |
| [mcp-sample](mcp-sample/) | OAuth-protected sample MCP resource server used by the recorded conformance bundle. | [MCP authorization evidence](../docs/conformance/mcp.md). |

## Development

Each package declares its own Node requirement and scripts. For the admin
SPA, use Node `^22.22.2 || ^24.15.0 || >=26.0.0`; Node 20 does not satisfy
the current console test dependencies. A recent supported Node 22 or 24
version can also run the remaining packages.

Run `npm ci` within the package whose committed lockfile you are using, then
its `typecheck`, `build`, and `test` scripts where declared. The reference
app has no bundled production dependency tree and uses a separate binding
freshness check. See each README for the exact workflow.

`scripts/gate.sh` runs the package-specific structural and freshness checks.
The console additionally uses generated management bindings, a public-route
audit, and an embed freshness check. Changing its production build requires
regenerating the committed assets in `crates/ironauth-admin-ui/embedded/`;
follow the [SPA README](admin-spa/README.md).
