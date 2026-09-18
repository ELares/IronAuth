# IronAuth

[![OIDF conformance](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/ELares/IronAuth/main/docs/conformance/status/badge.json)](docs/conformance/README.md)

IronAuth is a self-hosted identity platform for people, organizations, services,
and agents. Its Rust server combines an OpenID Connect provider, hosted sign-in
pages, a management API, an embedded administration console, and background
workers. PostgreSQL is the required persistence layer.

**Status: pre-1.0 and under active development.** The repository contains the
capabilities described below, but this is not a production-readiness or
certification claim. The live OpenID Foundation suite has not been provisioned;
its status is [not yet run](docs/conformance/README.md). Track ongoing work in
the [issue tracker](https://github.com/ELares/IronAuth/issues) and
[milestones](https://github.com/ELares/IronAuth/milestones).

## Start here

| Goal | Guide |
| --- | --- |
| Understand the feature set and its current limits | [Capabilities](docs/CAPABILITIES.md) |
| Run locally or deploy and operate a server | [Operations](docs/OPERATIONS.md) and [local emulator](docs/EMULATOR.md) |
| Sign in to the console and administer resources | [Admin console](docs/ADMIN-CONSOLE.md) |
| Add authentication or authorization to an application | [Integrations](docs/INTEGRATIONS.md) |
| Find a protocol, security, or configuration reference | [Documentation index](docs/README.md) |

## What is implemented

Features have separate configuration and, in some cases, build requirements.
The [capability guide](docs/CAPABILITIES.md) identifies those requirements and
the surfaces that are experimental or incomplete.

| Area | Capabilities |
| --- | --- |
| Authentication | OIDC discovery, authorization code with PKCE, refresh rotation and reuse detection, client credentials, device authorization, token exchange, PAR, DPoP, introspection, revocation, and logout/session-management surfaces. Ed25519 is the default signing algorithm; clients can negotiate other supported signing algorithms. |
| Sign-in experience | Hosted login, registration, recovery, consent, MFA enrollment and challenge, passkeys, passwordless methods, organization selection, branding, localization, and a shared headless flow contract for custom pages. |
| Federation and provisioning | Upstream OIDC and SAML connections, social provider integration, inbound and outbound SCIM, LDAP directory synchronization, bulk imports, and migration support. |
| Identity and access | Tenants and environments, users, organizations and memberships, groups, invitations, permissions, grants, service accounts, workload federation, agent principals, and an AuthZEN policy decision point. |
| Administration | An API-first console with resource lists, explicit creation dialogs, search, diagnostics, API keys, and organization administration. The management API additionally exposes audit and configuration resources, and drives generated Go/Python clients, CLI configuration workflows, and admin MCP tools. |
| Security and operations | Tenant-scoped storage and row-level security, envelope encryption, key lifecycle tools, password policy and breached-password screening, step-up authentication, quotas, a transactional outbox, webhooks, signed log streams, health/readiness probes, metrics, and optional trace export. |
| Developer tools | A seeded local emulator, React/Next.js/Go/Python quickstarts, a framework-agnostic BFF helper, WebCrypto token/protocol helpers, Java/.NET verification samples, mobile AppAuth samples, and edge verification snippets. |

PostgreSQL alone is a supported mode. IronBus notifications are an optional
build/configuration choice. The IronCache backend is present, but the current
server boot path does not attach it; enabling its Cargo feature alone does not
activate a cache. WASM hooks require an optional build and a newer Rust compiler.
See [build options and limits](docs/CAPABILITIES.md).

## Try it locally

Install the toolchain in [rust-toolchain.toml](rust-toolchain.toml), PostgreSQL
server binaries (`initdb`, `pg_ctl`, and `postgres`), and Git. Build the default
server, then start its local emulator:

```bash
git clone https://github.com/ELares/IronAuth.git
cd IronAuth
cargo build --locked -p ironauth --bin ironauth
env -u DATABASE_URL ./target/debug/ironauth dev --seed 1
```

The emulator creates a disposable PostgreSQL cluster and seeds a tenant,
environment, public OAuth client, test user, and development operator token.
It prints the scoped issuer, management address, and test credentials. Use the
printed issuer's `/.well-known/openid-configuration` endpoint to check discovery.
These deterministic credentials are for local development.

Set `PG_BIN` to the directory containing the PostgreSQL binaries if they are
not discovered automatically. Removing `DATABASE_URL` in the example ensures
the emulator owns its database; using an external database follows a different
setup path. The emulator does not enable the admin console. See the
[emulator guide](docs/EMULATOR.md) for ports, reset behavior, and that distinction.

To connect an app, follow a [tested quickstart](docs/INTEGRATIONS.md#quickstarts).
For the console or a persistent deployment, follow
[server setup](docs/OPERATIONS.md) and [console setup](docs/ADMIN-CONSOLE.md).

## Build and contribute

```bash
cargo build --locked -p ironauth --bin ironauth
scripts/gate.sh > gate.log 2>&1
```

The default server and most crates support Rust 1.85. The optional WASM hook
engine requires Rust 1.95. A whole-workspace build includes that engine even
when the server's `wasm-hooks` feature is disabled. The pinned development
toolchain satisfies both; see the generated
[artifact compatibility matrix](docs/COMPATIBILITY.md).

The console's current dependency tree requires Node
`^22.22.2 || ^24.15.0 || >=26.0.0`. Follow the
[SPA development guide](packages/admin-spa/README.md) when changing browser code.
The local gate checks compilation, formatting, Clippy, tests, security
invariants, generated contracts, and documentation freshness. Read
[CONTRIBUTING.md](CONTRIBUTING.md) before opening a change.
The full gate also uses Node and npm to build the TypeScript hook test fixture
from source. For direct integration tests, run
`scripts/build-ts-hook-fixture.sh` first; ordinary Rust builds use no Node tools.
See [security scanning](docs/SECURITY-SCANNING.md) for scanner coverage and
reviewed dependency exceptions.

## Repository layout

| Path | Contents |
| --- | --- |
| [crates/](crates/) | Rust server, management and protocol APIs, workers, storage, and supporting libraries. |
| [packages/](packages/README.md) | Admin SPA, custom hosted-page reference app, TypeScript SDK/BFF helpers, MCP implementations, and sample resource server. |
| [sdks/](sdks/) and [clients/](clients/) | Generated Go/Python management clients, Java/.NET token verifiers, a reference client, and mobile samples. |
| [docs/](docs/README.md) | User guides, generated contracts, security references, and operator runbooks. |
| [charts/ironauth/](charts/ironauth/README.md) and [deploy/](deploy/) | Helm chart, packaging, configuration examples, and conformance infrastructure. |
| [scripts/](scripts/) | Local gate, generators, structural audits, quickstart checks, and benchmarks. |
| [terraform-provider-ironauth/](terraform-provider-ironauth/) | Management API provider; current resource coverage is limited to tenants. |
| [fuzz/](fuzz/README.md) and crate-local fuzz directories | Parser and protocol fuzzing harnesses. |

## Project commitments

No paywalled security features, no mandatory first-party infrastructure, and
no unexportable data. Read the [covenants](COVENANTS.md),
[security policy](SECURITY.md), [threat model](docs/THREAT-MODEL.md),
[deliberate refusals](docs/WILL-NOT-IMPLEMENT.md), and
[exit guide](docs/exit-guide.md) for the commitments and their boundaries.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your
option. See [LICENSE](LICENSE) and the licensing commitments in
[COVENANTS.md](COVENANTS.md).
