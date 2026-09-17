<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# IronAuth capabilities

IronAuth implements an identity provider, management API, administration console,
hosted authentication pages, and background workers in one Rust server. PostgreSQL
is the primary store. This guide describes the code in this repository, including
the switches and limits that determine what a deployment actually exposes.

IronAuth is pre-1.0. Implemented protocol support does not imply OpenID Foundation
certification: the live OIDF runner is not provisioned in this repository. Read the
[conformance status and enforcement table](conformance/README.md) and
[profile matrix](conformance/MATRIX.md) before relying on a certification profile.

For setup, use [Operations](OPERATIONS.md). For console workflows, use
[Admin console](ADMIN-CONSOLE.md). The [documentation index](README.md) connects
these overview guides to the detailed contracts.

## Availability and configuration

Most capabilities compile into the normal server but require configuration,
credentials, or a registered resource before they serve useful traffic.
In particular, `oidc.enabled` defaults to `false`. Authentication defaults below
describe an OIDC-enabled deployment, not an empty configuration file.

| Surface | How it becomes available | Default |
| --- | --- | --- |
| OIDC provider and account APIs | Set `oidc.enabled`; configure the database, issuer URL, and scoped resources. | Off |
| Management API | Configure the management credentials and database roles; serve it on the management plane. | Requires credentials |
| Admin console at `/admin` | Set `admin_spa.enabled` and its management API connection settings. | Off |
| Headless JSON flows | Set `flows.enabled`. | Off |
| Hosted flow pages | Set `hosted_pages.enabled`; this is a separate browser cutover from the JSON flow switch. | Off |
| Inbound SCIM | Set `scim.enabled`; create an organization SCIM connection and credential. | Off |
| Outbound SCIM | Configure a push connection and set `scim_push.enabled` on a worker process. | Off |
| LDAP/AD synchronization | Configure an LDAP connector and set `ldap_sync.sweep_enabled`. | Off |
| Shared Signals transmitter | Set `ssf.enabled`; register authenticated receivers and streams. | Off |
| Google Cross-Account Protection receiver | Set `risc_receiver.enabled` and configure the trusted issuer, keys, audience, and Google connector. | Off |
| Reverse-proxy forward auth | Set `forward_auth.enabled` and configure ordered access rules. | Off |
| Message, webhook, flow-target, and SIEM delivery | Configure destinations and enable each subsystem's delivery worker. | Off |
| Scheduled user offboarding | Schedule an offboarding through the management API; `users.offboarding_worker_enabled` controls execution. | Worker on |
| Outbox retention | Configure `[outbox]`; `outbox.reap_enabled` controls terminal-row cleanup. | Worker on |

The authoritative keys, validation rules, defaults, and experimental acknowledgment
versions are in [CONFIG.md](CONFIG.md) and the generated
[configuration schema](config-schema.json). Unknown keys fail configuration load.
Use file or environment references for secrets instead of committing secret values.

### Optional build features

Cargo build features are different from the runtime switches above:

| Build feature on `ironauth` | What it adds | Runtime requirement or limit |
| --- | --- | --- |
| `wasm-hooks` | Wasmtime component hooks for token claims. | Requires Rust 1.95, the experimental `wasm-hooks` acknowledgment, and a registered hook. |
| `ironbus` | Optional IronBus wake-up notifications for the PostgreSQL outbox. | Set `outbox.ironbus_addr`; PostgreSQL remains authoritative and polling remains the fallback. |
| `otlp` | OpenTelemetry OTLP trace export. | Configure `telemetry.otlp_endpoint`; the default build does not include this exporter. |
| `ironcache` | The Redis-compatible IronCache hot-state backend. | Backend code exists, but the shipped server does not attach a `HotState` implementation. Setting the address does not activate request acceleration. |
| `testing` | Database test harness and observation accessors. | Test scaffolding; not a deployment capability. |

The normal binary and most libraries publish Rust 1.85 compatibility. The optional
hook runtime publishes Rust 1.95. See [COMPATIBILITY.md](COMPATIBILITY.md), the
[server manifest](../crates/ironauth/Cargo.toml), and the
[hot-state implementation status](../crates/ironauth-hot/src/lib.rs).

## Authentication and OAuth protocols

Use the environment's discovery document as the client contract. Issuers and JWKS
are scoped to a tenant and environment; several protocol endpoints, including
`/token`, are shared at the deployment root and recover the scope from the client
or credential. Do not construct all endpoint URLs by appending paths to the issuer.
The [router](../crates/ironauth-oidc/src/lib.rs) and
[discovery generator](../crates/ironauth-oidc/src/discovery.rs) define the served URLs.

| Capability | Implemented behavior and setup |
| --- | --- |
| OIDC authorization code | `/authorize` and `/token`, single-use codes, redirect and client binding, PKCE S256, nonce, authentication context, and UserInfo. Public clients use PKCE; confidential clients require it by default too. |
| Discovery | OIDC and OAuth authorization-server metadata, environment JWKS, supported grants, algorithms, scopes, and enabled legacy response modes. |
| Subjects and claims | Public or pairwise subjects, standard OIDC scope claims, requested claim handling, `acr`, `amr`, and authentication-time handling. |
| Refresh tokens | Rotating refresh families, replay/reuse handling, idle and absolute lifetimes, and consent rules for `offline_access`. Refresh issuance is on by default. |
| Client credentials | Confidential clients obtain access tokens for their service-account principal. This grant does not issue an ID token or refresh token. |
| JWT bearer grants | Exchange an assertion from a registered external issuer under configured subject mappings and scope bounds. Workload federation does not require a stored password. |
| Device authorization | RFC 8628 device codes and user codes, a scoped human verification page, explicit approval, and bounded polling. Allow the device grant on the client. |
| Token exchange | RFC 8693 subject and optional actor tokens, revalidation against current grant state, scope narrowing, registered audiences, and visible actor chains. |
| CIBA | Backchannel authentication, a scoped human approval page, and token polling. Poll is the advertised usable mode. Ping has schema profiles, queued notifications, and a consumer implementation, but no production profile writer or server worker wiring; push mode is refused. |
| PAR | RFC 9126 pushed authorization requests with single-use request references. Require PAR at the environment or client level when needed. |
| Resource indicators | RFC 8707 resource selection and registered resource-server audiences. |
| Rich authorization requests | RFC 9396 `authorization_details` validation and grant propagation. Configure the accepted authorization-detail types. |
| DPoP | RFC 9449 proof-of-possession handling and replay checks; optional server nonce enforcement. A plain bearer client remains supported unless its policy requires otherwise. |
| Client authentication | `client_secret_basic`, `client_secret_post`, and `private_key_jwt`; public clients use `none` only on eligible flows. Configure the client's allowed method and trusted keys. `client_secret_jwt` is recognized but always fails closed because client secrets are stored as irreversible digests. |
| Access-token formats | Signed RFC 9068 `at+jwt` by default; digest-backed opaque tokens can be selected by environment or resource server. |
| Revocation and introspection | RFC 7009 revocation and RFC 7662 active-state lookup for the caller's permitted token scope. |
| Logout | RP-initiated logout with exact registered return URLs, session termination, and optional asynchronous back-channel logout delivery. Enable the back-channel worker for actual notifications. |
| Dynamic client registration | RFC 7591 and RFC 7592 registration, read, update, and delete. Off by default; supports initial access tokens, registration policies, verification, and abuse controls. |
| Protected resource metadata | RFC 9728 metadata for registered hosted resources and MCP authorization discovery. |
| Legacy certification switches | ID-token-only, `code id_token`, `none`, `form_post`, session-management iframe, and front-channel logout are explicit opt-ins. They are not the recommended application defaults. |

Token signing defaults to Ed25519/EdDSA, with per-client signing selection and
environment key provisioning for legacy-compatible asymmetric algorithms. The
JOSE verifier's supported algorithm set is broader than the normal signing
selection; see [signing design](adr/0005-jose-signing.md) and
[verification design](adr/0004-jose-verification.md) rather than assuming every
verified algorithm is a selectable issuance algorithm.

Offline JWT validation checks a signature and claims, not current revocation.
Introspection observes grant revocation immediately; a resource server that only
validates a previously issued JWT can keep accepting it until `exp`. The default
access-token lifetime is 300 seconds. See [token formats](design/TOKEN-FORMATS.md)
and [agent revocation](agents.md#revocation-stated-plainly).

### Authentication methods and account self-service

| Capability | User experience and controls |
| --- | --- |
| Passwords | Native Argon2id hashing in a bounded hashing pool; imported foreign verifiers can be upgraded after successful login. Breached-password screening is on by default, using online HIBP or a configured offline corpus. |
| Passkeys | WebAuthn registration and authentication, discoverable credentials, conditional UI, user verification, related origins, and credential management. WebAuthn is on by default within the enabled provider. |
| Passkey-only accounts | Remove a password after fresh passkey authentication; the last-usable-method guard prevents losing the only sign-in method. |
| TOTP and recovery codes | Authenticator enrollment, verification, single-use recovery codes, and factor management. TOTP is on by default. |
| Email OTP and magic links | Passwordless verification flows with expiring, single-use credentials and delivery-provider integration. Both methods are on by default, but useful delivery requires a sender. |
| SMS OTP | Explicit opt-in, destination/country controls, send caps, cooldowns, conversion monitoring, and automatic route throttling. Off by default. |
| MFA and step-up | Factor orchestration and RFC 9470 authentication-context policies, including fresh authentication requirements for sensitive scopes. Global MFA is not required by default. |
| Remembered devices | Optional trusted-device enrollment, expiry, and immediate server-side revocation. Remembered MFA has a weaker context than a fresh MFA ceremony. |
| Recovery | Independent recovery policy, expiring recovery links, delay/cancel windows, notifications, and guards against replacing a stronger credential through a weaker factor. |
| Sessions | User-visible session lists, revoke one or other sessions, idle and absolute timeouts, optional peer/device binding, and management fleet revocation. |
| Linked identities | List, explicitly link after fresh reauthentication, and unlink upstream identities under the last-usable-method guard. Upstream email is not automatically trusted. |
| Connected applications | List remembered consents and revoke an application's consent with its refresh-family cascade. |
| Session tokenizer | Exchange an authenticated opaque session for a short-lived JWT using named templates and separate template JWKS; optional JWT session mode. Revocation and idle-timeout limits are documented in [session-tokenizer.md](session-tokenizer.md). |

The password policy defaults to a 15-code-point minimum for a sole-factor password,
an 8-code-point minimum when used as an MFA factor, Unicode acceptance, and no
composition rule or forced rotation. These are configurable policy defaults,
not a claim of NIST certification. See `[password_policy]`, `[password_hashing]`,
and the authentication keys in [CONFIG.md](CONFIG.md).

## Federation and enterprise onboarding

| Capability | Implemented scope |
| --- | --- |
| Declarative OIDC federation | Store a validated connector definition, credentials, claim mapping, and trust/capability settings. A generic connector and Google, Microsoft, Apple, and GitHub presets exist; GitHub uses its OAuth user/email API path. Enable the federation runtime and configure provider credentials. |
| Enterprise routing | Organization connections, verified-domain routing, routing rules, and per-client upstream token-capture permissions. |
| Upstream token retrieval | Authorized applications can retrieve captured upstream credentials for their own session under client and connection capability checks. Capture is an explicit permission. |
| Inbound SAML | IronAuth acts as a service provider: SP-initiated sign-in, HTTP POST assertion consumption, signed requests, SP metadata, pinned identity-provider keys, assertion validation, replay checks, and explicitly controlled IdP-initiated mode. |
| Self-service setup portal | Organization-scoped, expiring portal links and sessions with intent fences for OIDC/SAML setup, SCIM setup/testing, SSO testing, IT contacts, certificate renewal, and SAML response diagnostics. |
| Certificate operations | Replacement certificate pinning, configurable expiry sweeps, warnings, and IT-contact notification integration. |
| Inbound SCIM 2.0 | Public-plane, connection-scoped provisioning of users and groups, parsed filters, patch operations, bulk limits, schemas, service-provider metadata, and rotatable digest-backed credentials. |
| Outbound SCIM | Configured downstream connections, asynchronous push, reconciliation/resource state, credential references, and explicit worker activation. |
| LDAP/AD inbound synchronization | Read-only directory connectors, TLS/bind configuration, periodic sweeps, lifecycle and membership synchronization, and connector health. There is no LDAP write-back. |

Connector capabilities are deliberately machine readable. The management API
exposes `GET .../connectors/{connector_id}/capabilities`; the
[capability-matrix schema](capability-matrix.schema.json) describes **a federation
connector**, not the whole IronAuth platform. In particular, the default
`email_verified` trust is untrusted. See the
[connector schema](connector-schema.json), [presets](../crates/ironauth-connector/src/presets.rs),
and [federation runtime](../crates/ironauth-oidc/src/federation.rs).

Outbound SAML identity-provider service is deferred. An inbound SAML service
provider does not give IronAuth an outbound SAML IdP role.

## Identity lifecycle, migration, and portability

| Capability | What administrators can do |
| --- | --- |
| Tenants and environments | Create isolated environments within tenants, inspect them, and manage tenant suspend, resume, delete, restore, and purge lifecycle operations. Environment issuers, keys, credentials, and runtime data remain distinct. |
| Users | Create, inspect, update, transition lifecycle state, offboard immediately or on a schedule, correlate external IDs, and revoke a user's session fleet. Session-ending transitions cascade to the relevant grants. |
| Flexible identifiers | Register and remove typed login identifiers under environment-wide or organization-scoped uniqueness policies, with normalization and migration preflight. |
| Identity traits | Versioned JSON Schema traits, active-schema introspection, activation checks, progressive profiling, and worker-driven migrations with per-run violations. |
| Invitations | Provision pending-verification users, issue expiring single-use invitation links, inspect, resend, and revoke invitations. |
| Signup policy | Per-client schema-validated signup forms, registration controls, disposable-email checks, proof-of-work, waitlist policy, and optional fraud quarantine. |
| Bulk import | Stream newline-delimited identities into a resumable job. Stable record keys allow an interrupted run to re-present records without duplicating users; migration-run views expose progress and violations. |
| Source importers | Offline transforms for Keycloak realm exports, Auth0 user plus password-hash exports, Firebase exports with project hash parameters, SCIM-shaped users, and LDAP entries. Gap reports disclose unmapped source data. |
| Foreign passwords | Verify supported bcrypt, scrypt, PBKDF2, Argon2, Firebase modified-scrypt, SHA-crypt, and LDAP digest records under cost bounds; successful authentication upgrades to the native verifier. |
| Lazy inbound migration | Call a configured legacy credential verifier on demand, with request bounds and circuit-breaker state, then create or upgrade the local credential. |
| Identity export | Stream users, traits, lifecycle state, external IDs, tagged password verifiers, and supported factor material in the import record format. The export is authorized and audited. |
| Outbound lazy migration | A successor identity system can use the documented credential-verification contract to migrate away without forcing every user to reset a password. |

Start migrations with a validation-only importer pass and its gap report.
Registered WebAuthn passkey private keys are not exportable from authenticators;
the credential registry export must not be mistaken for portable passkey sign-in.
The [exit guide](exit-guide.md) specifies exported TOTP seeds, recovery-code hashes,
credential metadata, and other exclusions. See also
[migration tooling](skills/migrate-to-ironauth.md),
[user lifecycle](design/USER-LIFECYCLE.md), and [tenancy](design/TENANCY.md).

## Organizations, authorization, and machine identities

| Capability | Implemented policy model |
| --- | --- |
| Organizations and membership | Organization lifecycle, user and service-account memberships, contacts, project grants, administrative consent, and organization selection in authenticated flows. |
| Roles and groups | Per-organization named roles, group forests, membership, role assignment, ancestor-group inheritance, effective-role reads, cycle rejection, and configurable maximum group depth. |
| Permissions | An environment-level permission vocabulary, organization role-to-permission mappings, default roles, and optional access-token permission claims for registered resource servers. |
| Claim budgets | Bound permission-claim count and total token size without capping stored roles or permissions. Overflow policy can require the PDP instead of emitting a truncated authorization set. |
| AuthZEN PDP | Single and batch live permission evaluations and discovery over IronAuth's organization, group, role, and permission model. The Search APIs are deferred. |
| External authorization | Allowlisted, additive claim enrichment at issuance and an identity-fact/event contract for synchronizing an external fine-grained authorization system. There is no built-in Zanzibar/ReBAC engine. |
| Machine scope bounds | Per-client allowed OAuth scopes are a ceiling on what a machine grant may request. Scope allowlists do not replace RBAC permissions. |
| API keys and PATs | Service-account or organization API keys and user personal access tokens, with explicit scopes, one-time secret display, expiry, rotation, revocation, and machine issuance controls. |
| Workload federation | Trusted external issuers and subject mappings for JWT bearer grants. |
| Agent principals | Organization-scoped agents linked to a human, declared exact tool scopes, optional OAuth-client binding, auditable issuance/denial, suspension, and terminal revocation. |
| Reverse-proxy access | Forward-auth checks with ordered rules and configured proxy dialects, request matching, authentication requirements, headers, and rate limits. Off by default. |

Organization group inheritance is implemented. **Parent organization inheritance
and a combined `isEntitled` API are design work**, not runtime behavior; see
[the hierarchy/entitlement design record](design/ORG-HIERARCHY-AND-ENTITLEMENTS.md).
Use [coarse claims and a live PDP](design/COARSE-CLAIMS-FINE-PDP.md) to choose the
correct authorization boundary, and [agents.md](agents.md) for agent registration,
tool enforcement, suspension, revocation, and attribution limits.

## Flows, presentation, and administration

The administration console is a client of the public management API. Its
dashboard and scoped resource pages provide lists, detail views, explicit create
actions, lifecycle controls, diagnostics, and operational views; they do not
define a separate administration contract. See [Admin console](ADMIN-CONSOLE.md)
for the available pages, authentication model, and setup.

The flow engine represents a persisted interaction as typed nodes and messages,
consumed through JSON or hosted HTML. Built-in flows cover login, registration,
consent, MFA, recovery, profiling, federation, and organization selection.
Declarative journey artifacts add validated topology, guard predicates, reusable
subflows, templates, immutable versions, pins, and recorded-path replay. Journey
documents call built-in executors; they do not contain arbitrary authentication
code or replace the executor's security checks.

Presentation is configured as data: per-environment brands, typed design tokens,
light/dark variants, sanitized rich-text slots, raster logo/favicon uploads,
localized message bundles, and per-client signup forms. Custom challenge
components and signed HTTP flow targets provide extension seams. Target delivery
requires its worker and supports dead-letter inspection and replay.

See [FLOWS.md](FLOWS.md), the generated [flow schema](flow-schema.json),
[journey schema](journey-schema.json), and
[journey artifact implementation](../crates/ironauth-journey/src/lib.rs).
The management contract is [OpenAPI 3.1](openapi/management.json), with opaque
cursor pagination, request idempotency, rate-limit information, and audited
mutations. Use the current contract to check exact operations rather than
assuming every resource supports every CRUD verb.

## Security, events, and operations

| Capability | What it provides and what to configure |
| --- | --- |
| Tenant isolation | Typed scoped identifiers, scope-only repositories, forced PostgreSQL row-level security, and distinct control/data-plane database roles. |
| Secret storage | Per-tenant/environment key hierarchy, sealed sensitive values, secret references, storage rekey tooling, and recovery procedures. The master key remains an operator-managed deployment secret. |
| Outbound fetch hardening | Address validation, DNS pinning, redirect refusal, size/time bounds, and one shared outbound dispatcher for supported integrations. These controls do not make an unreachable private callback reachable. |
| Authentication abuse controls | Bounded hashing work, tenant/environment quota admission, escalating failure regulation, durable bans, proof-of-work, signup controls, and SMS pumping limits. |
| Risk decisions | Optional explainable new-device, travel, IP, and velocity inputs; configurable step-up thresholds and notifications. The risk engine is off by default, and scoring without an enforcing policy is observation. |
| Recovery and admin safeguards | Recovery delay/cancel and downgrade guards, fresh-authentication checks, optional sudo freshness, and attributed impersonation. Sudo does not add an independent factor to a stolen management bearer. |
| Audit and diagnostics | Same-transaction mutation audit, audit verification, scoped event reads, safe client-auth diagnostics, policy traces, flow inspector/dry-run, risk decisions, and warnings. Retention and verbosity are configurable. |
| Ordered event feed | Cursor-based committed domain events for synchronization, reconciliation, SIEM, and metering. Retention expiry is explicit; truncated membership events require reconciliation. |
| Webhooks | Event subscriptions, signed outbound deliveries, event-type selection, attempts, pause/resume, secret rotation, failure disabling, dead letters, and replay. Enable the delivery worker. |
| SIEM streams | Scoped audit shipping to HTTP, S3, Datadog, and Splunk sinks, optional signed batches and attestations, durable cursor progress, dead letters, and replay. Enable `log_streams.shipping_enabled`. |
| Shared Signals | SSF stream CRUD/status/verification/subject management, signed CAEP/RISC SETs, push delivery and RFC 8936 polling. Management authentication currently supports `client_secret_basic`; the receiver supplies the audience. |
| Cross-Account Protection | Verify Google's RISC SETs and apply configured session/trusted-device revocation for identities linked to the configured connector. This is a specific receiver integration, not a general RISC policy engine. |
| Transactional workers | PostgreSQL outbox, independent lease-based claims, bounded retry/dead-letter behavior, per-aggregate ordering, queue health, and optional IronBus wake-ups. |
| Observability | Structured scrubbed logs, Prometheus metrics, management-plane health/readiness, graceful shutdown, and optional OTLP traces. |
| Deployment tooling | Docker Compose, Helm, a Debian package with systemd unit, static musl build/release lanes, database migration commands, preflight `doctor`, and storage recovery/rekey tools. |
| Config as code | Secret-free snapshots, promotion plan/diff/apply, CLI validate/plan/apply/drift, named target-environment secret resolution, and drift inspection. |
| Integration tooling | TypeScript verification/protocol utilities, Node BFF middleware, framework quickstarts, generated management SDKs, CLI/TUI tools, MCP servers, and a Terraform provider. Consult each artifact's scope and compatibility before adopting it. |

For reliable reconciliation, use the [events contract](EVENTS.md), not webhook
delivery as a change ledger; [EVENTS-VS-WEBHOOKS.md](EVENTS-VS-WEBHOOKS.md) explains
the difference. [Signed log-stream verification](log-stream-verification.md)
documents integrity, replay handling, vendor payload wrapping, and the current
gap-detection limitation.

Config snapshot coverage and promotion coverage differ. The engine currently
applies `resource_server`, `dcr_policy`, `variable`, `brand`, `locale_bundle`,
`flow_version`, and `message_template`. Clients, signup forms, and federation
resources also export for diff/review but are not applied by promotion. Read the
[snapshot contract and exclusions](snapshot/README.md#exported-is-not-the-same-as-promoted)
before planning an environment copy. A snapshot excludes users, sessions,
private keys, secret values, and other runtime/environment-identity resources.

Customer-managed BYOK has store/KMS foundations but **is not wired into the
server**. Non-default `[byok]` configuration is refused at startup. Do not
represent those settings as active customer key protection; see
[CONFIG.md](CONFIG.md), [key recovery](KEK-RECOVERY.md), and
[the BYOK design record](design/BYOK-AND-SHREDDING.md).

See [Operations](OPERATIONS.md), [release procedures](RELEASING.md),
[retention](design/RETENTION.md), [performance methodology](PERFORMANCE.md), and
[unit-cost measurements](UNIT-COSTS.md). Health checks, runtime metrics, tests,
and benchmarks are evidence for their measured cases, not a universal throughput
or availability guarantee.

## Experimental and exploratory capabilities

Every feature below defaults off and requires `enabled = true` plus the **exact
current acknowledgment version** under `[features.<name>]`. Find that version and
the owning changelog in the [feature maturity ladder](CONFIG.md#feature-maturity-ladder).
Acknowledgments intentionally fail after incompatible revisions. Enable only the
surface whose contract and limitations you have reviewed.

| Feature name | Current scope and material limits |
| --- | --- |
| `wasm-hooks` | In-process claim-shaping components with capability, fuel, memory, deadline, and host-resource limits. Requires the Cargo feature and Rust 1.95; the WIT interface may change. |
| `custom-domains-acme` | Custom-domain/ACME foundations, domain verification and encrypted certificate storage. Live issuance requires provisioned CA/domain infrastructure; the operational model is exploratory. |
| `fedcm` | IdP config, accounts, assertion, and Login Status surfaces. Browser integration remains exploratory; redirect flows are unaffected. Read [fedcm.md](fedcm.md) for browser-test status. |
| `client-id-metadata-documents` | Resolve URL client IDs using bounded HTTPS metadata fetches and domain trust/quarantine rules. It changes the registration trust model and tracks a draft. |
| `first-party-challenge` | Browserless first-party native authentication that issues a code for the normal token endpoint. Draft protocol, distinct from the permanently refused ROPC grant. |
| `global-token-revocation` | Strongly authenticated subject-scoped revoke-everything receiver. Draft wire contract. |
| `risk-signals` | Signed third-party SET ingestion feeding weighted risk inputs. A signal is not an authorization verdict. |
| `signup-quarantine` | Review queue for risky registrations with restricted authorization until release, rejection, or extension. |
| `advanced-recovery` | Admin review, trusted-contact confirmation, and external IDV-gated recovery through the delay/downgrade guard. IronAuth does not verify identity documents itself. |
| `org-scoped-clients` | Organization ownership schema/model for OAuth clients. This does not establish complete organization client CRUD or hierarchy inheritance. |
| `agent-token-vault` | Sealed downstream credentials, declared agent connection bounds, configured provider refresh, and human approval for sensitive exchanges. Makes IronAuth the custodian of third-party credentials. |
| `native-sso` | Mobile app token/device-secret pair exchanged through RFC 8693. The device secret is a bearer credential, not a hardware/device binding. See [native SSO](experimental/native-sso.md). |
| `identity-chaining` | Receiving-side ID-JAG checks layered on JWT bearer grants. No requesting side; process-global flag and per-issuer trust limits apply. See [identity chaining](experimental/identity-chaining.md). |
| `transaction-tokens` | Short-lived internal request tokens under a configured trust domain. No replacement flow; authorization data contains narrowed scopes. See [transaction tokens](experimental/transaction-tokens.md). |
| `attestation-client-auth` | Attester-configured client attestation and possession proof. Proof `jti` replay recording is not wired. See [attestation auth](experimental/attestation-client-auth.md). |
| `authzen-agent-profile` | Agent tool decisions intersect declared tools with the linked human's organization permissions. IronAuth-specific composition, not a claim of draft-profile conformance. See [agent profile](experimental/authzen-agent-profile.md). |
| `access-request-approval` | Time-boxed request/decision records and separation of duties. Management effective-role reads can display the grants, but token issuance and AuthZEN decisions do not consume them. |
| `device-posture-policy-hooks` | Verify signed MDM/EDR signals and evaluate CEL predicates. No data-plane grant/session/token enforcement calls this evaluator yet. |
| `admin-portal-widgets` | Read-only organization-scoped SSO/SCIM JSON with bearer-only authentication for a vendor's own frontend. Shape is exploratory. |

`sample-experimental` exists solely to exercise configuration acknowledgment; it
does not gate a product capability. The
[feature registry](../crates/ironauth-config/src/features.rs) is the source for
registered flags. Other exploratory WebAuthn options, such as Signal API and
conditional-create enrollment, have their own default-off OIDC settings and
browser support constraints.

## Deliberate exclusions and deferred work

The server does not offer ROPC, implicit **access-token** issuance, plain PKCE,
wildcard redirects, unsecured `alg: none`, or a public-token HMAC verification
path. Its authorization model does not include a Zanzibar/ReBAC engine, full IGA,
PAM, session recording, embedded JavaScript plugins, or a second primary database.
These are deliberate boundaries, not missing configuration.

JAR request objects and JARM response modes are not implemented by the current
provider registries. Do not infer them from the implemented PAR endpoint or
asymmetric JWT support. Similarly, the repository's conformance harness does not
establish FAPI certification. Outbound SAML IdP, LDAP write-back, a Kubernetes
operator, and several legacy protocol facades remain deferred. Read
[WILL-NOT-IMPLEMENT.md](WILL-NOT-IMPLEMENT.md) for the distinction between refusal
and deferral, and check implementation or an artifact changelog before treating
a design document or issue-tracker milestone as a shipped feature.
