# Running and operating IronAuth

IronAuth runs as one server binary with PostgreSQL as its required persistent
store. Protocol endpoints and user-facing pages use the public data plane;
administration, probes, and metrics use a separate management plane. Enabling a
listener does not automatically enable every protocol or the admin console.

Use the [capability guide](CAPABILITIES.md) to choose surfaces, the generated
[configuration reference](CONFIG.md) for exact settings and defaults, and the
[management OpenAPI contract](openapi/management.json) for administration.
IronAuth is pre-1.0; check the owning artifact's changelog before upgrading.

## Start locally

Install Rust using the repository's `rust-toolchain.toml` and install PostgreSQL
binaries, including `initdb`, `pg_ctl`, and `psql`. No running PostgreSQL service
is needed for the emulator. From the repository root:

```sh
cargo build --locked -p ironauth
env -u DATABASE_URL ./target/debug/ironauth dev --seed 1
```

Run this as an ordinary user because `initdb` refuses root. Set `PG_BIN` to the
directory containing your PostgreSQL binaries if they are not found automatically.
For example, a Homebrew PostgreSQL installation can be selected with
`PG_BIN="$(brew --prefix postgresql@17)/bin"` before starting the emulator.

The emulator starts on `http://127.0.0.1:8080`. Its output supplies the scoped
issuer URL, public client ID, loopback management URL, development operator token,
seeded user's credentials, and capture-sink URL. Copy the printed issuer URL;
discovery lives at `<issuer>/.well-known/openid-configuration`, not at the
deployment root. The admin console is not enabled by this command. See the
[emulator guide](EMULATOR.md) for login tests, deterministic secrets, cleanup,
and the current offline federation limitation.

To put the binary on your PATH instead of using `target/debug`:

```sh
cargo install --locked --path crates/ironauth
ironauth --version
```

The default server artifact supports Rust 1.85. Building the optional
`wasm-hooks` feature requires Rust 1.95 or newer, and runtime use also requires
the `wasm-hooks` experimental feature acknowledgment. The pinned development
toolchain may be newer than either minimum. Node is needed to develop or rebuild
the console; Rust builds use its committed embedded assets. See
[compatibility](COMPATIBILITY.md) and the
[console package guide](../packages/admin-spa/README.md).

## Configure a persistent deployment

Provision a PostgreSQL database and the three roles named by the migration
grants: `ironauth_app`, `ironauth_control`, and `ironauth_audit_retention`.
Migrations deliberately do not create these roles or assign passwords. Configure
credentials and database access with your database administrator. Runtime
application and control roles must not be superusers, schema owners, or have
`BYPASSRLS`; the application and control credentials are distinct.

Run the schema migration with a separately controlled migration credential that
can create and alter the schema and apply its grants:

```sh
ironauth migrate --url "$MIGRATION_DSN"
```

`serve` does not apply migrations. A fresh database receives the full chain;
upgrades defer contract migrations until an explicit operator decision. Do not
give the migration credential to serving processes.

Here is a minimal persistent-provider configuration. Replace the example URL
and application DSN, and provide each referenced secret to the process before
launch. The data-plane connection currently reads `database.url` directly: put
the full connection string there rather than relying on `database.password` to
override it. Keep the configuration file protected because it contains a DSN.

```toml
[server]
bind = "0.0.0.0:8443"
management_bind = "127.0.0.1:9443"
public_url = "https://id.example.com"
shutdown_grace_secs = 25

[database]
url = "postgres://ironauth_app:REPLACE_ME@db:5432/ironauth"
master_key = { env = "IRONAUTH_MASTER_KEY" }

[admin]
control_database_url = { env = "IRONAUTH_CONTROL_DSN" }
bootstrap_operator_token = { env = "IRONAUTH_BOOTSTRAP_OPERATOR_TOKEN" }

[oidc]
enabled = true
```

```sh
ironauth serve --config /etc/ironauth/ironauth.toml
```

The envelope master key is a stable, high-entropy secret held outside the
database. Without it, encrypted user and login paths fail closed. Losing it
cannot be repaired with a database backup. Unknown TOML keys abort startup;
arbitrary `IRONAUTH_*` environment variables are not a configuration overlay.
Only explicit `{ env = "..." }` and `{ file = "..." }` secret references are
resolved where the consuming path supports them.

`server.public_url` is the external origin used to construct issuers and
endpoints. Ports 8443 and 9443 do not imply TLS: the server's listeners are HTTP,
so terminate TLS in a reverse proxy or ingress. Configure the actual public URL
and proxy trust settings explicitly; defaults trust no forwarding headers.
Bind the management plane privately, or restrict it with network policy when
it must listen on pod interfaces.

## Bootstrap a tenant and verify the provider

The management API mounts only when a bootstrap operator token is configured
and the control-plane store can open. In production, an unset
`admin.control_database_url` prevents it from mounting. Setting only
`oidc.enabled` provides no tenant or environment to serve.

With a management connection on loopback, create your first tenant explicitly:

```sh
curl --fail-with-body http://127.0.0.1:9443/v1/tenants \
  -H "Authorization: Bearer $IRONAUTH_BOOTSTRAP_OPERATOR_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: first-tenant-v1' \
  --data '{"display_name":"Example","environment_display_name":"development","environment_kind":"dev"}'
```

The response contains `tenant.id` and `environment.id`. Creation provisions
the first environment and its signing keys in the same transaction. Save those
IDs as `TENANT_ID` and `ENVIRONMENT_ID`, then check the public issuer:

```sh
curl --fail-with-body \
  "https://id.example.com/t/$TENANT_ID/e/$ENVIRONMENT_ID/.well-known/openid-configuration"
```

Supply an `Idempotency-Key` for management POSTs whose public contract requires
one, including tenant creation. Naturally repeatable operations such as sudo
elevation document it as optional. Reuse a key only when replaying the identical
operation and body. Production environments have
additional guardrails, including a configured custom domain; use the typed
errors to correct those requirements rather than relabeling production as dev.

Provision users and scoped management credentials through the documented
management API. Register application clients through Dynamic Client Registration,
independently enabled with `oidc.registration_enabled`; its default exposure mode
requires an initial access token minted through management. Configure resource
servers through the supported snapshot/promotion path. The management API does
not currently offer generic client or resource-server creation endpoints. Neither
a bootstrap token nor an environment management credential is an end-user login
credential.

## Enable the dashboard and login screens

`admin_spa.enabled = true` serves the embedded console at `/admin/` on the public
plane. Console login additionally needs an admin issuer tenant and environment,
a public Authorization Code + PKCE client authorized for `openid ironauth.manage`,
a registered management resource audience, and an allowed operator subject. Configure
`admin_spa.admin_issuer_tenant`, `admin_spa.admin_issuer_environment`,
`admin_spa.console_client_id`, `admin_spa.management_audience`, and
`admin_spa.operator_subjects` with the provisioned values. Register the console's
redirect URL `<public_url>/admin/` on its client. An empty subject
allowlist authorizes nobody.

The console currently sends no DPoP proofs, so its public client must also have
`allow_bearer_tokens = true` set through the operator-only client bearer-token
posture endpoint. This explicitly exempts that client from the public-client
DPoP requirement and makes its access token a bearer credential. Follow the
[console setup guide](ADMIN-CONSOLE.md#enable-and-configure-sign-in) for the
exact management request, and keep this exception scoped to the console client.

The embedded console receives these non-secret identifiers from the server and
uses `/admin/api` as its same-origin management proxy. This proxy is armed only
when the admin OIDC bridge is configured, and verifies the exact issuer,
audience, and operator mapping. Do not place bootstrap or management bearer
tokens in browser configuration. See the
[console guide](ADMIN-CONSOLE.md) for the UI, authorization, and
embedded or standalone deployment.

End-user application sign-in starts through a registered client's OAuth
authorization request. The scoped `/login`, `/register`, and `/consent` pages
belong to that flow. The headless flow API (`flows.enabled`) and the hosted flow
render app (`hosted_pages.enabled`) are separate opt-ins; see
[the flow contract](FLOWS.md) and the integration quickstarts.

CLI sign-in stores its credential in the platform keychain and uses browser
loopback login where available, with device authorization as a fallback:

```sh
ironauth login --issuer "$ISSUER" --client-id "$CLIENT_ID" --account staging
ironauth logout --account staging
```

The client must permit the selected grant and redirect. `--device` and
`--loopback` choose the flow explicitly; `--redirect` supplies a loopback
redirect; `--force` requests a fresh login even when a usable credential exists.
`logout` clears local stored credentials; it does not claim to revoke every
remote session. The config-as-code CLI separately accepts its API URL and
bearer credential; it does not automatically consume the keychain entry.

## Deploy on Kubernetes

The [Helm chart guide](../charts/ironauth/README.md) has the install sequence and
the exact values. The chart creates the server Deployment, public Service,
ServiceAccount, configuration Secret, and disruption budget. It does not deploy
PostgreSQL, apply migrations, install an ingress, terminate TLS, or create a
tenant. Provision those prerequisites explicitly.

For advanced settings, including the dashboard, use a complete operator-owned
configuration Secret via `database.existingConfigSecret`. This avoids adding
settings to values that the chart does not read. The Secret must contain
`ironauth.toml`. You can include an additional `control-dsn` file and use
`control_database_url = { file = "/etc/ironauth/control-dsn" }` because the whole
Secret is mounted there. The chart only injects the master-key and bootstrap
token environment references that its documented values configure.

For a single-node development cluster, `replicaCount: 1` is an explicit choice;
the default is three replicas with node spreading and a disruption budget. A
local image must be made available to the cluster nodes, and the chart's
`image.repository` and `image.tag` must name that image. See
[release and image verification](RELEASING.md) before selecting a published image.

## Containers and the checked-in Compose files

`deploy/Dockerfile` packages an already-built, static Linux binary. Its build
context must contain that binary as `ironauth`; it does not compile Rust. Build
the artifact for the container's target architecture using the musl release
lane, then build the image with that artifact directory as the context:

```sh
docker build -f deploy/Dockerfile -t ironauth:local /path/to/artifact-directory
```

The scratch image runs as UID/GID 65532 and contains no shell, package manager,
or curl. Supply `serve --config PATH` arguments and a mounted configuration
when launching it. Its process cannot execute a shell-based healthcheck.

The checked-in `deploy/docker-compose.yml` currently describes a development
PostgreSQL and collector topology, not a working one-command full-provider
launch: its build expects a root-level prebuilt binary, its healthcheck calls
curl absent from the shipped image, and its bundled configuration leaves OIDC
and the management API disabled. The configuration also relies on the currently
unused database-password override. Use the emulator or the Helm sequence above
for a complete launch. The separate
[conformance Compose stack](../deploy/conformance/README.md) has its own
configuration and runbook.

## Observe readiness and diagnose a rollout

Probe the management plane, not the public Service:

```sh
curl --fail-with-body http://127.0.0.1:9443/healthz
curl --fail-with-body http://127.0.0.1:9443/readyz
curl --fail-with-body http://127.0.0.1:9443/metrics
```

| Probe result | Meaning and action |
| --- | --- |
| `/healthz` returns 200 | The process is serving; this does not prove a configured protocol is usable. |
| `/readyz` returns `ready` | The serving pool answered a database query and optional configured components answered. |
| `/readyz` returns 200 `degraded: <tier>` | An optional component is absent or unavailable. Traffic stays routed; inspect the body and component logs. |
| `/readyz` returns 503 `not ready: database unreachable` | Restore the serving database connection. |
| `/readyz` returns 503 `not ready: schema not migrated` | Apply the required schema before continuing the rollout. |
| Readiness includes `probe=...` | A weaker probe was used, such as a listener-only skeleton; verify which serving planes actually mounted. |
| Management `/v1/*` returns 404 | Check the bootstrap token, control DSN, and startup logs for a plane that did not mount. |
| Public discovery returns 404 | Check `oidc.enabled`, the scoped issuer path, tenant/environment state, and the data-plane startup logs. |
| `/admin/*` returns 404 or sign-in is unavailable | Check the console enable flag and its separate issuer/client/audience/subject configuration. |

JSON or text logs are selected by `telemetry.log_format`. OTLP export additionally
requires the `otlp` Cargo feature and `telemetry.otlp_endpoint`; setting an
endpoint on a binary without the exporter feature is insufficient. Prometheus
metrics stay on the private management plane. Audit APIs, event streams,
webhooks, and SIEM/log sinks are distinct surfaces; see
[events](EVENTS.md), [events versus webhooks](EVENTS-VS-WEBHOOKS.md), and
[log-stream verification](log-stream-verification.md).

## Background work and optional accelerators

Durable async work uses the PostgreSQL transactional outbox, with visibility
leases, retry bounds, dead-letter states, and per-aggregate ordering. Queue
concurrency and polling are per process and per consumer; size them with the
number of replicas and database capacity in mind. A stored configuration or
queued job does not prove its worker is enabled.

| Worker or service | Runtime setting or prerequisite |
| --- | --- |
| Scheduled user offboarding | `users.offboarding_worker_enabled`, on by default, plus control-plane scope enumeration. |
| Outbox retention | `outbox.reap_enabled`, on by default, plus control-plane scope enumeration. |
| Webhooks | `webhooks.delivery_enabled`, off by default. |
| Async flow targets | `flow_targets.delivery_enabled`, off by default. |
| Identity-trait migration | `traits.migration_worker_enabled`, off by default. |
| Outbound SCIM | `scim_push.enabled`, off by default; distinct from inbound `scim.enabled`. |
| SAML certificate expiry sweep | `certificate_expiry.sweep_enabled`, off by default. |
| Audit retention | `audit_retention.enabled`, off by default, with an `ironauth_audit_retention` DSN and control-plane enumeration. |

The configuration reference lists the remaining consumer switches, retention
windows, and bounds. The audit retention role is intentionally separate from
the application and control roles. A zero audit-retention window means keep
forever; do not assume every retention field interprets zero the same way.

IronBus is optional wake-up delivery for outbox workers; messages and processing
state remain durable in PostgreSQL. Build with `--features ironbus` to use the
broker backend, and configure `outbox.ironbus_addr`. Without the backend feature,
the configured wake path is unavailable and polling remains the fallback.

IronCache is also optional. The library provides hot-state backends and JWKS
call sites, and `hot_state.ironcache_addr` participates in readiness. The shipped
binary does not currently attach a `HotState` implementation to those read paths,
including when built with `--features ironcache`, so configuring reachability
does not enable request acceleration. PostgreSQL-only deployments are complete.

## Upgrade, back up, and recover

Before an upgrade, take a database backup and preserve the envelope master key
outside it. Test restoration of both in an isolated environment. Config
snapshots are secret-free exports of promotable environment settings, not
database or credential backups; see [snapshot format](snapshot/README.md).

Run the new binary's preflight against a superuser or a separately authorized
`BYPASSRLS` connection. The command refuses a restricted runtime or schema-owner
connection because forced row-level security could hide the rows it must inspect:

```sh
ironauth doctor --url "$DOCTOR_DSN"
ironauth migrate --url "$MIGRATION_DSN"
```

Read the migration report. If it stops before a contract migration, deploy and
observe the compatible schema before choosing either `--contract` or a soak:

```sh
ironauth migrate --url "$MIGRATION_DSN" --soak 24h
```

`--soak` needs a unit (`s`, `m`, `h`, or `d`) and at least 60 seconds. It checks
elapsed time recorded in the database when invoked; it is not a background
scheduler. `--contract` and `--soak` are mutually exclusive. Contract removal
can end compatibility with the previous binary. Rolling the image back does
not recreate removed data. The [release guide](RELEASING.md) covers the DEB and
systemd lifecycle; graceful shutdown uses SIGTERM/SIGINT and the configured
drain period.

Wrapped tenant-key backup and restore are available through
`ironauth storage kek-backup` and `kek-restore`. Store the backup manifest
separately and follow [KEK recovery](KEK-RECOVERY.md), including checks on every
recovered scope and the consequences of crypto-shred and older backups.

Signing-key lifecycle operations are documented in the management contract;
they are separate from the platform envelope master key. Platform
`storage rekey` is offline and rewraps KEKs without rebuilding blind indexes.
Changing key material is refused by default because identifier lookups would
stop matching. There is no shipped lookup-rebuild tool. Do not treat this
command as an online, complete master-secret rotation procedure.

For configuration changes, export a snapshot, run `ironauth validate`, and use
the server-computed `plan`, `apply`, and `drift` commands against an explicit
target. Supply `IRONAUTH_API_URL` and `IRONAUTH_TOKEN` or the documented flags;
inspect `ironauth plan --help` before applying. For identity migrations and
exports, see [the migration skill guide](skills/migrate-to-ironauth.md),
[user lifecycle](design/USER-LIFECYCLE.md), and [the exit guide](exit-guide.md).
