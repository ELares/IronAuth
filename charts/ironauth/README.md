# IronAuth Helm chart

This chart deploys the IronAuth server on Kubernetes. Its default shape is three
replicas with node spreading, a disruption budget, no service-account API token,
and non-root containers with a read-only root filesystem and a writable `/tmp`.
It publishes only the public data plane. PostgreSQL is required and is not
installed by this chart.

The chart does not apply migrations, install an ingress, terminate TLS, create a
tenant, or enable the admin console. OIDC is off by default. The steps below
turn a server installation into a provider; see the
[operations guide](../../docs/OPERATIONS.md) for persistent setup and recovery.

## Prerequisites

1. A reachable PostgreSQL database with the out-of-band roles `ironauth_app`,
   `ironauth_control`, and `ironauth_audit_retention`. Application and control
   credentials are separate and restricted; migrations use a separate privileged
   credential.
2. The schema applied with the binary version you are deploying:
   `ironauth migrate --url "$MIGRATION_DSN"`. `serve` does not migrate on boot.
3. A stable envelope master key and bootstrap operator token in Kubernetes
   Secrets. Without the master key, encrypted login and user paths fail closed.
4. A server image available to your cluster. The default repository is
   `ghcr.io/elares/ironauth`; an empty image tag uses the chart's `appVersion`.
   Select an actually published artifact or supply your own image. See
   [release/image verification](../../docs/RELEASING.md).
5. An external origin and TLS termination suitable for your clients. The port
   names 8443 and 9443 do not enable TLS in the binary.

## Install a provider

The following commands run from the repository root. The example files
`/secure/master-key` and `/secure/bootstrap-operator-token` contain secrets you
provisioned, not example constants. Avoid trailing newlines in those files when
the secret value must match another deployment. Provision them through your
secret manager or create the referenced Kubernetes Secret:

```sh
kubectl create namespace ironauth --dry-run=client -o yaml | kubectl apply -f -
kubectl -n ironauth create secret generic ironauth-runtime \
  --from-file=master-key=/secure/master-key \
  --from-file=bootstrap-operator-token=/secure/bootstrap-operator-token
```

Create a protected values file. The example DSNs must be replaced with the real
application and control credentials. They are rendered into a Kubernetes Secret
and remain sensitive in the values file and Helm release state.

```yaml
# provider-values.yaml
server:
  publicUrl: https://id.example.com
database:
  url: postgres://ironauth_app:REPLACE_ME@postgres:5432/ironauth
  masterKey:
    existingSecret: ironauth-runtime
    key: master-key
admin:
  controlDatabaseUrl: postgres://ironauth_control:REPLACE_ME@postgres:5432/ironauth
  bootstrapOperatorToken:
    existingSecret: ironauth-runtime
    key: bootstrap-operator-token
oidc:
  enabled: true
```

```sh
chmod 600 provider-values.yaml
helm upgrade --install ironauth charts/ironauth \
  --namespace ironauth --values provider-values.yaml --wait --timeout 5m
kubectl -n ironauth rollout status deployment/ironauth
```

The literal control DSN in this generated-config mode produces the server's
literal-secret warning. For out-of-band control DSNs, dashboard settings, or
other advanced configuration, use the complete configuration Secret mode below.
The chart offers no literal master-key or operator-token values: those are
Secret references only.

Reach the private management plane using a loopback port-forward:

```sh
kubectl -n ironauth port-forward deployment/ironauth 9443:9443
```

In another terminal, use a local copy of the same bootstrap token to create the
first tenant as shown in [operations](../../docs/OPERATIONS.md#bootstrap-a-tenant-and-verify-the-provider).
The response supplies the tenant and first environment IDs; verify discovery
at `https://id.example.com/t/<tenant_id>/e/<environment_id>/.well-known/openid-configuration`.
The root is not the environment discovery endpoint.

Configure ingress separately to reach the data-plane Service and terminate TLS.
For development access, `kubectl -n ironauth port-forward service/ironauth 8443:8443`
forwards HTTP. The configured public origin must still agree with what the client
uses, including scheme and port; port-forwarding alone does not rewrite issuers.
On a single-node local cluster, set `replicaCount: 1` if one replica is intended.

## Complete configuration Secret

Set `database.existingConfigSecret` to supply a full server configuration. The
chart then renders no configuration Secret of its own and mounts yours at
`/etc/ironauth`. It must contain the key `ironauth.toml`. This is the way to
configure capabilities for which the chart has no first-class values, including
the admin console, headless flows, provider adapters, and worker settings.

For example, prepare a protected `ironauth.toml` following
[operations](../../docs/OPERATIONS.md#configure-a-persistent-deployment), using
the pod bind addresses `0.0.0.0:8443` and `0.0.0.0:9443`. For the control DSN,
use a file reference inside that mount:

```toml
[admin]
control_database_url = { file = "/etc/ironauth/control-dsn" }
bootstrap_operator_token = { env = "IRONAUTH_BOOTSTRAP_OPERATOR_TOKEN" }
```

```sh
kubectl -n ironauth create secret generic ironauth-config \
  --from-file=ironauth.toml=/secure/ironauth.toml \
  --from-file=control-dsn=/secure/control-dsn
helm upgrade --install ironauth charts/ironauth --namespace ironauth \
  --set server.publicUrl=https://id.example.com \
  --set database.existingConfigSecret=ironauth-config \
  --set database.masterKey.existingSecret=ironauth-runtime \
  --set admin.bootstrapOperatorToken.existingSecret=ironauth-runtime \
  --wait --timeout 5m
```

In this mode, the values do not merge runtime settings into the supplied file.
Put `database.master_key = { env = "IRONAUTH_MASTER_KEY" }`, OIDC enablement,
the actual public URL, and every desired runtime setting in your TOML. The
master-key and bootstrap-token values above only inject the corresponding
environment variables into the pod. Keep chart bind values consistent with the
file so Service targets and probes address the correct ports.

The chart still requires `server.publicUrl` when using an existing Secret.
Updating an external configuration Secret does not automatically change the
Deployment checksum or make a running process reload configuration. After an
intentional Secret update, restart the Deployment and watch its readiness:

```sh
kubectl -n ironauth rollout restart deployment/ironauth
kubectl -n ironauth rollout status deployment/ironauth
```

For console provisioning and its OIDC bridge, follow
[admin console setup](../../docs/ADMIN-CONSOLE.md). Enabling the shell alone
does not configure login or grant an operator access.

## Ports, probes, and network boundaries

| Plane | Default pod port | Service exposure |
| --- | --- | --- |
| Data: protocols, hosted pages, enabled `/admin/` console | 8443 | Public-plane Service only. |
| Management: `/v1/*`, `/healthz`, `/readyz`, `/metrics` | 9443 | No Service; pod probes, controlled scraping, or port-forward. |

Both planes bind all pod interfaces so kubelet probes can reach management.
Use NetworkPolicy and controlled scrape access to restrict it; the chart does
not create that policy. `/healthz` only proves the process is serving.
`/readyz` uses the serving database pool and returns 503 for unreachable or
unmigrated storage. Optional-component degradation remains HTTP 200 so it does
not remove a usable provider from the Service. Inspect the body and logs as well
as the pod's Ready status.

## Optional accelerators

IronAuth is complete on PostgreSQL alone. `ironbus.enabled: false` renders no
broker setting. To configure broker wakeups, set `ironbus.enabled: true` and a
nonempty `ironbus.addr`; this writes `outbox.ironbus_addr`. The selected server
image must also have been built with the `ironbus` feature. An unreachable or
uncompiled backend falls back to PostgreSQL polling. IronBus never replaces the
durable outbox, and the chart does not install the broker.

There is no IronCache chart value. `hot_state.ironcache_addr` exists and
participates in readiness, and the library has accelerator implementations and
JWKS read call sites. The shipped server does not attach a `HotState` backend,
so those call sites are inert even when the backend feature is compiled. To
configure reachability monitoring alone, put `[hot_state]` in a complete
configuration Secret; this does not enable acceleration.

## Rendering and validation

Rendering refuses an empty `server.publicUrl`, an absent database URL/configuration
Secret, or enabled IronBus with no address. It does not validate every runtime
prerequisite: supply both the control DSN and operator token to mount management,
and apply migrations before serving protocols. TOML configuration validation and
the server's startup logs remain authoritative.

From the repository root:

```sh
helm lint charts/ironauth --values provider-values.yaml
scripts/helm-chart.sh
```

The script needs Helm and Python with PyYAML. It checks rendered hardening,
probe targets, the Secret rather than ConfigMap, the unpublished management
plane, replica spreading, optional accelerator defaults, OIDC enablement,
bootstrap token indirection, invalid-value refusals, and `appVersion` consistency.
Rendering a real values file reveals its DSNs; treat rendered output as secret.

See [values.yaml](values.yaml) for all supported chart settings. Custom arbitrary
values are not passed through to the binary, and an environment variable named
after a configuration field is not a runtime override.
