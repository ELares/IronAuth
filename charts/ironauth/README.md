# IronAuth Helm chart

Deploys IronAuth on Kubernetes. `helm install` with no values beyond the two
required ones gives a three-replica deployment, spread across nodes, with a
disruption budget, running non-root on a read-only root filesystem.

```console
helm install ironauth charts/ironauth \
  --set server.publicUrl=https://id.example.com \
  --set database.url='postgres://ironauth:PASSWORD@postgres:5432/ironauth'
```

## Two values are required, and the chart refuses to render without them

`server.publicUrl` is required because scheme, host and issuer derive from it and
never from request headers. A deployment that guessed the issuer from `Host`
would mint tokens under whatever hostname it was asked with, so there is no safe
default to fall back to.

`database.url` (or `database.existingConfigSecret`) is required for the obvious
reason. The chart also refuses an accelerator switched on with nowhere to reach,
because that reads as configured and is not.

## Why the config is a Secret

`database.url` carries the credential inline, and the config schema gives it no
environment indirection: the DSN has to reach the process inside the file. So the
chart renders `ironauth.toml` into a **Secret**, never a ConfigMap, and mounts it
`0400`. A chart that used a ConfigMap here would publish the database password to
anything able to read ConfigMaps in the namespace.

(`database.password` exists in the schema and is not a way around this. Nothing
reads it to build a connection.)

The envelope master key is different: it *does* have an environment indirection,
so it is referenced as `{ env = "IRONAUTH_MASTER_KEY" }` and sourced from a Secret
you supply. It never lands in the file at all.

## Two planes, one Service

| plane | port | published |
|---|---|---|
| data (protocol, hosted pages) | 8443 | yes, through the Service |
| management (`/healthz`, `/readyz`, metrics) | 9443 | **no** |

The management plane is reached on the pod IP, by kubelet probes and by a
Prometheus scrape. It has no Service on purpose: an identity provider that
publishes its own readiness and metrics to every in-cluster caller has exposed an
internal surface for nothing.

Both planes bind `0.0.0.0` inside the pod. The boundary is the Service and your
NetworkPolicy, not a loopback bind that would also stop the kubelet probing.

## Accelerators are absent, not merely disabled

IronAuth is complete on Postgres alone. With `ironcache.enabled` and
`ironbus.enabled` false (the default) the rendered manifests contain no
accelerator endpoint, no environment variable, and no reference to a service you
have not deployed. `scripts/helm-chart.sh` asserts that against the rendered
output, in both directions.

## What the gate checks

`scripts/helm-chart.sh` renders the chart and asserts properties of the OUTPUT,
because a value is not a property: `readOnlyRootFilesystem: true` in `values.yaml`
proves nothing if no template reads it. It covers the pod hardening, the probe
targets, the Secret-not-ConfigMap rule, the unpublished management plane, the HA
shape, both accelerator directions, the four refusals, and that `appVersion`
matches the workspace version.

## Values

See `values.yaml`; every key is commented with why it defaults as it does.
