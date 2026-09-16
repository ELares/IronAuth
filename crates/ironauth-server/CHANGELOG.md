# ironauth-server changelog

All notable changes to the `ironauth-server` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- `/readyz` now SPEAKS THE DATABASE PROTOCOL rather than opening a socket (issue #149).
  `ReadinessProbe::with_database_probe` takes a `DatabaseProbe` and readiness asks it for a
  real query; without one the socket check remains and the body reports `probe=socket-only`
  so the weaker answer cannot pass for the stronger.

  BREAKING for direct users of the enum: `Readiness::Ready` now carries a `ProbeDepth` and
  `Readiness::Degraded` carries one alongside its tier. A new `Readiness::SchemaNotReady`
  answers 503 with `not ready: schema not migrated`, kept separate from
  `not ready: database unreachable` because the two page different people. The healthy body
  is unchanged (`ready`), and `not ready: database address unreachable (provisional check
  until #7)` loses its stale reference to a long-closed issue.

- The observability middleware now stamps the POLICY-RESOLVED client IP on
  `PEER_IP_HEADER` for the off-by-default peer-IP session binding (issue #32). It
  `insert`s (never appends), REPLACING any value a client supplied, so the downstream
  binding reads what the trusted-proxy policy resolved and a spoofed header cannot
  survive.

- Add `Server::mount_public` (issue #12): mount a self-contained router on the
  PUBLIC data plane, mirroring `mount_management`. The OIDC provider mounts here.
- Initial HTTP server skeleton on tokio + axum (see docs/adr/0001-http-runtime.md):
  - Dual-plane `Server`: a public data plane (`server.bind`) and a private
    management plane (`server.management_bind`) serving disjoint routes.
    Management: `GET /healthz`, `GET /readyz` (TCP reachability of the database
    address, provisional until issue #7), `GET /metrics` (Prometheus). Public:
    `GET /` and `GET /.well-known/security.txt` (embedded).
  - Graceful shutdown on `SIGTERM`/`SIGINT` draining in-flight requests within
    `server.shutdown_grace_secs`.
  - Observability: structured JSON logs with an async writer and ECS-friendly
    field names, a Prometheus recorder with route-template metric labels, and
    OTLP trace export behind the non-default `otlp` feature.
  - `Redacted<T>` typed redaction and a log-scrubbing test corpus.
  - Trusted-proxy policy: scheme, host, and issuer derive from config, never
    from headers; forwarding headers are honored only under an exact trusted-hop
    topology and fail closed (with a counter) on any ambiguity.
