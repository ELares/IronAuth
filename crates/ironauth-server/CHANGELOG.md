# ironauth-server changelog

All notable changes to the `ironauth-server` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

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
