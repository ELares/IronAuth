# ADR 0001: HTTP runtime and server stack

Status: accepted (M1, server-skeleton issue #5)

## Context

IronAuth is one stateless static binary that terminates behind a reverse proxy.
The server skeleton is the foundation every later endpoint inherits, so the
runtime choice is load-bearing: it must produce a static musl binary with no C
or TLS dependency on the default path, keep a low MSRV (1.85), and be the stack
the Rust ecosystem's middleware (tracing, metrics, tower) targets first.

The sibling Iron projects made different choices for different reasons:
IronCache is thread-per-core for cache throughput; IronBus uses a blocking model
for its durable log. Neither fits an IdP, whose work is I/O-bound request
handling (database round-trips, outbound token fetches) with modest per-request
CPU. Mirroring either would trade ecosystem fit for no benefit here.

## Decision

Use tokio (multi-threaded runtime) with axum (on hyper) and tower/tower-http.

- tokio multi-threaded runtime: the default work-stealing scheduler suits
  I/O-bound request handling; no thread-per-core partitioning.
- axum + hyper: the idiomatic hyper-based router; native `MatchedPath` gives
  route templates for low-cardinality metric labels and clean request spans.
- tower/tower-http: middleware is expressed as tower layers, which the
  observability and trusted-proxy layers reuse.
- No TLS crate. The server runs behind a terminating proxy; the request scheme
  derives from `server.public_url` per the trusted-proxy policy, never from a
  header. Pulling openssl (or any C-linked TLS) would break the musl static
  lane, so it is excluded from the default dependency path.
- OTLP trace export lives behind the non-default `otlp` feature (it pulls tonic
  and prost), so the default build and the musl static lane stay lean and
  protoc-free.

## Consequences

- The default build is pure Rust and links statically against musl; the CI
  musl lane builds `ironauth` with `musl-tools` and asserts a static binary.
- Request latency is measured through the `ironauth-env` clock seam, not
  `Instant::now`; tokio's internal timers are unaffected by that rule.
- Later endpoints add routes and tower layers to the existing routers; they do
  not reintroduce a TLS dependency on the default path (in-process TLS, if ever
  needed, would be a separate opt-in decision recorded in a new ADR).
- Adopting axum ties the crate to axum's extractor and `MatchedPath` APIs; a
  major axum bump is a tracked migration, not an incidental upgrade.
