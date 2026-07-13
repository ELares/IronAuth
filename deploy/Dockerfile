# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Two-stage build producing a static musl `ironauth` binary. The default path
# is pure Rust with no TLS or C dependency; the `otlp` feature is enabled here
# so the compose stack can export traces to the bundled collector (it stays
# protoc-free: opentelemetry-proto ships pre-generated code).

FROM rust:1.97-bookworm AS builder
WORKDIR /src
# musl-tools provides the musl cross-linker; the target is added through rustup
# so it honors the toolchain pinned by rust-toolchain.toml.
RUN apt-get update \
    && apt-get install -y --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add x86_64-unknown-linux-musl
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl -p ironauth --features otlp \
    && strip target/x86_64-unknown-linux-musl/release/ironauth

# Runtime: debian-slim (not scratch) so the compose healthcheck has curl. The
# static binary itself needs nothing from the base image.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 ironauth
COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/ironauth /usr/local/bin/ironauth
USER ironauth
# Public data plane only; the management plane binds to loopback (see config).
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/ironauth"]
CMD ["serve", "--config", "/etc/ironauth/ironauth.toml"]
