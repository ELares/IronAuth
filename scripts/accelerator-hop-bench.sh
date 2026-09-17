#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# WHAT A HIT AGAINST THE IRONCACHE TIER COSTS (issue #146).
#
#     IRONCACHE_ADDR=127.0.0.1:17379 scripts/accelerator-hop-bench.sh
#
# This is the number every wiring decision in `docs/UNIT-COSTS.md` turns on, and it was the one
# nothing measured. That document could price a scoped read (166 us) and a hit against the
# Postgres-backed tier (145 us, because `HotStateRepo::get` is itself a scoped read), and from
# those two alone the seam looks pointless: thirteen per cent for a cache. The missing figure is
# what a hit costs when the tier is genuinely a different store.
#
# # What this measures, and what it does not
#
# One `GET` of a 512-byte value over loopback TCP on a single connection, against an IronCache
# server the caller started. One connection because that is the shape a pooled client has; the
# handshake is paid once and every iteration is a round trip.
#
# It is a protocol round trip, NOT the Rust client's cost. `ironauth-hot`'s IronCache backend
# goes through the `redis` crate, which adds its own encoding and connection handling on top.
# So this is a FLOOR for that path, and it is labelled as one rather than as the client's
# latency. A floor is the right shape here: the argument is that the hop is small compared with
# 166 us, and a floor that is already small settles it.
#
# It measures a HIT. A miss costs this plus the read it failed to avoid plus the write-back, and
# the hit rate is a property of a deployment rather than of the software.
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel)" || {
    echo "::error::accelerator-hop-bench: not inside a git repository" >&2
    exit 1
}
cd "$ROOT" || exit 1

ADDR="${IRONCACHE_ADDR:-}"
if [ -z "$ADDR" ]; then
    echo "accelerator-hop-bench: set IRONCACHE_ADDR to host:port of a running IronCache" >&2
    echo "  The CI lane installs one; locally:" >&2
    echo "    cargo install --locked --git https://github.com/ELares/IronCache ironcache" >&2
    echo "    ironcache server --port 17379 --metrics-addr off &" >&2
    exit 1
fi

ITERATIONS="${HOP_ITERATIONS:-20000}"
WARMUP="${HOP_WARMUP:-2000}"

# A HAND-ROLLED RESP CLIENT, so this script depends on nothing but python3. Adding a redis
# library would make the benchmark's availability depend on a package the repo does not
# otherwise need, and the protocol here is four lines.
python3 - "$ADDR" "$ITERATIONS" "$WARMUP" <<'PY'
import socket, sys, time

addr, iterations, warmup = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
host, _, port = addr.rpartition(":")
try:
    connection = socket.create_connection((host, int(port)), timeout=10)
except OSError as error:
    print(f"::error::accelerator-hop-bench: cannot reach IronCache at {addr}: {error}")
    raise SystemExit(1)
# TCP_NODELAY, because Nagle would batch these tiny requests and measure the delayed-ack timer
# rather than the server. A real client sets it for the same reason.
connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


def command(*parts):
    out = f"*{len(parts)}\r\n".encode()
    for part in parts:
        raw = part.encode() if isinstance(part, str) else part
        out += b"$%d\r\n" % len(raw) + raw + b"\r\n"
    connection.sendall(out)
    return connection.recv(65536)


# THE KEY SHAPE `ironcache.rs` BUILDS: {namespace}:{tenant}:{env}:{use}:{key}. A shorter key
# would measure a smaller request than the code sends.
key = "ironauth:t1:e1:introspection:k5000"
value = b"v" * 512
if not command("SET", key, value).startswith(b"+OK"):
    print("::error::accelerator-hop-bench: the server refused the seed SET")
    raise SystemExit(1)

# ASSERT THE HIT IS A HIT before timing it. A GET that misses returns a null bulk string and is
# CHEAPER than a hit, so timing a miss would publish a smaller number under a label that says
# hit. This is the degenerate case the figure has to be protected from.
probe = command("GET", key)
if probe.startswith(b"$-1") or not probe.startswith(b"$"):
    print("::error::accelerator-hop-bench: the seeded key did not read back as a hit")
    raise SystemExit(1)

for _ in range(warmup):
    command("GET", key)

started = time.monotonic()
for _ in range(iterations):
    command("GET", key)
micros = (time.monotonic() - started) * 1_000_000 / iterations

print("accelerator-hop-bench: host")
print(f"  address     {addr}")
print(f"  iterations  {iterations} GETs after {warmup} warm-up")
print(f"  value       {len(value)} bytes, key {len(key)} chars")
print()
print(f"accelerator-hop-bench: one IronCache GET hit costs {micros:.1f} us")
print("accelerator-hop-bench: a protocol round trip on one connection, so a FLOOR for the")
print("accelerator-hop-bench: `redis`-crate path ironauth-hot actually uses, and a hit rather")
print("accelerator-hop-bench: than a miss.")
PY
