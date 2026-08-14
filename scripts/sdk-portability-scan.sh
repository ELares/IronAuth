#!/usr/bin/env bash
# Fail if a RUNTIME-PORTABLE SDK source imports a Node-only module (issue #115).
#
# The premise of the pure-WebCrypto core is that one published package runs unmodified on
# Node, Deno, Bun, Cloudflare Workers, and Vercel Edge. A `node:` import breaks exactly
# two of those and NOTHING else: it compiles, it type-checks, and it passes every test on
# Node, so it is invisible until it reaches a runtime nobody ran the suite on.
#
# The five-runtime CI matrix catches it eventually. This catches it in a second, and it
# catches it in a diff rather than in a job that takes minutes to provision five runtimes.
#
# SCOPE, deliberately narrow. Only `src/**` excluding tests:
#   * TEST files may use `node:crypto` freely. They run on Node under `node --test`, they
#     are never published, and forbidding them would push test authors toward worse
#     fixtures for no portability gain.
#   * `scripts/**` are BUILD tooling (vector generation, benchmarks). They run on Node by
#     definition and ship to nobody.
# What ships and must stay portable is the non-test source, and that is what this reads.
set -euo pipefail

cd "$(dirname "$0")/.."
pkg="packages/ironauth-sdk/src"

if [ ! -d "$pkg" ]; then
  echo "sdk-portability-scan: $pkg not found" >&2
  exit 1
fi

# `node:` covers every builtin specifier; the bare forms are the pre-`node:` spellings that
# still resolve on Node and still fail on Workers.
pattern="from[[:space:]]+['\"](node:[a-z_/]+|crypto|fs|path|os|buffer|stream|util)['\"]"

violations="$(
  find "$pkg" -name '*.ts' ! -name '*.test.ts' -print0 \
    | xargs -0 grep -nE "$pattern" 2>/dev/null || true
)"

if [ -n "$violations" ]; then
  echo "sdk-portability-scan: a Node-only import in a runtime-portable source file." >&2
  echo "  These compile and pass on Node, then fail on Workers, Deno, and Vercel Edge." >&2
  echo "  Use globalThis.crypto.subtle (WebCrypto) instead." >&2
  echo "$violations" >&2
  exit 1
fi

scanned="$(find "$pkg" -name '*.ts' ! -name '*.test.ts' | wc -l | tr -d ' ')"
echo "sdk-portability-scan: clean ($scanned portable sources, no Node-only imports)"
