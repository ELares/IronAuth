# Edge verification

Verifying an IronAuth token needs no IronAuth service, no SDK install, and no network call on
the hot path. This page is the runtime support matrix, the measured latency, and the
methodology behind it.

Ed25519 is IronAuth's default signing algorithm, and WebCrypto Ed25519 is now available in
every runtime that matters at the edge. That is what makes a copy-paste verifier possible at
all.

## Runtime support

Every row says how the claim is BACKED, because "supported" without that is an
assertion. Until issue #118's snippet conformance landed, this table said `yes` six times
on the strength of one runtime's test suite: the snippet ran only on Node, and the other
five rows were reasoning about what WebCrypto-only code ought to do.

| Runtime | Supported | Evidence |
|---|---|---|
| Node.js 20+ | yes | **measured**: the snippet runs the full conformance corpus in the `node` CI lane |
| Deno | yes | **measured**: same corpus, `deno` lane |
| Bun | yes | **measured**: same corpus, `bun` lane |
| Cloudflare Workers | yes | **measured**: same corpus, executed inside `workerd` (the real Workers runtime, not a Node shim) |
| Vercel Edge | yes | **by proxy**: covered by the `workerd` lane. Vercel Edge and Workers are both V8 isolates with the same WebCrypto surface, and no Vercel-hosted lane runs in CI. Treat this as a strong inference rather than a measurement |
| Lambda@Edge | yes | **by inference**: Lambda@Edge IS a full Node runtime, so the `node` lane covers it. The inference is sound because the runtime is the same, not merely similar |
| Fastly Compute | yes | **measured, with a stated limit**: `snippets/fastly-compute-verify` is a Rust snippet that runs the SAME conformance corpus under `cargo test`, and `cargo check --target wasm32-wasip2` proves it builds for the Compute target. It is NOT executed on Fastly in CI -- no Fastly lane exists -- so this is a conformance-and-builds claim, not a deployment one |
| **CloudFront Functions** | **no** | see below |

### Why Fastly needs its own file

Compute runs WebAssembly, so the WebCrypto snippet does not apply. Less obviously, IronAuth's
own verifier cannot be reused either: `ironauth-jose` is backed by `ring`, which does not build
for `wasm32`. That is why `snippets/fastly-compute-verify` exists as a fourth implementation of
one contract rather than a wrapper around the server's, and why it is judged against the shared
corpus rather than trusted for resembling it.

Take `src/lib.rs` and its three cryptography dependencies. It has no Fastly-specific imports:
the JWKS arrives as bytes and the clock as a number, so the same file runs under `cargo test`,
inside Compute, and anywhere else that builds for `wasm32`.

### CloudFront Functions is not supported

CloudFront Functions exposes only HMAC and digest primitives. It has no asymmetric
verification for any algorithm, so verifying a JWT signed with EdDSA, ES256 or RS256 is not
possible there. This is a platform limitation, not something a cleverer implementation gets
around.

**Use Lambda@Edge instead** on AWS. It runs a full Node runtime and the snippet works unchanged.

## Measured latency

Reproduce with one command:

```
cd packages/ironauth-sdk && npm run bench
```

Representative output, Node 24 on an arm64 laptop, captured on an OTHERWISE IDLE machine. That
qualifier is load-bearing: a first attempt at this refresh was taken while a full test gate was
running and reported p99s between two and five times higher (4.6x on EdDSA, 2.3x on each of the
others), which would have published a degraded machine's numbers as the software's. The range
rather than the worst row, because quoting only the 4.6x would be the same kind of hand-written
number about a measurement that this page is being corrected for.

THREE rows, one per algorithm the corpus accepts. An earlier revision listed two, because the
corpus carried two accepted algorithms when it was written and has carried three since RS256 was
added. The command derives its rows from the corpus, so the table and the corpus can disagree
only in the direction of the table being stale.

| Algorithm | p50 (ms) | p95 (ms) | p99 (ms) | max (ms) | ops/s |
|---|---|---|---|---|---|
| EdDSA | 0.067 | 0.080 | 0.087 | 0.227 | ~14,600 |
| ES256 | 0.080 | 0.099 | 0.148 | 0.287 | ~11,900 |
| RS256 | 0.053 | 0.066 | 0.122 | 0.497 | ~17,700 |

Sub-millisecond at p99 for all three, with EdDSA roughly 20 percent faster than ES256 on
throughput.

RS256 leads on p50, p95 and throughput, and trails on p99 and max, so "fastest" depends on which
column you read. Either way it is not a recommendation: this table measures VERIFICATION only,
which is the cheap half of RSA, since a public exponent of 65537 makes the modular exponentiation
short while signing cost, key size and token size all run the other way.

Nothing on this page is a reason to change an environment's signing algorithm. An earlier
revision of this sentence said EdDSA is the default BECAUSE it is fastest; nothing in the tree
states a performance rationale for that default, and the table above no longer supports one.

**These numbers are one machine, one runtime, one moment.** They reproduce on that machine and
are not a claim about yours. The benchmark prints the runtime and platform with every run so a
pasted table cannot lose its context.

## Methodology

What is timed: decode, algorithm allow-list check, key lookup against an already-warm cache,
signature verification, and claim validation.

- **The JWKS fetch is excluded.** A verifier fetches keys once per cache lifetime and verifies
  on every request. Folding a network round trip into a per-request figure would report a cost
  no production request pays. The first fetch happens during warmup, outside the timed region,
  exactly as a real process does it.
- **Key import is included.** The implementation imports the key per verification, so that is a
  real cost of this design and excluding it would flatter the result.
- **200 untimed warmup iterations** precede 2000 timed ones, so the measurement is steady state
  rather than first-call compilation.
- **A fresh key cache per algorithm**, so one subject cannot inherit another's warm state.
- **Percentiles, not a mean.** A p50 of 0.2 ms with a p99 of 40 ms is a bad verifier wearing a
  good average, and a mean would hide exactly what an edge operator cares about.
- **One vector per algorithm.** The conformance corpus holds five accepted vectors across three
  distinct algorithms, so two of the five are a second EdDSA case. Timing all five would print
  near-identical rows and imply the table measured more than it did.

## Correctness comes first

Latency is the easy half. A verifier that is fast and wrong is worse than no verifier, so both
the SDK core and the copy-paste snippet are judged against the same conformance corpus at
`packages/ironauth-sdk/vectors/verify-vectors.json`: nineteen vectors, fourteen of them
refusals, including `alg: none`, an HS256 forgery keyed with the public key, a token signed by a
published-but-wrong key, and a sibling environment's issuer.

Two implementations that agree on all nineteen are two implementations that agree. Every further
verifier added under issue #118 runs the same corpus.

These counts are CHECKED rather than remembered: `scripts/verify-vectors.sh` reads them out of
the corpus and fails if this page disagrees. They had already drifted once, saying sixteen and
twelve after the corpus grew, which is what a hand-written number beside a generated artifact
does given time.

The corpus is generated and gate-checked (`scripts/verify-vectors.sh`), because a conformance
corpus is exactly the artifact that gets weakened under deadline: delete the `alg: none` vector
and every verifier goes green.

## Interop escape hatch

Consumers that cannot verify EdDSA can be issued ES256 or RS256 tokens via the per-client
algorithm override. Two ecosystems make this worth knowing about:

- **Java**: Nimbus JOSE+JWT needs the optional Google Tink dependency for EdDSA.
- **.NET**: no in-box EdDSA before .NET 11, leaving BouncyCastle or NSec.

Official verifier artifacts for both that bundle the glue are tracked in issue #118 and are not
yet shipped. Until they are, the override is the documented path.
