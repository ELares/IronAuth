# Edge verification

Verifying an IronAuth token needs no IronAuth service, no SDK install, and no network call on
the hot path. This page is the runtime support matrix, the measured latency, and the
methodology behind it.

Ed25519 is IronAuth's default signing algorithm, and WebCrypto Ed25519 is now available in
every runtime that matters at the edge. That is what makes a copy-paste verifier possible at
all.

## Runtime support

| Runtime | Supported | How |
|---|---|---|
| Cloudflare Workers | yes | `packages/ironauth-sdk/snippets/verify-webcrypto.mjs`, unmodified |
| Deno | yes | the same file |
| Bun | yes | the same file |
| Node.js 20+ | yes | the same file, or `@ironauth/sdk` |
| Vercel Edge | yes | the same file |
| Lambda@Edge | yes | the same file (full Node runtime) |
| **CloudFront Functions** | **no** | see below |

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

Representative output, Node 24 on an arm64 laptop:

| Algorithm | p50 (ms) | p95 (ms) | p99 (ms) | max (ms) | ops/s |
|---|---|---|---|---|---|
| EdDSA | 0.067 | 0.081 | 0.088 | 0.137 | ~14,500 |
| ES256 | 0.080 | 0.103 | 0.150 | 0.271 | ~11,700 |

Sub-millisecond at p99 for both, with EdDSA roughly 20 percent faster than ES256, which is the
reason it is the default.

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
- **One vector per algorithm.** The conformance corpus holds four accepted vectors but only two
  distinct algorithms; timing all four would print near-identical rows and imply the table
  measured more than it did.

## Correctness comes first

Latency is the easy half. A verifier that is fast and wrong is worse than no verifier, so both
the SDK core and the copy-paste snippet are judged against the same conformance corpus at
`packages/ironauth-sdk/vectors/verify-vectors.json`: sixteen vectors, twelve of them refusals,
including `alg: none`, an HS256 forgery keyed with the public key, a token signed by a
published-but-wrong key, and a sibling environment's issuer.

Two implementations that agree on all sixteen are two implementations that agree. Every further
verifier added under issue #118 runs the same corpus.

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
