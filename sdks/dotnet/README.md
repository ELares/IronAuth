# IronAuth token verification for .NET

Verify an IronAuth JWT on .NET with **one dependency**: BouncyCastle, for Ed25519 and nothing else.

## Why exactly one

.NET has **no in-box Ed25519 as of .NET 10**. That is checked rather than assumed: reflecting over
`System.Security.Cryptography` turns up no Ed-anything public type. So Ed25519 comes from
BouncyCastle, while RSA and P-256 come from the platform. JSON comes from `System.Text.Json`.

This is the honest difference from [the Java artifact](../java/README.md), which needs no
dependencies at all because the JDK has had Ed25519 since Java 15. Same design, same three suites,
one extra package here because the platform genuinely lacks the primitive.

Targets **net8.0**, so it is usable on the current LTS and on everything newer.

## Verifying a token

```csharp
var algorithms = new[] { "EdDSA" };              // from the ISSUER's metadata, never the token
var keys = TrustedKey.FromJwks(jwksDocument);

var verifier = new IronAuthVerifier(algorithms, keys, issuer, audience, skewSeconds: 60);
JsonElement claims = verifier.Verify(token, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
```

`Verify` throws `VerifyException` carrying a machine-readable `RejectReason` -- `Expired`,
`AlgNotAllowed`, `UnknownKid`, and twelve more. Log the reason. A verifier that collapses every
refusal into "invalid token" makes a clock-skew outage indistinguishable from an attack, which is
how incidents get misdiagnosed for hours.

`VerifyException` deliberately has **no** parameterless or message-only constructor, despite what
CA1032 asks for. The type exists to carry a reason; a constructor leaving it at the enum's zero
would produce an exception claiming a refusal that never happened, and a caller switching on
`Reason` would take a branch nothing chose.

For the whole path including discovery and key fetching, see `Sample.cs`.

## The one rule that matters

**The algorithm allow-list is the issuer's published metadata, never the token's header.** It is a
required constructor argument with no default for that reason. A verifier that reads `alg` from the
token to decide what to accept is broken no matter how careful the rest of it is: that is exactly
what `alg: none` and HS256-forged-with-the-public-key exploit, and both are in the corpus below.

`Sample.cs` reads the list from `id_token_signing_alg_values_supported` in the discovery document,
so you can watch the rule happen rather than take it on trust.

## What is tested, and by what

`scripts/dotnet-verify.sh` runs three suites, divided by what only each can prove:

| Suite | What only it can prove |
| --- | --- |
| `conformance` | Agreement with the **shared** cross-language corpus: 19 vectors, 14 of them refusals. The only thing measuring interoperability rather than self-consistency. |
| `selftest` | Properties needing a token this repo can **sign**, which a fixed corpus cannot contain: that key injection is refused *before* the signature is checked, that size is bounded before decoding, that a token without `exp` never verifies, that the claims depth cap holds. |
| `sample` | The **sample**, run end to end against a real loopback issuer: discovery, `jwks_uri`, key decode, allow-list, verification. |

Like the Java artifact, this verifies **every accepted vector in the corpus** -- Ed25519, P-256 and
RSA. Most of the other verifiers cannot: the Rust one has no P-256 key type, so it refuses the
ES256 vector on the allow-list rather than verifying it. That matters for one vector in particular.
`alg_not_published_by_the_issuer` is the *same token* as `valid_es256`, judged against an issuer
publishing EdDSA only; for a verifier that cannot do ES256 at all, passing it proves nothing.

### Two bounds that mutation testing changed

- **The claims depth cap is 32, and that number is load-bearing.** `System.Text.Json` already
  refuses runaway nesting at its own default of 64, so raising the cap to 10000 originally survived
  every check: the deeply nested *header* test was refused either way. A bound nothing distinguishes
  is decoration. There is now a vector nesting claims 40 deep -- legal JSON, inside the platform
  default, outside this cap -- plus a shallow control, because without one a cap of 1 would also
  pass.
- **The document size ceiling is a bounded read, not a length check.** `ReadAsStringAsync` buffers
  the whole body first, so checking afterwards spends the memory before refusing it. The sample
  reads in chunks from `ResponseHeadersRead` and stops at the limit, and the harness serves a
  two-megabyte key set to prove it.

## Scope limits, stated rather than left to be discovered

- **No key fetching or caching.** `IronAuthVerifier` takes keys the caller resolved. `Sample`
  fetches on every call; a production verifier caches, refetches on an unknown `kid` at a bounded
  rate, and keeps serving the cached set through a brief issuer outage. Left out because a cache
  with an eviction policy would be most of the file and would bury the four steps it shows.
- **`typ` is not enforced.** The shared corpus is run by six verifiers in five languages and mints
  ordinary `typ: JWT` tokens. IronAuth deployments pin their media type in the layer above.
