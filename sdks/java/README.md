# IronAuth token verification for Java

Verify an IronAuth JWT with **no dependencies at all** -- not Nimbus, not Tink, not even a JSON
parser. Just the JDK.

## Why there is nothing to install

Issue #118 asked for a Java artifact that verifies an IronAuth Ed25519 token "out of the box, no
extra user dependencies", and assumed that meant bundling Google Tink, because Nimbus JOSE+JWT
historically needed Tink to do EdDSA.

That is no longer true. **Java 15 added Ed25519 to the platform** ([JEP 339][jep339]), and RSA and
P-256 have been there far longer. So this artifact bundles nothing, which is a stronger form of
the promise than bundling glue would be: there is no dependency to resolve, so there is nothing to
drift, break, or pin. `javac` compiles it and `java` runs it.

[jep339]: https://openjdk.org/jeps/339

Requires **JDK 17 or newer** (Ed25519 needs 15; records and switch expressions need 17).

## Verifying a token

```java
Set<String> algorithms = Set.of("EdDSA");           // from the ISSUER's metadata, never the token
List<TrustedKey> keys = TrustedKey.fromJwks(jwksDocument);

var verifier = new IronAuthVerifier(algorithms, keys, issuer, audience, 60 /* seconds of skew */);
Map<String, Object> claims = verifier.verify(token, Instant.now().getEpochSecond());
```

`verify` throws `VerifyException` carrying a machine-readable `Reason` -- `EXPIRED`,
`ALG_NOT_ALLOWED`, `UNKNOWN_KID`, and eleven more. Log the reason. A verifier that collapses every
refusal into "invalid token" makes a clock-skew outage indistinguishable from an attack, which is
how incidents get misdiagnosed for hours.

For the whole path including discovery and key fetching, see `Sample.java`:

```
java dev.ironauth.verify.Sample https://issuer.example/t/tnt_1/e/env_1 cli_1 <token>
```

## The one rule that matters

**The algorithm allow-list is the issuer's published metadata, never the token's header.** It is a
required constructor argument with no default for that reason. A verifier that reads `alg` from the
token to decide what to accept is broken no matter how careful the rest of it is: that is exactly
what `alg: none` and HS256-forged-with-the-public-key exploit, and both are in the corpus below.

`Sample.java` reads the list from `id_token_signing_alg_values_supported` in the discovery
document, so you can watch the rule happen rather than take it on trust.

## What is tested, and by what

`scripts/java-verify.sh` runs three suites. They divide the work deliberately, and the division
came out of mutating the verifier and seeing which suite noticed:

| Suite | What only it can prove |
| --- | --- |
| `Conformance` | Agreement with the **shared** cross-language corpus: 19 vectors, 14 of them refusals. This is the only thing that measures interoperability rather than self-consistency. |
| `SelfTest` | Properties needing a token this repo can **sign**, which a fixed corpus cannot contain: that key injection is refused *before* the signature is checked, that size is bounded before decoding, that a token without `exp` never verifies. Also that **no input escapes `verify` as an unchecked exception** -- the corpus's malformed vectors are malformed *base64*, and these are valid base64 carrying hostile *JSON*. |
| `SampleHarness` | The **sample**, run end to end against a real loopback issuer: discovery, `jwks_uri`, key decode, allow-list, verification. |

### This is the first verifier to check every accepted vector

The corpus is judged by six verifiers across five languages, and every other one has a capability
gap: the Rust verifier has no P-256 key type, so it refuses the ES256 vector on the allow-list
rather than verifying it. The JDK does all three algorithms, so **this run verifies every accepted
vector in the corpus** -- Ed25519, P-256 and RSA -- and it is the first for which
`alg_not_published_by_the_issuer` tests what it was written to test.

That vector is the *same token* as `valid_es256`, judged against an issuer publishing EdDSA only.
For a verifier that cannot do ES256 at all, passing it proves nothing -- it would refuse that token
whatever the allow-list said. Here the two vectors differ in exactly one respect, the published
algorithm set, and the outcomes differ with them. That is the only arrangement in which the rule
above is actually measured.

## Scope limits, stated rather than left to be discovered

- **No key fetching or caching.** `IronAuthVerifier` takes keys the caller resolved. `Sample`
  fetches on every call; a production verifier caches, refetches on an unknown `kid` at a bounded
  rate, and keeps serving the cached set through a brief issuer outage. That was left out because a
  cache with an eviction policy would be most of the file and would bury the four steps it exists
  to show.
- **`typ` is not enforced.** The shared corpus is run by six verifiers in five languages and mints
  ordinary `typ: JWT` tokens. IronAuth deployments pin their media type in the layer above.
- **`Json` throws only `IllegalArgumentException`,** and that is a tested contract rather than a
  convention. `verify` declares `VerifyException`, so a caller writes one `catch` and expects it to
  cover every bad token; a reader that threw `StringIndexOutOfBoundsException` on a truncated escape
  would turn an invalid token into a 500. Nesting is capped at 32 for the same reason -- the parser
  is recursive, and a `StackOverflowError` is an `Error` that escapes every `catch` in the verifier.
- **`Json` is not a general-purpose parser.** It reads what a JWT header, a claim set and a JWK Set
  contain, and nothing else. It is also **not a security boundary**: it parses segments *before*
  the signature is checked, so everything it returns is attacker-controlled until the verifier says
  otherwise. What protects the verifier is that nothing `Json` returns chooses a key or an
  algorithm.
