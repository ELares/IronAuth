# ADR 0004: The hardened JOSE verification core

Status: accepted (M1, JOSE-core issue #8)

## Context

Every token surface IronAuth will ever ship (ID tokens, RFC 9068 access tokens,
logout tokens, request objects, DPoP proofs, software statements) verifies a
JWS. The 2025-2026 JOSE library CVE wave hit Authlib, PyJWT, jsonwebtoken, and
jose with the same recurring classes, and they were not exotic bugs: they are
the predictable result of letting attacker-controlled token headers influence
trust, multiplied by many verification call sites with subtly different
behavior. The wave's classes are `alg: none` acceptance (including the OIDC Core
code-flow-permitted variant), RS/HS key confusion (verifying an `RS256` token as
`HS256` with the RSA public key as the HMAC secret), in-token key injection via
`jwk`/`jku`/`x5u`/`x5c`, `crit` mishandling, and decompression bombs.

The structural answer is one hardened, fuzz-tested verification function that
every token path must use, with RFC 8725's guidance turned into property tests
and the CVE wave itself turned into a permanent regression corpus. This is
verify-only; signing, key storage, and JWKS publication are issue #9.

## Decision

Add one crate, `crates/ironauth-jose`, whose single public function
`verify(token, policy, clock)` is the ONLY way IronAuth code verifies a JWS/JWT.
It is built DIRECTLY on `ring`'s low-level signature primitives, not on a
high-level JOSE crate: those crates carry the very CVE classes this core closes.

### Trust comes only from the policy, never from the token

The caller supplies a `VerificationPolicy` and the verifier trusts nothing else.
The algorithm comes from the policy's allowlist; the key comes from the policy's
trusted set (resolved out of band from configuration or a JWKS, never from the
token); the expected `iss`, `aud`, skew, and caps come from the policy. The
token's headers are read only to be matched against the policy, never followed
outside it:

- **`alg`** is an untrusted claim. It is checked against the allowlist and must
  map to the trusted key's family; it never selects the algorithm or key on its
  own. A token cannot verify by claiming a favorable `alg` (proven by property
  test: arbitrary `alg` strings never verify).
- **`alg: none`** (in any case or whitespace variant, and the absent, null, and
  empty forms) is always rejected. There is no configuration to permit it, not
  even for the OIDC Core code-flow case.
- **`kid`** may only select among already-trusted keys. A `kid` that names no
  trusted key is a rejection; it never introduces a key.
- **`jwk`, `jku`, `x5u`, `x5c`** (in-token or by-reference key material) are
  rejected outright (fail closed), never trusted and never fetched, because trust
  always comes from out-of-band keys.
- **`crit`** naming any extension is rejected: the core understands no critical
  extensions in M1, and a malformed, empty, duplicate, or registered-parameter
  `crit` is rejected too.

### No HMAC, by design

The supported verify algorithms are all asymmetric: EdDSA (Ed25519), ES256/ES384
(ECDSA P-256/P-384), RS256/RS384/RS512 (RSA PKCS1-v1_5), and PS256/PS384/PS512
(RSA-PSS), each backed by a `ring` primitive. HMAC (`HS*`) is intentionally
absent. With no symmetric verification path in the core, the classic public-key-
as-HMAC-secret confusion is not merely blocked but inexpressible, and any claimed
algorithm whose family does not match the trusted key is rejected before the
signature check.

### Module visibility plus a CI lint

The raw `ring` calls live in a private `crypto` module; the header parser and its
trust guards live in a private `header` module; a trusted key's inner material is
a private field. Rust module visibility alone makes a second, weaker verifier
unassemblable from outside the crate, and compile-fail (`trybuild`) tests pin
that. The second net is `scripts/jose-audit.sh` (mirroring `http-audit.sh`): it
fails the build if any crate other than `ironauth-jose` declares a direct
dependency on a JOSE/JWT crate or on `ring`, or names a JOSE verification
primitive in source. The assembler wires that lint into CI.

### Caps before crypto

`VerificationCaps` bound the work an attacker can force before any base64, JSON,
or signature work happens: a maximum token size checked first of all, per-segment
decoded-size caps checked before any decode buffer is allocated, a decompression-
ratio guard, and a PBES2 iteration cap. Compressed (`zip`) and PBES2 inputs, and
the five-segment JWE shape, are rejected at the structural or header stage before
anything can expand. The caps are configurable with safe defaults (the tunability
principle); the structural rejections are not.

### Central claim enforcement the caller cannot opt out of

After (and only after) the signature verifies, the claims are enforced following
OIDC Core 3.1.3.7: `iss` and `aud` are matched EXACTLY (no substring, prefix, or
case folding; `aud` may be a JSON array in which the expected value must appear
as an exact member), and `exp`/`nbf`/`iat` are checked against the env clock
within a bounded, configurable skew. There is no flag to skip any of this: a
policy cannot be constructed without an expected issuer and audience, and `exp`
is required by default. Time flows through the `ironauth-env` `Clock` seam, so
the claim windows are deterministic under test.

### Uniform errors, rich diagnostics

Every failure returns the single opaque `VerifyError`, so a caller (and an
attacker) cannot tell which check failed. The precise, bounded-cardinality
`RejectReason` is available through `VerifyError::reason` for server-side logs
and metrics only, consistent with the log-scrubbing stance and the fetcher's
uniform-`Blocked` pattern.

### Fuzzing

A cargo-fuzz target (`crates/ironauth-jose/fuzz/`, a detached non-workspace crate
out of the cargo-deny graph, like `ironauth-fetch/fuzz/`) drives the public
`verify` over arbitrary input, seeded from the committed regression vectors. The
same input space has stable, in-CI coverage in `cve_corpus.rs` and `property.rs`.
Issue #8 asks the fuzz target to run in CI on a schedule; no scheduled fuzz
workflow exists yet, so the exact job the assembler should add is documented in
`crates/ironauth-jose/fuzz/README.md`.

## Consequences

- Later token features (ID tokens, RFC 9068, logout tokens, request objects, DPoP)
  CONSUME `ironauth_jose::verify` with a policy they build from resolved config or
  JWKS; they do not re-implement verification.
- The excluded algorithms (Ed448, ES512, RS1, `alg: none`, RSA1_5, PBES2/PBKDF2
  JWE, and HMAC in this core) are published with reasons in
  `docs/WILL-NOT-IMPLEMENT.md`. The supported matrix with the EdDSA default is
  issue #9's signing core.
- `ring` gains a direct dependency edge from `ironauth-jose`. It was already in
  the tree via rustls, so the crate graph, licenses (Apache-2.0 AND ISC), MSRV
  1.85, and the musl static lane are unchanged.
- JWE remains out of scope beyond rejecting the excluded modes; when encryption
  lands it consumes this same core rather than adding a parallel path.
