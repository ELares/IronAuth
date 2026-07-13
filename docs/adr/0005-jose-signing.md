# ADR 0005: The JOSE signing core

Status: accepted (M1, signing-core issue #9)

## Context

ADR 0004 shipped the verify-only half of the JOSE core: one hardened
`verify(token, policy, clock)` that trusts nothing but its policy. Issue #9 adds
the mint half. Every token surface IronAuth will ship (ID tokens, RFC 9068
access tokens, logout tokens, request objects) must SIGN a JWS as well as verify
one, and the same failure modes that produced the 2025-2026 JOSE CVE wave on the
verify side reappear on the mint side when signing and verification drift apart:
a second backend, a second algorithm vocabulary, a symmetric key that leaks into
an asymmetric default, or a key that prints into a log.

The decisions here keep the mint side welded to the verify side and make the
dangerous states unrepresentable rather than merely rejected.

## Decision

Extend `crates/ironauth-jose` (do not fork it) with the signing core. The mint
lives in the SAME crate as the verifier so `scripts/jose-audit.sh` still holds:
`ironauth-jose` is the only crate that may name a `ring` signature primitive.

### One backend, the full matrix, EdDSA default

Signing rides the same `ring` backend the verifier already uses: Ed25519
(`EdDSA`, the default for new environments and clients), ES256/ES384,
RS256/RS384/RS512, and PS256/PS384/PS512. No second crypto backend enters the
tree. `ring`'s RSA signing is constant time, and JWS performs only RSA signing
and verification (public/private key operations over a message), never RSA
decryption, so there is no PKCS#1 v1.5 padding-oracle (Bleichenbacher / Marvin)
surface to motivate a second backend. `Ed25519` is accepted as the
fully-specified alias of the polymorphic `EdDSA`
(draft-ietf-jose-fully-specified-algorithms); a per-mint emission toggle can emit
it, defaulting off. No new dependency is added; `Cargo.lock` is unchanged.

### Every mint round-trips through the one verifier

A `SigningKey` hands out its matching public `TrustedKey` via
`verifying_key()`, so a freshly signed token is proven against the single
`verify` path, not a bespoke check. Signing therefore inherits the verifier's
allowlist and its exclusions (`none`, embedded key material, `crit`) for free.
The RFC 8037 Ed25519 test vectors are reproduced byte for byte (Ed25519 is
deterministic), and the whole matrix is round-trip tested.

### HMAC is unrepresentable as a default

`HS256`/`HS384`/`HS512` signing is reachable only through
`ClientSecretContext::sign_jws`, keyed from a `ClientSecret`, for exactly the two
OIDC client-secret cases (an `id_token_signed_response_alg = HS*` ID token per
OIDC Core 10.1, and `client_secret_jwt`). There is no HMAC signing-key type and
the environment key store is keyed by `JwsAlgorithm`, which has no `HS*` member,
so a tenant or environment default cannot be an HS algorithm: the illegal state
does not typecheck. The verify core still has no HMAC path at all, so an
HS-signed token is `UnsupportedAlg` there.

### Keys are per-environment, secret, and published from day one

Signing keys live in an `EnvironmentKeyStore`, generic over the environment key
type so the security core does not depend on the persistence stack (it is meant
to be instantiated with `ironauth_store::EnvironmentId` at the composition
layer). A fresh environment holds an Ed25519, an ECDSA P-256, and an RSA key from
the start, and the `JwkSet` builder publishes all three public keys, so moving a
client from `EdDSA` to `RS256` is a configuration flip effective on the next
mint, with no key generation and no JWKS propagation delay. Secret key material
is wrapped so it never prints, logs, or serializes (`Redacted`, and a redacting
`Debug` on `SigningKey`).

### The determinism seam and its one sanctioned exception

Ed25519 key generation draws its seed from the `ironauth-env` `Entropy` seam and
is reproducible under a fixed test source; Ed25519 signing is deterministic and
takes no RNG. ECDSA signing (its nonce), RSA-PSS signing (its salt), RSA
blinding, and ECDSA key loading require `ring`'s own `SecureRandom`, a sealed
trait no `Entropy`-backed type can implement. That single OS-RNG touch point is
isolated to the private `sign` module and carries the workspace's one
`invariant-allow: entropy-via-env` marker; the RNG affects only the
nonce/salt/blinding, never key material or the verify outcome, so determinism
under test is preserved by asserting round-trips (and by the deterministic
Ed25519 byte vectors) rather than by pinning ECDSA/RSA signature bytes.

### Seams for the protocol surfaces that grow by draft

Client-authentication methods, grant types, and token-binding methods are fixed
as traits (`seams`) so future drafts land as implementations, not refactors.
Token binding ties to one generalized confirmation model (`cnf`, RFC 7800) shared
across issuance and verification, with `jkt` (DPoP, RFC 9449) and `x5t#S256`
(mTLS, RFC 8705) as the initial binding types, both exercised through the one
embed-and-extract path.

## Consequences

- Token features (ID tokens, RFC 9068, logout tokens, DPoP, mTLS) CONSUME this
  mint and this `cnf` model; they do not re-implement signing or confirmation.
- The full DPoP and mTLS features remain out of scope: only the shared `cnf`
  plumbing and the binding-method seam ship now.
- Key rotation state machines and external KMS/HSM remain out of scope; the store
  is polymorphic over key type and ready for both.
- ECDSA and RSA keys are LOADED from provisioned PKCS#8 / PKCS#1 material rather
  than generated in-process (`ring` cannot generate RSA keys, and its ECDSA
  generation is bound to its own RNG). Provisioning and rotation of those keys is
  a later milestone.
