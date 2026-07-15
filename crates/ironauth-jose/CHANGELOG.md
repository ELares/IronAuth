# ironauth-jose changelog

All notable changes to the `ironauth-jose` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- `VerificationPolicy::allow_expired(bool)` (issue #33): an opt-in, default-OFF
  policy setter that waives ONLY the "now past exp" rejection, so a well-formed
  but EXPIRED token still verifies. Every other check is untouched: `exp` is still
  required to be present and well formed, and the signature, algorithm allowlist,
  key selection, issuer, audience, `nbf`, and `iat` checks all remain fully
  enforced. The one caller is OIDC RP-Initiated Logout, whose `id_token_hint` is a
  past id token presented ONLY to identify a session to end (it confers no access),
  which the spec requires to still validate for logout targeting.
- `trusted_keys_from_jwks(json)` (issue #25): parse a JWK Set document into the
  `TrustedKey`s the verify core accepts, for authenticating a client's
  `private_key_jwt` assertion against its registered `jwks`/`jwks_uri`. Fails
  closed by construction: a key of a type the verify core cannot represent (an
  OKP curve other than Ed25519, an EC P-521 key -- the `ES512` family M1
  excludes, an `oct` symmetric key) or a malformed member is skipped rather than
  guessed, so an unparsable or all-unrepresentable document yields an empty set
  and the caller rejects. Public keys only; no secret material crosses this seam.
- `KeySet::published_signing_keys(now)` (issue #194): the private signing keys
  published at `now` (publish window open, not yet expired), for a caller that
  needs the trusted VERIFYING projection of an issuer's own currently-valid keys
  (the OIDC provider's `verify_access_token`). Mirrors `published_kids` but hands
  back the `SigningKey`s rather than the serialized public JWK Set.
- Initial hardened JOSE verification core (issue #8): the single, allowlist-
  driven JWS/JWT verify choke point every IronAuth token surface inherits its
  security from. Verify-only; signing/key-storage/JWKS are issue #9. See
  docs/adr/0004-jose-verification.md.
  - **One public path.** `verify(token, policy, clock)` is the only way to verify
    a token. The raw `ring` signature calls, the header parser, and a trusted
    key's inner material are module-private; compile-fail (`trybuild`) tests and
    `scripts/jose-audit.sh` (module visibility plus the lint) prove no second
    verifier can be assembled outside the crate.
  - **Built directly on `ring`, not a high-level JOSE crate**, which would carry
    the very CVE classes this core closes. Supported verify algorithms: EdDSA
    (Ed25519), ES256/ES384 (ECDSA P-256/P-384), RS256/RS384/RS512 (RSA
    PKCS1-v1_5), PS256/PS384/PS512 (RSA-PSS).
  - **Trust comes only from the policy.** The algorithm comes from the caller's
    allowlist and the key from the caller's trusted set; the token's `alg`/`kid`
    are matched against them, never followed outside them. `alg: none` (every
    case/whitespace/absent/null/empty variant) is always rejected. `kid` only
    selects among trusted keys. `jwk`/`jku`/`x5u`/`x5c` are fail-closed rejects.
    Any `crit` (unknown, malformed, empty, duplicate, or registered) is rejected.
  - **No HMAC by design.** With no symmetric verify path, RS/HS key confusion is
    inexpressible; a claimed algorithm whose family does not match the trusted
    key is rejected before any signature check.
  - **Caps before crypto.** `VerificationCaps` bound work before any base64/JSON/
    crypto: a token-size cap checked first, per-segment decoded-size caps, a
    decompression-ratio guard, and a PBES2 iteration cap. Compressed (`zip`),
    PBES2, and five-segment JWE inputs are rejected structurally before they can
    expand. Configurable with safe defaults (16 KiB token, 4 KiB header, 16 KiB
    claims, 60 s skew); the structural rejections are not.
  - **Central claim enforcement (OIDC Core 3.1.3.7) the caller cannot opt out
    of.** Exact `iss`/`aud` matching (no substring/prefix; `aud` array membership
    is exact) and `exp`/`nbf`/`iat` within a bounded skew, evaluated against the
    `ironauth-env` clock seam. A policy cannot be built without an expected issuer
    and audience, and `exp` is required by default.
  - **Uniform errors, rich diagnostics.** Every failure returns the single opaque
    `VerifyError`; the bounded-cardinality `RejectReason` is reachable only via
    `VerifyError::reason` for server-side logs and metrics.
  - **CVE regression corpus** as tests that must pass on every build: `alg: none`
    variants, RS/HS confusion (HMAC-signed with the RSA public key bytes), key-
    family mismatch, allowlist bypass, embedded-`jwk`/`jku`/`x5u`/`x5c` injection,
    unknown/malformed/duplicate `crit`, `zip` and `enc` and five-segment JWE,
    PBES2 parameters and iteration bombs, oversized token and segment, tampered
    signature and payload, malformed structure and duplicate header keys, unknown
    `kid`, and the full `exp`/`nbf`/`iat`/`iss`/`aud` claim edges. Positive vectors
    for all nine algorithms verify and return claims. Property tests (fixed-seed,
    no proptest dependency) prove arbitrary `alg` strings never verify, alg-swaps
    always break, and arbitrary input never panics or verifies.
  - **Fuzzing.** A cargo-fuzz target over `verify` (`fuzz/`, a detached non-
    workspace crate, not in the cargo-deny graph), corpus seeded from the
    regression vectors. The exact scheduled-fuzz CI job for the assembler to add
    is in `fuzz/README.md`; stable in-CI coverage of the same space lives in the
    `cve_corpus.rs` and `property.rs` suites.
  - `ring` gains a direct dependency edge (already in the tree via rustls, so no
    new crate, no license change; Apache-2.0 AND ISC). MSRV 1.85 and the musl
    static lane are unchanged.
