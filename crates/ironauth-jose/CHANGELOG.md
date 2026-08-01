# ironauth-jose changelog

All notable changes to the `ironauth-jose` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- **RFC 9068 section 4: a verification policy now states which token profile it accepts,
  and it cannot decline to** (issue #192). `VerificationPolicy::new` takes an
  `ExpectedTyp` as a fifth positional argument, `verify` matches the protected header's
  `typ` against it, and a mismatch is the new `RejectReason::TypMismatch`. Before this,
  the verify core read `typ` for exactly one purpose, deciding whether a `crit` member
  naming it was malformed, and never compared it to anything. That was the whole of the
  separation between an ID token and an access token: IronAuth signs both with one
  environment key under one issuer, and the code flow gives both `aud = client_id`, so
  with the media type unread they are byte for byte the same token in every field a
  verifier looks at, and an ID token travels through the front channel where a referrer,
  a proxy log, or browser history can leak it.
  - **Impossible to omit, not merely present.** `ExpectedTyp` is positional, has no
    default, and has no setter, so a policy that says nothing about the profile it
    accepts is a compile error. `tests/compile-fail/policy_requires_expected_typ.rs`
    pins that: a runtime test can only show that a STATED expectation is honored, never
    that a caller could not have left it unstated. An `Option` defaulting to "no
    opinion" would have put every future verify site one forgotten line from the
    confusion this argument exists to close.
  - **One declaration, read by both sides.** The new `TokenTyp` enum names each profile
    IronAuth mints and holds its media type behind an exhaustive `match` with no wildcard
    arm, so a fourth profile does not compile until its media type is written against its
    RFC. The mint stamps from it (`EmissionOptions::with_token_typ`) and the verifier
    requires from it, so a profile cannot be minted under one spelling and required under
    another. The enum, that match, and `TokenTyp::ALL` are all GENERATED from one
    `token_profiles!` list, which is what keeps `ALL` from falling behind: a hand-written
    array beside the enum would go on naming the original three, and every check that
    iterates the profiles (`no_two_profiles_share_a_media_type` above all, since it is
    what makes `typ` a separator) would simply never see the new one and would keep
    passing. The workspace `typ-via-declaration` invariant lint keeps the raw
    `EmissionOptions::with_typ` out of production mint paths, in both the method and the
    UFCS spelling (the same function reached the second way is the same hole, and a rule
    defeated by a spelling rather than by a decision is not a rule), across every Rust
    tree in the repository rather than `crates/` alone; a foreign peer's dictated media
    type, or a test forging the wrong one, carries an explicit allow marker and a written
    reason.
  - `ExpectedTyp::ForeignIssuer` is the one way to accept an arbitrary media type, and it
    is a value an author has to write down. It is correct only where the trusted keys are
    the foreign party's own and the issuer and audience pin one relationship, which is
    what does the separating there. How strongly varies, and the doc says which: pinning
    `iss == client_id` is structural, because a client id is a prefix-tagged identifier
    that can never equal an issuer URL, while a pinned issuer and JWKS that both come
    from operator configuration is a configuration property and nothing more. The new
    `tests/token_confusion.rs` asserts exactly what the variant admits, so nobody can
    believe it is doing a partial check.
  - `typ` is decided in one more place in this crate, which the "one declaration" claim
    does not cover: `validate_dpop_proof` requires `typ == "dpop+jwt"` byte-exactly. A
    DPoP proof is minted by the client, not by IronAuth, and that check is stricter than
    the media-type comparison here rather than a way around it.
  - Media types are compared as media types: case-insensitively (RFC 2045 section 5.1)
    with an optional `application/` prefix stripped (RFC 7515 section 4.1.9). A
    non-string `typ` is `HeaderMalformed` rather than "no typ", so a hostile header
    cannot have the member silently ignored.
  - The check runs alongside the algorithm allowlist, before the signature. Like that
    check it can only REJECT: acceptance still requires the signature, which
    `the_media_type_guard_never_admits_an_unsigned_token` pins.
  - `tests/token_confusion.rs` is the full CROSS PRODUCT of the three profiles against
    the three policies, not the one pair the issue named. Asserting only "an ID token
    fails an access-token policy" would have left the Logout Token, which carries
    `aud = client_id` and a `sid`, free to stand in for either.

- Pre-signature compact-length arithmetic (issue #98), three new public functions plus one
  accessor: `b64_no_pad_len`, `compact_len`, `protected_header`, and
  `SigningKey::signature_len`. Together they answer "how long will this token be" BEFORE the
  token exists, which is what lets a caller apply a size budget to a claim set while it can
  still choose not to emit it; measuring after signing is too late, because by then the token
  is minted and no policy can be applied to it.
  - **Exact, never an upper bound.** `sign_jws` composes `b64(header) '.' b64(payload) '.'
    b64(signature)`, and every one of those lengths is determined, so `compact_len` returns
    the number that ships. An upper bound would be wrong in the direction that matters: it
    would withhold content that in fact fits. `signature_len` is exact for the same reason,
    64 bytes for Ed25519 and `ES256`, 96 for `ES384`, and THAT KEY's modulus width for every
    RSA algorithm. The RSA width follows the key rather than the enforced 2048-bit floor,
    which is a minimum and not a fixed size: a 3072-bit key loads and signs 384 bytes. The
    ECDSA widths hold because this crate signs through ring's `ECDSA_*_FIXED_SIGNING`
    algorithms (the JWS `R || S` form of RFC 7518 section 3.4); an ASN.1 DER signature would
    be VARIABLE length and would make the prediction silently wrong on the fraction of
    signatures with a short `R` or `S`.
  - `protected_header` returns the header bytes `sign_jws` will emit for a key and its
    emission options. The predicted header cannot drift from the minted one because
    `sign_jws` now obtains its own header BY CALLING it: sharing a builder would not have
    been enough, since the builder's arguments would still be assembled at two independent
    call sites. It is the one compact-JWS segment a caller does not already hold.
  - The exactness is PROVEN rather than asserted: the signing suite mints real tokens across
    the full nine-algorithm matrix (over both a 2048-bit and a 3072-bit RSA fixture, so a
    per-key modulus width is distinguishable from a constant), three header shapes, keys with
    and without a `kid`, and every payload length from 0 to 32 bytes (all three `len % 3`
    residues, which is where base64 arithmetic goes off by one), and requires
    `compact_len(...) == token.len()` exactly, through `sign_jws_with_policy` as well as
    `sign_jws`. A separate test signs the same payload 512 times per algorithm and requires
    the signature width never to vary.

- Compact-JWS `kid` hint (issue #75): `compact_jws_kid` reads the `kid` from a compact
  JWS/JWT protected header WITHOUT verifying the token, bounded and allocating no key
  material. It is a REFETCH HINT only (inbound federation uses it to decide whether a cached
  upstream JWKS answers to the token's `kid` and so whether to refetch on a key rotation); it
  reads no trust and never selects or introduces a key, which stays inside `verify`.
- MDS3 BLOB signature primitive (issue #66 PR B): `verify_jws_signature` verifies a
  JWS/JWT compact-serialization signature (fixed-width ES256 `r||s` per JWA, plus EdDSA
  and RS256) for the FIDO MDS3 BLOB. It is the sibling of `verify_webauthn_signature`,
  which stays ASN.1-DER for WebAuthn ceremony signatures; the MDS3 chain verifier calls
  it out of band after pinning the `x5c` chain, since the JWS `verify` core deliberately
  rejects `x5c`. `ring` stays confined to this crate.
- RFC 6238 TOTP primitive (issue #69), a new public `totp` module. The
  second-factor code is a keyed HMAC over a time-step counter plus RFC 4226
  dynamic truncation, so it lives here for the same structural reason as
  `envelope` and `webauthn`: `scripts/jose-audit.sh` lets exactly one crate name
  `ring::hmac`, and building on the ring HMAC that already signs JOSE HMACs keeps
  the workspace free of a high-level TOTP crate and a raw `hmac`/`sha1` edge. It
  exposes `TotpAlgorithm` (SHA1 default, SHA256, SHA512), `TotpParams` (6..=8
  digits, a 15..=60 second period), `code_at`, `verify` (constant-time over the
  drift window, returning the matched absolute time-step for single-use and
  resync), Base32 encode/decode plus `grouped_secret` for manual entry, and
  `provisioning_uri` for the `otpauth://` QR payload. The primitive is pure (the
  caller supplies `env.clock().now_utc()`), tested against the RFC 6238 appendix
  vectors. No HOTP surface: the only counter formed is `unix_time / period`.

- WebAuthn ceremony signature verification (issue #65), a new public `webauthn`
  module. A FIDO2 ceremony signature is not a JWS: the signed message is
  `authenticatorData || SHA-256(clientDataJSON)`, the ECDSA signature is ASN.1
  DER (not the fixed `r||s` a JWS carries), and the public key is a COSE key. So
  the JWS `verify` path cannot be reused. This module lives here for the same
  structural reason as `envelope`: `scripts/jose-audit.sh` lets exactly one crate
  name `ring::signature`. It exposes `WebauthnKey` (the ES256 / EdDSA / RS256
  public-key material, never secret) and `verify_webauthn_signature`, which uses
  ring's `ECDSA_P256_SHA256_ASN1` (DER), `ED25519`, and `RSA_PKCS1_2048_8192_SHA256`
  verifiers. `ironauth-webauthn` owns all CBOR/COSE/authenticator-data parsing and
  hands already-parsed key material plus the signed message here for the one
  cryptographic check. Failures collapse to the opaque `WebauthnSignatureError`,
  keeping the no-oracle stance of the rest of the crate.

- Envelope-encryption AEAD primitive (issue #48), a new `envelope` module. The
  DEK/KEK envelope scheme for per-tenant PII and secret encryption at rest lives
  here because the workspace lets exactly one crate name `ring` directly
  (`scripts/jose-audit.sh`); `ironauth-store` consumes it and owns the key tables.
  - **Standard AEAD, no novel cipher.** Built on `ring::aead` AES-256-GCM (NIST SP
    800-38D). Three 256-bit key tiers: a platform `MasterKey` (wraps per-tenant
    KEKs), a per-tenant `Kek` (wraps that tenant's DEKs), and a per-tenant `Dek`
    (seals the actual payloads). Wrapping is itself an AEAD seal of the child key's
    32 bytes, so there is one reviewed construction at every tier.
  - **Context binding.** `Aad::builder()` length-prefixes each field (tenant,
    environment, purpose/column, key version) so a ciphertext lifted to another
    row, tenant, environment, or column fails authenticated decryption. The
    `MasterKey` carries a stable id bound into every wrapped KEK's AAD.
  - **Entropy seam.** Every key and every 96-bit nonce comes from
    `ironauth_env::Entropy` (invariant 3), never an OS RNG directly, so the whole
    scheme is deterministic under a test entropy source; a fresh nonce is drawn per
    seal and never reused under one key.
  - **Key material never leaks.** `MasterKey`, `Kek`, and `Dek` never `Display`,
    render bytes in `Debug` (`<redacted>`), or serialize, and their bytes are
    best-effort zeroed on drop. `EnvelopeError` carries no key material or
    plaintext and distinguishes a decryption failure from a malformed blob.
  - **Blind index for searchable encrypted columns.** `MasterKey::blind_index`
    computes a deterministic keyed HMAC-SHA256 of an `Aad` context, keyed by a
    subkey derived (domain-separated) from the master key, so an AEAD-sealed lookup
    column (a login handle) stays equality-searchable without a plaintext column,
    while the caller binding the tenant into the context makes the tag per-tenant
    (an index collision cannot leak across tenants) and never a bare unsalted hash.
    Returned as a `BlindIndex` whose `Debug` is byte-free.
  - **Key derivation from a configured secret.** `MasterKey::derive(id, ikm)`
    derives the 32-byte master key deterministically (a domain-separated HMAC) from
    any-length high-entropy key material, so an operator supplies a secret rather
    than exactly 32 raw bytes and the same secret is stable across restarts.
  - **Zeroization of transient key/plaintext buffers.** The intermediate unwrapped
    key bytes in `unwrap_kek`/`unwrap_dek` and the working plaintext buffer in the
    AEAD open path are wiped (fill + `black_box`) once copied out, matching the
    on-drop key wipe, so no key material or decrypted plaintext lingers in freed
    heap.
  - Fourteen module unit tests: round-trip, wrong-context/wrong-key failure, nonce
    freshness, KEK/DEK wrap round-trips, a master-key crypto-shred, a
    Debug-redaction proof, blind-index determinism/per-tenant separation, and
    derive stability.
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
