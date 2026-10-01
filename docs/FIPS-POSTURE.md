# The FIPS posture and build seam (issue #162)

This page is the published posture document for security questionnaires and
procurement. It states precisely: which builds use which crypto module and its
validation status, the EdDSA-under-FIPS nuance, the recommended FIPS tenant
configuration, and the current post-quantum position.

## Which builds use which module

- **The default build** signs, verifies, and keys with **ring** (the
  RustCrypto-free, pure-assembly backend; not FIPS 140-3 validated). This is
  the build everyone runs by default.
- **The FIPS build variant** (the build seam, in progress) signs, verifies,
  and keys through **aws-lc-rs**, the AWS libcrypto fork that holds a
  **FIPS 140-3 validated** module — and notably includes **EdDSA**, which is
  why the seam is viable for this product rather than a downgrade.

IronAuth itself does not pursue its own CMVP certificate: the validated module
is aws-lc-rs, and IronAuth documents module usage. The seam's contract: all
signing, verification, key generation, and JWE operations go through a single
abstraction with the backend selected at build time, both backends pass
identical test vectors for every supported algorithm on every merge, and a
backend-specific capability gap is a **startup-checked configuration error**,
never a silent difference.

## The EdDSA-under-FIPS nuance (why the FIPS profile defaults to ES256)

A genuine subtlety the posture must carry:

- Server-side, a validated module (aws-lc-rs) **includes** EdDSA, so the
  server can sign Ed25519 under a validated module.
- Client-side, validated-module coverage for **EdDSA verification is thin** —
  most validated client modules do not include it.
- **CNSA 2.0 excludes EdDSA entirely.**

So a FIPS-constrained tenant should run **ES256** (or RS256) defaults today.
The per-tenant algorithm policy makes this a **configuration stance rather
than a code fork**: a tenant whose environments carry the FIPS profile signs
ES256 by default, keeps RS256 available, and makes EdDSA unavailable — the
policy refuses it even though the environment's keys include it, so the key
material's presence never leaks an algorithm the tenant's assurance posture
excludes.

## The recommended FIPS tenant configuration

1. Set the FIPS profile on the tenant's environments (the per-environment
   `fips_profile` guardrail).
2. The environment's issuer then signs ES256 (the default signer), keeps
   RS256 available, and refuses EdDSA.
3. Constant-time RSA comes with aws-lc-rs (the hand-rolled cautionary tale is
   the Rauthy Marvin-attack response); the FIPS build never reaches a
   non-constant-time path.
4. A deployment that additionally runs the external-signer backend on an HSM
   composes with this seam: the HSM performs the operation, and the seam
   still governs what the HSM is asked to do.

## The post-quantum position

The current position, for questionnaires: **no post-quantum signer ships
yet.** The algorithm set is conventional (EdDSA/ES256/RS256 + ECDH-ES), and
the post-quantum readiness bet is owned by the exploratory work; this page
publishes the posture and will be updated when that work lands.

## What changes operationally in a FIPS build

- The build is selected at build/deploy time (feature flag + CI job).
- Nothing else changes: no feature loss beyond the algorithm policy.
- Startup verifies backend availability; a mis-selected backend is a
  configuration error, not a runtime surprise.