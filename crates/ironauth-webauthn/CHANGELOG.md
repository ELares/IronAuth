# ironauth-webauthn changelog

All notable changes to the `ironauth-webauthn` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- Char-boundary panics in the DER time parser and the MDS3 AAGUID parser (issue #419):
  `der::parse_time` cut every field at a constant byte offset behind a byte-LENGTH
  check, with the ASCII-digit validation running INSIDE `parse_2` AFTER the slice, so a
  value of the right length carrying a multi-byte character panicked ("end byte index 2
  is not a char boundary"). It runs on a `packed` attestation statement's `x5c` chain
  BEFORE the signature, AAGUID, and chain checks, so an unauthenticated passkey signup
  reached it on a tenant configured for `direct` attestation, and on an MDS3 BLOB's
  `x5c` chain BEFORE the JWS signature check. `mds3::parse_aaguid` had the same shape.
  Both now require the value to be ASCII, which is what the digit and hex-digit parses
  already assumed, so every constant offset is a character boundary and no value that
  parsed before parses differently. The root `fuzz/ceremony_parse` target now covers
  `x509::parse_certificate` through both carriers, with the crashing certificate
  committed as a corpus seed.
- X.509 path-constraint enforcement (issue #66 PR B, adversarial review): the `x509`
  chain verifier now parses `basicConstraints` and `keyUsage` and enforces them on every
  certificate that signs another: an issuer MUST be a CA (`CA:TRUE`), a present `keyUsage`
  MUST permit `keyCertSign`, and a present `pathLenConstraint` MUST NOT be exceeded. This
  closes a path-validation defect where a genuine end-entity attestation leaf (CA:FALSE)
  could be wielded as an intermediate to sign a forged sub-certificate for a different
  AAGUID and still chain to the pinned root, defeating the AAGUID-spoof defense for anyone
  holding a key under a shared vendor root. The parser stays panic-safe (every length read
  guarded). New regression tests: the exact leaf-as-CA break is now rejected, a proper
  CA:TRUE intermediate still verifies, and the keyUsage and pathLen constraints are exercised.
- Attestation policy and FIDO MDS3 (issue #66 PR B): `verify_attestation` now verifies
  the attestation statement under a tenant's `direct` mode, supporting `none` and
  `packed` (WebAuthn L3 section 8.2) and failing closed on any other format; the new
  `mds3` module verifies the FIDO Metadata Service BLOB (a JWS with an `x5c` chain)
  against a pinned FIDO root and returns the per-AAGUID attestation roots. An in-tree
  minimal DER reader (`der`) and X.509 chain verifier (`x509`) anchor both, with every
  certificate-signature check delegated to `ironauth-jose` so `ring` stays confined.
  Ships the AAGUID-spoof, chain-to-wrong-root, expired-certificate, and tampered-BLOB
  adversarial tests over a self-generated Ed25519 test PKI.
- Related-origin coverage (issue #67): a `client_data` test documents that with the
  serving origin AND a related origin in the allowed set, a ceremony from either
  verifies while an unlisted origin still fails with `OriginMismatch`. No code change:
  `validate_client_data`/`VerificationParams` already take the full `allowed_origins`
  slice, so WebAuthn Level 3 Related Origin Requests is served entirely by the caller
  (ironauth-oidc) widening that set; the RP-ID-hash and signature checks are untouched.
- RSA modulus floor at registration (issue #65 review hardening): an RS256 COSE key
  whose modulus is outside 2048..=8192 bits is now rejected when the credential is
  parsed. `ring` rejects such a key at verify time, so a sub-2048-bit key would have
  registered but been permanently unusable (a dead-credential foot-gun); it is now
  refused up front.
- Initial release (issue #65): the WebAuthn Level 3 ceremony core. Builds the
  registration and authentication option documents (discoverable credentials and
  the `credProps` extension requested by default, `excludeCredentials` populated
  for dedupe, `attestation: "none"`) and parses and verifies the ceremony
  responses: the attestationObject CBOR, the COSE credential public key (ES256 /
  EdDSA / RS256), the authenticator data flags (UP/UV/BE/BS/AT/ED), and the
  clientDataJSON. Verification enforces the single-use challenge echo, the origin,
  the RP ID hash, and the flags, and for an assertion verifies the signature over
  `authenticatorData || SHA-256(clientDataJSON)` against the stored public key
  (delegated to the ring-backed `ironauth-jose` core) and computes the sign-count
  clone-detection verdict (a zero/zero counter is `NotSupported`, never a false
  positive). Pure and side-effect free: no clock, no entropy, no database, so a
  cancelled ceremony leaves no partial state. Built on `ciborium` for CBOR;
  `webauthn-rs` was rejected because `webauthn-rs-core` is MPL-2.0, which fails
  the `cargo deny` license gate. Attestation-statement trust (MDS3, AAGUID
  allowlists) is out of scope (issue #66); ceremonies request `attestation: "none"`.
