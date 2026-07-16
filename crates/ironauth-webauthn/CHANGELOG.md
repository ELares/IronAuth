# ironauth-webauthn changelog

All notable changes to the `ironauth-webauthn` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

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
