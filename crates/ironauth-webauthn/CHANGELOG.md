# ironauth-webauthn changelog

All notable changes to the `ironauth-webauthn` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

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
