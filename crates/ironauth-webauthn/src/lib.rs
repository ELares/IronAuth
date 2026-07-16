// SPDX-License-Identifier: MIT OR Apache-2.0

//! The IronAuth WebAuthn (FIDO2) ceremony core.
//!
//! This crate implements WebAuthn Level 3 registration and authentication
//! ceremonies: it builds the option documents the browser consumes and it
//! parses and verifies the responses the browser returns. It is a pure,
//! side-effect free library. It never touches the database, the clock, or an
//! entropy source: the store layer generates and single-uses challenges from the
//! determinism seam and persists credentials, the OIDC layer mounts the HTTP
//! endpoints and the hosted-page conditional UI, and this crate does only the
//! protocol.
//!
//! # Why in-tree rather than `webauthn-rs`
//!
//! `webauthn-rs-core` is licensed MPL-2.0, which is not on the workspace
//! `cargo deny` license allowlist, so it would fail the supply-chain gate. It is
//! also a heavyweight framework that owns the whole ceremony, which does not fit
//! the codebase's own single-use challenge tables, per-tenant clone-detection
//! policy, and BE/BS persistence. This crate is a focused implementation over
//! `ciborium` (CBOR) and the existing ring-backed `ironauth-jose` core (the one
//! crate allowed to name `ring`), keeping the dependency graph clean and
//! `cargo deny` green.
//!
//! # The verification contract
//!
//! Both [`verify_registration`] and [`verify_authentication`] are total and
//! carry no wire oracle. They enforce, in order: the ceremony type, the
//! single-use challenge echo, the origin, the RP ID hash, and the authenticator
//! flags (user presence always; user verification when required). Authentication
//! additionally verifies the assertion signature over
//! `authenticatorData || SHA-256(clientDataJSON)` against the stored credential
//! public key, and computes the sign-count clone-detection verdict.
//!
//! Verification never mutates state, so a timed-out or cancelled ceremony leaves
//! no partial credential: the store layer persists only after `Ok`.
//!
//! Attestation-statement trust (MDS3, AAGUID allowlists) is deliberately OUT OF
//! SCOPE here (issue #66); ceremonies request `attestation: "none"`.

mod attestation;
mod authdata;
mod client_data;
mod cose;
mod digest;
mod encoding;
mod error;
mod flags;
mod options;
mod types;
mod verify;

pub use attestation::extract_auth_data;
pub use authdata::{AttestedCredential, AuthenticatorData, parse_authenticator_data};
pub use client_data::{ClientData, TYPE_CREATE, TYPE_GET, validate_client_data};
pub use cose::parse_cose_key;
pub use encoding::{b64_decode, b64_encode};
pub use error::CeremonyError;
pub use flags::AuthenticatorFlags;
pub use options::{
    AuthenticationResponse, ClientExtensionResults, CredProps, RegistrationResponse,
    authentication_options, registration_options,
};
pub use types::{
    AssertionOutcome, CeremonyUser, CredentialDescriptor, RegisteredCredential, RelyingParty,
    SignCountVerdict, UserVerification, sign_count_verdict,
};
pub use verify::{
    StoredCredential, VerificationParams, verify_authentication, verify_registration,
};

// The one cryptographic dependency's public key type is re-exported so callers
// that persist and reconstruct COSE keys can name it without depending on the
// JOSE crate directly.
pub use ironauth_jose::WebauthnKey;
