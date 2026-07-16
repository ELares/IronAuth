// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ceremony option documents sent to the browser and the response envelopes
//! parsed back from it.
//!
//! The option builders produce the exact WebAuthn JSON a browser's
//! `navigator.credentials.create` / `.get` consumes. Discoverable credentials
//! (resident keys) are requested by default and the `credProps` extension is
//! always requested so the `rk` result can be stored. The response envelopes are
//! the JSON the client posts back after the ceremony.

use serde::Deserialize;
use serde_json::{Value, json};

use crate::encoding::b64_encode;
use crate::types::{CeremonyUser, CredentialDescriptor, RelyingParty, UserVerification};

/// The COSE algorithm identifiers advertised in `pubKeyCredParams`, in
/// preference order: ES256 (most widely supported), then `EdDSA`, then RS256.
const PUB_KEY_CRED_PARAMS: [i32; 3] = [-7, -8, -257];

fn cred_params_json() -> Value {
    Value::Array(
        PUB_KEY_CRED_PARAMS
            .iter()
            .map(|alg| json!({ "type": "public-key", "alg": alg }))
            .collect(),
    )
}

fn descriptors_json(descriptors: &[CredentialDescriptor]) -> Value {
    Value::Array(
        descriptors
            .iter()
            .map(|d| {
                json!({
                    "type": "public-key",
                    "id": b64_encode(&d.id),
                    "transports": d.transports,
                })
            })
            .collect(),
    )
}

/// Build the `PublicKeyCredentialCreationOptions` JSON for a registration
/// ceremony.
///
/// Discoverable credentials are requested (`residentKey: "required"`), the
/// `credProps` extension is requested, and `excludeCredentials` is populated so
/// an authenticator that already holds a credential for this user cannot enroll
/// a duplicate. Attestation is `"none"`: attestation-statement trust is out of
/// scope for this issue.
#[must_use]
pub fn registration_options(
    rp: &RelyingParty,
    user: &CeremonyUser,
    challenge: &[u8],
    exclude_credentials: &[CredentialDescriptor],
    timeout_ms: u64,
    user_verification: UserVerification,
) -> Value {
    json!({
        "rp": { "id": rp.id, "name": rp.name },
        "user": {
            "id": b64_encode(&user.id),
            "name": user.name,
            "displayName": user.display_name,
        },
        "challenge": b64_encode(challenge),
        "pubKeyCredParams": cred_params_json(),
        "timeout": timeout_ms,
        "excludeCredentials": descriptors_json(exclude_credentials),
        "authenticatorSelection": {
            "residentKey": "required",
            "requireResidentKey": true,
            "userVerification": user_verification.as_str(),
        },
        "attestation": "none",
        "extensions": { "credProps": true },
    })
}

/// Build the `PublicKeyCredentialRequestOptions` JSON for an authentication
/// ceremony.
///
/// `allow_credentials` is empty for a discoverable-credential / conditional-UI
/// sign-in (the authenticator offers whatever passkeys it holds for the RP ID);
/// it may be populated for a non-discoverable authenticator whose credential id
/// is known.
#[must_use]
pub fn authentication_options(
    rp_id: &str,
    challenge: &[u8],
    allow_credentials: &[CredentialDescriptor],
    timeout_ms: u64,
    user_verification: UserVerification,
) -> Value {
    json!({
        "challenge": b64_encode(challenge),
        "timeout": timeout_ms,
        "rpId": rp_id,
        "allowCredentials": descriptors_json(allow_credentials),
        "userVerification": user_verification.as_str(),
    })
}

/// The registration response envelope the client posts back after
/// `navigator.credentials.create`.
#[derive(Debug, Deserialize)]
pub struct RegistrationResponse {
    /// The base64url raw credential id (the `id` field; `rawId` is the same
    /// value and is accepted as a fallback).
    #[serde(default)]
    pub id: Option<String>,
    /// The base64url raw credential id.
    #[serde(default, rename = "rawId")]
    pub raw_id: Option<String>,
    /// The inner authenticator response.
    pub response: RegistrationResponseInner,
    /// Client extension results (`credProps`, ...).
    #[serde(default, rename = "clientExtensionResults")]
    pub client_extension_results: ClientExtensionResults,
}

/// The inner authenticator response for a registration.
#[derive(Debug, Deserialize)]
pub struct RegistrationResponseInner {
    /// base64url clientDataJSON.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// base64url attestationObject.
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    /// The transports the client observed for the new credential.
    #[serde(default)]
    pub transports: Vec<String>,
}

/// The authentication response envelope the client posts back after
/// `navigator.credentials.get`.
#[derive(Debug, Deserialize)]
pub struct AuthenticationResponse {
    /// The base64url raw credential id.
    #[serde(default)]
    pub id: Option<String>,
    /// The base64url raw credential id.
    #[serde(default, rename = "rawId")]
    pub raw_id: Option<String>,
    /// The inner authenticator response.
    pub response: AuthenticationResponseInner,
}

/// The inner authenticator response for an authentication.
#[derive(Debug, Deserialize)]
pub struct AuthenticationResponseInner {
    /// base64url clientDataJSON.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// base64url authenticatorData.
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    /// base64url signature.
    pub signature: String,
    /// base64url user handle (present for a discoverable-credential assertion).
    #[serde(default, rename = "userHandle")]
    pub user_handle: Option<String>,
}

/// The client extension results relevant to this issue.
#[derive(Debug, Default, Deserialize)]
pub struct ClientExtensionResults {
    /// The `credProps` extension result.
    #[serde(default, rename = "credProps")]
    pub cred_props: Option<CredProps>,
}

/// The `credProps` client-extension result.
#[derive(Debug, Deserialize)]
pub struct CredProps {
    /// Whether the created credential is discoverable (a resident key).
    #[serde(default)]
    pub rk: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_options_request_discoverable_and_credprops() {
        let rp = RelyingParty {
            id: "auth.example.test".into(),
            name: "Example".into(),
        };
        let user = CeremonyUser {
            id: vec![1, 2, 3],
            name: "alice".into(),
            display_name: "Alice".into(),
        };
        let exclude = vec![CredentialDescriptor {
            id: vec![9, 9, 9],
            transports: vec!["internal".into()],
        }];
        let opts = registration_options(
            &rp,
            &user,
            b"challenge",
            &exclude,
            60_000,
            UserVerification::Required,
        );
        assert_eq!(opts["rp"]["id"], "auth.example.test");
        assert_eq!(opts["authenticatorSelection"]["residentKey"], "required");
        assert_eq!(
            opts["authenticatorSelection"]["userVerification"],
            "required"
        );
        assert_eq!(opts["extensions"]["credProps"], true);
        assert_eq!(opts["attestation"], "none");
        assert_eq!(opts["excludeCredentials"][0]["id"], b64_encode(&[9, 9, 9]));
        // ES256 advertised first.
        assert_eq!(opts["pubKeyCredParams"][0]["alg"], -7);
    }

    #[test]
    fn authentication_options_empty_allow_list_for_conditional_ui() {
        let opts = authentication_options(
            "auth.example.test",
            b"challenge",
            &[],
            60_000,
            UserVerification::Required,
        );
        assert_eq!(opts["rpId"], "auth.example.test");
        assert_eq!(opts["userVerification"], "required");
        assert!(opts["allowCredentials"].as_array().unwrap().is_empty());
    }

    #[test]
    fn parses_a_registration_response_envelope() {
        let json = r#"{
            "id": "abc",
            "rawId": "abc",
            "type": "public-key",
            "response": {
                "clientDataJSON": "eyJ9",
                "attestationObject": "o2Nm",
                "transports": ["internal", "hybrid"]
            },
            "clientExtensionResults": { "credProps": { "rk": true } }
        }"#;
        let parsed: RegistrationResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.response.transports, vec!["internal", "hybrid"]);
        assert_eq!(
            parsed.client_extension_results.cred_props.unwrap().rk,
            Some(true)
        );
    }
}
