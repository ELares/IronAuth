wit_bindgen::generate!({ path: "../../wit", world: "token-customize-hook" });

use exports::ironauth::hooks::token_customize::{Guest, Request, Response};
use ironauth::hooks::types::Claim;

struct Hook;

impl Guest for Hook {
    fn customize(req: Request) -> Result<Response, String> {
        // Returns every SCALAR field of the request as a claim, so the host can assert each one
        // arrived where it belongs. Without this, four of the six fields cross the boundary
        // unobserved: `grant_type` and `client_id` are both strings and can be swapped with
        // nothing red, and `payload_version` and `subject` can be dropped entirely.
        //
        // A hook that gates on the grant type is a first-class use of this contract, so a
        // transport that silently hands it the client id is a correctness bug in the hook's
        // decision, not a cosmetic one.
        Ok(Response {
            id_token_claims: vec![Claim {
                name: "echo_subject".to_string(),
                value_json: match req.subject {
                    Some(subject) => format!("\"{subject}\""),
                    None => "null".to_string(),
                },
            }],
            access_token_claims: vec![
                Claim {
                    name: "echo_grant_type".to_string(),
                    value_json: format!("\"{}\"", req.grant_type),
                },
                Claim {
                    name: "echo_client_id".to_string(),
                    value_json: format!("\"{}\"", req.client_id),
                },
                Claim {
                    name: "echo_payload_version".to_string(),
                    value_json: req.payload_version.to_string(),
                },
            ],
        })
    }
}

export!(Hook);
