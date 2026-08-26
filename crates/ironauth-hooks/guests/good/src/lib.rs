wit_bindgen::generate!({ path: "../../wit", world: "token-customize-hook" });

use exports::ironauth::hooks::token_customize::{Guest, Request, Response};
use ironauth::hooks::types::Claim;

struct Hook;

impl Guest for Hook {
    fn customize(req: Request) -> Result<Response, String> {
        // Adds one claim it is allowed to add, and echoes the rest untouched.
        let mut access = req.access_token_claims;
        access.push(Claim { name: "tier".to_string(), value_json: "\"gold\"".to_string() });
        Ok(Response { id_token_claims: req.id_token_claims, access_token_claims: access })
    }
}

export!(Hook);
