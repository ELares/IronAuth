wit_bindgen::generate!({ path: "../../wit", world: "token-customize-hook" });

use exports::ironauth::hooks::token_customize::{Guest, Request, Response};
use ironauth::hooks::types::Claim;
use std::collections::HashMap;

struct Hook;

impl Guest for Hook {
    fn customize(req: Request) -> Result<Response, String> {
        // A HashMap, which is the ordinary way to write this and is exactly the point: std's
        // default hasher is randomly seeded, so this imports `wasi:random/insecure-seed`
        // whether or not the author has any idea randomness is involved. The sandbox links no
        // randomness, so this component never instantiates.
        //
        // That is deny-by-default working, and it is also a real cost to hook authors, which is
        // why it is a fixture rather than a footnote: the refusal has to be a tested,
        // legible one and not a surprise at deploy time.
        let mut by_name: HashMap<String, String> = HashMap::new();
        for claim in req.access_token_claims {
            by_name.insert(claim.name, claim.value_json);
        }
        Ok(Response {
            id_token_claims: vec![],
            access_token_claims: by_name
                .into_iter()
                .map(|(name, value_json)| Claim { name, value_json })
                .collect(),
        })
    }
}

export!(Hook);
