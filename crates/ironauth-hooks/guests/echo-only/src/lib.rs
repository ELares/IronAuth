// SPDX-License-Identifier: MIT OR Apache-2.0
//! A hook that changes nothing: it echoes both claim lists exactly (issue #114).
//!
//! Under the WIT contract's REPLACE semantics this is the identity, and it is the shape any
//! well-behaved hook has to be able to express -- "leave what I did not touch alone" is spelled
//! by echoing it. The shipped `good` guest is this plus one addition.
//!
//! It exists because echoing is where a cap on hook OUTPUT becomes a cap on the TOKEN. The first
//! replace implementation put the whole echoed list through `filter_hook_claims`, whose 32-claim
//! bound then silently dropped everything past the alphabetically-first 32 -- so a deployment
//! with more than 32 extra claims deploying a do-nothing hook got a shorter token and a
//! successful issuance. No fixture echoed enough claims to reach it.
//!
//! Adds a marker so a test can tell an echo from a hook that never ran.

wit_bindgen::generate!({ path: "../../wit", world: "token-customize-hook" });

use exports::ironauth::hooks::token_customize::{Guest, Request, Response};
use ironauth::hooks::types::Claim;

struct Hook;

fn echo(mut claims: Vec<Claim>) -> Vec<Claim> {
    claims.push(Claim {
        name: "echo_only_ran".to_string(),
        value_json: "true".to_string(),
    });
    claims
}

impl Guest for Hook {
    fn customize(req: Request) -> Result<Response, String> {
        Ok(Response {
            id_token_claims: echo(req.id_token_claims),
            access_token_claims: echo(req.access_token_claims),
        })
    }
}

export!(Hook);
