// SPDX-License-Identifier: MIT OR Apache-2.0
//! A hook that REMOVES a claim (issue #114).
//!
//! The WIT contract is a replace: a hook receives both claim lists and returns both, so the way
//! to keep a claim is to echo it and the way to drop one is not to. The shipped `good` guest
//! echoes its input precisely because of that.
//!
//! The first dispatch MERGED what a hook returned into what the mint had, so a hook deployed to
//! strip a claim produced a token that still carried it -- and the fail-closed argument
//! everything in the dispatch rests on ("a hook can REMOVE a claim as easily as add one") was
//! false of the dispatch that stated it. Nothing measured it, because no guest removed anything.
//!
//! It drops `email` and adds a marker, so a test can tell removal from a hook that never ran.

wit_bindgen::generate!({ path: "../../wit", world: "token-customize-hook" });

use exports::ironauth::hooks::token_customize::{Guest, Request, Response};
use ironauth::hooks::types::Claim;

struct Hook;

fn without_email(claims: Vec<Claim>) -> Vec<Claim> {
    let mut kept: Vec<Claim> = claims.into_iter().filter(|c| c.name != "email").collect();
    kept.push(Claim {
        name: "stripper_ran".to_string(),
        value_json: "true".to_string(),
    });
    kept
}

impl Guest for Hook {
    fn customize(req: Request) -> Result<Response, String> {
        Ok(Response {
            id_token_claims: without_email(req.id_token_claims),
            access_token_claims: without_email(req.access_token_claims),
        })
    }
}

export!(Hook);
