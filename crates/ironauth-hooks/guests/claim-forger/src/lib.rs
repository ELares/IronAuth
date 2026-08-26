// SPDX-License-Identifier: MIT OR Apache-2.0
//! A hook that tries to rewrite the identity (issue #113 criterion 5, the "or hook" half).
//!
//! The criterion says protected claims "cannot be overridden by any mapping OR HOOK". The
//! mapping half is fenced at the admin write and again at issuance; the hook half is fenced by
//! `filter_hook_claims` on what a hook RETURNS -- and until this guest existed, deleting that
//! fence left every test green, because no guest ever returned a protected claim.
//!
//! It returns `sub` and `iss` alongside one claim it is allowed to write. The allowed one is
//! what makes the test able to distinguish "the fence dropped the forged claims" from "the hook
//! never ran at all", which are the same observation without it.

wit_bindgen::generate!({ path: "../../wit", world: "token-customize-hook" });

use exports::ironauth::hooks::token_customize::{Guest, Request, Response};
use ironauth::hooks::types::Claim;

struct Hook;

fn forged() -> Vec<Claim> {
    vec![
        // The identity itself. A token whose `sub` a hook chose is a token that authenticates
        // whoever the hook says.
        Claim {
            name: "sub".to_string(),
            value_json: "\"usr_attacker\"".to_string(),
        },
        // And the issuer, which is what a verifier checks before it trusts anything else.
        Claim {
            name: "iss".to_string(),
            value_json: "\"https://attacker.example\"".to_string(),
        },
        // One the fence ALLOWS, so a test can tell a working fence from a hook that never ran.
        Claim {
            name: "forger_ran".to_string(),
            value_json: "true".to_string(),
        },
        // AND THREE THE HOOK FENCE ALONE CATCHES. `sub` and `iss` above are also refused by the
        // mint's own channel fence, so a test asserting only those measures the composite and
        // says nothing about `filter_hook_claims` -- measured: replacing that function with an
        // identity left such a test green.
        //
        // These three are name HYGIENE, which the mint's name-list fence does not look at:
        Claim {
            // Untrimmed. Two claims differing only by whitespace are two claims to a JSON
            // reader and one to a human, which is a way to shadow a name.
            name: "  forged_untrimmed  ".to_string(),
            value_json: "true".to_string(),
        },
        Claim {
            // Empty, which is a claim with no name at all.
            name: String::new(),
            value_json: "true".to_string(),
        },
        Claim {
            // Longer than the fence's byte bound. An unbounded name is an unbounded string in
            // every token, every log line, and every downstream parser.
            name: "f".repeat(4096),
            value_json: "true".to_string(),
        },
    ]
}

impl Guest for Hook {
    fn customize(_req: Request) -> Result<Response, String> {
        Ok(Response {
            id_token_claims: forged(),
            access_token_claims: forged(),
        })
    }
}

export!(Hook);
