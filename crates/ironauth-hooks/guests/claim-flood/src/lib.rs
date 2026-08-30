// SPDX-License-Identifier: MIT OR Apache-2.0
//! A hook that refuses MORE than the fence will report (issue #114 criterion 5).
//!
//! `filter_hook_claims` reports at most sixty-four refusals per token and walks a `BTreeMap`,
//! so it keeps the alphabetically FIRST names and counts the rest into
//! `refusals_not_reported`. Every other fixture refuses a handful at most -- `claim-forger`,
//! the widest, refuses five -- so that count was zero on every test in the tree, and a draft
//! report that threw it away was indistinguishable from one that carried it.
//!
//! It returns `a000`..`a095` plus a forged `sub`, in both tokens. The ninety-six padding names
//! sort ahead of `sub`: thirty-two are accepted, sixty-four overflow and fill the report, and
//! `sub` is the sixty-fifth refusal -- so it is COUNTED and never NAMED. That is the exact
//! scenario the response field exists for. An operator reviewing this hook cannot see the
//! forgery in `refused`; the count is the only thing telling them the list is a sample.

wit_bindgen::generate!({ path: "../../wit", world: "token-customize-hook" });

use exports::ironauth::hooks::token_customize::{Guest, Request, Response};
use ironauth::hooks::types::Claim;

struct Hook;

/// Ninety-six padding names, then `sub`, which sorts after every one of them.
fn flood() -> Vec<Claim> {
    let mut claims: Vec<Claim> = (0..96)
        .map(|index| Claim {
            name: format!("a{index:03}"),
            value_json: "true".to_string(),
        })
        .collect();
    // A DIFFERENT value from the one the fixture event carries, deliberately: the fence judges
    // what a hook CONTRIBUTED, and a claim handed back unchanged is one it echoed. A `sub`
    // echoed verbatim would never reach the fence at all.
    claims.push(Claim {
        name: "sub".to_string(),
        value_json: "\"usr_attacker\"".to_string(),
    });
    claims
}

impl Guest for Hook {
    fn customize(_req: Request) -> Result<Response, String> {
        // BOTH tokens, because the two are capped independently and their remainders are
        // summed. Flooding one would leave a fence that reported only the ID token's count
        // reading as the whole truth.
        Ok(Response {
            id_token_claims: flood(),
            access_token_claims: flood(),
        })
    }
}

export!(Hook);
