// SPDX-License-Identifier: MIT OR Apache-2.0
//! A hook that reports what it was HANDED, so a chain's order can be measured (issue #114).
//!
//! # Why the other fixtures cannot measure an order
//!
//! The first version of the chain test deployed `good` (adds `tier`, echoes the rest) and
//! `claim-stripper` (drops `email`, adds a marker) and asserted that the token carried both
//! markers and had lost `email`. That holds in EITHER order -- the two compose commutatively --
//! so the test passed with the chain read `ORDER BY ordinal DESC`. Measured: it did.
//!
//! An order is only observable through a hook whose OUTPUT depends on its INPUT. This one
//! echoes both lists unchanged and adds a single boolean: whether the access list it received
//! already carried `tier`, which is `good`'s contribution. Behind `good` that is true; ahead of
//! it, false. The claim is named for the question rather than the fixture, because what it
//! pins is "was I handed the previous hook's work".
//!
//! It adds exactly one claim and removes nothing, so it composes with anything and can be
//! placed at any position in a chain under test.

wit_bindgen::generate!({ path: "../../wit", world: "token-customize-hook" });

use exports::ironauth::hooks::token_customize::{Guest, Request, Response};
use ironauth::hooks::types::Claim;

struct Hook;

impl Guest for Hook {
    fn customize(req: Request) -> Result<Response, String> {
        let saw_tier = req
            .access_token_claims
            .iter()
            .any(|claim| claim.name == "tier");
        let mut access = req.access_token_claims;
        access.push(Claim {
            name: "saw_previous_hook".to_string(),
            value_json: if saw_tier { "true" } else { "false" }.to_string(),
        });
        Ok(Response {
            id_token_claims: req.id_token_claims,
            access_token_claims: access,
        })
    }
}

export!(Hook);
