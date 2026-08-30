// SPDX-License-Identifier: MIT OR Apache-2.0
//! A hook that reads a granted secret, so the capability can be measured (issue #114).
//!
//! Per-hook secrets are an IMPORT rather than a field on the request, which is what lets them
//! be added without breaking every already-compiled guest. This is the fixture that exercises
//! the import: it asks for two names and reports what it was told.
//!
//! # Two names, and the second is the point
//!
//! `granted` is the name a test grants. `withheld` is a name the test never grants, and asking
//! for it is what makes DENY BY DEFAULT observable: a host that answered every name would
//! satisfy any test that only asked for the granted one.
//!
//! It reports the VALUE of the granted secret, not merely that it got one. A hook that received
//! an empty string and one that received the operator's key are the same observation otherwise,
//! and the second is what a real hook signs with.

wit_bindgen::generate!({ path: "../../wit", world: "token-customize-hook" });

use exports::ironauth::hooks::token_customize::{Guest, Request, Response};
use ironauth::hooks::secrets;
use ironauth::hooks::types::Claim;

struct Hook;

/// The name a test grants, and one it never does.
const GRANTED: &str = "granted";
const WITHHELD: &str = "withheld";

fn json_string(value: &str) -> String {
    // Minimal escaping: the fixture controls what it is handed, and a secret value with a
    // quote in it would otherwise produce a claim the host cannot parse -- which the host
    // counts as `values_not_json` and drops, turning a capability test into a serialisation
    // test.
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

impl Guest for Hook {
    fn customize(req: Request) -> Result<Response, String> {
        let mut access = req.access_token_claims;
        access.push(Claim {
            name: "secret_granted".to_string(),
            value_json: match secrets::get(GRANTED) {
                Some(value) => json_string(&value),
                None => "null".to_string(),
            },
        });
        access.push(Claim {
            name: "secret_withheld".to_string(),
            value_json: match secrets::get(WITHHELD) {
                Some(value) => json_string(&value),
                None => "null".to_string(),
            },
        });
        Ok(Response {
            id_token_claims: req.id_token_claims,
            access_token_claims: access,
        })
    }
}

export!(Hook);
