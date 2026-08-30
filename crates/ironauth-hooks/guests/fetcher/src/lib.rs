// SPDX-License-Identifier: MIT OR Apache-2.0
//! A hook that makes outbound requests, so the capability and its budget can be measured
//! (issue #114 criterion 2).
//!
//! It asks for THREE, which is the point: a test grants fewer and asserts where the refusals
//! begin. A guest that made one request could only show granted-or-not, and the criterion is
//! about what happens when a hook asks for more than it was given.
//!
//! Each attempt is reported as its own claim -- `fetch_1`, `fetch_2`, `fetch_3` -- carrying
//! either the response body or the host's refusal. Reporting them separately is what makes the
//! BOUNDARY visible: a test can see that the first two succeeded and the third did not, which a
//! single "did it work" claim could not distinguish from "none of them worked".
//!
//! It does not stop at the first refusal, deliberately. A hook that gave up would leave the
//! host's counter untested past the boundary, and "the budget stays exhausted" is a property
//! worth having: a refusal must not refund.

wit_bindgen::generate!({ path: "../../wit", world: "token-customize-hook" });

use exports::ironauth::hooks::token_customize::{Guest, Request, Response};
use ironauth::hooks::fetch;
use ironauth::hooks::types::Claim;

struct Hook;

/// How many attempts this guest makes. More than any test grants, so the boundary is inside it.
const ATTEMPTS: usize = 3;

fn json_string(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

impl Guest for Hook {
    fn customize(req: Request) -> Result<Response, String> {
        let mut access = req.access_token_claims;
        for attempt in 1..=ATTEMPTS {
            let reported = match fetch::get("https://upstream.test/claims") {
                Ok(response) => format!("ok:{}:{}", response.status, response.body),
                Err(refusal) => format!("err:{refusal}"),
            };
            access.push(Claim {
                name: format!("fetch_{attempt}"),
                value_json: json_string(&reported),
            });
        }
        Ok(Response {
            id_token_claims: req.id_token_claims,
            access_token_claims: access,
        })
    }
}

export!(Hook);
