// SPDX-License-Identifier: MIT OR Apache-2.0
//! A hook written the way a MACHINE-GRANT author writes one (issue #113 criterion 1).
//!
//! It echoes `access_token_claims` faithfully, adds a marker, and returns an EMPTY
//! `id_token_claims` -- because `client_credentials`, `jwt:bearer` and token exchange mint no ID
//! token, so an author targeting them has no reason to fill that list.
//!
//! That makes it the discriminator for where the host puts a machine client's existing claims.
//! The seam used to hand them over as `id_token_claims`, on a token with no ID token, so this
//! hook -- which does everything right under the REPLACE contract -- silently deleted every
//! static claim the client had. `echo-only` cannot catch it (it echoes BOTH lists, so the old
//! union folded them back) and `good` cannot either (it echoes the ID list untouched).
//!
//! The distinction being pinned is not "a hook that ignores a list loses it": that is the
//! replace contract working. It is that the claims must arrive in the list an author for THIS
//! grant would actually read.

wit_bindgen::generate!({ path: "../../wit", world: "token-customize-hook" });

use exports::ironauth::hooks::token_customize::{Guest, Request, Response};
use ironauth::hooks::types::Claim;

struct Hook;

impl Guest for Hook {
    fn customize(req: Request) -> Result<Response, String> {
        let mut access = req.access_token_claims;
        access.push(Claim {
            name: "echo_access_only_ran".to_string(),
            value_json: "true".to_string(),
        });
        Ok(Response {
            id_token_claims: Vec::new(),
            access_token_claims: access,
        })
    }
}

export!(Hook);
