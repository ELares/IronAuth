wit_bindgen::generate!({ path: "../../wit", world: "token-customize-hook" });

use exports::ironauth::hooks::token_customize::{Guest, Request, Response};
use ironauth::hooks::types::Claim;

struct Hook;

/// How much this guest allocates before returning, in bytes.
///
/// A FIXED amount rather than an unbounded loop, deliberately. An unbounded allocator proves
/// only that something stopped it, and "something" could be fuel, a trap, or the host running
/// out of its own memory. A fixed 32 MiB lets the test run the same guest under two caps, one
/// below and one above, and show that the CAP is what decides. That is the difference between
/// observing a failure and pinning its cause.
const APPETITE: usize = 32 << 20;

impl Guest for Hook {
    fn customize(_req: Request) -> Result<Response, String> {
        // Touched, not just reserved: an allocation the guest never writes to can be a
        // bookkeeping entry that never grows linear memory, and would make the cap look
        // enforced when nothing was allocated at all.
        let mut held: Vec<u8> = Vec::with_capacity(APPETITE);
        let mut index = 0;
        while index < APPETITE {
            held.push((index % 251) as u8);
            index += 4096;
        }
        std::hint::black_box(&held);
        Ok(Response {
            id_token_claims: vec![],
            access_token_claims: vec![Claim {
                name: "allocated".to_string(),
                value_json: APPETITE.to_string(),
            }],
        })
    }
}

export!(Hook);
