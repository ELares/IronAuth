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

/// Bytes per page touched, so the allocation is real rather than reserved.
const PAGE: usize = 4096;

impl Guest for Hook {
    fn customize(_req: Request) -> Result<Response, String> {
        // `vec![0u8; APPETITE]` then a WRITE into each page. An earlier version of this fixture
        // pushed one byte per page onto an empty Vec, which wrote 8 KiB at the head of the
        // buffer and touched nothing else: deleting the loop entirely changed no test outcome,
        // so the "touched, not just reserved" claim was a sentence with no mechanism under it.
        //
        // It matters because a reservation an allocator never writes to can be bookkeeping that
        // never grows linear memory, which would make the cap look enforced while nothing was
        // allocated at all.
        let mut held: Vec<u8> = vec![0u8; APPETITE];
        let mut touched: usize = 0;
        let mut index = 0;
        while index < APPETITE {
            held[index] = (index % 251) as u8;
            touched += 1;
            index += PAGE;
        }
        std::hint::black_box(&held);
        Ok(Response {
            id_token_claims: vec![],
            access_token_claims: vec![Claim {
                name: "pages_touched".to_string(),
                value_json: touched.to_string(),
            }],
        })
    }
}

export!(Hook);
