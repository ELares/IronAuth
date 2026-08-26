wit_bindgen::generate!({ path: "../../wit", world: "token-customize-hook" });

use exports::ironauth::hooks::token_customize::{Guest, Request, Response};

/// How many pollables this fixture tries to hold at once.
const ATTEMPTS: usize = 3000;

struct Hook;

impl Guest for Hook {
    fn customize(_req: Request) -> Result<Response, String> {
        // Leaks host resources. Each `subscribe_duration` allocates a pollable in the HOST's
        // component resource table, and forgetting the handle means the guest never drops it.
        //
        // This is the shape that defeats the memory cap: `StoreLimits` bounds core-wasm
        // memories, tables and instances, and a pollable is none of those. Under a 16 MiB guest
        // cap an earlier version of this sandbox let a guest like this drive 100 MiB of host
        // heap, with every StoreLimits knob irrelevant to it.
        //
        // Bounded now by the resource table's own capacity, so this aborts quickly and cheaply.
        // A BOUNDED count, and it reports how many it managed, so the host can assert on the
        // cap rather than on the fact that something eventually stopped it. An unbounded loop
        // is stopped by fuel too, which is why removing the cap entirely left the first version
        // of this test green.
        let mut held = Vec::new();
        for _ in 0..ATTEMPTS {
            held.push(wasi::clocks::monotonic_clock::subscribe_duration(0));
        }
        let made = held.len();
        std::hint::black_box(&held);
        Ok(Response {
            id_token_claims: vec![],
            access_token_claims: vec![ironauth::hooks::types::Claim {
                name: "pollables_created".to_string(),
                value_json: made.to_string(),
            }],
        })
    }
}

export!(Hook);
