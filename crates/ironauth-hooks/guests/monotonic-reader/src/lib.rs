wit_bindgen::generate!({ path: "../../wit", world: "token-customize-hook" });

use exports::ironauth::hooks::token_customize::{Guest, Request, Response};
use ironauth::hooks::types::Claim;

struct Hook;

impl Guest for Hook {
    fn customize(_req: Request) -> Result<Response, String> {
        // Reads the clock, does real work, reads it again. Against the frozen clock the
        // difference must be 0 while the resolution is still fine-grained: the interface is
        // present, and it tells the guest nothing.
        let start = wasi::clocks::monotonic_clock::now();
        let mut n: u64 = 0;
        for i in 0..500_000u64 {
            n = n.wrapping_add(i);
        }
        std::hint::black_box(n);
        let end = wasi::clocks::monotonic_clock::now();
        let resolution = wasi::clocks::monotonic_clock::resolution();
        Ok(Response {
            id_token_claims: vec![],
            access_token_claims: vec![
                Claim {
                    name: "elapsed_ns".to_string(),
                    value_json: end.saturating_sub(start).to_string(),
                },
                Claim {
                    name: "resolution_ns".to_string(),
                    value_json: resolution.to_string(),
                },
            ],
        })
    }
}

export!(Hook);
