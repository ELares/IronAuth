wit_bindgen::generate!({ path: "../../wit", world: "token-customize-hook" });

use exports::ironauth::hooks::token_customize::{Claim, Guest, Request, Response};

struct Hook;

impl Guest for Hook {
    fn customize(_req: Request) -> Result<Response, String> {
        // Reads the monotonic clock twice with work in between, and reports the elapsed
        // nanoseconds as a claim. Against the frozen clock the answer must be 0: the interface
        // is present, because std imports it whether or not a hook uses it, but it tells the
        // guest nothing.
        let start = std::time::Instant::now();
        let mut n: u64 = 0;
        for i in 0..200_000u64 {
            n = n.wrapping_add(i);
        }
        std::hint::black_box(n);
        let elapsed = start.elapsed().as_nanos();
        Ok(Response {
            id_token_claims: vec![],
            access_token_claims: vec![Claim {
                name: "elapsed_ns".to_string(),
                value_json: elapsed.to_string(),
            }],
        })
    }
}

export!(Hook);
