wit_bindgen::generate!({ path: "../../wit", world: "token-customize-hook" });

use exports::ironauth::hooks::token_customize::{Claim, Guest, Request, Response};

struct Hook;

impl Guest for Hook {
    fn customize(_req: Request) -> Result<Response, String> {
        // Uses `std::time`, which on wasm32-wasip2 imports `wasi:clocks/wall-clock` as well as
        // the monotonic clock. The sandbox links only the latter, so this component fails to
        // INSTANTIATE and none of the code below ever runs.
        //
        // That is the finding this fixture exists to pin: the frozen monotonic clock is not
        // reachable through `std::time` at all. A hook author who wants it must call the `wasi`
        // crate's `clocks::monotonic_clock` directly, which is what `monotonic-reader` does.
        //
        // invariant-allow: time-via-env -- guest code compiled to wasm32-wasip2, not host
        // protocol logic, and the raw call IS the test subject: it is here precisely to force
        // the wall-clock import so the sandbox can be shown refusing it.
        let start = std::time::Instant::now(); // invariant-allow: time-via-env -- GUEST code compiled to wasm32-wasip2, not host protocol logic, and the raw call IS the test subject: it is here to force the wasi:clocks/wall-clock import so the sandbox can be shown refusing it
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
