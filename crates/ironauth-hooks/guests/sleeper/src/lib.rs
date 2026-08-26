wit_bindgen::generate!({ path: "../../wit", world: "token-customize-hook" });

use exports::ironauth::hooks::token_customize::{Guest, Request, Response};

struct Hook;

impl Guest for Hook {
    fn customize(_req: Request) -> Result<Response, String> {
        // Plain std, no WASI knowledge required. On wasm32-wasip2 this lowers to
        // `wasi:clocks/monotonic-clock#subscribe-duration` plus `wasi:io/poll#poll`, and against
        // wasmtime-wasi's own clock it holds the host thread for the full thirty seconds while
        // executing no instructions: invisible to fuel, invisible to the memory cap, and
        // invisible to the epoch deadline, which is only checked when wasm code runs.
        //
        // Against this sandbox the wait is answered immediately, so the hook returns at once.
        std::thread::sleep(std::time::Duration::from_secs(30));
        Ok(Response {
            id_token_claims: vec![],
            access_token_claims: vec![],
        })
    }
}

export!(Hook);
