wit_bindgen::generate!({ path: "../../wit", world: "token-customize-hook" });

use exports::ironauth::hooks::token_customize::{Guest, Request, Response};

struct Hook;

impl Guest for Hook {
    fn customize(_req: Request) -> Result<Response, String> {
        // Waits on subscribe_INSTANT, the other half of the clock's waiting surface.
        //
        // `sleeper` covers `subscribe_duration`, which is what `std::thread::sleep` lowers to.
        // A guest can ask to wait until an absolute instant instead, and that is a separate
        // function: reintroducing a real timer on this one alone held the host thread for
        // twenty seconds with the whole suite green.
        let pollable = wasi::clocks::monotonic_clock::subscribe_instant(u64::MAX);
        pollable.block();
        Ok(Response {
            id_token_claims: vec![],
            access_token_claims: vec![],
        })
    }
}

export!(Hook);
