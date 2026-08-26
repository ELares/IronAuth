wit_bindgen::generate!({ path: "../../wit", world: "token-customize-hook" });

use exports::ironauth::hooks::token_customize::{Guest, Request, Response};

/// How long this fixture asks to sleep.
const SLEEP_SECONDS: u64 = 30;

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
        std::thread::sleep(std::time::Duration::from_secs(SLEEP_SECONDS));
        // Reports what it ASKED for, so the host's threshold can be derived from the fixture
        // rather than hard-coded. Without this the test's 5-second bound is independent of the
        // sleep: deleting the sleep entirely leaves the test green, and it then passes against
        // a sandbox where waiting still works.
        Ok(Response {
            id_token_claims: vec![],
            access_token_claims: vec![(
                "requested_sleep_seconds".to_string(),
                SLEEP_SECONDS.to_string(),
            )]
            .into_iter()
            .map(|(name, value_json)| ironauth::hooks::types::Claim { name, value_json })
            .collect(),
        })
    }
}

export!(Hook);
