wit_bindgen::generate!({ path: "../../wit", world: "token-customize-hook" });

use exports::ironauth::hooks::token_customize::{Guest, Request, Response};

struct Hook;

/// How many entries this fixture puts in one poll list.
const ENTRIES: usize = 1_000_000;

impl Guest for Hook {
    fn customize(_req: Request) -> Result<Response, String> {
        // ONE pollable, polled a million times in a single call. The resource-table cap does not
        // see this: the table bounds DISTINCT resources, and every entry here is the same
        // handle. Measured before the poll list was bounded: 11.5 MiB of host RSS per call,
        // completing normally under a 16 MiB guest cap, and 739 MiB after sixty-four
        // invocations -- permanent, because it is the host's heap and not the guest's.
        let pollable = wasi::clocks::monotonic_clock::subscribe_duration(0);
        let list: Vec<&wasi::io::poll::Pollable> = (0..ENTRIES).map(|_| &pollable).collect();
        wasi::io::poll::poll(&list);
        Ok(Response {
            id_token_claims: vec![],
            access_token_claims: vec![],
        })
    }
}

export!(Hook);
