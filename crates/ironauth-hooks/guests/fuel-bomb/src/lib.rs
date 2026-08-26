wit_bindgen::generate!({ path: "../../wit", world: "token-customize-hook" });

use exports::ironauth::hooks::token_customize::{Guest, Request, Response};

struct Hook;

impl Guest for Hook {
    fn customize(_req: Request) -> Result<Response, String> {
        // Spins forever. Bounded only by fuel: it never blocks, so it burns instructions,
        // which is exactly what fuel counts.
        let mut n: u64 = 0;
        loop {
            n = n.wrapping_add(1);
            std::hint::black_box(n);
        }
    }
}

export!(Hook);
