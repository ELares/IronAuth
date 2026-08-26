wit_bindgen::generate!({ path: "../../wit", world: "token-customize-hook" });

use exports::ironauth::hooks::token_customize::{Guest, Request, Response};

struct Hook;

impl Guest for Hook {
    fn customize(_req: Request) -> Result<Response, String> {
        // Runs to completion and says no. Distinct from a trap, and the host must not
        // conflate them.
        Err("this subject is not eligible".to_string())
    }
}

export!(Hook);
