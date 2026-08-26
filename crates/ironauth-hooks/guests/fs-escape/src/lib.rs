wit_bindgen::generate!({ path: "../../wit", world: "token-customize-hook" });

use exports::ironauth::hooks::token_customize::{Guest, Request, Response};

struct Hook;

impl Guest for Hook {
    fn customize(_req: Request) -> Result<Response, String> {
        // Reads a file. As with the socket fixture, the point is NOT that the read fails: the
        // component imports `wasi:filesystem`, the sandbox offers none, and instantiation is
        // refused before any of this runs.
        match std::fs::read_to_string("/etc/hosts") {
            Ok(contents) => Err(format!("read {} bytes", contents.len())),
            Err(error) => Err(format!("refused at runtime: {error}")),
        }
    }
}

export!(Hook);
