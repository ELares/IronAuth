wit_bindgen::generate!({ path: "../../wit", world: "token-customize-hook" });

use exports::ironauth::hooks::token_customize::{Guest, Request, Response};

struct Hook;

impl Guest for Hook {
    fn customize(_req: Request) -> Result<Response, String> {
        // Tries to reach the network. The point of this fixture is NOT that the connection
        // fails: it is that this guest never runs at all, because using TcpStream makes the
        // compiler emit a `wasi:sockets` import and the sandbox's linker offers none. The
        // failure is at instantiation, before any of this executes.
        match std::net::TcpStream::connect("127.0.0.1:9") {
            Ok(_) => Err("connected".to_string()),
            Err(error) => Err(format!("refused at runtime: {error}")),
        }
    }
}

export!(Hook);
