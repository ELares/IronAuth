// SPDX-License-Identifier: MIT OR Apache-2.0

//! Prints the management API OpenAPI 3.1 document as pretty JSON.
//!
//! Consumed by scripts/openapi-check.sh, which writes it to
//! docs/openapi/management.json and fails CI on any drift from the committed
//! artifact. The output is deterministic and database-free (the spec is
//! generated from the handler annotations, not from a running server).

fn main() {
    // `openapi_json` already ends with a trailing newline.
    print!("{}", ironauth_admin::openapi_json());
}
