// SPDX-License-Identifier: MIT OR Apache-2.0

// The header parser and its trust guards live in the private `header` module.
// An outside caller cannot parse a header on its own to bypass the guards, so
// this fails to compile: the module is private.

fn main() {
    // ERROR: module `header` is private.
    let _ = ironauth_jose::header::parse;
}
