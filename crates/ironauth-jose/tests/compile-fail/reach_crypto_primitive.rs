// SPDX-License-Identifier: MIT OR Apache-2.0

// The raw signature check lives in the private `crypto` module. There is no
// path to it from outside the crate, so this fails to compile: the module is
// private.

fn main() {
    // ERROR: module `crypto` is private.
    let _ = ironauth_jose::crypto::verify_signature;
}
