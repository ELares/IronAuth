// SPDX-License-Identifier: MIT OR Apache-2.0

// A trusted key is opaque: its inner key material is a private field, so an
// outside caller cannot extract the raw bytes and hand them to a hand-rolled
// verifier. This fails to compile: the field is private.

fn main() {
    let key = ironauth_jose::TrustedKey::ed25519(None, &[0u8; 32]).unwrap();
    // ERROR: field `material` of struct `TrustedKey` is private.
    let _ = key.material;
}
