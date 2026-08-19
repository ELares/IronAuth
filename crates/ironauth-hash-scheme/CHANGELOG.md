# ironauth-hash-scheme changelog

All notable changes to the `ironauth-hash-scheme` crate. Format: keep a section per
released version, newest first; every release names the artifact and version range per
docs/RELEASING.md.

## Unreleased

- **The RustCrypto block ciphers moved to their 2024 line**: `aes` 0.8 -> 0.9 and `ctr` 0.9
  -> 0.10. They move as a family (`aes` 0.9 does not accept a `ctr` 0.9 cipher and vice
  versa), so the TWO dependabot PRs proposing them one at a time could not compile. A third
  proposed `cipher` 0.4 -> 0.5, which built and passed; see the next entry for why it
  existed at all.

  No source change was needed. The published Firebase known-answer vector still verifies,
  which is the assertion that matters for a cipher migration: it either reproduces a fixed
  ciphertext or it does not.

  A second test now pins the COUNTER WIDTH, which that vector structurally cannot see.
  Firebase's signer key is four AES blocks under an all-zero IV, so the counter never
  crosses the 64-bit boundary and `Ctr64BE` would reproduce the vector byte for byte.
  Measured, and closed with a fixed expected block taken on an IV that does carry.

- **Dropped `cipher` as a direct dependency.** The traits this crate uses arrive through
  `aes`'s re-export (`use aes::cipher::{KeyIvInit, StreamCipher}`), and the manifest entry
  named a crate the source never does. It is the reason dependabot opened a third PR against
  a crate that could not have noticed.
