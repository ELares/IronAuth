// SPDX-License-Identifier: MIT OR Apache-2.0

// A verification policy that does not say which token profile it accepts cannot
// exist (issue #192). `ExpectedTyp` is a positional argument of
// `VerificationPolicy::new` with no default and no setter, so omitting it is a
// compile error rather than a policy that quietly accepts any media type.
//
// This is the difference between the requirement being PRESENT and the
// requirement being IMPOSSIBLE TO OMIT. A `with_expected_typ` setter, or an
// `Option` that defaulted to "no opinion", would leave every future verify site
// one forgotten line away from the confusion this argument exists to close, and
// no runtime test can witness the line that was never written.

fn main() {
    let key = ironauth_jose::TrustedKey::ed25519(None, &[0_u8; 32]).expect("key");
    // ERROR: this function takes 5 arguments but 4 arguments were supplied.
    let _ = ironauth_jose::VerificationPolicy::new(
        vec![ironauth_jose::JwsAlgorithm::EdDsa],
        vec![key],
        "https://issuer.example.test",
        "client-abc",
    );
}
