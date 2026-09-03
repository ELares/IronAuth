// SPDX-License-Identifier: MIT OR Apache-2.0

//! Nothing can read an attribute or a text node out of a document nobody has verified.
//!
//! This is the misuse-resistance criterion at the type level. A runtime test can only show that
//! a particular call site did not read a value; only this can show that no call site could.

fn main() {
    let document = ironauth_saml::parse(
        br#"<Response Destination="https://sp.example.test/acs"><NameID>victim</NameID></Response>"#,
        &ironauth_saml::Limits::default(),
    )
    .expect("parses");

    // The `Destination` an attacker controls.
    let _ = document.root().attribute("Destination");
    // The `NameID` an attacker controls.
    let _ = document.root().children()[0].text();
}
