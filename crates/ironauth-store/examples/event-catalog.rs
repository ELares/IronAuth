// SPDX-License-Identifier: MIT OR Apache-2.0

//! Emit the event catalog as JSON (issue #108), for `scripts/event-catalog.sh`.
//!
//! An example binary rather than a build script, mirroring
//! `ironauth-config`'s `config-schema` example: the generator is something a person can run
//! and read the output of, and nothing in the shipped build depends on it having run.

fn main() {
    let document = ironauth_store::event_catalog::catalog_document();
    println!(
        "{}",
        serde_json::to_string_pretty(&document).expect("the catalog serializes")
    );
}
