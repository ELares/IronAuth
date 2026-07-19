// SPDX-License-Identifier: MIT OR Apache-2.0

//! Prints the golden flow object corpus as one JSON document (issue #84, PR 4): the contract
//! version plus every representative flow object (one per journey per state, on both
//! transports) keyed by its stable name. Consumed by scripts/flow-golden.sh, which stamps the
//! "do not edit by hand" comment and writes docs/flow-golden.json. Output is deterministic (the
//! corpus is built from the pure node builders with a fixed flow id and expiry, and
//! `serde_json` emits sorted object maps).

use ironauth_oidc::flow::golden_corpus;

fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&golden_corpus()).expect("the golden corpus serializes")
    );
}
