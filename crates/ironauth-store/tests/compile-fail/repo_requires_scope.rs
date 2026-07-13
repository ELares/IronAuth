// SPDX-License-Identifier: MIT OR Apache-2.0

// A repository can ONLY be reached through `Store::scoped`, which requires a
// `Scope`. There is no scope-free path to a scoped repository, so this fails to
// compile: `scoped` is called with no scope argument.

use ironauth_store::Store;

fn build_repo_without_a_scope(store: &Store) {
    // ERROR: `scoped` takes a `Scope`; a repository without a scope is not
    // expressible.
    let _scoped = store.scoped();
}

fn main() {}
