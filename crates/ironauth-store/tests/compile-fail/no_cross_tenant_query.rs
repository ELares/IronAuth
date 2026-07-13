// SPDX-License-Identifier: MIT OR Apache-2.0

// A scoped repository applies its own scope to every query and exposes no way
// to target another tenant. This proves it: there is no cross-tenant query
// method, and the scope is a private field that cannot be read or retargeted.

use ironauth_store::{ClientRepo, TenantId};

fn reach_another_tenant(repo: ClientRepo<'_>, other: TenantId) {
    // ERROR: no method takes a foreign tenant; the API to cross tenants does
    // not exist.
    let _ = repo.get_for_tenant(other, "cli_whatever");

    // ERROR: the scope is private, so it cannot be overwritten to point the
    // repository at another tenant.
    let _ = repo.scope;
}

fn main() {}
