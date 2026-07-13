// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `(tenant, environment)` isolation scope.
//!
//! A [`Scope`] is the single value that binds every persistence operation to
//! one tenant and one environment. It is produced from the authenticated
//! caller context (a later surface) and consumed by the repository layer: a
//! repository can only be built *from* a scope, and it applies that scope to
//! every query itself. A handler never passes a tenant or environment per call,
//! so it cannot express a cross-tenant read.

use crate::id::{EnvironmentId, TenantId};

/// A tenant-and-environment isolation scope.
///
/// This is the deny-by-default filter of the persistence layer, made a value so
/// that it is impossible to run a scoped query without one. Construct it from
/// the authenticated caller's tenant and environment, then hand it to
/// [`crate::Store::scoped`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Scope {
    tenant: TenantId,
    environment: EnvironmentId,
}

impl Scope {
    /// Bind a tenant and an environment into a scope.
    #[must_use]
    pub fn new(tenant: TenantId, environment: EnvironmentId) -> Self {
        Self {
            tenant,
            environment,
        }
    }

    /// The tenant this scope is bound to.
    #[must_use]
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// The environment this scope is bound to.
    #[must_use]
    pub fn environment(&self) -> EnvironmentId {
        self.environment
    }
}
