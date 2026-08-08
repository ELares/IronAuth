// SPDX-License-Identifier: MIT OR Apache-2.0

//! The ONE crossing from the data plane into the control plane (issue #96, criterion 5).
//!
//! # Why this exists at all
//!
//! `organizations` grants the data plane `SELECT` and nothing else; `INSERT` belongs to
//! `ironauth_control`. That is the #31 least-privilege split working as designed:
//! `organizations` anchors every org-scoped authorization decision, and the plane that serves
//! unauthenticated traffic holds no INSERT on it. Probed against a real migrated database:
//!
//! ```text
//! organizations    ironauth_app     = SELECT
//! organizations    ironauth_control = INSERT,SELECT
//! ```
//!
//! Criterion 5 of issue #96 asks the login discovery flow to support creating an organization.
//! The flow runs as the data plane, so it cannot perform that write, and the two ways to make it
//! possible are not equally good. Granting the data plane INSERT would invert the split for the
//! one table it most exists to protect and would require weakening the migration tests that
//! enforce it. This is the other way: a seam with exactly one operation.
//!
//! # What makes it narrow rather than an escape hatch
//!
//! A general "here is a control-plane `Store`" handle passed into the OIDC crate would be WORSE
//! than the grant, because it would be reusable: every future feature that found a wall would
//! reach for it. So:
//!
//! - The type holds the control-plane [`Store`] PRIVATELY and never lends it out. Nothing in
//!   `ironauth-oidc` can obtain a control-plane `Store` through this.
//! - It exposes ONE method. Adding a second is a visible, reviewable act, not an import.
//! - It lives here rather than in the OIDC crate, so `git grep OrgProvisioningSeam` finds every
//!   crossing in the repository.
//! - Construction takes a control-plane `Store` explicitly, so a caller cannot build one by
//!   accident from the store it already has.
//!
//! # What bounds its use
//!
//! The step that calls it renders only AFTER the primary factor has succeeded, so reaching it
//! requires credentials for a real account; it is not an unauthenticated surface. It is also
//! gated by a configuration toggle that is off by default, so a deployment that has not opted in
//! never constructs this type at all and the seam is not merely unused but absent.

use crate::error::StoreError;
use crate::id::{OrgMembershipId, OrganizationId, UserId};
use crate::repository::NewMembership;
use crate::scope::Scope;
use crate::store::Store;
use crate::{ActorRef, CorrelationId};
use ironauth_env::Env;

/// The single data-plane-to-control-plane crossing for organization creation (issue #96).
///
/// See the module documentation for why this exists and what keeps it narrow. Construct one with
/// [`OrgProvisioningSeam::new`] from a CONTROL-plane store and inject it where it is needed; the
/// holder gains the ability to run [`OrgProvisioningSeam::create_and_enroll`] and nothing else.
pub struct OrgProvisioningSeam {
    /// The control-plane store. PRIVATE and never returned: this field is the whole reason the
    /// type exists, and an accessor for it would turn the seam into the general escape hatch the
    /// module documentation rules out.
    control: Store,
}

impl std::fmt::Debug for OrgProvisioningSeam {
    /// Deliberately opaque. A `Store` carries connection configuration, and this type is held by
    /// the OIDC state, which appears in diagnostics.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OrgProvisioningSeam")
    }
}

impl OrgProvisioningSeam {
    /// Build the seam over a CONTROL-plane store.
    ///
    /// The caller is responsible for passing the control-plane store rather than the app-role
    /// one. Passing the app-role store does not silently degrade: the INSERT below is refused by
    /// the engine with a permission error, which surfaces as [`StoreError::Database`], and the
    /// test `the_seam_refuses_to_work_through_the_data_plane_store` pins exactly that.
    #[must_use]
    pub fn new(control: Store) -> Self {
        Self { control }
    }

    /// Create an organization and enroll `user` as its first member, in ONE transaction each,
    /// both audited (issue #96, criterion 5).
    ///
    /// # Atomicity, and what is not atomic
    ///
    /// The two writes go through the existing audited-write primitives, which each own their
    /// transaction. So a failure of the enrollment leaves an organization with no members. That
    /// is the safe direction and it is deliberate: the alternative orderings either enroll a user
    /// into an organization that does not exist, which the foreign key refuses anyway, or require
    /// a new cross-repository transaction primitive whose only caller would be this. An
    /// organization with no members grants nobody anything, is invisible in every picker (which
    /// list memberships), and is reclaimable by an operator.
    ///
    /// The error is returned rather than swallowed, so the caller can refuse the login step
    /// instead of completing it against a half-built organization.
    ///
    /// # Errors
    ///
    /// [`StoreError::Database`] if either write fails, including the permission error raised when
    /// this was built over a data-plane store; [`StoreError::NotFound`] if `user` or the minted
    /// ids are out of `scope`.
    pub async fn create_and_enroll(
        &self,
        env: &Env,
        scope: Scope,
        actor: ActorRef,
        display_name: &str,
        user: &UserId,
        now_micros: i64,
    ) -> Result<OrganizationId, StoreError> {
        if user.scope() != scope {
            return Err(StoreError::NotFound);
        }
        let organization = OrganizationId::generate(env, &scope);
        self.control
            .management()
            .acting(actor, CorrelationId::generate(env))
            .organizations(scope)
            .create(env, &organization, now_micros, display_name, None)
            .await?;

        let membership = OrgMembershipId::generate(env, &scope);
        self.control
            .scoped(scope)
            .acting(actor, CorrelationId::generate(env))
            .org_memberships()
            .create(
                env,
                NewMembership {
                    id: &membership,
                    organization_id: &organization,
                    user_id: user,
                    metadata: None,
                },
                now_micros,
                None,
            )
            .await?;
        Ok(organization)
    }
}
