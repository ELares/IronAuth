// SPDX-License-Identifier: MIT OR Apache-2.0

//! The audit envelope: who did what to which resource, under which scope, when.
//!
//! Every repository mutation writes exactly one audit row in the SAME
//! transaction as the data change (see the repository module). This module holds
//! the value types that make up that row's envelope; the repository owns the
//! single write primitive that commits them together. The envelope is
//! deliberately richer than milestone M1 consumes: it is the substrate for the
//! later OCSF mapping and the auth-stream versus admin-stream separation (M11).
//! Those streams are not built here; only the fields they will need are carried.
//!
//! The envelope has four moving parts:
//!
//! - an [`ActorRef`]: a typed principal ([`ActorRef::Human`], [`ActorRef::Service`],
//!   [`ActorRef::Agent`]), each wrapping a typed actor identifier;
//! - an [`Action`]: the verb, for example `client.create`;
//! - a target: the typed scoped identifier of the resource acted on (carried by
//!   the repository, not stored here);
//! - the ambient context: the `(tenant, environment)` scope, the wall-clock
//!   time (drawn from the [`ironauth_env`] clock seam, never a direct process
//!   clock read), and a [`CorrelationId`] tying the row back to the request.
//!
//! Writes require an [`ActingContext`] (actor plus correlation id); reads do not.
//! That asymmetry is enforced at the type level by the repository: a plain
//! scoped repository can only read, and the mutating repository is reachable
//! only through [`crate::ScopedStore::acting`], which demands the context.

use std::fmt;

use crate::id::{AgentId, CorrelationId, HumanId, IdParseError, ServiceId};

/// A typed reference to the principal responsible for a mutation.
///
/// The three kinds are distinct on the wire (`human`, `service`, `agent`) and
/// each carries its own typed, non-guessable identifier, so an audit row always
/// attributes a change to a concrete principal of a known kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorRef {
    /// An interactive human user.
    Human(HumanId),
    /// A machine client acting on its own behalf (a service account).
    Service(ServiceId),
    /// An autonomous agent acting for a principal.
    Agent(AgentId),
}

impl ActorRef {
    /// Reference a human actor.
    #[must_use]
    pub fn human(id: HumanId) -> Self {
        Self::Human(id)
    }

    /// Reference a service actor.
    #[must_use]
    pub fn service(id: ServiceId) -> Self {
        Self::Service(id)
    }

    /// Reference an agent actor.
    #[must_use]
    pub fn agent(id: AgentId) -> Self {
        Self::Agent(id)
    }

    /// The stable wire tag for this actor's kind (`human`, `service`, `agent`).
    /// Stored in its own column so the audit log can be filtered by actor kind
    /// without parsing the identifier.
    #[must_use]
    pub fn kind_str(&self) -> &'static str {
        match self {
            ActorRef::Human(_) => "human",
            ActorRef::Service(_) => "service",
            ActorRef::Agent(_) => "agent",
        }
    }

    /// The typed actor identifier in its wire form (for example `hum_...`).
    #[must_use]
    pub fn id_string(&self) -> String {
        match self {
            ActorRef::Human(id) => id.to_string(),
            ActorRef::Service(id) => id.to_string(),
            ActorRef::Agent(id) => id.to_string(),
        }
    }

    /// Reconstruct an actor from the two columns an audit row stores.
    ///
    /// # Errors
    ///
    /// [`IdParseError`] if the kind tag is unknown or the identifier does not
    /// parse under the kind. Reading a stored audit row should never hit this;
    /// it exists so a corrupt row surfaces as a decode error rather than a panic.
    pub(crate) fn from_parts(kind: &str, id: &str) -> Result<Self, IdParseError> {
        match kind {
            "human" => Ok(Self::Human(HumanId::parse(id)?)),
            "service" => Ok(Self::Service(ServiceId::parse(id)?)),
            "agent" => Ok(Self::Agent(AgentId::parse(id)?)),
            _ => Err(IdParseError::Prefix),
        }
    }
}

impl fmt::Display for ActorRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind_str(), self.id_string())
    }
}

/// The action recorded on an audit row: the verb of the mutation.
///
/// Modeled as an enum so that every mutation type shipped to date is a named,
/// exhaustively matched variant rather than a free-form string a caller could
/// mistype. Each variant renders to a stable dotted string (`client.create`)
/// that is what the OCSF mapping (M11) will key on. Adding a mutation is a
/// deliberate act: it must add a variant here.
///
/// # Soft delete, and the retention rule the variants below refer to
///
/// Many of the delete variants below are written by a SOFT delete that RETAINS
/// the row it names. The reason is that the audit row's `target_id` must stay
/// RESOLVABLE: a hard delete would leave the audit row naming an id nothing can
/// look up.
///
/// No foreign key enforces that, and there deliberately is none. `audit_log`
/// (migration 0002) stores `target_id` as free text and references only
/// `tenants` and `environments`, because an append-only audit trail must not be
/// constrained by a data table's lifecycle. It could not be constrained by one
/// here in any case: `target_id` is a single polymorphic column naming the
/// target of every variant in this enum, and a column can reference only one
/// table. Retention is therefore an APPLICATION rule, carried by the repository
/// writing `deleted_at` instead of issuing a DELETE and by the GRANTs that
/// withhold DELETE from both planes. Migration 0092 records the same reasoning
/// from the schema side.
///
/// The rule is not universal, which is the clearest evidence that no such
/// foreign key could be added later. NINETEEN hard `DELETE FROM` statements in
/// `repository.rs` run inside an audited write closure, and THIRTEEN of them delete
/// the very row the enclosing audit row addresses: [`Action::ClientDelete`],
/// [`Action::ConnectorDelete`], [`Action::BrandDelete`],
/// [`Action::BrandAssetDelete`],
/// [`Action::LocaleDelete`], [`Action::SignupFormDelete`],
/// [`Action::EnvironmentVariableDelete`], [`Action::EnvironmentSecretDelete`],
/// [`Action::AaguidRuleRemove`], [`Action::CredentialClassPolicyRemove`],
/// [`Action::ScopeStepUpPolicyRemove`], [`Action::AdminConsentRevoke`] and
/// [`Action::AbuseBanLift`]. Those audit rows name an id that is already gone by
/// the time the row is inserted. (The other six clear PRIOR or DEPENDENT rows
/// rather than the target: an OTP or magic-link issue invalidates the outstanding
/// code, a TOTP enrolment supersedes a pending one, an SMS config update rewrites
/// the country allowlist, and a brand delete sweeps the assets installed under its
/// slug.)
///
/// The count matters because the argument is one of impossibility, not of taste.
/// It was first written as two variants, which understated it by ten and made a
/// true conclusion rest on a thin premise; it was measured by mapping every
/// `DELETE FROM` in `repository.rs` to the `write_audited` call whose closure
/// encloses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {
    /// A client was created.
    ClientCreate,
    /// A client was deleted.
    ClientDelete,
    /// A client's registered redirect URIs were set (issue #13).
    ClientRedirectUrisRegister,
    /// A client's registered POST-LOGOUT redirect URIs were set (issue #33): the
    /// exact-match set the RP-Initiated Logout `end_session` endpoint honors a
    /// `post_logout_redirect_uri` against. Distinct from
    /// [`Action::ClientRedirectUrisRegister`] so the two registered sets are legible
    /// apart in the audit trail.
    ClientPostLogoutRedirectUrisRegister,
    /// A client's OIDC Front-Channel Logout 1.0 registration was set (issue #39):
    /// its `frontchannel_logout_uri` and `frontchannel_logout_session_required`
    /// flag, the per-client opt-in the `end_session` flow reads when the environment
    /// feature is enabled.
    ClientFrontchannelLogoutRegister,
    /// A client's Back-Channel Logout registration was set (issue #34): the
    /// `backchannel_logout_uri` the OP POSTs a signed Logout Token to, and the
    /// `backchannel_logout_session_required` flag. Distinct from the redirect-URI
    /// registrations so the back-channel target is legible on its own in the audit trail.
    ClientBackchannelLogoutRegister,
    /// A client's consent mode and refresh-rotation policy were configured (issue
    /// #21): the consent mode, the skip and no-store consent knobs, and the optional
    /// per-client rotation override.
    ClientConfigure,
    /// A client was registered through Dynamic Client Registration (issue #30,
    /// RFC 7591). Distinct from [`Action::ClientCreate`] so a self-service DCR
    /// registration is legible in the audit trail as such.
    ClientRegistered,
    /// A dynamically registered client's configuration was updated through the
    /// RFC 7592 management endpoint (issue #30). Every successful update also
    /// ROTATES the client's registration access token in the same transaction, so
    /// this one action covers the metadata change and the token rotation together.
    ClientUpdated,
    /// A tenant was created (management plane, issue #11).
    TenantCreate,
    /// A tenant was offboarded into the GRACE stage (management plane, issue
    /// #46): a soft delete that fences the data plane and keeps every key INTACT,
    /// so a restore inside the retention window loses no data. It does NOT
    /// crypto-shred; erasure is the terminal purge's job.
    TenantDelete,
    /// A tenant was RESTORED from the grace stage (management plane, issue #46):
    /// the soft-delete tombstones are cleared and the data plane serves again with
    /// no data loss.
    TenantRestore,
    /// A grace tenant was terminally HARD-DELETED (purged) after its retention
    /// window elapsed (management plane, issue #46): the envelope keys are
    /// crypto-shredded (through #48) so the tenant's PII is permanently
    /// unrecoverable, and the tenant can no longer be restored.
    TenantPurge,
    /// A tenant was SUSPENDED (management plane, issue #46): a reversible fence
    /// that stops it serving the data plane while keeping its data intact.
    TenantSuspend,
    /// A suspended tenant was RESUMED (management plane, issue #46): service is
    /// restored with no data loss.
    TenantResume,
    /// An environment was created (management plane, issue #11).
    EnvironmentCreate,
    /// An environment was deactivated (management plane, issue #11).
    EnvironmentDelete,
    /// An environment's per-environment auto-link posture override was set (management
    /// plane, issue #78): the operator opted this environment into (or back out of) the
    /// verified-to-verified auto-link posture, overriding the deployment default.
    EnvironmentAutoLinkPostureSet,
    /// A management API key was minted (management plane, issue #11).
    ManagementKeyCreate,
    /// A management API key was revoked (management plane, issue #11).
    ManagementKeyDelete,
    /// An organization was created (management plane, issue #41). The minimal
    /// per-environment organization shell M10 later extends with membership.
    OrganizationCreate,
    /// An organization was deactivated (management plane, issue #41): a soft
    /// delete that retains the row, so this audit row's target stays resolvable
    /// (the retention rule above).
    OrganizationDelete,
    /// An organization's lifecycle STATE was changed (management plane, issue #94):
    /// the enable or disable action toggled the org between 'active' and 'disabled'.
    /// The disabled STATE lands here; the login-time ENFORCEMENT is a later PR. The
    /// audit row's operator-safe `detail` records the target state.
    OrganizationStateChange,
    /// A user was ADDED to an organization (issue #94): a new membership row was
    /// written binding the user into the organization, either through the admin
    /// membership surface or as the invitation-accept side effect of redeeming an
    /// invitation that carried an org-context. The target is the new membership.
    OrganizationMembershipAdd,
    /// A user was REMOVED from an organization (issue #94): the membership was
    /// soft-deleted through the admin surface, so this audit row's target stays
    /// resolvable (the retention rule above). The target is the removed
    /// membership.
    OrganizationMembershipRemove,
    /// A project grant was created, binding one application to one customer
    /// organization with the subset of roles its delegated administrators may assign
    /// (issue #102). The target is the `pgt_` id.
    ProjectGrantCreate,
    /// A project grant was withdrawn (issue #102). This WIDENS what the organization's
    /// delegated administrators may assign, because absence of a grant means
    /// unrestricted, so it is the more dangerous of the two and is audited as its own
    /// action rather than as a generic delete.
    ProjectGrantWithdraw,
    /// A named role was DEFINED in an organization (issue #97). The target is the
    /// new role. A role in M10 is a name only; what it grants is issue #98.
    OrganizationRoleCreate,
    /// An organization role's MUTABLE fields were changed (issue #97): its
    /// display name, its metadata, or both. The role's `slug` (the stable name)
    /// is immutable by GRANT, so this action never means the role's identity
    /// changed. The target is the renamed role.
    OrganizationRoleUpdate,
    /// An organization role was DELETED (issue #97): a soft delete that retains
    /// the row, so this audit row's target stays resolvable (the retention rule
    /// above), and the slug is freed for a new role. The target is the deleted
    /// role.
    OrganizationRoleDelete,
    /// A named group was DEFINED in an organization (issue #97), possibly directly
    /// under a parent group. The target is the new group. A group in M10 is a name
    /// and a position in the organization's group forest; who is IN it and what it
    /// grants are later PRs of the same issue.
    OrganizationGroupCreate,
    /// An organization group's MUTABLE fields were changed (issue #97): its
    /// display name, its metadata, or both. The group's `slug` (the stable name)
    /// is immutable by GRANT and its PARENT is changed only under the separate
    /// reparent action, so this action never means the group's identity or its
    /// position in the hierarchy changed. The target is the renamed group.
    OrganizationGroupUpdate,
    /// An organization group was DELETED (issue #97): a soft delete that retains
    /// the row, so this audit row's target stays resolvable (the retention rule
    /// above), and the slug is freed for a new group. The target is the deleted
    /// group.
    OrganizationGroupDelete,
    /// An organization group was MOVED within its organization's group forest
    /// (issue #97): given a new parent, or promoted to a root. Deliberately its
    /// own action rather than a flavor of the update: a reparent silently changes
    /// the inherited roles of every DESCENDANT of the moved group, so it is the
    /// one group mutation whose blast radius is not the target row, and the audit
    /// history has to be able to say so. The target is the moved group, and the
    /// audit row's operator-safe `detail` records the new parent (or its absence),
    /// so the whole shape of the tree is reconstructable from the audit log alone.
    OrganizationGroupReparent,
    /// An organization MEMBERSHIP was bound into a GROUP (issue #97). The target
    /// is the new binding. The subject is a membership, never a bare user, so this
    /// action can only ever appear for someone who is already in the organization.
    OrganizationGroupMemberAdd,
    /// An organization membership was UNBOUND from a group (issue #97): a soft
    /// delete that retains the row, so this audit row's target stays resolvable
    /// (the retention rule above), and the (group, member) pair is free again.
    /// The target is the
    /// removed binding. A binding removed as part of the membership cascade is NOT
    /// reported here (it is not individually addressed by the request that caused
    /// it); see [`Action::OrganizationMembershipAttachmentsRevoke`].
    OrganizationGroupMemberRemove,
    /// A role was GRANTED to a group (issue #97). The target is the new
    /// assignment. Its blast radius is not the target row: every live member of
    /// that group and of every DESCENDANT of it gains the role at their next token
    /// issuance, because roles flow down the group forest.
    OrganizationGroupRoleAssign,
    /// A role was WITHDRAWN from a group (issue #97): a soft delete that retains
    /// the row, so this audit row's target stays resolvable (the retention rule
    /// above), and the (group, role) pair is free again. The target is the
    /// withdrawn assignment. Its blast
    /// radius is the same descendant set the assignment had.
    OrganizationGroupRoleUnassign,
    /// A role was GRANTED DIRECTLY to one organization membership, with no group
    /// involved (issue #97). The target is the new assignment, and its blast
    /// radius really is just that one membership.
    OrganizationMembershipRoleAssign,
    /// A direct role grant was WITHDRAWN from an organization membership (issue
    /// #97): a soft delete that retains the row, so this audit row's target stays
    /// resolvable (the retention rule above), and the (membership, role) pair is
    /// free again. The target
    /// is the withdrawn assignment. A grant withdrawn as part of the membership
    /// cascade is NOT reported here; see
    /// [`Action::OrganizationMembershipAttachmentsRevoke`].
    OrganizationMembershipRoleUnassign,
    /// A membership's group bindings and DIRECT role grants were revoked wholesale
    /// as a side effect of the membership itself changing hands (issue #97): the
    /// membership was removed, or a previously removed membership was REVIVED by a
    /// re-add or by an invitation accept.
    ///
    /// Its own action rather than a burst of per-row remove and unassign events,
    /// deliberately. The revoked rows are not individually addressed by the request
    /// that caused them to disappear, so reporting them as ordinary removals would
    /// claim an operator asked for each one; and an organization may hold unlimited
    /// groups and assignments by covenant, so a per-row burst would make one
    /// membership removal write an unbounded number of audit rows. The target is
    /// the MEMBERSHIP, and the audit row's operator-safe `detail` carries the
    /// COUNTS of what was stripped (`groups=<n>,roles=<n>`), which are structural
    /// numbers and never tenant data. The row is written only when the cascade
    /// actually revoked something, so an ordinary add of a never-before-seen member
    /// does not pollute the log with an empty cascade.
    OrganizationMembershipAttachmentsRevoke,
    /// An organization's authentication policy was created or changed (issue #95).
    /// Target: the `oap_` policy row.
    ///
    /// The policy is 1:1 with its organization and the write is a whole-document
    /// upsert, so a create and a change are ONE operation and ONE action, matching
    /// [`Action::CredentialClassPolicySet`]. The audit row's operator-safe `detail`
    /// carries a compact CLOSED-TOKEN summary of the dimensions the write states
    /// (never a domain string and never a factor token list), because turning on
    /// `mfa_required` for an organization forces enrollment for every member: its
    /// blast radius is not the target row, so the audit row alone would otherwise
    /// not let an operator reconstruct what happened.
    ///
    /// It does NOT mean the organization itself changed.
    OrganizationPolicySet,
    /// An organization's authentication policy was removed (issue #95): the soft
    /// delete. Target: the `oap_` policy row.
    ///
    /// After this the organization inherits the environment result unchanged. It
    /// does NOT mean the organization was deleted, and it does NOT mean any
    /// member's session was terminated.
    OrganizationPolicyRemove,
    /// A permission was DEFINED in an environment's vocabulary (issue #98). The
    /// target is the new `prm_` row.
    ///
    /// The three permission actions carry NO `organization.` prefix, unlike every
    /// action above, and that is the design rather than an inconsistency: the
    /// vocabulary hangs off the ENVIRONMENT and carries no organization at all, so
    /// an `organization.` prefix would name a dimension the row does not have. The
    /// header of migration 0091 states the same three strings as the delta contract
    /// for a permission, so an operator reading the audit log and a consumer reading
    /// that header see one vocabulary.
    ///
    /// A permission in issue #98 is a NAME and a label. What it GRANTS is the
    /// role-to-permission mapping, which is its own resource with its own actions.
    PermissionCreate,
    /// A permission's MUTABLE fields were changed (issue #98): its display name, its
    /// metadata, or both. The target is the relabelled permission.
    ///
    /// Both the `slug` (the string a token claim carries) and the `kind` (which
    /// decides whether a resolution projection selects the row at all) are immutable
    /// by GRANT, so this action can never mean that a permission's identity moved or
    /// that a row was reclassified. That is what makes it safe to read a
    /// `permission.update` as "a label changed" and nothing more.
    PermissionUpdate,
    /// A permission was DELETED from an environment's vocabulary (issue #98): a soft
    /// delete that retains the row, so this audit row's target stays resolvable
    /// (the retention rule above), and the slug is freed for a new permission. The
    /// target is the deleted row.
    ///
    /// A re-create of the same slug mints a FRESH id and is never a revival, so this
    /// action is not reversible in its authorization effects: whatever a later PR of
    /// the issue maps onto the dead id stays mapped to the dead id.
    PermissionDelete,
    /// A permission was ATTACHED to an organization's role (issue #98). The target
    /// is the new `rpm_` mapping row.
    ///
    /// This pair of actions DOES carry the `organization.` prefix that the three
    /// permission actions above deliberately do not, and the difference is the whole
    /// shape of the model: the vocabulary hangs off the ENVIRONMENT and has no
    /// organization dimension to name, while a mapping joins that vocabulary to an
    /// organization's role and therefore has one.
    ///
    /// Its blast radius is not the target row. Every member who effectively holds
    /// that role, directly or through the group forest, gains the permission at their
    /// next token issuance, so this action is the one an operator reconstructs a
    /// capability grant from. The header of migration 0092 names the same two strings
    /// as the delta contract for a mapping.
    OrganizationRolePermissionAssign,
    /// A permission was DETACHED from an organization's role (issue #98): a soft
    /// delete that retains the row, so this audit row's target stays resolvable
    /// (the retention rule above), and the (role, permission) pair is free again.
    /// The target is the withdrawn mapping.
    ///
    /// Its blast radius is the same member set the attachment had. A re-attach mints
    /// a FRESH row rather than reviving this one, so a detachment is never quietly
    /// undone in place.
    ///
    /// Deleting the ROLE or the PERMISSION does NOT write this action: neither
    /// cascades here, and the resolution projection stops selecting the mapping on
    /// the endpoint's own liveness filter instead. So the absence of this action
    /// never means the grant is still in force.
    OrganizationRolePermissionUnassign,
    /// An organization DESIGNATED one of its roles as its DEFAULT role (issue #98).
    /// The target is the role that is the default AFTER the write.
    ///
    /// The designation is a per-organization singleton (`org_roles.is_default` under
    /// the partial unique index migration 0093 creates), so this action states the
    /// whole of the new designation on its own: a set naming role B means role A, if
    /// there was one, is no longer the default. Moving the designation is ONE
    /// request, ONE transaction, and therefore ONE audit row, and the row that names
    /// B is what an operator reads the move from. There is no separate clear row for
    /// the outgoing role.
    ///
    /// Its blast radius is not the target row and it is the largest of any action in
    /// this family: every LIVE ACTIVE member of the organization resolves the role at
    /// their next token issuance, without an assignment row existing for any of them.
    /// The default role is RESOLVED AT READ and never materialized (migration 0093
    /// states why in full), so no `organization.membership.role.assign` accompanies
    /// this action and the absence of one never means the role is not held.
    OrganizationDefaultRoleSet,
    /// An organization's DEFAULT role designation was CLEARED (issue #98). The target
    /// is the role that WAS the default, which is what keeps the trail legible: the
    /// organization is not an addressable target of this table's actions, and naming
    /// the outgoing role is what lets an operator pair a clear with the set that
    /// preceded it.
    ///
    /// After this the organization has no default role, so its members resolve only
    /// the roles some row grants them. Nothing is deleted: the role itself stays a
    /// live role of the organization and every direct and group grant of it stands.
    ///
    /// Deleting the default ROLE does NOT write this action. A soft-deleted role
    /// keeps its `is_default` value and simply stops resolving and stops occupying
    /// the designation, because every read and the unique index alike are partial
    /// over live rows. So the absence of this action never means an organization
    /// still has a default role.
    OrganizationDefaultRoleClear,
    /// An authorization code and its grant were issued (issue #12).
    AuthorizationCodeIssue,
    /// An authorization code was redeemed at the token endpoint (issue #12).
    AuthorizationCodeRedeem,
    /// A consumed authorization code was replayed, revoking its grant chain
    /// (issue #12). This is the reuse event: it is written only when a code that
    /// was already redeemed is presented again.
    AuthorizationCodeReuse,
    /// Tokens (access and/or ID) were issued from a grant (issue #12).
    TokenIssue,
    /// A bootstrap end user was registered (issue #20).
    UserRegister,
    /// A user was created through the management API (issue #52): the admin
    /// create, optionally with a caller-supplied id. Distinct from
    /// [`Action::UserRegister`] (the data-plane self-registration) so an
    /// operator-created account is legible as such in the audit trail.
    UserCreate,
    /// A user's mutable profile was updated through the management API (issue #52):
    /// a PATCH of the standard-claim document. The claim values are never recorded
    /// on the audit row; only that the user was updated, by whom, and when.
    UserUpdate,
    /// A user was DELETED through the management API (issue #52): a soft-delete
    /// tombstone that cascades the user's sessions and non-offline refresh families
    /// and publishes to the session-ended fan-out (issue #35), then reads as a
    /// uniform not-found. Offboarding, not erasure (crypto-shredding is #48/#49).
    UserDelete,
    /// A user's lifecycle STATE was changed through the management API (issue #52):
    /// a validated transition of the user state machine (active, blocked, disabled,
    /// `pending_verification`, `scheduled_offboarding`). The audit row's operator-safe
    /// `detail` records the target state; a session-ending transition (block,
    /// disable) cascades in the same transaction and fans out to relying parties.
    UserStateChange,
    /// A user's imported FOREIGN password hash was verified on first login and
    /// transparently rehashed to the native Argon2id verifier (issue #55): the
    /// verify-then-rehash upgrade. The foreign hash and its algorithm tag are
    /// cleared in the same transaction; no credential material is recorded on the
    /// audit row, only that the user's credential was upgraded, and when.
    UserPasswordUpgrade,
    /// A user's EXTERNAL ID was linked through the management API (issue #52): a
    /// correlation id from the tenant's own systems was claimed for the user
    /// (unique per scope, so a second claim of the same external id is refused).
    /// The external-id value is never recorded on the audit row.
    UserExternalIdLink,
    /// A user's EXTERNAL ID was unlinked through the management API (issue #52): the
    /// user's correlation id was cleared, freeing it for another user in the scope.
    UserExternalIdUnlink,
    /// A scheduled-offboarding user was EXECUTED by the worker (issue #52): at or
    /// past its scheduled instant the user was disabled and its sessions and
    /// non-offline refresh families cascaded, fanning out identically to a manual
    /// disable. Idempotent: once executed the user is no longer scheduled, so a
    /// re-run of the worker re-processes nothing.
    UserOffboardingExecute,
    /// A typed login IDENTIFIER was added to a user (issue #54): an email, username,
    /// or phone, canonicalized once at the seam and blind-indexed for uniqueness. The
    /// identifier value is never recorded on the audit row (it is sealed and
    /// blind-indexed on its row); only that the user gained an identifier, and when.
    UserIdentifierAdd,
    /// A typed login IDENTIFIER was REMOVED from a user (issue #54, epic #514). A hard
    /// delete, because the row IS the claim on the uniqueness slot and a tombstone would
    /// hold that slot forever; this audit row is what survives it, so who removed an
    /// identifier and when is still answerable once the row is gone. The identifier
    /// value is never recorded here, for the same reason the add does not record it.
    UserIdentifierRemove,
    /// A per-environment identifier UNIQUENESS mode was APPLIED (issue #54): an
    /// operator switched the environment's mode and the store recomputed every
    /// identifier row's uniqueness discriminator under the new mode, in one
    /// scope-fenced transaction, after refusing the change while a
    /// post-canonicalization collision the new mode would enforce still existed. The
    /// target is the environment; no identifier value is recorded (they are sealed and
    /// blind-indexed on their rows).
    UserIdentifierApplyUniquenessMode,
    /// A user invitation was CREATED through the management API (issue #60): an
    /// admin invited a new identity, provisioning a `pending_verification` user and a
    /// single-use, expiring, unguessable token. The token is never recorded on the
    /// audit row (only its digest is stored anywhere); the audit row's operator-safe
    /// `detail` records the enrolled credential type.
    InvitationCreate,
    /// A user invitation was REDEEMED (issue #60): the invitee presented a valid
    /// token, which was consumed atomically (pending -> accepted), and the invited
    /// user was activated (`pending_verification` -> active) with a credential set.
    InvitationRedeem,
    /// A pending user invitation was REVOKED through the management API (issue #60):
    /// an admin invalidated it before it was accepted, so its token can never be
    /// redeemed.
    InvitationRevoke,
    /// A pending user invitation was RESENT through the management API (issue #60):
    /// the prior token was invalidated (its digest overwritten) and a fresh
    /// single-use token with a reset expiry was issued for the same invitation.
    InvitationResend,
    /// A user's identity TRAITS were set or updated through an audited write (issue
    /// #53): the custom profile fields beyond the standard OIDC claims, validated
    /// against the active trait-schema version and sealed at rest. The trait values
    /// are never recorded on the audit row; only that the user's traits changed, by
    /// whom, and when.
    UserTraitsUpdate,
    /// A full identity EXPORT was served through the management API (issue #58): the
    /// exit-friendliness covenant made observable. Every export is a permission-gated
    /// admin action attributed to its actor, so a bulk read of sensitive credential
    /// material (password hashes, foreign hashes, sealed PII) leaves an auditable
    /// trail. The exported values are never recorded on the audit row; the
    /// operator-safe `detail` records only how many identities were exported, targeted
    /// at the environment the export drained.
    UserExport,
    /// A new identity trait-schema VERSION was created in a (tenant, environment)
    /// registry (issue #53): an immutable candidate JSON Schema (draft 2020-12) the
    /// scope's future trait writes may validate against once it is activated.
    TraitSchemaCreate,
    /// A trait-schema version was ACTIVATED as the scope's served default (issue
    /// #53): the cutover, refused while a dry-run or migration reports unresolved
    /// invalid identities. The audit row's operator-safe `detail` records the
    /// activated version.
    TraitSchemaActivate,
    /// A trait migration or dry-run JOB was created (issue #53): a queued job that
    /// validates (dry-run) or transforms and re-validates (migrate) the scope's
    /// existing identities against a candidate schema version.
    TraitMigrationJobCreate,
    /// A trait migration/dry-run job was ADVANCED by a worker step (issue #53): a
    /// deterministic, idempotent, resumable batch that processed a bounded run of the
    /// scope's identities and recorded per-record failures. Re-running a completed or
    /// failed job is a no-op (idempotent), so a crash mid-migration resumes without
    /// double-migrating.
    TraitMigrationJobAdvance,
    /// A wrapped migration RUN was defined (issue #59): a long-running data
    /// migration (a streaming bulk import, a schema migration job) enrolled into the
    /// invariant-checked state machine in its initial `defined` state.
    MigrationRunCreate,
    /// A wrapped migration run TRANSITIONED between lifecycle states (issue #59):
    /// defined -> validating -> running -> reconciling. Every transition is audited
    /// with actor attribution; the target state is the operator-safe `detail`.
    MigrationRunTransition,
    /// A batch of per-record OUTCOMES was ingested into a migration run (issue #59):
    /// the imported / failed / skipped accounting and consistency the invariants
    /// later re-evaluate. One audit row per ingest batch, not per record.
    MigrationRunIngest,
    /// A migration run's records were marked by a BACKFILL pass (issue #59): the
    /// sentinel the backfill invariant requires set. One audit row per backfill batch.
    MigrationRunBackfill,
    /// A migration run's records were RECONCILED (issue #59): a previously-inconsistent
    /// identity that an operator triaged or repaired is flipped back to consistent (and
    /// its recorded reason cleared), so a fixed identity unblocks the consistency
    /// invariant exactly as re-ingest unblocks count and a backfill mark unblocks the
    /// sentinel. One audit row per reconcile batch; the next completion attempt
    /// re-evaluates the invariant live, never a cached verdict.
    MigrationRunReconcile,
    /// A migration run COMPLETED (issue #59): the terminal success transition, taken
    /// only after every invariant re-evaluated satisfied. A blocked completion
    /// attempt writes NO row (it is not a transition), so a `migration_run.complete`
    /// row in the trail always means the invariants were clean.
    MigrationRunComplete,
    /// A migration run was explicitly ABANDONED (issue #59): the terminal giving-up
    /// transition, so a stuck half-applied migration cannot be silently forgotten.
    /// The operator-safe reason is the audit row's `detail`.
    MigrationRunAbandon,
    /// A bootstrap session was established at login or registration (issue #20).
    SessionCreate,
    /// An SSO session identifier was ROTATED at a privilege transition (issue #32):
    /// login (and the future MFA / step-up seam) mints a fresh unpredictable session
    /// id and INVALIDATES the prior one in the SAME transaction (session-fixation
    /// defense). Distinct from [`Action::SessionRevoke`] so a rotation is never
    /// mistaken for a terminal revoke in the audit trail.
    SessionRotate,
    /// A single SSO session was REVOKED by the management API (issue #32), stopping it
    /// from resolving immediately and cascading to its session-bound refresh-token
    /// families (the `offline_access` families survive unless a hard kill was asked
    /// for). Written in the same transaction as the revocation.
    SessionRevoke,
    /// One session of a BULK session revocation was revoked by the management API
    /// (issue #32). Each session in the batch is its own audited transaction, so the
    /// audit trail names every revoked session individually.
    SessionsBulkRevoke,
    /// EVERY session of one user was revoked by the management API (issue #32),
    /// cascading to the user's refresh-token families in the SAME transaction (the
    /// `offline_access` families survive unless a hard kill was asked for). One audit
    /// row targets the user.
    UserSessionsRevokeAll,
    /// A subject granted consent to a client (issue #20).
    ConsentGrant,
    /// A recorded consent grant was revoked (issue #88): its `revoked_at` was stamped
    /// so the authorization gate treats it as absent and re-prompts. Written by the
    /// self-service and admin revocation surfaces in the same transaction as the
    /// revocation.
    ConsentRevoke,
    /// A user consent screen was SKIPPED and the authorization auto-granted (issue #88, PR 4):
    /// either a trusted first-party carve-out with the no-store knob off (so no consent row is
    /// written), or a third-party client covered by an admin consent pre-authorization (the admin
    /// grant is the consent of record). The audit row TARGETS the client and carries an
    /// operator-safe `detail` naming the reason (`first_party_carveout` or `admin_preauthorized`),
    /// so a silent auto-grant that persists no consent row still leaves an audit trail.
    ConsentSkipped,
    /// A per-environment signing key was provisioned (issue #19). Covers both a
    /// day-one key and a manually rotated-in successor.
    SigningKeyProvision,
    /// A resource server was registered (issue #29). Records the audience and the
    /// access-token format a registered protected API receives.
    ResourceServerRegister,
    /// A resource server's PERMISSION-CLAIM opt-in was set or cleared (issue #98).
    /// The second mutation `resource_servers` admits, and the only one that changes
    /// what a token minted for that audience may carry. One action for both
    /// directions: whether the opt-in is on is always the stored column, never a fold
    /// over these events (ADR 0002), so a separate `clear` action would be two names
    /// for one state transition and would invite exactly that fold.
    ResourceServerPermissionClaimsSet,
    /// A refresh-token family was opened at first issuance (issue #21). The
    /// generation-0 refresh token and its family were recorded against the grant.
    RefreshTokenIssue,
    /// A refresh token was rotated (issue #21): a presented token was superseded by
    /// a fresh successor generation and a new access token was issued.
    RefreshTokenRotate,
    /// A refresh token was reused outside the grace window (issue #21), revoking the
    /// whole family. This is the typed reuse event: it is written only when a
    /// superseded refresh token is presented beyond the grace window, and exactly
    /// once per incident (only the revocation that flips the family emits it).
    RefreshTokenReuse,
    /// A session's session-bound refresh-token families were revoked at RP logout
    /// (issue #21). The `offline_access` families are left intact by construction.
    /// Also emitted when a client REVOKES a refresh token at the RFC 7009 revocation
    /// endpoint (issue #22): the whole family and its grant are revoked together, so
    /// the reuse of this action covers both the logout and the explicit-revoke paths.
    RefreshFamilyRevoke,
    /// A token was revoked at the RFC 7009 revocation endpoint (issue #22). Written
    /// against the token's GRANT (the append-only issued/opaque token rows derive
    /// their active state from `grants.revoked_at`), so revoking an access token
    /// revokes its grant chain. The refresh-token revoke path audits through
    /// [`Action::RefreshFamilyRevoke`] instead (it also revokes the family spine).
    TokenRevoke,
    /// A pushed authorization request was stored behind a one-time `request_uri`
    /// (RFC 9126, issue #27). The back-channel push the authorization endpoint later
    /// consumes exactly once.
    PushedAuthorizationRequestPush,
    /// A pushed authorization request's `request_uri` was consumed at the
    /// authorization endpoint (RFC 9126, issue #27). Written only on the winning
    /// single-use consume; a reuse, expiry, or client-mismatch miss writes nothing.
    PushedAuthorizationRequestConsume,
    /// A client's `require_pushed_authorization_requests` flag was set (RFC 9126
    /// section 5, issue #27).
    ClientRequirePushedAuthorizationSet,
    /// A client's `allow_bearer_tokens` flag was set (issue #124): the per-client
    /// escape hatch from the `DPoP`-by-default posture for public clients. Audited
    /// because relaxing it WEAKENS a client, and a weakening should be a recorded
    /// act rather than a silent column update.
    ClientAllowBearerTokensSet,
    /// A client's RFC 8693 token-exchange policy was set (issue #125): the
    /// impersonation and/or exchanged-refresh switches. Both default-deny, so this row
    /// records a WEAKENING and is audited like the other per-client posture toggles.
    ClientTokenExchangePolicySet,
    /// A DCR initial access token was minted through the management API (issue
    /// #31, RFC 7591 section 1.2). The token authorizes future self-service client
    /// registrations, optionally under an attached policy chain.
    DcrInitialAccessTokenMint,
    /// A DCR policy object was created through the management API (issue #31): a
    /// named, reusable set of registration-metadata primitives.
    DcrPolicyCreate,
    /// A DCR registration was refused because its submitted metadata violated the
    /// initial access token's policy chain (issue #31). The actionable diagnostic
    /// is recorded out of band; the wire response stays an opaque
    /// `invalid_client_metadata`.
    DcrPolicyRejected,
    /// A DCR registration was refused because the environment's registered-client
    /// quota was already reached (issue #31).
    DcrQuotaHit,
    /// A DCR registration was refused because the endpoint's per-source or per-token
    /// rate limit was exceeded (issue #31).
    DcrRateLimited,
    /// An admin verified a dynamically registered client through the management API
    /// (issue #31), lifting its unverified-client quarantine.
    DcrClientVerified,
    /// A service-account principal was minted for a client (issue #23), lazily on
    /// its first client-credentials issuance. The stable machine `sub` the client's
    /// M2M tokens carry.
    ServiceAccountCreate,
    /// A client's static custom-claims configuration was set (issue #23): the
    /// declarative claims embedded in its client-credentials access tokens.
    ClientCustomClaimsSet,
    /// An external assertion issuer was registered as a trust anchor for the RFC
    /// 7521 / RFC 7523 JWT bearer assertion grant (issue #26). Records the `xai_`
    /// issuer registration (its key source and enable switch).
    ExternalAssertionIssuerRegister,
    /// A subject-mapping rule was created for the JWT bearer assertion grant (issue
    /// #26): the explicit rule mapping an external (issuer + `sub`) to an IronAuth
    /// principal. Unmapped subjects are rejected, never auto-provisioned.
    ExternalAssertionSubjectMappingCreate,
    /// An external assertion issuer's enable switch was toggled (issue #26): a
    /// compromised or decommissioned trust anchor was DISABLED (or re-enabled)
    /// through the column-scoped data-plane grant, so its assertions are rejected
    /// exactly as an unregistered issuer's are. The data-plane revocation capability;
    /// the HTTP management surface for it shipped with issue #126.
    ExternalAssertionIssuerSetEnabled,
    /// A subject-mapping rule's enable switch was toggled (issue #26): a mis-authored
    /// or decommissioned mapping was DISABLED (or re-enabled) through the
    /// column-scoped data-plane grant, so it resolves to no rule and the grant
    /// rejects the subject exactly as an unmapped one.
    ExternalAssertionSubjectMappingSetEnabled,
    /// An external assertion issuer registration was REMOVED (issue #126). Distinct
    /// from disabling one: disable is revocation and keeps the row, delete frees the
    /// `(tenant, environment, issuer)` unique key so the same issuer can be registered
    /// again with a different key source. That is the only way to repoint an anchor
    /// whose keys rotated, since the key columns are immutable to both planes.
    ExternalAssertionIssuerDelete,
    /// A subject-mapping rule was REMOVED (issue #126). Frees the
    /// `(tenant, environment, issuer, external_subject)` unique key, which is what lets
    /// a rule authored against the wrong principal be replaced rather than only parked.
    ExternalAssertionSubjectMappingDelete,
    /// A short-lived access token was issued under the JWT bearer assertion grant
    /// (issue #26): a validated external assertion was exchanged for a token under
    /// the mapped identity. No refresh token accompanies it (RFC 7521 4.1).
    JwtBearerAssertionIssue,
    /// A token was issued under the RFC 8693 token-exchange grant (issue #125): a
    /// presented `subject_token` was revalidated in full and traded for a strictly weaker
    /// one.
    ///
    /// A DISTINCT verb rather than [`Action::TokenIssue`], because an exchange is the one
    /// issuance where the token's subject need not be the party that authenticated. Every
    /// CVE in this family is an exchange that should not have been permitted, so "which
    /// issuances were exchanges" has to be answerable from the trail without joining
    /// anything: the criterion in #125 asks for an audit event on EVERY exchange, and
    /// impersonation in particular is only defensible because it is recorded.
    TokenExchangeIssue,
    /// A client's RFC 8707 resource-indicator policy was set (issue #28): the
    /// per-client allowed-resource allowlist and the no-resource behavior
    /// (default audience or refusal).
    ClientResourceIndicatorPolicySet,
    /// A client's per-client OAuth SCOPE allowlist was set or cleared (issue #98):
    /// which scope tokens the client may request on a machine grant. A DELEGATION
    /// restriction, never the RBAC permission set (machine principal permissions are
    /// issue #99), and never able to re-admit a scope the machine-grant denylist
    /// floor refuses.
    ClientAllowedScopesSet,
    /// A device-authorization device code and user code were issued (issue #24, RFC
    /// 8628 section 3.2). The back-channel row a constrained device polls against and
    /// a human approves through the verification page.
    DeviceCodeIssue,
    /// A device-authorization request was APPROVED by an authenticated human at the
    /// verification page (issue #24, RFC 8628 section 3.3): the explicit
    /// confirmation that binds the flow to a subject and opens its grant, so the
    /// next poll at the token endpoint issues tokens.
    DeviceCodeApprove,
    /// A device-authorization request was DENIED (issue #24, RFC 8628 section 3.5):
    /// the human explicitly rejected it at the verification page, or the user code
    /// was invalidated after exhausting its bounded failed-match budget (RFC 8628
    /// section 5.1). A subsequent poll at the token endpoint yields `access_denied`.
    DeviceCodeDeny,
    /// A per-tenant envelope key-encryption key was provisioned (issue #48): a
    /// day-one KEK, generated and stored wrapped under the platform master key.
    EnvelopeKekProvision,
    /// A per-tenant envelope KEK was rotated (issue #48): a fresh KEK version was
    /// generated and every one of the scope's DEKs was re-wrapped under it in the
    /// same transaction, with NO record-payload rewrite. Online and cheap.
    EnvelopeKekRotate,
    /// A per-tenant envelope KEK was DESTROYED (issue #48): the crypto-shred. Every
    /// KEK version of the scope is overwritten and marked destroyed, so the scope's
    /// DEKs can never be unwrapped again and all of its envelope-protected data is
    /// permanently unreadable. The productized offboarding flow is #49.
    EnvelopeKekDestroy,
    /// A scope was enrolled in bring-your-own-key (issue #49): a BYOK binding was
    /// recorded so a customer-managed root key (in an external KMS/HSM, or a
    /// customer-supplied key) governs the scope's key hierarchy. The audit row
    /// carries only the driver and the opaque external key reference, never key
    /// material. The binding is severed at the terminal offboarding stage.
    EnvelopeByokEnroll,
    /// A per-tenant envelope data-encryption key was provisioned (issue #48): a
    /// day-one DEK, generated and stored wrapped under the scope's active KEK.
    EnvelopeDekProvision,
    /// A per-tenant envelope DEK was rotated (issue #48): a fresh DEK version was
    /// generated for new writes and the prior version was retired but stays
    /// readable for background re-encryption of old rows.
    EnvelopeDekRotate,
    /// An encrypted secret value was written (issue #48): a plaintext secret was
    /// sealed under the scope's active DEK with its column context bound as
    /// associated data, and stored as ciphertext.
    EncryptedSecretPut,
    /// An encrypted secret value was re-encrypted from an older DEK version to the
    /// active one (issue #48): the observable background re-encryption step that
    /// follows a DEK rotation. The plaintext never changes; only the sealing key
    /// version does.
    EncryptedSecretReencrypt,
    /// A custom domain was registered for an environment (issue #47): a
    /// customer-owned hostname claimed for later ACME verification and issuance.
    /// The domain starts unverified and is never served until a challenge proves
    /// control of it.
    CustomDomainRegister,
    /// A custom domain's ACME challenge SUCCEEDED (issue #47): a domain-control
    /// verification (http-01 or dns-01) completed and the domain moved to
    /// verified, so it is now eligible to be served. Refused (and NOT written) if
    /// another tenant already verified the same domain.
    CustomDomainChallengeSucceed,
    /// A custom domain's ACME challenge FAILED (issue #47): a domain-control
    /// verification could not be satisfied, so the domain stays unserved. The
    /// failure surfaces to the operator rather than silently degrading.
    CustomDomainChallengeFail,
    /// A custom domain's issued certificate was stored (issue #47): the cert chain
    /// and its PRIVATE KEY were sealed under the scope's envelope DEK (issue #48)
    /// and the domain row was pointed at the sealed bundle. The key never touches
    /// a plaintext column.
    CustomDomainCertificateStore,
    /// A per-environment BRAND was set through the management API (issue #86): a first
    /// write or an overwrite of a named branding definition (design tokens, dark-mode
    /// variants, wordmark, and sanitized rich-text slots). The audit row names the brand
    /// id and scope; the branding values themselves are not recorded here.
    BrandSet,
    /// A per-environment BRAND was deleted through the management API (issue #475). The audit
    /// row names the brand id and scope. The delete also sweeps every asset installed under
    /// the brand's slug, in the same transaction, so no orphaned bytes survive the brand.
    BrandDelete,
    /// A per-environment brand ASSET was uploaded through the management API (issue #86, PR 3):
    /// a first write or an overwrite of a magic-byte-sniffed raster (a logo or favicon). The
    /// audit row names the brand id and scope; the asset bytes themselves are not recorded here.
    BrandAssetSet,
    /// A per-environment brand ASSET was deleted through the management API (issue #86, PR 3).
    /// The audit row names the brand id and scope.
    BrandAssetDelete,
    /// A per-environment LOCALE BUNDLE was set through the management API (issue #86, PR 2):
    /// a first write or an overwrite of an installed localization (a BCP47 tag and its map of
    /// numeric message id to plain text render). The audit row names the locale bundle id and
    /// scope; the bundle entries themselves are not recorded here.
    LocaleSet,
    /// A per-environment LOCALE BUNDLE was deleted through the management API (issue #86,
    /// PR 2). The audit row names the locale bundle id and scope.
    LocaleDelete,
    /// A MESSAGE TEMPLATE override was set through the management API (issue #111): a first
    /// write or an overwrite at one (level, organization, kind, locale). The audit row names
    /// the template id and scope; the authored body itself is not recorded here, for the same
    /// reason a locale bundle's entries are not -- an audit row is a record that somebody
    /// changed something, not a copy of what they wrote.
    MessageTemplateSet,
    /// An operator re-queued an outbound message for delivery (issue #111 criterion 1).
    ///
    /// Audited because it CAUSES MAIL. The row this re-delivers carries whatever the original
    /// send carried, which for an `email_otp` is the code and for a magic link is the token, so
    /// "who re-sent this, and when" is exactly the question an incident asks.
    MessageResend,
    /// An HTTP FLOW TARGET was registered or reconfigured through the management API
    /// (issue #112). The audit row names the target id and scope; the target's config is not
    /// recorded here, for the reason a locale bundle's entries are not -- an audit row records
    /// that somebody changed something, not a copy of what they wrote.
    FlowTargetSet,
    /// An HTTP FLOW TARGET was deregistered through the management API (issue #112), so it
    /// stops being dispatched. The audit row names the target id and scope.
    FlowTargetDelete,
    /// An operator asked for an HTTP FLOW TARGET's dead-lettered async deliveries to be
    /// REPLAYED (issue #112 criterion 2). The audit row names the target id, the scope, and
    /// the `since` bound the request carried, because "replay everything" and "replay since
    /// noon" are materially different acts against a third party.
    ///
    /// The row records the REQUEST, not the outcome: the revive runs later on the data plane,
    /// since the role that may ask holds no UPDATE on the queue.
    FlowTargetReplayDeadLetters,
    /// A MESSAGE TEMPLATE override was deleted through the management API (issue #111),
    /// restoring whatever the next level up provides. The audit row names the template id and
    /// scope.
    MessageTemplateDelete,
    /// A per-environment, per-client SIGNUP FORM was set through the management API (issue #87):
    /// a first write or an overwrite of the fail-fast validated field list. The audit row names
    /// the signup form id and scope; the field list itself is not recorded here.
    SignupFormSet,
    /// A per-environment, per-client SIGNUP FORM was deleted through the management API (issue
    /// #87). The audit row names the signup form id and scope.
    SignupFormDelete,
    /// A new custom-journey VERSION was created in a (tenant, environment) registry (issue #92,
    /// PR 5): an immutable, load-valid journey artifact (validated + compiled before the write).
    /// The audit row names the flow version id and scope; the artifact itself is not recorded here.
    FlowVersionCreate,
    /// A custom-journey ACTIVE VERSION PIN was set or moved through the management API (issue #92,
    /// PR 5): the version a fresh custom flow of the journey is created against. The audit row
    /// names the pin id and scope; the pinned version is the operator-safe `detail`.
    FlowVersionPin,
    /// A per-environment, per-client ADMIN CONSENT PRE-AUTHORIZATION was set through the
    /// management API (issue #88, PR 4): a first write or an overwrite of the scope set an admin
    /// pre-authorized for a third-party client. The audit row names the pre-authorization id and
    /// scope; the pre-authorized scope set itself is not recorded here.
    AdminConsentGrant,
    /// A per-environment, per-client ADMIN CONSENT PRE-AUTHORIZATION was deleted (revoked) through
    /// the management API (issue #88, PR 4). The audit row names the pre-authorization id and
    /// scope; the third-party client is once again refused with the administrator-approval
    /// terminal until re-authorized.
    AdminConsentRevoke,
    /// An environment VARIABLE (a non-secret named config value) was set through
    /// the management API (issue #45): a first write or an overwrite. The audit row
    /// names the variable id and scope; the value itself is not recorded here.
    EnvironmentVariableSet,
    /// An environment VARIABLE was deleted through the management API (issue #45).
    EnvironmentVariableDelete,
    /// An environment SECRET was set through the management API (issue #45): a
    /// plaintext value was sealed under the scope's envelope DEK (issue #48) and
    /// stored as ciphertext. The audit row names the secret id and scope; the
    /// value is NEVER recorded (the write-only discipline, the #11 secret lesson).
    EnvironmentSecretPut,
    /// An environment SECRET was deleted through the management API (issue #45).
    EnvironmentSecretDelete,
    /// A server-side config PROMOTION was applied (issue #44): a source snapshot's
    /// promotable configuration was transactionally applied onto a target
    /// environment. The row targets the environment and is written in the SAME
    /// transaction as every resource change the apply makes, so a promotion without
    /// its audit row is structurally impossible and a rolled-back apply leaves no
    /// row. The operator-safe `detail` records the change counts (create, update,
    /// delete); no promoted value or secret is recorded.
    ConfigPromotionApply,
    /// An end user CHANGED their OWN password through the self-service account
    /// surface (issue #61): the current password was verified and a fresh Argon2id
    /// verifier was written, and (session-fixation defense) every OTHER session of
    /// the user was revoked in the SAME transaction. The row targets the user and
    /// is attributed to the end user. No password or hash is ever recorded; the
    /// `detail` records the step-up policy the sensitive change declared.
    AccountPasswordChange,
    /// An end user CONVERTED their account to passkey-only by REMOVING their password
    /// (issue #66): the native `password_hash` was flipped to the unusable sentinel and
    /// `passwordless` set true, gated by fresh re-authentication and the cross-source
    /// last-credential guard (the account must retain a usable passkey). The row targets
    /// the user and is attributed to the end user; the `detail` records the step-up
    /// policy. No password or hash is ever recorded.
    AccountPasswordRemove,
    /// An end user CONVERTED a passkey-only account to password-holding by SETTING a
    /// first password (issue #66): the sentinel `password_hash` was replaced with a fresh
    /// Argon2id verifier and `passwordless` cleared, gated by fresh passkey
    /// re-authentication and the full set-path policy (length, strength, breach screen).
    /// The row targets the user and is attributed to the end user; the `detail` records
    /// the step-up policy. No password or hash is ever recorded.
    AccountPasswordSet,
    /// An end user ENROLLED a credential through the self-service account surface
    /// (issue #61): a passkey, TOTP authenticator, or recovery-code set was added
    /// to their own registry. The row targets the credential and is attributed to
    /// the end user; the `detail` records the step-up policy the sensitive change
    /// declared. The concrete factor material lands with the M7 factor issues.
    AccountCredentialEnroll,
    /// An end user REMOVED one of their OWN credentials through the self-service
    /// account surface (issue #61). Blocked by the last-usable-credential guardrail
    /// unless it is not the last, or the request carried the documented recovery
    /// acknowledgment. The row targets the credential and is attributed to the end
    /// user; the `detail` records the step-up policy the sensitive change declared.
    AccountCredentialRemove,
    /// An end user (or an auto link at a federated login) BOUND a federated identity to
    /// their local account through the guarded account linking subsystem (issue #78): a
    /// new `account_links` row was written. The row targets the `alk_` link and is
    /// attributed to the end user; the `detail` records the connector and link method,
    /// NEVER the raw federated identifier. No verified flag of the local identity is ever
    /// touched (the link stores its OWN immutable trust snapshot).
    AccountIdentityLink,
    /// An end user UNLINKED a federated identity from their local account (issue #78): an
    /// `account_links` row was removed. Blocked by the last usable method guard when the
    /// link is the account's sole surviving authentication method. The row targets the
    /// `alk_` link and is attributed to the end user; the `detail` records the step-up
    /// policy the sensitive change declared.
    AccountIdentityUnlink,
    /// An end user REGISTERED a WebAuthn passkey (issue #65): a verified
    /// registration ceremony persisted a new credential (its COSE public key,
    /// AAGUID, transports, and BE/BS flags). The row targets the `pky_` credential
    /// and is attributed to the end user.
    WebauthnCredentialRegister,
    /// An end user RENAMED one of their OWN WebAuthn passkeys (issue #65): the
    /// user-authored nickname was resealed. The row targets the `pky_` credential
    /// and is attributed to the end user.
    WebauthnCredentialRename,
    /// An end user REMOVED one of their OWN WebAuthn passkeys (issue #65). The row
    /// targets the `pky_` credential and is attributed to the end user.
    WebauthnCredentialRemove,
    /// A WebAuthn assertion presented a backup-eligibility (BE) flag that DIVERGED
    /// from the credential's registration-time, stored BE (issue #65). BE is
    /// immutable across a credential's life (WebAuthn L3 7.2), so a flip is a spec
    /// violation and a signal of a cloned or spoofed authenticator: the sign-in is
    /// refused and this security event is written. The row targets the `pky_`
    /// credential; the `detail` records the stored and presented BE values.
    WebauthnBackupEligibilityMismatch,
    /// A WebAuthn assertion presented a REGRESSING signature counter (issue #65):
    /// the credential's stored counter did not advance, a possible cloned
    /// authenticator. The row targets the `pky_` credential; the `detail` records
    /// the per-tenant policy applied (warn or block). A zero/zero counter (a synced
    /// passkey with no counter) never emits this event.
    WebauthnCloneDetected,
    /// An end user BEGAN a TOTP enrollment (issue #69): a pending `tot_` row was
    /// created with a freshly generated, sealed seed. It cannot satisfy MFA until
    /// activation. The row targets the credential and is attributed to the end user.
    TotpEnrollBegin,
    /// An end user ACTIVATED a TOTP authenticator (issue #69): they proved
    /// possession with a valid current code, so the pending factor became active
    /// and its recovery codes were minted. The row targets the `tot_` credential.
    TotpActivate,
    /// An end user VERIFIED a TOTP code as a second factor (issue #69). Audited
    /// DISTINCTLY from a recovery-code redemption so the two second-factor paths are
    /// never conflated. The row targets the `tot_` credential.
    TotpVerify,
    /// An end user REMOVED one of their OWN TOTP authenticators (issue #69). The row
    /// targets the `tot_` credential and is attributed to the end user.
    TotpRemove,
    /// An end user GENERATED (or REGENERATED) their recovery codes (issue #69):
    /// a fresh batch replaced any prior set, invalidating every outstanding code.
    /// The row targets the user and is attributed to the end user.
    RecoveryCodesGenerate,
    /// An end user REDEEMED a one-time recovery code in place of a second factor
    /// (issue #69). Audited DISTINCTLY from a TOTP verification. The row targets the
    /// redeemed `rvc_` code and is attributed to the end user.
    RecoveryCodeRedeem,
    /// An end user REVOKED one of their OWN sessions through the self-service
    /// account surface (issue #61): a single session the user chose to sign out,
    /// stopping it from resolving immediately and cascading through the unified
    /// session-ended fan-out exactly as an admin revoke does. The row targets the
    /// session and is attributed to the end user.
    AccountSessionRevoke,
    /// An end user REVOKED all of their OTHER sessions through the self-service
    /// account surface (issue #61): every session except the one making the request
    /// (the "sign out everywhere else" action). Each revoked session cascades
    /// through the unified session-ended fan-out. The row targets the user and is
    /// attributed to the end user; the `detail` records the step-up policy the
    /// sensitive change declared.
    AccountSessionsRevokeOthers,
    /// A device was REMEMBERED as trusted after a completed multi-factor login (issue
    /// #71): the remember-device state a subsequent login skips the second factor
    /// against. The row targets the `tdv_` device and is attributed to the end user.
    TrustedDeviceRemember,
    /// A remembered device was REVOKED (issue #71): the user (through the self-service
    /// account surface), an admin, or a password/factor-change invalidation flipped it,
    /// so a replayed device cookie fails server-side IMMEDIATELY. The row targets the
    /// `tdv_` device; the `detail` records the revocation reason.
    TrustedDeviceRevoke,
    /// A credential-abuse BAN was placed on a regulated dimension (issue #64): an
    /// operator, through the CLI or the admin API, banned an attacker IP, an account,
    /// or a canonical identifier on ONE authentication path. The row targets the
    /// `abn_` ban; the `detail` records the banned dimension and path (never the
    /// plaintext subject, which is sealed on the row). The per-path scope is the
    /// account-DoS safeguard: a `password` ban never governs the `passkey` or
    /// `recovery` path (Keycloak CVE-2024-1722).
    AbuseBanCreate,
    /// A credential-abuse ban was LIFTED (issue #64): an operator un-banned a
    /// previously banned dimension and path through the CLI or admin API. The row
    /// targets the `abn_` ban; the `detail` records the dimension and path.
    AbuseBanLift,
    /// A per-scope step-up policy was SET (created or updated) through the
    /// management seam (RFC 9470, issue #72): the (acr floor, max auth age)
    /// requirement governing an OAuth scope token. The row targets the `sup_`
    /// policy.
    ScopeStepUpPolicySet,
    /// A per-scope step-up policy was REMOVED (issue #72): the requirement governing
    /// an OAuth scope token was deleted. The row targets the `sup_` policy.
    ScopeStepUpPolicyRemove,
    /// A per-CLIENT step-up floor was SET (issue #72): the client's `step_up_acr` /
    /// `step_up_max_age_secs` registration floor was configured through the
    /// management seam. The row targets the `cli_` client.
    ClientStepUpPolicySet,
    /// A per-CLIENT `id_token_signed_response_alg` was SET (issue #93): the
    /// compatibility wizard pinned the algorithm this client's ID tokens are signed
    /// with through the management seam, validated against the environment's actually
    /// signable set. The row targets the `cli_` client.
    ClientIdTokenAlgSet,
    /// A client's OWNING ORGANIZATION was set or cleared (issue #103, migration 0121):
    /// the client passed from environment-owned to organization-owned or back. The row
    /// targets the `cli_` client, and the detail names which way it moved. It never
    /// carries the organization identifier, matching every other write in this file.
    ClientOwningOrganizationSet,
    /// An API key or personal access token was CREATED (issue #99). The row targets the
    /// `akey_` handle, never the key and never its digest, and the detail names the owner
    /// KIND only.
    ApiKeyCreated,
    /// An API key or personal access token was REVOKED (issue #99). The row targets the
    /// `akey_` handle.
    ApiKeyRevoked,
    /// An impersonation was AUTHORIZED (issue #101): the control plane issued a single-use
    /// authorization after checking the permission and the justification. The row targets the
    /// `imp_` authorization.
    ///
    /// Distinct from [`Action::ImpersonationStarted`], and the distinction is the point: an
    /// authorization may be issued and never redeemed. Collapsing the two would record an
    /// impersonation that never happened, which is exactly as misleading as missing one that
    /// did.
    ImpersonationAuthorized,
    /// An IMPERSONATION was STARTED (issue #101). The row targets the `ses_` session, which
    /// is what links the justification to everything the impersonator subsequently did, and
    /// its detail carries the impersonator, the structured reason, the written justification
    /// and the cap. The acting actor is the operator who started it.
    ///
    /// The detail is the ONLY place the written justification is durably retrievable: it is
    /// deliberately not carried in any token, because a token is read by the client, by every
    /// resource server it reaches, and by whatever logs them.
    ImpersonationStarted,
    /// An IMPERSONATION was ENDED (issue #101), by a revoke, a logout, or any other cause
    /// that ends the session. The row targets the same `ses_` session the start did, so the
    /// pair brackets the window in the audit stream.
    ///
    /// Emitted only for a session that CARRIED an impersonation, so an ordinary logout does
    /// not produce one. A lapse at the cap emits nothing, because no event fires: the bound is
    /// enforced by refusal on the read and refresh paths rather than by a sweep.
    ImpersonationEnded,
    /// An admin sudo elevation was RECORDED (issue #73): a management credential
    /// completed a re-authentication that opens a freshness window for admin
    /// mutations in a (tenant, environment). The row targets the `elv_` elevation; the
    /// `detail` records the achieved acr and the window expiry.
    AdminPrivilegeElevated,
    /// An admin mutation was REFUSED because the sudo freshness window had lapsed
    /// (issue #73): the recorded elevation was absent or expired, so a structured
    /// re-authentication challenge was returned instead of executing the mutation. The
    /// row targets the `elv_` elevation handle; the freshness expiry is the audited
    /// fact (a stolen credential without a fresh re-auth cannot mutate).
    AdminPrivilegeChallenged,
    /// A credential-class policy was SET (created or updated) through the management
    /// seam (issue #66): the minimum credential class required of a login for a
    /// subject (the tenant, a group, or an org). The row targets the `ccp_` policy;
    /// the `detail` records the subject and the minimum class.
    CredentialClassPolicySet,
    /// A credential-class policy was REMOVED (issue #66): the minimum-class
    /// requirement for a subject was deleted. The row targets the `ccp_` policy.
    CredentialClassPolicyRemove,
    /// The per-scope attestation mode was SET (issue #66): the attestation conveyance
    /// ('none' or 'direct') the passkey registration path requests. The row targets
    /// the `atc_` config; the `detail` records the mode.
    AttestationConfigSet,
    /// The per-scope MDS3 BLOB cache was REFRESHED (issue #66, PR B): a newer, re-verified
    /// FIDO MDS3 metadata BLOB was fetched and cached (or a byte-identical refetch touched
    /// the row). The row targets the `mbc_` cache; the `detail` records the BLOB `no`.
    Mds3BlobCacheRefresh,
    /// An AAGUID allow/deny rule was SET (created or updated) through the management seam
    /// (issue #66, PR B): a specific authenticator model was pinned to a disposition
    /// ('allow' or 'deny'). The row targets the `aag_` rule; the `detail` records the
    /// disposition.
    AaguidRuleSet,
    /// An AAGUID allow/deny rule was REMOVED (issue #66, PR B): the disposition for a
    /// pinned authenticator model was deleted. The row targets the `aag_` rule.
    AaguidRuleRemove,
    /// An email-OTP code was SENT (issue #68): a fresh numeric code was issued to a
    /// user for a purpose, invalidating any prior active code. The row targets the
    /// `eot_` code; the `detail` records the purpose (never the plaintext code, which
    /// is hashed on the row). A send suppressed for anti-enumeration writes no row.
    EmailOtpSend,
    /// An email-OTP code was VERIFIED (issue #68): a user presented the correct code
    /// and it was consumed single-use. The row targets the `eot_` code; the `detail`
    /// records the purpose.
    EmailOtpVerify,
    /// A scanner-safe magic link was SENT (issue #68): a fresh single-use link token
    /// and its cross-device short code were issued to a user for a purpose,
    /// invalidating any prior active link. The row targets the `mlk_` token; the
    /// `detail` records the purpose (never the token or code, both one-way on the row).
    MagicLinkSend,
    /// A scanner-safe magic link was CONSUMED (issue #68): a user completed the POST
    /// confirmation (or the cross-device short code) and the link was consumed
    /// single-use, establishing a session. A prefetching scanner's GET never reaches
    /// this. The row targets the `mlk_` token; the `detail` records the purpose.
    MagicLinkConsume,
    /// An SMS-OTP code was SENT (issue #70): a fresh numeric code was issued to a
    /// user for a purpose, invalidating any prior active code. The row targets the
    /// `sot_` code; the `detail` records the purpose (never the plaintext code, which
    /// is hashed on the row). A send suppressed / refused for anti-enumeration writes
    /// no row.
    SmsOtpSend,
    /// An SMS-OTP code was VERIFIED (issue #70): a user presented the correct code
    /// and it was consumed single-use. The row targets the `sot_` code; the `detail`
    /// records the purpose.
    SmsOtpVerify,
    /// An SMS route was AUTO-THROTTLED by the pumping defense (issue #70): the
    /// send-to-verify conversion on the route dropped below the configured threshold
    /// over a sufficient sample, so the route was throttled WITHOUT operator
    /// intervention. The row targets the route; the `detail` records the route and
    /// the observed conversion.
    SmsRouteThrottled,
    /// An SMS route's low-conversion ALARM fired (issue #70): the send-to-verify
    /// conversion crossed below the configured threshold. The row targets the route;
    /// the `detail` records the route and the observed conversion.
    SmsConversionAlarm,
    /// The per (tenant, environment) SMS configuration was CHANGED (issue #70):
    /// SMS OTP was enabled/disabled, the factor-downgrade path was set, or the
    /// country allowlist was edited. The row records what changed in `detail`.
    SmsConfigUpdate,
    /// The per (tenant, environment) EMAIL-FACTOR configuration was CHANGED (issue
    /// #267): the factor-downgrade opt-in for the email possession family (email OTP,
    /// magic link, headless recovery) was set. Turning it ON permits an email
    /// possession proof to mint a primary session over a passkey or an active TOTP, so
    /// the change is attributable either way; the `detail` records the new value.
    EmailFactorConfigUpdate,
    /// An account-recovery flow was INITIATED (issue #81): the first-class recovery
    /// state machine started for a subject. The row targets the `rcv_` flow; the
    /// `detail` records the entry point, the recover-factor strength (acr), whether a
    /// delay was applied, and the number of channels notified (never the plaintext
    /// recipient, which is sealed on the row). A recovery init for a NON-EXISTENT
    /// account writes no row (the anti-enumeration suppressed path).
    RecoveryInitiate,
    /// An account-recovery flow was CANCELLED (issue #81): a held recovery was
    /// revoked from a notification link (or superseded by a newer request), so the
    /// pending recovery can never complete. The row targets the `rcv_` flow; the
    /// `detail` records the cancellation reason.
    RecoveryCancel,
    /// An account-recovery flow COMPLETED (issue #81): the recovery restored access
    /// after the delay elapsed or the challenge was satisfied. The row targets the
    /// `rcv_` flow; the `detail` records the recover-factor strength (acr).
    RecoveryComplete,
    /// A factor change was evaluated against an active recovery (issue #81, the
    /// downgrade invariant): removing or replacing a factor STRONGER than the one used
    /// to recover was either ALLOWED (the delay elapsed or a fresh equal-or-stronger
    /// re-verification was presented) or BLOCKED. The row targets the `rcv_` flow; the
    /// `detail` records the decision and the target factor strength (acr), so an
    /// attacker-initiated downgrade attempt is always reconstructable from the log.
    RecoveryFactorChange,
    /// A risk decision was RECORDED (issue #79): the minimal risk engine scored a
    /// login LOW/MED/HIGH from its enumerated signals and dispatched an action
    /// (allow/block/challenge/notify). The row targets the `rsk_` decision; the
    /// `detail` records the score, the action, and each contributing signal with its
    /// typed value (never plaintext PII), so a sampled decision is fully
    /// reconstructable from the audit trail alone.
    RiskDecisionRecord,
    /// A "this wasn't me" disavowal token was ISSUED (issue #79): a new-device login
    /// planted a single-use, digest-only token in the notification. The row targets
    /// the `dis_` disavowal; the `detail` records the risk decision it descends from.
    RiskDisavowalIssue,
    /// A "this wasn't me" disavowal was CONSUMED (issue #79): the end user followed the
    /// single-use notification link, so the flagged sessions were revoked and the
    /// subject's credentials were marked for review. The row targets the `dis_`
    /// disavowal; the `detail` records how many sessions and devices were revoked.
    RiskDisavow,
    /// A third-party risk signal was INGESTED (issue #82, PR 1): an external fraud/risk
    /// source delivered a signal about a subject as a signed Security Event Token, whose
    /// signature verified against the source's registered public key. The row targets the
    /// `rsg_` signal; the `detail` records the source, the event type, the subject format,
    /// and the resolved local subject (or that it was unresolved), never the raw external
    /// subject. Written only for a signal that was actually ingested (a verified, fresh,
    /// non-duplicate delivery).
    RiskSignalIngest,
    /// A signup-quarantine case was APPROVED / RELEASED (issue #82, PR 2): an admin cleared
    /// the account's `quarantined` flag through the management review queue, turning a
    /// quarantined account into a normal unrestricted one. The row targets the released
    /// `usr_` subject; the actor is the deciding admin, so the trail names WHO released the
    /// account. This is the ONLY path that lifts a quarantine.
    SignupQuarantineApproved,
    /// A signup-quarantine case was REJECTED (issue #82, PR 2): an admin confirmed a
    /// fraudulent signup through the management review queue, disabling the account and
    /// ending its sessions. The row targets the disabled `usr_` subject; the actor is the
    /// deciding admin, so the trail names WHO rejected the signup.
    SignupQuarantineRejected,
    /// A signup-quarantine review window was EXTENDED (issue #82, PR 2): an admin bumped a
    /// case's review deadline through the management queue; the account stays quarantined.
    /// The row targets the `usr_` subject; the actor is the deciding admin.
    SignupQuarantineExtended,
    /// An admin-approved recovery was APPROVED (issue #82, PR 3): an admin approved a pending
    /// admin-approved recovery flow through the management review queue, satisfying its method
    /// precondition (completion still runs THROUGH the #81 delay/downgrade gate). The row
    /// targets the `rcv_` recovery flow; the actor is the deciding admin, so the trail names
    /// WHO approved the recovery.
    RecoveryApproved,
    /// An admin-approved recovery was REJECTED (issue #82, PR 3): an admin refused a pending
    /// admin-approved recovery flow through the management review queue. The row targets the
    /// `rcv_` recovery flow; the actor is the deciding admin.
    RecoveryApprovalRejected,
    /// A trusted contact CONFIRMED a recovery out of band (issue #82, PR 3): one designated
    /// contact spent its single-use confirmation token toward a trusted-contact recovery's
    /// threshold. The row targets the `rcv_` recovery flow; the `detail` records the
    /// contact id (never the contact address).
    RecoveryContactConfirmed,
    /// An IDV-gated recovery consumed a signed provider CALLBACK (issue #82, PR 3): a
    /// single-use, case-bound, JOSE-verified callback asserted a verification result. The row
    /// targets the `rcv_` recovery flow; the `detail` records the provider and the verdict
    /// (never any document data; IronAuth only consumes the provider's signed assertion).
    RecoveryIdvCallback,
    /// A federation connector was CREATED (issue #75): a declarative OIDC-shaped
    /// upstream definition was registered through the management API. The row targets
    /// the `cnr_` connector; the `detail` records the connector slug. The definition
    /// is validated before it lands, and the upstream client secret is sealed inline
    /// under the scope DEK.
    ConnectorCreate,
    /// A metering snapshot was published onto the event feed (issue #107): an operator
    /// or scheduler took a usage reading and made every webhook subscriber receive it.
    /// Usage belongs to the scope rather than to any row, so the target is the
    /// scope-level `usage` handle.
    UsagePublish,
    /// A Standard Webhooks delivery endpoint was registered (issue #105): a POST target
    /// and its sealed signing secret. The row targets the `whe_` endpoint.
    WebhookEndpointCreate,
    /// A Standard Webhooks delivery endpoint's signing secret was ROTATED (issue #105),
    /// opening the overlap window during which both secrets verify.
    WebhookEndpointRotateSecret,
    /// A Standard Webhooks delivery endpoint was PAUSED or RESUMED (issue #105): its
    /// `active` flag was flipped. Distinct from a delete, because the endpoint and its
    /// signing secret survive, so resuming needs no re-registration and no consumer has
    /// to adopt a new secret.
    WebhookEndpointSetActive,
    /// An operator REPLAYED a webhook endpoint's dead-lettered deliveries (issue #106):
    /// messages that already failed their whole retry schedule were revived so they are
    /// delivered again. Audited because it causes outbound requests to a customer's
    /// endpoint, which is an operator decision rather than queue bookkeeping; the `detail`
    /// records the recover-from-timestamp bound.
    WebhookEndpointReplayDeadLetters,
    /// A Standard Webhooks delivery endpoint's event-type SUBSCRIPTION changed (issue
    /// #106): which event types it receives, or a clear back to receiving every type. The
    /// `detail` records the subscription the write committed.
    WebhookEndpointSetEventTypes,
    /// A Standard Webhooks delivery endpoint was removed (issue #105).
    WebhookEndpointDelete,
    /// A federation connector was UPDATED (issue #75): its definition, sealed secret,
    /// capability matrix, or enabled flag was replaced through the management API. The
    /// row targets the `cnr_` connector; the `detail` records the connector slug.
    ConnectorUpdate,
    /// A federation connector was DELETED (issue #75): the definition was removed
    /// through the management API. The row targets the `cnr_` connector; the `detail`
    /// records the connector slug.
    ConnectorDelete,
    /// An organization-to-connector binding was CREATED (issue #77): an organization
    /// was bound to a connector through the management API. The row targets the `ocn_`
    /// binding; the `detail` records the organization and connector ids.
    OrgConnectionCreate,
    /// A routing rule was CREATED (issue #77): a domain, app, or user selector was
    /// mapped to an org connection through the management API. The row targets the
    /// `rrl_` rule; the `detail` records the rule kind.
    RoutingRuleCreate,
    /// A domain rule's ownership verification outcome was recorded (issue #96): the
    /// transition to `verified` is what makes the rule route at all, so it is audited
    /// separately from the create that only claimed the domain.
    RoutingRuleDomainVerification,
    /// Upstream tokens were CAPTURED (issue #77, PR 3): the sealed upstream access and
    /// refresh tokens were persisted after a brokered login. The row targets the `utk_`
    /// vault row; the `detail` records the session and connector, NEVER a token value.
    UpstreamTokenCapture,
    /// A session's captured upstream tokens were READ (issue #77, PR 3) by an authorized
    /// client. The row targets the `utk_` vault row; the `detail` records the session and
    /// connector, so the trail shows WHO read WHOSE session's token, NEVER the value.
    UpstreamTokenRead,
    /// An upstream-token retrieval grant was CREATED (issue #77, PR 3): a client was
    /// authorized to retrieve a session's captured upstream tokens for an org connection.
    /// The row targets the `utg_` grant; the `detail` records the client and org connection.
    UpstreamTokenGrantCreate,
    /// An IdP-side FedCM ID assertion was issued (issue #83, EXPLORATORY): the
    /// credential-issuing endpoint minted an ID token directly to a relying party
    /// after the same client, origin, consent, and single-use-nonce discipline the
    /// redirect flow enforces. The row targets the `fdn_` single-use nonce it
    /// consumed; the `detail` records the RP `client_id` and the session subject, and
    /// the actor is the RP client, so the trail reads "client X issued a FedCM
    /// assertion for subject Y". The token value is NEVER recorded.
    FedcmAssertionIssue,
}

impl Action {
    /// The stable wire string for this action.
    // One flat arm per action verb; splitting the map would not make it clearer.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::ClientCreate => "client.create",
            Action::ClientDelete => "client.delete",
            Action::ClientRedirectUrisRegister => "client.redirect_uris.register",
            Action::ClientBackchannelLogoutRegister => "client.backchannel_logout.register",
            Action::ClientPostLogoutRedirectUrisRegister => {
                "client.post_logout_redirect_uris.register"
            }
            Action::ClientFrontchannelLogoutRegister => "client.frontchannel_logout.register",
            Action::ClientConfigure => "client.configure",
            Action::ClientRegistered => "client.registered",
            Action::ClientUpdated => "client.updated",
            Action::TenantCreate => "tenant.create",
            Action::TenantDelete => "tenant.delete",
            Action::TenantRestore => "tenant.restore",
            Action::TenantPurge => "tenant.purge",
            Action::TenantSuspend => "tenant.suspend",
            Action::TenantResume => "tenant.resume",
            Action::EnvironmentCreate => "environment.create",
            Action::EnvironmentDelete => "environment.delete",
            Action::EnvironmentAutoLinkPostureSet => "environment.auto_link_posture.set",
            Action::ManagementKeyCreate => "management_key.create",
            Action::ManagementKeyDelete => "management_key.delete",
            Action::OrganizationCreate => "organization.create",
            Action::OrganizationDelete => "organization.delete",
            Action::OrganizationStateChange => "organization.state_change",
            Action::OrganizationMembershipAdd => "organization.membership.add",
            Action::OrganizationMembershipRemove => "organization.membership.remove",
            Action::ProjectGrantCreate => "project_grant.create",
            Action::ProjectGrantWithdraw => "project_grant.withdraw",
            Action::OrganizationRoleCreate => "organization.role.create",
            Action::OrganizationRoleUpdate => "organization.role.update",
            Action::OrganizationRoleDelete => "organization.role.delete",
            Action::OrganizationGroupCreate => "organization.group.create",
            Action::OrganizationGroupUpdate => "organization.group.update",
            Action::OrganizationGroupDelete => "organization.group.delete",
            Action::OrganizationGroupReparent => "organization.group.reparent",
            Action::OrganizationGroupMemberAdd => "organization.group.member.add",
            Action::OrganizationGroupMemberRemove => "organization.group.member.remove",
            Action::OrganizationGroupRoleAssign => "organization.group.role.assign",
            Action::OrganizationGroupRoleUnassign => "organization.group.role.unassign",
            Action::OrganizationMembershipRoleAssign => "organization.membership.role.assign",
            Action::OrganizationMembershipRoleUnassign => "organization.membership.role.unassign",
            Action::OrganizationMembershipAttachmentsRevoke => {
                "organization.membership.attachments.revoke"
            }
            Action::OrganizationPolicySet => "organization.policy.set",
            Action::OrganizationPolicyRemove => "organization.policy.remove",
            Action::PermissionCreate => "permission.create",
            Action::PermissionUpdate => "permission.update",
            Action::PermissionDelete => "permission.delete",
            Action::OrganizationRolePermissionAssign => "organization.role.permission.assign",
            Action::OrganizationRolePermissionUnassign => "organization.role.permission.unassign",
            Action::OrganizationDefaultRoleSet => "organization.default_role.set",
            Action::OrganizationDefaultRoleClear => "organization.default_role.clear",
            Action::AuthorizationCodeIssue => "authorization_code.issue",
            Action::AuthorizationCodeRedeem => "authorization_code.redeem",
            Action::AuthorizationCodeReuse => "authorization_code.reuse",
            Action::TokenIssue => "token.issue",
            Action::UserRegister => "user.register",
            Action::UserCreate => "user.create",
            Action::UserUpdate => "user.update",
            Action::UserDelete => "user.delete",
            Action::UserStateChange => "user.state_change",
            Action::UserPasswordUpgrade => "user.password.upgrade",
            Action::UserExternalIdLink => "user.external_id.link",
            Action::UserExternalIdUnlink => "user.external_id.unlink",
            Action::UserOffboardingExecute => "user.offboarding.execute",
            Action::UserIdentifierAdd => "user.identifier.add",
            Action::UserIdentifierRemove => "user.identifier.remove",
            Action::UserIdentifierApplyUniquenessMode => "user.identifier.uniqueness.apply",
            Action::InvitationCreate => "invitation.create",
            Action::InvitationRedeem => "invitation.redeem",
            Action::InvitationRevoke => "invitation.revoke",
            Action::InvitationResend => "invitation.resend",
            Action::UserTraitsUpdate => "user.traits.update",
            Action::UserExport => "user.export",
            Action::TraitSchemaCreate => "trait_schema.create",
            Action::TraitSchemaActivate => "trait_schema.activate",
            Action::TraitMigrationJobCreate => "trait_migration_job.create",
            Action::TraitMigrationJobAdvance => "trait_migration_job.advance",
            Action::MigrationRunCreate => "migration_run.create",
            Action::MigrationRunTransition => "migration_run.transition",
            Action::MigrationRunIngest => "migration_run.ingest",
            Action::MigrationRunBackfill => "migration_run.backfill",
            Action::MigrationRunReconcile => "migration_run.reconcile",
            Action::MigrationRunComplete => "migration_run.complete",
            Action::MigrationRunAbandon => "migration_run.abandon",
            Action::SessionCreate => "session.create",
            Action::SessionRotate => "session.rotate",
            Action::SessionRevoke => "session.revoke",
            Action::SessionsBulkRevoke => "sessions.bulk_revoke",
            Action::UserSessionsRevokeAll => "user.sessions.revoke_all",
            Action::ConsentGrant => "consent.grant",
            Action::ConsentRevoke => "consent.revoke",
            Action::ConsentSkipped => "consent.skip",
            Action::SigningKeyProvision => "signing_key.provision",
            Action::ResourceServerRegister => "resource_server.register",
            Action::ResourceServerPermissionClaimsSet => "resource_server.permission_claims.set",
            Action::RefreshTokenIssue => "refresh_token.issue",
            Action::RefreshTokenRotate => "refresh_token.rotate",
            Action::RefreshTokenReuse => "refresh_token.reuse",
            Action::RefreshFamilyRevoke => "refresh_family.revoke",
            Action::TokenRevoke => "token.revoke",
            Action::PushedAuthorizationRequestPush => "pushed_authorization_request.push",
            Action::PushedAuthorizationRequestConsume => "pushed_authorization_request.consume",
            Action::ClientRequirePushedAuthorizationSet => {
                "client.require_pushed_authorization_requests.set"
            }
            Action::ClientAllowBearerTokensSet => "client.allow_bearer_tokens.set",
            Action::ClientTokenExchangePolicySet => "client.token_exchange_policy.set",
            Action::DcrInitialAccessTokenMint => "dcr.iat_minted",
            Action::DcrPolicyCreate => "dcr.policy_created",
            Action::DcrPolicyRejected => "dcr.policy_rejected",
            Action::DcrQuotaHit => "dcr.quota_hit",
            Action::DcrRateLimited => "dcr.rate_limited",
            Action::DcrClientVerified => "dcr.client_verified",
            Action::ServiceAccountCreate => "service_account.create",
            Action::ClientCustomClaimsSet => "client.custom_claims.set",
            Action::ExternalAssertionIssuerRegister => "external_assertion_issuer.register",
            Action::ExternalAssertionSubjectMappingCreate => {
                "external_assertion_subject_mapping.create"
            }
            Action::ExternalAssertionIssuerSetEnabled => "external_assertion_issuer.set_enabled",
            Action::ExternalAssertionIssuerDelete => "external_assertion_issuer.delete",
            Action::ExternalAssertionSubjectMappingDelete => {
                "external_assertion_subject_mapping.delete"
            }
            Action::ExternalAssertionSubjectMappingSetEnabled => {
                "external_assertion_subject_mapping.set_enabled"
            }
            Action::JwtBearerAssertionIssue => "jwt_bearer_assertion.issue",
            Action::TokenExchangeIssue => "token_exchange.issue",
            Action::ClientResourceIndicatorPolicySet => "client.resource_indicator_policy.set",
            Action::ClientAllowedScopesSet => "client.allowed_scopes.set",
            Action::DeviceCodeIssue => "device_code.issue",
            Action::DeviceCodeApprove => "device_code.approve",
            Action::DeviceCodeDeny => "device_code.deny",
            Action::EnvelopeKekProvision => "envelope.kek.provision",
            Action::EnvelopeKekRotate => "envelope.kek.rotate",
            Action::EnvelopeKekDestroy => "envelope.kek.destroy",
            Action::EnvelopeByokEnroll => "envelope.byok.enroll",
            Action::EnvelopeDekProvision => "envelope.dek.provision",
            Action::EnvelopeDekRotate => "envelope.dek.rotate",
            Action::EncryptedSecretPut => "encrypted_secret.put",
            Action::EncryptedSecretReencrypt => "encrypted_secret.reencrypt",
            Action::CustomDomainRegister => "custom_domain.register",
            Action::CustomDomainChallengeSucceed => "custom_domain.challenge.succeed",
            Action::CustomDomainChallengeFail => "custom_domain.challenge.fail",
            Action::CustomDomainCertificateStore => "custom_domain.certificate.store",
            Action::BrandSet => "brand.set",
            Action::BrandDelete => "brand.delete",
            Action::BrandAssetSet => "brand.asset.set",
            Action::BrandAssetDelete => "brand.asset.delete",
            Action::LocaleSet => "locale.set",
            Action::LocaleDelete => "locale.delete",
            Action::MessageTemplateSet => "message_template.set",
            Action::MessageResend => "message.resend",
            Action::FlowTargetSet => "flow_target.set",
            Action::FlowTargetDelete => "flow_target.delete",
            Action::FlowTargetReplayDeadLetters => "flow_target.replay_dead_letters",
            Action::MessageTemplateDelete => "message_template.delete",
            Action::SignupFormSet => "signup_form.set",
            Action::SignupFormDelete => "signup_form.delete",
            Action::FlowVersionCreate => "flow_version.create",
            Action::FlowVersionPin => "flow_version.pin",
            Action::AdminConsentGrant => "admin_consent.grant",
            Action::AdminConsentRevoke => "admin_consent.revoke",
            Action::EnvironmentVariableSet => "environment_variable.set",
            Action::EnvironmentVariableDelete => "environment_variable.delete",
            Action::EnvironmentSecretPut => "environment_secret.put",
            Action::EnvironmentSecretDelete => "environment_secret.delete",
            Action::ConfigPromotionApply => "config_promotion.apply",
            Action::AccountPasswordChange => "account.password.change",
            Action::AccountPasswordRemove => "account.password.remove",
            Action::AccountPasswordSet => "account.password.set",
            Action::AccountCredentialEnroll => "account.credential.enroll",
            Action::AccountCredentialRemove => "account.credential.remove",
            Action::AccountIdentityLink => "account.identity.link",
            Action::AccountIdentityUnlink => "account.identity.unlink",
            Action::WebauthnCredentialRegister => "webauthn.credential.register",
            Action::WebauthnCredentialRename => "webauthn.credential.rename",
            Action::WebauthnCredentialRemove => "webauthn.credential.remove",
            Action::WebauthnCloneDetected => "webauthn.clone.detected",
            Action::WebauthnBackupEligibilityMismatch => "webauthn.backup_eligibility.mismatch",
            Action::TotpEnrollBegin => "account.totp.enroll_begin",
            Action::TotpActivate => "account.totp.activate",
            Action::TotpVerify => "account.totp.verify",
            Action::TotpRemove => "account.totp.remove",
            Action::RecoveryCodesGenerate => "account.recovery_codes.generate",
            Action::RecoveryCodeRedeem => "account.recovery_code.redeem",
            Action::AccountSessionRevoke => "account.session.revoke",
            Action::TrustedDeviceRemember => "trusted_device.remember",
            Action::TrustedDeviceRevoke => "trusted_device.revoke",
            Action::AccountSessionsRevokeOthers => "account.sessions.revoke_others",
            Action::AbuseBanCreate => "abuse.ban.create",
            Action::AbuseBanLift => "abuse.ban.lift",
            Action::ScopeStepUpPolicySet => "step_up.scope_policy.set",
            Action::ScopeStepUpPolicyRemove => "step_up.scope_policy.remove",
            Action::ClientStepUpPolicySet => "client.step_up_policy.set",
            Action::ClientIdTokenAlgSet => "client.id_token_signed_response_alg.set",
            Action::ClientOwningOrganizationSet => "client.owning_organization.set",
            Action::ApiKeyCreated => "api_key.created",
            Action::ApiKeyRevoked => "api_key.revoked",
            Action::ImpersonationAuthorized => "impersonation.authorized",
            Action::ImpersonationStarted => "impersonation.started",
            Action::ImpersonationEnded => "impersonation.ended",
            Action::AdminPrivilegeElevated => "admin.privilege.elevated",
            Action::AdminPrivilegeChallenged => "admin.privilege.challenged",
            Action::CredentialClassPolicySet => "credential_class.policy.set",
            Action::CredentialClassPolicyRemove => "credential_class.policy.remove",
            Action::AttestationConfigSet => "attestation.config.set",
            Action::Mds3BlobCacheRefresh => "mds3.blob_cache.refresh",
            Action::AaguidRuleSet => "aaguid.rule.set",
            Action::AaguidRuleRemove => "aaguid.rule.remove",
            Action::EmailOtpSend => "email_otp.send",
            Action::EmailOtpVerify => "email_otp.verify",
            Action::SmsOtpSend => "sms_otp.send",
            Action::SmsOtpVerify => "sms_otp.verify",
            Action::SmsRouteThrottled => "sms_route.throttled",
            Action::SmsConversionAlarm => "sms_route.conversion_alarm",
            Action::SmsConfigUpdate => "sms_config.update",
            Action::EmailFactorConfigUpdate => "email_factor_config.update",
            Action::MagicLinkSend => "magic_link.send",
            Action::MagicLinkConsume => "magic_link.consume",
            Action::RecoveryInitiate => "recovery.initiate",
            Action::RecoveryCancel => "recovery.cancel",
            Action::RecoveryComplete => "recovery.complete",
            Action::RecoveryFactorChange => "recovery.factor_change",
            Action::RiskDecisionRecord => "risk.decision",
            Action::RiskDisavowalIssue => "risk.disavowal.issue",
            Action::RiskSignalIngest => "risk.signal.ingest",
            Action::SignupQuarantineApproved => "signup_quarantine.approved",
            Action::SignupQuarantineRejected => "signup_quarantine.rejected",
            Action::SignupQuarantineExtended => "signup_quarantine.extended",
            Action::RecoveryApproved => "recovery.approved",
            Action::RecoveryApprovalRejected => "recovery.approval.rejected",
            Action::RecoveryContactConfirmed => "recovery.contact.confirmed",
            Action::RecoveryIdvCallback => "recovery.idv.callback",
            Action::RiskDisavow => "risk.disavow",
            Action::UsagePublish => "usage.publish",
            Action::WebhookEndpointCreate => "webhook.endpoint.create",
            Action::WebhookEndpointRotateSecret => "webhook.endpoint.rotate_secret",
            Action::WebhookEndpointSetActive => "webhook.endpoint.set_active",
            Action::WebhookEndpointSetEventTypes => "webhook.endpoint.set_event_types",
            Action::WebhookEndpointReplayDeadLetters => "webhook.endpoint.replay_dead_letters",
            Action::WebhookEndpointDelete => "webhook.endpoint.delete",
            Action::ConnectorCreate => "connector.create",
            Action::ConnectorUpdate => "connector.update",
            Action::ConnectorDelete => "connector.delete",
            Action::OrgConnectionCreate => "org_connection.create",
            Action::UpstreamTokenCapture => "upstream_token.capture",
            Action::UpstreamTokenRead => "upstream_token.read",
            Action::UpstreamTokenGrantCreate => "upstream_token_grant.create",
            Action::FedcmAssertionIssue => "fedcm.assertion.issue",
            Action::RoutingRuleCreate => "routing_rule.create",
            Action::RoutingRuleDomainVerification => "routing_rule.domain_verification",
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The acting context a mutation runs under: who is acting and which request the
/// action belongs to.
///
/// Required for every write and for no read. It is threaded into the audit row
/// so the log answers "who did this, as part of which request" for every
/// mutation. Construct it once per request from the authenticated caller context
/// and the inbound correlation id (generate a fresh [`CorrelationId`] with
/// [`CorrelationId::generate`] when the caller supplies none).
#[derive(Debug, Clone, Copy)]
pub struct ActingContext {
    actor: ActorRef,
    correlation: CorrelationId,
    organization: Option<crate::id::OrganizationId>,
}

impl ActingContext {
    /// Bind an actor and a correlation id into an acting context.
    ///
    /// Carries NO organization. That is the honest default: most mutations belong to no
    /// organization at all, and a context that guessed one would attribute a tenant-level
    /// change to whichever organization happened to be in scope.
    #[must_use]
    pub fn new(actor: ActorRef, correlation: CorrelationId) -> Self {
        Self {
            actor,
            correlation,
            organization: None,
        }
    }

    /// Attribute every audit row written under this context to `organization`.
    ///
    /// Set ONLY where the caller has established that the mutation is that organization's
    /// event (issue #110). Per-organization SIEM streams select on this, so attributing a
    /// row to the wrong organization delivers it to the wrong customer's SIEM, and that
    /// failure is silent: the delivery succeeds.
    ///
    /// The TYPED id, not a string: an `OrganizationId` embeds its (tenant, environment),
    /// so an id from another scope cannot be attached here at all. A string would let a
    /// caller attribute a row to an organization that does not exist in this environment,
    /// and the resulting stream would deliver it to whoever owns that id elsewhere.
    #[must_use]
    pub fn in_organization(mut self, organization: crate::id::OrganizationId) -> Self {
        self.organization = Some(organization);
        self
    }

    /// The organization this action belongs to, if it belongs to one.
    ///
    /// [`None`] means "not an organization's event", which is a FACT rather than missing
    /// data: a per-org stream must not match it.
    #[must_use]
    pub fn organization(&self) -> Option<crate::id::OrganizationId> {
        self.organization
    }

    /// The acting principal.
    #[must_use]
    pub fn actor(&self) -> ActorRef {
        self.actor
    }

    /// The correlation id this action belongs to.
    #[must_use]
    pub fn correlation(&self) -> CorrelationId {
        self.correlation
    }
}

#[cfg(test)]
mod tests {
    use super::Action;
    use std::collections::BTreeMap;

    /// Every action wire string is DISTINCT, swept out of this file's own source
    /// rather than a hand-written list.
    ///
    /// The audit layer's sharpest asymmetry: [`crate::classification::ResourceType`]
    /// has `ALL`, a fixed-size array type, an in-crate uniqueness test, AND a shell
    /// lint. [`Action`] has none of the four. There is no `Action::ALL` to iterate,
    /// so a duplicated or misspelled action string would ship silently and two
    /// distinct mutations would become indistinguishable in the audit log and in
    /// the milestone-11 delta contract that reads it.
    ///
    /// The scan is over [`Action::as_str`]'s body, which is a flat match returning
    /// only string literals, so every quoted literal in it IS an action wire
    /// string. Two things keep the scanner honest about what it cannot read: the
    /// function-header needle is assembled from fragments so the scanner never
    /// matches its own source lines, and the number of literals found is asserted
    /// to be a plausible floor, so a scan that silently read NOTHING (an edit that
    /// renames the function or reflows the match) fails here instead of passing
    /// vacuously.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one scan of the whole action registry followed by the per-issue \
                  contract pins that read against it; splitting the pins into their \
                  own tests would re-run the scan and let the two copies drift"
    )]
    fn every_audit_action_wire_string_is_distinct_and_a_snake_case_dotted_token() {
        let source = include_str!("audit.rs");
        let needle = concat!("pub fn ", "as_str(&self) -> &'static str {");
        let body = source
            .split_once(needle)
            .map(|(_, rest)| rest)
            .expect("the as_str body is readable");
        // The match ends at the first line that is exactly four spaces and a close
        // brace, which is the function's own closing brace.
        let body = body
            .split_once("\n    }\n")
            .map(|(inside, _)| inside)
            .expect("the as_str body is terminated");

        let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
        for line in body.lines() {
            let Some((_, after_quote)) = line.split_once('"') else {
                continue;
            };
            let Some((wire, _)) = after_quote.split_once('"') else {
                continue;
            };
            *seen.entry(wire).or_default() += 1;
        }

        assert!(
            seen.len() > 100,
            "the scanner read only {} action wire strings; it is not reading the \
             match body any more",
            seen.len()
        );
        let duplicates: Vec<&str> = seen
            .iter()
            .filter(|(_, count)| **count > 1)
            .map(|(wire, _)| *wire)
            .collect();
        assert!(
            duplicates.is_empty(),
            "audit action wire strings must be mutually distinct; these appear more \
             than once: {duplicates:?}"
        );
        for wire in seen.keys() {
            assert!(
                wire.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.'),
                "the action wire string {wire} must be a dotted snake_case token"
            );
        }

        // Issue #95's two actions are present under exactly the spellings the
        // migration header records as the policy delta contract, so a rename here
        // fails rather than silently breaking that contract.
        assert_eq!(
            Action::OrganizationPolicySet.as_str(),
            "organization.policy.set"
        );
        assert_eq!(
            Action::OrganizationPolicyRemove.as_str(),
            "organization.policy.remove"
        );
        assert!(seen.contains_key("organization.policy.set"));
        assert!(seen.contains_key("organization.policy.remove"));

        // Issue #98's three actions, pinned against the DEPLOYED migration header
        // rather than against a literal copied out of it. 0091 names these three
        // strings as "the delta contract for a permission", so a rename on either
        // side has to fail: comparing a literal here to a literal there would agree
        // with itself while both drifted from the header a consumer reads.
        let migration_0091 = include_str!("../migrations/0091_permissions.sql");
        for action in [
            Action::PermissionCreate,
            Action::PermissionUpdate,
            Action::PermissionDelete,
        ] {
            assert!(
                seen.contains_key(action.as_str()),
                "{} must be in the as_str match",
                action.as_str()
            );
            assert!(
                migration_0091.contains(&format!("`{}`", action.as_str())),
                "migration 0091 declares the permission delta contract, so {} must \
                 appear in its header",
                action.as_str()
            );
            assert!(
                !action.as_str().starts_with("organization."),
                "the permission vocabulary is ENVIRONMENT scoped, so {} must not \
                 claim an organization dimension the row does not have",
                action.as_str()
            );
        }
        // The scanner really did read the migration, so the three assertions above
        // are not satisfied by an empty or unreadable file. Pinned on a constraint
        // name rather than on the DDL statement, because a bare table name in a
        // create position would trip `scripts/query-audit.sh`.
        assert!(migration_0091.contains("permissions_kind_slug_live_uniq"));

        // Issue #98's role-to-permission MAPPING actions, pinned against the
        // deployed 0092 header the same way, plus the property that separates them
        // from the three above: a mapping DOES have an organization dimension, so
        // its actions must claim one. That asymmetry is the reason the check on the
        // vocabulary actions above is spelled as a refusal rather than as a shared
        // rule, and asserting only one side of it would let a later rename collapse
        // the two vocabularies into one.
        let migration_0092 = include_str!("../migrations/0092_org_role_permissions.sql");
        for action in [
            Action::OrganizationRolePermissionAssign,
            Action::OrganizationRolePermissionUnassign,
        ] {
            assert!(
                seen.contains_key(action.as_str()),
                "{} must be in the as_str match",
                action.as_str()
            );
            assert!(
                migration_0092.contains(&format!("`{}`", action.as_str())),
                "migration 0092 declares the mapping delta contract, so {} must \
                 appear in its header",
                action.as_str()
            );
            assert!(
                action.as_str().starts_with("organization.role.permission."),
                "a mapping joins an ORGANIZATION's role to a permission, so {} must \
                 name the dimension the row actually has",
                action.as_str()
            );
        }
        assert!(migration_0092.contains("org_role_permissions_pair_live_uniq"));

        // Issue #98's DEFAULT-ROLE actions. `org_roles` is the one table in this
        // issue whose delta contract is stated across TWO migration headers: 0086
        // named three actions, and 0093 says that this PR takes it to five. Both
        // halves are pinned, because a check that read only 0093 would stay green if
        // a rename dropped one of 0086's three out of the union that header is
        // counting.
        let migration_0086 = include_str!("../migrations/0086_org_roles.sql");
        let migration_0093 = include_str!("../migrations/0093_org_default_role.sql");
        for (action, header, source) in [
            (Action::OrganizationRoleCreate, migration_0086, "0086"),
            (Action::OrganizationRoleUpdate, migration_0086, "0086"),
            (Action::OrganizationRoleDelete, migration_0086, "0086"),
            (Action::OrganizationDefaultRoleSet, migration_0093, "0093"),
            (Action::OrganizationDefaultRoleClear, migration_0093, "0093"),
        ] {
            assert!(
                seen.contains_key(action.as_str()),
                "{} must be in the as_str match",
                action.as_str()
            );
            assert!(
                header.contains(&format!("`{}`", action.as_str())),
                "migration {source} declares part of the org_roles delta contract, \
                 so {} must appear in its header",
                action.as_str()
            );
        }
        // The designation is a property of the ORGANIZATION rather than of the role
        // vocabulary, so unlike 0086's three these two name that dimension. Spelled
        // as a positive check on the prefix AND a refusal of the role-vocabulary
        // prefix, so a rename cannot quietly fold them into the create/update/delete
        // family whose target means something else.
        for action in [
            Action::OrganizationDefaultRoleSet,
            Action::OrganizationDefaultRoleClear,
        ] {
            assert!(
                action.as_str().starts_with("organization.default_role."),
                "{} designates one role for a whole ORGANIZATION, so it must name \
                 that dimension",
                action.as_str()
            );
        }
        assert!(migration_0093.contains("org_roles_org_default_live_uniq"));
    }
}
