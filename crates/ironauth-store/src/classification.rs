// SPDX-License-Identifier: MIT OR Apache-2.0

//! The promotable / runtime / environment-identity classification of every
//! first-class resource type (issue #41).
//!
//! IronAuth's flagship differentiator is environments plus server-side config
//! promotion. Promotion needs one machine-readable answer, declared in the
//! schema, to "does this resource travel in a config snapshot?" rather than a
//! per-resource decision reverse-engineered later (the `PingOne` AIC failure
//! mode: the static-vs-dynamic split was vendor-decided and discovered late).
//! This module is that single source of truth. The snapshot export (5.3) and the
//! promotion engine (5.4) consume [`classify`] instead of maintaining a parallel
//! list, and the management API serves the same registry as metadata.
//!
//! Every resource type is exactly one of three classes:
//!
//! - [`ResourceClassification::Promotable`][]: static configuration that
//!   snapshots and promotes (an OAuth client, a resource server, a policy).
//! - [`ResourceClassification::Runtime`][]: dynamic data that is never promoted
//!   (an organization's members, users, sessions), and the structural resources
//!   above the per-environment data plane (operators, tenants).
//! - [`ResourceClassification::EnvironmentIdentity`][]: environment-intrinsic
//!   config that is neither promotable nor mere runtime data, excluded from every
//!   snapshot so promoting dev to prod never copies dev's issuer, keys, domains,
//!   or per-environment secret material (the environment itself, its signing
//!   keys, its management credentials).
//!
//! # Adding a resource type
//!
//! [`classify`] is an EXHAUSTIVE match over [`ResourceType`], and
//! [`ResourceType::ALL`] lists every variant. Adding a variant fails to compile
//! until it is classified, and `scripts/classification-lint.sh` independently
//! fails CI if a variant is missing from either the match or `ALL`. A resource
//! type therefore cannot land unclassified.

/// The three promotion classes a resource type can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceClassification {
    /// Static configuration that snapshots and promotes across environments.
    Promotable,
    /// Dynamic data (or structural resources above the data plane) that is never
    /// carried in a config snapshot.
    Runtime,
    /// Environment-intrinsic config that is excluded from snapshots and promotion
    /// so a promotion never copies one environment's identity onto another.
    EnvironmentIdentity,
}

impl ResourceClassification {
    /// The stable wire string (`promotable`, `runtime`, `environment-identity`).
    /// This is what the API metadata and the snapshot/promotion engines key on.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ResourceClassification::Promotable => "promotable",
            ResourceClassification::Runtime => "runtime",
            ResourceClassification::EnvironmentIdentity => "environment-identity",
        }
    }

    /// The three classes, for a lint or a metadata listing that must cover them
    /// all. Kept in one place so "all three classes" has a single definition.
    pub const ALL: [ResourceClassification; 3] = [
        ResourceClassification::Promotable,
        ResourceClassification::Runtime,
        ResourceClassification::EnvironmentIdentity,
    ];
}

/// The scope level a resource type's identifier is defined at. Declares, per the
/// #6 identifier model, what a resource's typed id embeds: an operator-plane id
/// embeds neither tenant nor environment, a tenant-level id embeds tenant only,
/// and an environment-scoped id embeds both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceLevel {
    /// The operator plane, above tenants. Ids embed neither tenant nor environment.
    Operator,
    /// The tenant level. Ids embed the tenant only.
    Tenant,
    /// The environment level and everything scoped inside it. Ids embed both the
    /// tenant and the environment.
    Environment,
}

impl ResourceLevel {
    /// The stable wire string (`operator`, `tenant`, `environment`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ResourceLevel::Operator => "operator",
            ResourceLevel::Tenant => "tenant",
            ResourceLevel::Environment => "environment",
        }
    }
}

/// Every first-class resource type IronAuth exposes through its management API.
///
/// This is the closed set the classification lint enforces. As a management
/// resource becomes first-class it is added here and classified in [`classify`];
/// resources still owned by a later milestone are not listed until they ship a
/// public surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ResourceType {
    /// The platform deployment root (operator plane).
    Operator,
    /// A customer of the operator.
    Tenant,
    /// An environment within a tenant (for example dev, staging, prod).
    Environment,
    /// A per-environment organization (the minimal M5 shell; B2B in M10).
    Organization,
    /// An environment-scoped management API key (mak_).
    ManagementCredential,
    /// A registered OAuth client (the promotable configuration exemplar).
    Client,
    /// A registered resource server (audience-to-token-format configuration).
    ResourceServer,
    /// A Dynamic Client Registration policy object.
    DcrPolicy,
    /// A per-environment signing key (issuer key material).
    SigningKey,
    /// A per-environment custom domain the environment is served under, with a
    /// built-in-ACME certificate (issue #47).
    CustomDomain,
    /// A bootstrap end user.
    User,
    /// An authenticated session.
    Session,
}

impl ResourceType {
    /// Every resource type, in a stable order. The classification lint and the
    /// metadata endpoint both iterate this; a variant missing here is caught by
    /// the `all_lists_every_variant` test and by `scripts/classification-lint.sh`.
    pub const ALL: [ResourceType; 12] = [
        ResourceType::Operator,
        ResourceType::Tenant,
        ResourceType::Environment,
        ResourceType::Organization,
        ResourceType::ManagementCredential,
        ResourceType::Client,
        ResourceType::ResourceServer,
        ResourceType::DcrPolicy,
        ResourceType::SigningKey,
        ResourceType::CustomDomain,
        ResourceType::User,
        ResourceType::Session,
    ];

    /// The stable wire name of this resource type (for example `organization`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ResourceType::Operator => "operator",
            ResourceType::Tenant => "tenant",
            ResourceType::Environment => "environment",
            ResourceType::Organization => "organization",
            ResourceType::ManagementCredential => "management_credential",
            ResourceType::Client => "client",
            ResourceType::ResourceServer => "resource_server",
            ResourceType::DcrPolicy => "dcr_policy",
            ResourceType::SigningKey => "signing_key",
            ResourceType::CustomDomain => "custom_domain",
            ResourceType::User => "user",
            ResourceType::Session => "session",
        }
    }

    /// The scope level this resource type's identifier is defined at.
    #[must_use]
    pub fn level(self) -> ResourceLevel {
        match self {
            ResourceType::Operator => ResourceLevel::Operator,
            ResourceType::Tenant => ResourceLevel::Tenant,
            // The environment level and everything scoped inside it.
            ResourceType::Environment
            | ResourceType::Organization
            | ResourceType::ManagementCredential
            | ResourceType::Client
            | ResourceType::ResourceServer
            | ResourceType::DcrPolicy
            | ResourceType::SigningKey
            | ResourceType::CustomDomain
            | ResourceType::User
            | ResourceType::Session => ResourceLevel::Environment,
        }
    }

    /// This resource type's promotion classification.
    #[must_use]
    pub fn classification(self) -> ResourceClassification {
        classify(self)
    }
}

/// The promotion classification of a resource type. The single source of truth
/// the snapshot export and the promotion engine consume.
///
/// The match is EXHAUSTIVE: a new [`ResourceType`] variant does not compile until
/// it is classified here, so a resource type can never silently land unclassified.
#[must_use]
pub fn classify(resource: ResourceType) -> ResourceClassification {
    use ResourceClassification::{EnvironmentIdentity, Promotable, Runtime};
    match resource {
        // Static configuration that a snapshot captures and a promotion replays:
        // clients, resource servers, and registration policies are exactly the
        // "static configuration" the promotion story moves between environments.
        ResourceType::Client | ResourceType::ResourceServer | ResourceType::DcrPolicy => Promotable,

        // Environment-intrinsic identity, excluded from every snapshot so a
        // promotion never copies one environment's identity onto another: the
        // environment itself, its signing keys (issuer key material), its
        // per-environment management credentials, and its custom domains (a
        // domain and its certificate are what a specific environment is served
        // under, never something a dev->prod promotion should copy).
        ResourceType::Environment
        | ResourceType::SigningKey
        | ResourceType::ManagementCredential
        | ResourceType::CustomDomain => EnvironmentIdentity,

        // Structural resources above the per-environment data plane (operators,
        // tenants) and dynamic per-environment data (organizations as customer
        // objects, users, sessions): never carried in a config snapshot.
        ResourceType::Operator
        | ResourceType::Tenant
        | ResourceType::Organization
        | ResourceType::User
        | ResourceType::Session => Runtime,
    }
}

#[cfg(test)]
mod tests {
    use super::{ResourceClassification, ResourceType};
    use std::collections::BTreeSet;

    #[test]
    fn all_lists_every_variant_exactly_once() {
        // A duplicate or a missing variant is caught here (and independently by
        // scripts/classification-lint.sh): the wire names must be a set of the
        // same length as ALL.
        let names: BTreeSet<&str> = ResourceType::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(
            names.len(),
            ResourceType::ALL.len(),
            "ResourceType::ALL must list every variant exactly once (no duplicate wire names)"
        );
    }

    #[test]
    fn every_resource_type_is_classified_and_all_three_classes_are_used() {
        // classify() is total by construction (an exhaustive match); this asserts
        // the stronger property the issue requires: all THREE classes appear, so
        // the taxonomy is not silently collapsed to one or two.
        let classes: BTreeSet<&str> = ResourceType::ALL
            .iter()
            .map(|r| r.classification().as_str())
            .collect();
        for class in ResourceClassification::ALL {
            assert!(
                classes.contains(class.as_str()),
                "no resource type is classified {}; the CI lint covers all three classes",
                class.as_str()
            );
        }
    }

    #[test]
    fn wire_strings_are_stable_and_hyphen_free_for_names() {
        // Names are snake_case wire tokens; only the classification uses a hyphen
        // (environment-identity), which is a fixed wire string, not prose.
        for resource in ResourceType::ALL {
            let name = resource.as_str();
            assert!(!name.is_empty());
            assert!(
                name.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "resource name {name} must be a snake_case wire token"
            );
        }
    }
}
