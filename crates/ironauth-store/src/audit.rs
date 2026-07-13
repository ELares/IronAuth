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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {
    /// A client was created.
    ClientCreate,
    /// A client was deleted.
    ClientDelete,
    /// A tenant was created (management plane, issue #11).
    TenantCreate,
    /// A tenant was deactivated (management plane, issue #11).
    TenantDelete,
    /// An environment was created (management plane, issue #11).
    EnvironmentCreate,
    /// An environment was deactivated (management plane, issue #11).
    EnvironmentDelete,
    /// A management API key was minted (management plane, issue #11).
    ManagementKeyCreate,
    /// A management API key was revoked (management plane, issue #11).
    ManagementKeyDelete,
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
    /// A per-environment signing key was provisioned (issue #19). Covers both a
    /// day-one key and a manually rotated-in successor.
    SigningKeyProvision,
}

impl Action {
    /// The stable wire string for this action.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::ClientCreate => "client.create",
            Action::ClientDelete => "client.delete",
            Action::TenantCreate => "tenant.create",
            Action::TenantDelete => "tenant.delete",
            Action::EnvironmentCreate => "environment.create",
            Action::EnvironmentDelete => "environment.delete",
            Action::ManagementKeyCreate => "management_key.create",
            Action::ManagementKeyDelete => "management_key.delete",
            Action::AuthorizationCodeIssue => "authorization_code.issue",
            Action::AuthorizationCodeRedeem => "authorization_code.redeem",
            Action::AuthorizationCodeReuse => "authorization_code.reuse",
            Action::TokenIssue => "token.issue",
            Action::SigningKeyProvision => "signing_key.provision",
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
}

impl ActingContext {
    /// Bind an actor and a correlation id into an acting context.
    #[must_use]
    pub fn new(actor: ActorRef, correlation: CorrelationId) -> Self {
        Self { actor, correlation }
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
