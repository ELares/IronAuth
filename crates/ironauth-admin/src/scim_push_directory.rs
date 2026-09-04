// SPDX-License-Identifier: MIT OR Apache-2.0

//! The directory an outbound SCIM connection pushes: IronAuth's own users and organization
//! groups, mapped into SCIM resources (issue #137).
//!
//! # Why this module exists at all
//!
//! Criterion 1 of #137 asks that a downstream server receive writes for in-scope users and
//! groups WITH ATTRIBUTE MAPPING APPLIED. Three layers shipped to serve it and none of them was
//! composed: [`crate::scim_push_mapping`] had no caller outside its own test, the worker's
//! `SubjectSource` had exactly one implementor and it was a test double, and `run_due_connections`
//! had no caller in `src` at all. Every acceptance test passed against code nothing in a
//! deployment would run, which is the shape of a milestone that reports itself complete and
//! provisions nobody.
//!
//! This is the seam that was missing: the thing that reads a person or a group out of the store,
//! decides whether the connection's filter admits them, and hands the worker the body the mapping
//! produces.
//!
//! # What is NOT here
//!
//! No SCIM protocol, no HTTP, no cursor arithmetic. Those belong to
//! [`crate::scim_push_client`] and [`crate::scim_push_worker`], and keeping them out is what lets
//! this module be about one question: what does IronAuth know about this subject.

use ironauth_scim::{Filter, filter_matches};
use ironauth_store::{OrganizationId, ScimPushConnection, ScopedStore, StoreError, UserState};
use serde_json::{Map, Value};

use crate::scim_push_events::Collection;
use crate::scim_push_mapping::resource_for;
use crate::scim_push_worker::SubjectSource;

/// The SCIM 2.0 core User schema URN (RFC 7643 section 4.1).
const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
/// The SCIM 2.0 core Group schema URN (RFC 7643 section 4.2).
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";

/// How many members a group's enumeration reads before it stops.
///
/// A BOUND RATHER THAN A PAGE LOOP, deliberately. A `members` array is one SCIM attribute in one
/// request body, so a group larger than this cannot be expressed in a single push whatever this
/// code does; reading further would only build a body the downstream refuses for size. The
/// truncation is reported through [`DirectoryError::GroupTooLarge`] rather than silently applied,
/// because a group that syncs with some of its members is worse than one that refuses to sync:
/// the downstream would enforce access for a membership IronAuth does not have.
const MAX_GROUP_MEMBERS: i64 = 1000;

/// Why a subject could not be read or mapped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryError {
    /// The connection's scope filter is not a filter this server can evaluate.
    FilterInvalid(String),
    /// The connection's attribute mapping cannot be applied.
    MappingInvalid(String),
    /// The group has more members than one SCIM body can carry.
    GroupTooLarge {
        /// The group's subject id.
        subject_id: String,
    },
    /// The store could not answer.
    Store(String),
}

impl core::fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FilterInvalid(why) => {
                write!(f, "this connection's scope filter is invalid: {why}")
            }
            Self::MappingInvalid(why) => {
                write!(
                    f,
                    "this connection's attribute mapping cannot be applied: {why}"
                )
            }
            Self::GroupTooLarge { subject_id } => write!(
                f,
                "{subject_id} has more than {MAX_GROUP_MEMBERS} members, which is more than one \
                 SCIM body can carry"
            ),
            Self::Store(why) => write!(f, "the store could not answer: {why}"),
        }
    }
}

impl From<StoreError> for DirectoryError {
    fn from(error: StoreError) -> Self {
        Self::Store(format!("{error:?}"))
    }
}

/// One organization's people and groups, as one outbound connection sees them.
pub struct PushDirectory<'a> {
    store: &'a ScopedStore<'a>,
    organization: OrganizationId,
    attribute_mapping: Value,
    /// PARSED ONCE, at construction. A filter that cannot be parsed is a configuration fault, and
    /// discovering it per subject would report it as a per-subject failure on every person in the
    /// organization instead of once against the connection.
    user_filter: Option<Filter>,
    group_filter: Option<Filter>,
}

impl<'a> PushDirectory<'a> {
    /// Build the directory one connection pushes.
    ///
    /// # Errors
    ///
    /// [`DirectoryError::FilterInvalid`] if either scope filter is not a filter this server can
    /// evaluate. The management surface refuses those at write time with the same parser, so
    /// reaching this means a filter was stored before that check existed.
    pub fn new(
        store: &'a ScopedStore<'a>,
        connection: &ScimPushConnection,
    ) -> Result<Self, DirectoryError> {
        let parse = |raw: Option<&String>| -> Result<Option<Filter>, DirectoryError> {
            match raw {
                None => Ok(None),
                Some(raw) => ironauth_scim::parse_filter(raw)
                    .map(Some)
                    .map_err(|error| DirectoryError::FilterInvalid(format!("{error:?}"))),
            }
        };
        Ok(Self {
            store,
            organization: connection.organization_id.clone(),
            attribute_mapping: connection.attribute_mapping.clone(),
            user_filter: parse(connection.user_scope_filter.as_ref())?,
            group_filter: parse(connection.group_scope_filter.as_ref())?,
        })
    }

    /// The SCIM body for one subject, or `None` if this organization does not hold them.
    async fn build(
        &self,
        collection: Collection,
        subject_id: &str,
    ) -> Result<Option<Value>, DirectoryError> {
        match collection {
            Collection::User => self.build_user(subject_id).await,
            Collection::Group => self.build_group(subject_id).await,
        }
    }

    async fn build_user(&self, subject_id: &str) -> Result<Option<Value>, DirectoryError> {
        let Ok(user_id) = self.store.users().parse_id(subject_id) else {
            return Ok(None);
        };
        let Ok(user) = self.store.users().get(&user_id).await else {
            return Ok(None);
        };
        // MEMBERSHIP IS WHAT MAKES THEM THIS CONNECTION'S SUBJECT. A user who exists but is not a
        // live member of this organization is not somebody this connection provisions, and
        // answering `None` is what makes the worker step over them rather than push a stranger.
        let membership = self
            .store
            .org_memberships()
            .list_for_user(&user_id)
            .await?
            .into_iter()
            .find(|record| record.organization_id == self.organization);
        let Some(membership) = membership else {
            return Ok(None);
        };

        let traits = self
            .store
            .users()
            .traits(&user_id)
            .await?
            .map_or(Value::Null, |(_, document)| document);

        // ACTIVE IS BOTH STATES, not either. A user who can still sign in but whose membership
        // was suspended is not active in THIS organization, and a live membership belonging to a
        // disabled user is not an active person. Sending the wrong one means a departure that
        // never reaches the downstream.
        let active = user.state == UserState::Active && membership.state == "active";

        let source = Value::Object(Map::from_iter([
            ("id".to_owned(), Value::String(subject_id.to_owned())),
            (
                "identifier".to_owned(),
                Value::String(user.identifier.clone()),
            ),
            // UNDER ITS SCIM NAME TOO, because `userName` is required of a User by RFC 7643
            // section 4.1 and the mapper defaults it from the subject: a connection created with
            // no mapping, which the management surface allows, would otherwise build a body the
            // downstream refuses. An operator who maps `userName` somewhere else still wins.
            (
                "userName".to_owned(),
                Value::String(user.identifier.clone()),
            ),
            (
                "state".to_owned(),
                Value::String(user.state.as_str().to_owned()),
            ),
            ("traits".to_owned(), traits),
            (
                "membership".to_owned(),
                Value::Object(Map::from_iter([
                    ("state".to_owned(), Value::String(membership.state.clone())),
                    ("metadata".to_owned(), membership.metadata.clone()),
                ])),
            ),
        ]));

        resource_for(
            USER_SCHEMA,
            subject_id,
            active,
            &self.attribute_mapping,
            &source,
        )
        .map(Some)
        .map_err(|error| DirectoryError::MappingInvalid(format!("{error:?}")))
    }

    async fn build_group(&self, subject_id: &str) -> Result<Option<Value>, DirectoryError> {
        let Ok(group_id) = self.store.org_groups().parse_id(subject_id) else {
            return Ok(None);
        };
        let Ok(group) = self
            .store
            .org_groups()
            .get_in_org(&self.organization, &group_id)
            .await
        else {
            return Ok(None);
        };

        // ONE READ PAST THE CEILING, so a group at exactly the limit is served and one above it is
        // refused. Asking for the limit alone cannot tell those apart.
        let members = self
            .store
            .org_group_members()
            .list_for_group(&self.organization, &group_id, MAX_GROUP_MEMBERS + 1, None)
            .await?;
        if i64::try_from(members.len()).unwrap_or(i64::MAX) > MAX_GROUP_MEMBERS {
            return Err(DirectoryError::GroupTooLarge {
                subject_id: subject_id.to_owned(),
            });
        }
        let membership_ids: Vec<_> = members.iter().map(|m| m.membership_id.clone()).collect();
        let users = self
            .store
            .org_memberships()
            .users_for(&membership_ids)
            .await?;
        // THE MEMBER VALUE IS THE SUBJECT ID THE WORKER PUSHES, which is the user id and not the
        // membership id. A downstream resolves `members[].value` against what it was told the
        // person's `externalId` is, and that is what `build_user` stamps.
        let members: Vec<Value> = users
            .iter()
            .map(|(_, user_id)| {
                Value::Object(Map::from_iter([(
                    "value".to_owned(),
                    Value::String(user_id.to_string()),
                )]))
            })
            .collect();

        let source = Value::Object(Map::from_iter([
            ("id".to_owned(), Value::String(subject_id.to_owned())),
            ("slug".to_owned(), Value::String(group.slug.clone())),
            // UNDER ITS SCIM NAME, because `base_resource` stamps a Group's `displayName` from the
            // subject rather than from the mapping: RFC 7643 section 4.2 requires it, so leaving
            // it to an operator's mapping meant the default connection built a body the
            // downstream refuses.
            (
                "displayName".to_owned(),
                Value::String(group.display_name.clone()),
            ),
            ("members".to_owned(), Value::Array(members)),
            (
                "parentId".to_owned(),
                group
                    .parent_id
                    .as_ref()
                    .map_or(Value::Null, |id| Value::String(id.to_string())),
            ),
            ("metadata".to_owned(), group.metadata.clone()),
        ]));

        // A GROUP IS NEVER `active`. RFC 7643 section 4.2 gives it no such attribute, and the
        // mapper drops the argument for a Group schema; `true` is passed to say the value is
        // meaningless here rather than to assert anything about the group.
        resource_for(
            GROUP_SCHEMA,
            subject_id,
            true,
            &self.attribute_mapping,
            &source,
        )
        .map(Some)
        .map_err(|error| DirectoryError::MappingInvalid(format!("{error:?}")))
    }

    /// Whether this connection's filter admits `subject_id`.
    async fn admits(
        &self,
        collection: Collection,
        subject_id: &str,
    ) -> Result<bool, DirectoryError> {
        let filter = match collection {
            Collection::User => self.user_filter.as_ref(),
            Collection::Group => self.group_filter.as_ref(),
        };
        let Some(filter) = filter else {
            // NO FILTER MEANS EVERYONE IN THE ORGANIZATION, which is the whole scope already: the
            // connection is attached to one organization and every read here is confined to it.
            return Ok(true);
        };
        // EVALUATED AGAINST THE MAPPED RESOURCE, not against the source. An operator writes the
        // filter in SCIM attribute names because that is what the connection is configured in;
        // evaluating it against IronAuth's own field names would silently match nothing.
        let Some(resource) = self.build(collection, subject_id).await? else {
            return Ok(false);
        };
        Ok(filter_matches(filter, &resource))
    }
}

impl SubjectSource for PushDirectory<'_> {
    fn resource(
        &self,
        collection: Collection,
        subject_id: &str,
    ) -> impl Future<Output = Result<Option<Value>, String>> + Send {
        let subject_id = subject_id.to_owned();
        async move {
            self.build(collection, &subject_id)
                .await
                .map_err(|error| error.to_string())
        }
    }

    fn in_scope(
        &self,
        collection: Collection,
        subject_id: &str,
    ) -> impl Future<Output = Result<bool, String>> + Send {
        let subject_id = subject_id.to_owned();
        async move {
            self.admits(collection, &subject_id)
                .await
                .map_err(|error| error.to_string())
        }
    }

    fn enumerate(
        &self,
        collection: Collection,
        after: Option<&str>,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<String>, String>> + Send {
        let after = after.map(str::to_owned);
        async move {
            let limit = i64::try_from(limit).unwrap_or(i64::MAX);
            let ids = match collection {
                Collection::User => {
                    self.store
                        .org_memberships()
                        .user_ids_for_org_after(&self.organization, after.as_deref(), limit)
                        .await
                }
                Collection::Group => {
                    self.store
                        .org_groups()
                        .ids_for_org_after(&self.organization, after.as_deref(), limit)
                        .await
                }
            }
            .map_err(|error| DirectoryError::from(error).to_string())?;
            // UNFILTERED, and that is the contract. Filtering here can empty a page while the
            // organization still has people in it, and an empty page tells the worker the
            // collection is finished: everybody after that page would be skipped for good. The
            // worker asks `in_scope` about each subject instead, which is where the tail has
            // always decided it.
            Ok(ids)
        }
    }
}
