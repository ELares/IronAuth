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
use ironauth_store::{
    MANAGEMENT_LIST_HARD_CAP, OrganizationId, ScimPushConnection, ScimPushConnectionId,
    ScimPushResourceType, ScopedStore, StoreError, UserState,
};
use serde_json::{Map, Value};

use crate::scim_push_events::Collection;
use crate::scim_push_mapping::resource_for;
use crate::scim_push_worker::{SourceError, SubjectSource};

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

/// The ceiling is only detectable if the store will actually SERVE one row past it.
///
/// The oversize probe asks for `MAX_GROUP_MEMBERS + 1` and calls the group too large when that
/// many come back. Every paged read in the store clamps its limit to
/// `MANAGEMENT_LIST_HARD_CAP + 1`, so a ceiling at or above that cap makes the probe ask for
/// more than the store will ever return: `len()` could never exceed the ceiling and every group,
/// however large, would be silently truncated to a partial `members` array instead.
///
/// A bound that is only correct because of a constant declared in another crate is a bound
/// nobody will keep in step by reading it. This makes raising either one a compile error.
const _: () = assert!(
    MAX_GROUP_MEMBERS < MANAGEMENT_LIST_HARD_CAP + 1,
    "MAX_GROUP_MEMBERS must leave room for the store's clamp to serve one row past it"
);

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

impl From<DirectoryError> for SourceError {
    /// # Which of these get better by being tried again
    ///
    /// Only the store one. A mapping that targets a reserved attribute, a filter that does not
    /// parse and a group too large for one body are refusals this source will repeat every time
    /// it is asked, and reporting them as retryable made the pass return without checkpointing:
    /// the connection re-read the same page, hit the same subject, and paused with a doubling
    /// backoff for ever while everything behind it went undelivered.
    fn from(error: DirectoryError) -> Self {
        let why = error.to_string();
        match error {
            DirectoryError::Store(_) => Self::Retryable(why),
            // ABOUT THE CONNECTION, not about whoever happened to be read first. A mapping that
            // targets a reserved attribute and a filter that does not parse refuse EVERY subject,
            // so reporting them per subject would step over every person in the organization and
            // checkpoint past all of them: a clean-looking pass that delivered nothing and moved
            // the cursor past the events that would have said so.
            DirectoryError::FilterInvalid(_) | DirectoryError::MappingInvalid(_) => {
                Self::Configuration(why)
            }
            // ABOUT ONE GROUP. Every other subject on the page is unaffected, so the page steps
            // over it and the refusal is recorded where an operator looks for it.
            DirectoryError::GroupTooLarge { .. } => Self::Permanent(why),
        }
    }
}

/// One organization's people and groups, as one outbound connection sees them.
pub struct PushDirectory<'a> {
    store: &'a ScopedStore<'a>,
    connection: ScimPushConnectionId,
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
            connection: connection.id,
            organization: connection.organization_id,
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
        // A STORE FAULT IS NOT AN ABSENCE, and conflating them deprovisions live people.
        //
        // This was `let Ok(user) = ... else { return Ok(None) }`, which put a connection reset, a
        // statement timeout, a failover and a missing master key in the same arm as a deleted
        // user. `None` is what the tail reads as "this person is gone": `scope_decision` turns it
        // into a Withdraw and the connection deactivates them downstream. One database hiccup
        // during a pass would have deprovisioned everybody in the page.
        let user = match self.store.users().get(&user_id).await {
            Ok(user) => user,
            Err(StoreError::NotFound) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        // MEMBERSHIP IS WHAT MAKES THEM THIS CONNECTION'S SUBJECT, and the predicate is in the
        // statement. A user who is not a live member of this organization is not somebody this
        // connection provisions, and answering `None` is what makes the worker step over them
        // rather than push a stranger.
        let Some(membership) = self
            .store
            .org_memberships()
            .for_user_in_org(&self.organization, &user_id)
            .await?
        else {
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
        // A STORE FAULT IS NOT AN ABSENCE. See `build_user`: `None` reads as "this group is gone"
        // and the tail deprovisions it.
        let group = match self
            .store
            .org_groups()
            .get_in_org(&self.organization, &group_id)
            .await
        {
            Ok(group) => group,
            Err(StoreError::NotFound) => return Ok(None),
            Err(error) => return Err(error.into()),
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
        let membership_ids: Vec<_> = members.iter().map(|m| m.membership_id).collect();
        let users = self
            .store
            .org_memberships()
            .users_for(&membership_ids)
            .await?;

        // # A MEMBER REFERENCE IS THE DOWNSTREAM'S ID, AND ONLY FOR MEMBERS THIS CONNECTION SENT
        //
        // Two things were wrong with putting every member's IronAuth id in here.
        //
        // RFC 7643 section 4.2 says `members[].value` identifies the member AT THIS SERVER, so a
        // downstream resolves it against ids IT issued. IronAuth's own subject id is not one, and
        // the reference server refuses a membership it cannot resolve. The link table is where
        // the id it did issue lives, recorded when the subject was provisioned.
        //
        // And the members were not filtered. A connection with a `user_scope_filter` is one an
        // operator configured to send SOME of the organization, and the group body handed the
        // downstream the identifier of every member including the ones the filter excludes. The
        // filter reached `admits` for a User pushed on its own and never reached a User named
        // inside a Group, so the confinement the operator configured had a hole in exactly the
        // shape of their groups.
        //
        // A member with no link is omitted rather than refused: they are out of scope, or the
        // backfill has not reached them yet. Groups are enumerated after users, and a membership
        // event re-converges the group, so the reference appears once the person does.
        // THE CHEAP DISCRIMINATOR FIRST. Both conditions have to hold, so the order is free to
        // choose, and the link lookup is ONE statement while `admits_user` is a membership read
        // plus, when a filter is configured, a whole mapped body. Most members dropped from a
        // group are dropped by the link check, and asking the expensive question first paid for a
        // body that was about to be thrown away.
        let mut references = Vec::with_capacity(users.len());
        for (_, user_id) in &users {
            let member_subject = user_id.to_string();
            let link = self
                .store
                .scim_push_links()
                .find(
                    &self.connection,
                    ScimPushResourceType::User,
                    &member_subject,
                )
                .await?;
            let Some(link) = link.filter(|l| l.deprovisioned_at_unix_micros.is_none()) else {
                continue;
            };
            if !self.admits_user(&member_subject).await? {
                continue;
            }
            references.push(Value::Object(Map::from_iter([(
                "value".to_owned(),
                Value::String(link.downstream_id.clone()),
            )])));
        }

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
            ("members".to_owned(), Value::Array(references)),
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

    /// Whether `subject_id` is this connection's to push: in its organization, and admitted by
    /// its filter if it has one.
    ///
    /// # The organization check is not optional, and skipping it was a cross-organization leak
    ///
    /// An earlier version returned `true` without reading anything when no filter was configured,
    /// on the grounds that the connection is attached to one organization and every read here is
    /// confined to it. That sentence is true of `build`. It was not true of this method, which on
    /// that path never called `build` at all and answered `true` for any string.
    ///
    /// The worker relies on this for confinement and says so: the event feed is ENVIRONMENT-wide,
    /// and the fence in `apply_one` can only filter events whose schema names an organization.
    /// `user.deleted` and `user.deprovisioned` name none, so they are decided here. With no
    /// filter -- the default the management surface allows -- a deletion in organization B
    /// reached organization A's connection as an in-scope departure, and A's client sent
    /// `GET /Users?filter=externalId eq "<B's user id>"` to A's downstream. On a downstream both
    /// organizations point at, the match lands and the subject is deactivated on a connection
    /// that was never authorized for them.
    ///
    /// So the membership read happens whatever the filter says, and the filter narrows what is
    /// left. It costs a read the old path skipped; a fence that fails open on the default
    /// configuration is not a fence.
    async fn admits(
        &self,
        collection: Collection,
        subject_id: &str,
    ) -> Result<bool, DirectoryError> {
        match collection {
            Collection::User => self.admits_user(subject_id).await,
            Collection::Group => self.admits_group(subject_id).await,
        }
    }

    /// [`Self::admits`] for a person.
    ///
    /// SPELLED OUT PER COLLECTION rather than dispatched inside one body, because `build_group`
    /// asks this about each member: routing that through the general form makes `build` call
    /// itself, which an `async fn` cannot do without boxing. Splitting it says in the type system
    /// what is true in fact -- a group's members are people, and deciding a person never asks
    /// about a group.
    async fn admits_user(&self, subject_id: &str) -> Result<bool, DirectoryError> {
        // WITH NO FILTER, THE MEMBERSHIP READ IS THE WHOLE ANSWER, and building the body to throw
        // it away is three reads plus a mapping for a question one read settles. It matters most
        // where it is asked most: `build_group` asks this about every member, so the cheap path
        // is the difference between one read per member and four.
        //
        // What must NOT come back is the version that skipped the read as well. That was the
        // cross-organization leak: `admits` answered true for any string when no filter was
        // configured, and the worker's only fence for an organization-less event is this method.
        let Some(filter) = self.user_filter.as_ref() else {
            let Ok(user_id) = self.store.users().parse_id(subject_id) else {
                return Ok(false);
            };
            return Ok(self
                .store
                .org_memberships()
                .for_user_in_org(&self.organization, &user_id)
                .await?
                .is_some());
        };
        // WITH a filter, the body is what the filter reads, so it has to be built anyway.
        let Some(resource) = self.build_user(subject_id).await? else {
            return Ok(false);
        };
        // EVALUATED AGAINST THE MAPPED RESOURCE, not against the source. An operator writes the
        // filter in SCIM attribute names because that is what the connection is configured in;
        // evaluating it against IronAuth's own field names would silently match nothing.
        Ok(filter_matches(filter, &resource))
    }

    /// [`Self::admits`] for a group.
    async fn admits_group(&self, subject_id: &str) -> Result<bool, DirectoryError> {
        // THE CHEAP PATH MATTERS MORE HERE. `build_group` fans out over every member, so building
        // a body only to discard it against an absent filter costs four reads per member of a
        // group nobody asked to filter.
        let Some(filter) = self.group_filter.as_ref() else {
            let Ok(group_id) = self.store.org_groups().parse_id(subject_id) else {
                return Ok(false);
            };
            return match self
                .store
                .org_groups()
                .get_in_org(&self.organization, &group_id)
                .await
            {
                Ok(_) => Ok(true),
                Err(StoreError::NotFound) => Ok(false),
                Err(error) => Err(error.into()),
            };
        };
        let Some(resource) = self.build_group(subject_id).await? else {
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
    ) -> impl Future<Output = Result<Option<Value>, SourceError>> + Send {
        let subject_id = subject_id.to_owned();
        async move {
            self.build(collection, &subject_id)
                .await
                .map_err(Into::into)
        }
    }

    fn in_scope(
        &self,
        collection: Collection,
        subject_id: &str,
    ) -> impl Future<Output = Result<bool, SourceError>> + Send {
        let subject_id = subject_id.to_owned();
        async move {
            self.admits(collection, &subject_id)
                .await
                .map_err(Into::into)
        }
    }

    fn enumerate(
        &self,
        collection: Collection,
        after: Option<&str>,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<String>, SourceError>> + Send {
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
            .map_err(|error| SourceError::from(DirectoryError::from(error)))?;
            // UNFILTERED, and that is the contract. Filtering here can empty a page while the
            // organization still has people in it, and an empty page tells the worker the
            // collection is finished: everybody after that page would be skipped for good. The
            // worker asks `in_scope` about each subject instead, which is where the tail has
            // always decided it.
            Ok(ids)
        }
    }
}
