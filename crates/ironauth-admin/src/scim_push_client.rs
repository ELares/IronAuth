// SPDX-License-Identifier: MIT OR Apache-2.0

//! Converging one resource into a downstream SCIM server (issue #137).
//!
//! # The whole protocol is LOOK UP, THEN WRITE
//!
//! Issue #137's criterion 3 is that killing the downstream mid-sync and restoring it later
//! converges with NO DUPLICATE USERS, proven by `externalId` idempotency. A client that simply
//! POSTs on a create event satisfies the happy path and fails that criterion the first time a
//! response is lost: the resource exists downstream, the client never learned its id, and the
//! replay creates a second one.
//!
//! So every write here begins with the query RFC 7644 section 3.4.2 describes, and the query is
//! not an optimisation to skip when a local mapping happens to exist. It is what makes the
//! operation IDEMPOTENT rather than merely usually-correct.
//!
//! # The three answers a create can get, and why 409 is not a failure
//!
//! A downstream that enforces `externalId` uniqueness answers 409 when the lookup missed and the
//! resource exists anyway. That is not an error: it is the race between a lost response and a
//! replay, which is exactly the situation criterion 3 describes. The client re-queries and
//! proceeds with what it finds, so the outcome is the same as if the lookup had seen it.
//!
//! Treating 409 as a permanent failure would DEAD-LETTER precisely the events that outage
//! recovery replays, which is the opposite of converging.
//!
//! # PATCH is optional and this client behaves as if it is
//!
//! RFC 7644 section 3.5.2 makes PATCH OPTIONAL, and real servers answer 501. A connection's
//! `write_mode` says which to prefer, and a 501 from `PATCH` falls back to `PUT` for that request.
//! The fallback is per-request rather than sticky because this type is constructed per push and
//! has nowhere durable to remember; persisting the downgrade is the worker's job and belongs
//! with the worker, not here.

use serde_json::Value;

use crate::scim_push_transport::{ScimRequest, ScimResponse, ScimTransport, ScimTransportError};

/// Which write verb a connection prefers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    /// Prefer `PATCH`, falling back to `PUT` when the downstream answers 501.
    Patch,
    /// Always `PUT`.
    Put,
}

/// What a connection does when a resource leaves scope or is removed upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletionPolicy {
    /// `PATCH`/`PUT` the resource to `active: false`. The safer default: a DELETE against a
    /// downstream directory is not reversible and an accidental scope change should not be.
    Deactivate,
    /// `DELETE` the resource.
    Delete,
}

/// What converging one resource did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Converged {
    /// The resource did not exist downstream and was created. Carries the downstream id.
    Created(String),
    /// The resource existed and was updated in place. Carries the downstream id.
    Updated(String),
    /// A deprovision found nothing to do, which is a SUCCESS rather than a failure: the desired
    /// state is "absent or inactive" and it already holds. A replay of a delete must be able to
    /// reach this.
    AlreadyGone,
}

/// Why converging did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushError {
    /// The downstream is unreachable or answered 5xx. THE CURSOR PAUSES: the event is not
    /// consumed, and the same event is replayed when the downstream returns.
    Retryable(String),
    /// The downstream refused the request itself, and a replay reproduces it. An operator has to
    /// act, and the connection records the error rather than spinning.
    Permanent(String),
}

impl PushError {
    /// Whether a caller should pause its cursor rather than record a per-resource failure.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Retryable(_))
    }
}

impl From<ScimTransportError> for PushError {
    fn from(error: ScimTransportError) -> Self {
        // EVERY transport failure is retryable, including `Blocked`. A blocked destination needs
        // an operator, but the correct mechanical response is still to pause: consuming the
        // event would drop a directory change that nothing will replay once the URL is fixed.
        Self::Retryable(
            match error {
                ScimTransportError::Blocked => "the destination is refused by the outbound policy",
                ScimTransportError::Timeout => "the downstream timed out",
                ScimTransportError::Transport => "the downstream could not be reached",
            }
            .to_owned(),
        )
    }
}

/// A SCIM client pointed at one connection's downstream.
#[derive(Debug, Clone)]
pub struct ScimPushClient<T> {
    transport: T,
    base_url: String,
    bearer: String,
    write_mode: WriteMode,
}

impl<T: ScimTransport> ScimPushClient<T> {
    /// A client for one connection.
    pub fn new(
        transport: T,
        base_url: impl Into<String>,
        bearer: impl Into<String>,
        write_mode: WriteMode,
    ) -> Self {
        Self {
            transport,
            base_url: base_url.into(),
            bearer: bearer.into(),
            write_mode,
        }
    }

    async fn send(&self, request: ScimRequest) -> Result<ScimResponse, PushError> {
        Ok(self
            .transport
            .send(&self.base_url, &self.bearer, request)
            .await?)
    }

    /// The downstream id of the resource carrying this `externalId`, if the downstream has one.
    ///
    /// # The three shapes a miss can take
    ///
    /// A `ListResponse` with `totalResults` zero is a miss. So is one with an empty `Resources`.
    /// Both are read, rather than trusting the count, because a server that reports a count and
    /// returns nothing would otherwise index into an empty array.
    ///
    /// A 400 `invalidFilter` is NOT a miss and must not be read as one: it means this downstream
    /// does not support the lookup, and treating it as "no match" would create a duplicate on
    /// every replay. It is permanent, and an operator needs to see it.
    async fn find_by_external_id(
        &self,
        collection: &str,
        external_id: &str,
    ) -> Result<Option<String>, PushError> {
        let filter = format!("externalId eq \"{}\"", escape_filter_literal(external_id));
        let response = self.send(ScimRequest::query(collection, filter)).await?;
        if response.status.is_server_error() {
            return Err(PushError::Retryable(format!(
                "the downstream answered {} to a lookup",
                response.status
            )));
        }
        if !response.status.is_success() {
            return Err(PushError::Permanent(format!(
                "the downstream answered {} to a lookup{}",
                response.status,
                response
                    .scim_type()
                    .map(|t| format!(" ({t})"))
                    .unwrap_or_default()
            )));
        }
        let Some(body) = response.body else {
            return Err(PushError::Permanent(
                "the downstream answered a lookup with no body".to_owned(),
            ));
        };
        let first = body
            .get("Resources")
            .and_then(Value::as_array)
            .and_then(|r| r.first());
        Ok(first
            .and_then(|r| r.get("id"))
            .and_then(Value::as_str)
            .map(str::to_owned))
    }

    /// Create or update one resource so the downstream matches `resource`.
    ///
    /// `collection` is `/Users` or `/Groups`; `external_id` is IronAuth's own id for the subject,
    /// which is what makes the operation idempotent across a replay.
    ///
    /// # Errors
    ///
    /// [`PushError::Retryable`] when the downstream is unreachable or answered 5xx, in which case
    /// the caller pauses its cursor. [`PushError::Permanent`] when the downstream refused the
    /// request itself.
    pub async fn converge(
        &self,
        collection: &str,
        external_id: &str,
        resource: &Value,
    ) -> Result<Converged, PushError> {
        if let Some(id) = self.find_by_external_id(collection, external_id).await? {
            self.update(collection, &id, resource).await?;
            return Ok(Converged::Updated(id));
        }
        let create_response = self
            .send(ScimRequest::with_body(
                http::Method::POST,
                collection,
                resource.clone(),
            ))
            .await?;
        if create_response.status == http::StatusCode::CONFLICT {
            // THE RACE, not a failure. The lookup missed and the resource exists anyway, which is
            // what a lost response followed by a replay looks like. Re-query and proceed with
            // what is actually there; dead-lettering here would reject exactly the events that
            // outage recovery replays.
            let Some(id) = self.find_by_external_id(collection, external_id).await? else {
                // A 409 the re-query cannot explain. The downstream is enforcing a uniqueness
                // rule on something other than `externalId` -- a `userName` already taken by a
                // resource this connection does not own is the usual one -- and no amount of
                // retrying resolves it.
                return Err(PushError::Permanent(format!(
                    "the downstream refused the create as a duplicate{}, and no resource carries \
                     that externalId",
                    create_response
                        .scim_type()
                        .map(|t| format!(" ({t})"))
                        .unwrap_or_default()
                )));
            };
            self.update(collection, &id, resource).await?;
            return Ok(Converged::Updated(id));
        }
        if create_response.status.is_server_error() {
            return Err(PushError::Retryable(format!(
                "the downstream answered {} to a create",
                create_response.status
            )));
        }
        if !create_response.status.is_success() {
            return Err(PushError::Permanent(format!(
                "the downstream answered {} to a create{}",
                create_response.status,
                create_response
                    .scim_type()
                    .map(|t| format!(" ({t})"))
                    .unwrap_or_default()
            )));
        }
        // THE SERVER'S id, read from the response. RFC 7643 section 3.1 makes `id` server-issued,
        // so a client that assumed its own would address the wrong resource forever after.
        let id = create_response
            .body
            .as_ref()
            .and_then(|b| b.get("id"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                PushError::Permanent(
                    "the downstream answered a create without an id, so the resource cannot be \
                     addressed again"
                        .to_owned(),
                )
            })?
            .to_owned();
        Ok(Converged::Created(id))
    }

    /// Bring one existing resource up to date, preferring the connection's write mode.
    async fn update(&self, collection: &str, id: &str, resource: &Value) -> Result<(), PushError> {
        let path = format!("{collection}/{id}");
        if self.write_mode == WriteMode::Patch {
            let document = patch_document(resource);
            let patched = self
                .send(ScimRequest::with_body(
                    http::Method::PATCH,
                    path.clone(),
                    document,
                ))
                .await?;
            // 501 IS THE FALLBACK SIGNAL, and only 501. A 400 from PATCH means this document was
            // wrong and a PUT of the same content would hide that; a 405 means the route is not
            // there at all and is treated the same as 501, because both say "not this verb".
            if patched.status != http::StatusCode::NOT_IMPLEMENTED
                && patched.status != http::StatusCode::METHOD_NOT_ALLOWED
            {
                return classify_write(&patched, "a patch");
            }
        }
        let response = self
            .send(ScimRequest::with_body(
                http::Method::PUT,
                path,
                resource.clone(),
            ))
            .await?;
        classify_write(&response, "a replace")
    }

    /// Remove a resource downstream, or deactivate it, per the connection's policy.
    ///
    /// # Errors
    ///
    /// As [`ScimPushClient::converge`].
    pub async fn deprovision(
        &self,
        collection: &str,
        external_id: &str,
        policy: DeletionPolicy,
    ) -> Result<Converged, PushError> {
        let Some(id) = self.find_by_external_id(collection, external_id).await? else {
            // NOTHING TO DO IS SUCCESS. The desired state is "absent or inactive" and it holds.
            // A replayed delete reaches this, and it must not be an error or every replay after
            // a successful delete would fail forever.
            return Ok(Converged::AlreadyGone);
        };
        match policy {
            DeletionPolicy::Delete => {
                let response = self
                    .send(ScimRequest::delete(format!("{collection}/{id}")))
                    .await?;
                if response.status == http::StatusCode::NOT_FOUND {
                    // Deleted between the lookup and the delete. Still the desired state.
                    return Ok(Converged::AlreadyGone);
                }
                classify_write(&response, "a delete")?;
                Ok(Converged::AlreadyGone)
            }
            DeletionPolicy::Deactivate => {
                let inactive = serde_json::json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                    "active": false,
                });
                self.update(collection, &id, &inactive).await?;
                Ok(Converged::Updated(id))
            }
        }
    }
}

/// Split a write response into success, retry, or refuse.
fn classify_write(response: &ScimResponse, what: &str) -> Result<(), PushError> {
    if response.status.is_success() {
        return Ok(());
    }
    if response.status.is_server_error() {
        return Err(PushError::Retryable(format!(
            "the downstream answered {} to {what}",
            response.status
        )));
    }
    Err(PushError::Permanent(format!(
        "the downstream answered {} to {what}{}",
        response.status,
        response
            .scim_type()
            .map(|t| format!(" ({t})"))
            .unwrap_or_default()
    )))
}

/// A PATCH document that replaces every attribute the resource carries.
///
/// A PATHLESS `replace` with the whole object, which RFC 7644 section 3.5.2 permits and which
/// every server implementing PATCH accepts. Per-attribute paths would be smaller on the wire and
/// would require this client to know which attributes are multi-valued and which are complex, a
/// judgement the mapping layer already made when it built the resource.
///
/// `schemas` is dropped from the value: it describes the RESOURCE, and a PATCH document declares
/// its own (`...:api:messages:2.0:PatchOp`). Sending the resource's `schemas` as an attribute to
/// replace is a request to overwrite a server-managed field, which servers variously ignore,
/// reject, or obey.
fn patch_document(resource: &Value) -> Value {
    let mut value = resource.clone();
    if let Some(object) = value.as_object_mut() {
        object.remove("schemas");
        object.remove("id");
        object.remove("meta");
    }
    serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{ "op": "replace", "value": value }],
    })
}

/// Escape a literal for a SCIM filter comparison.
///
/// RFC 7644 section 3.4.2.2 writes comparison values as JSON strings, so a value carrying a quote
/// or a backslash has to be escaped or it terminates the literal early. An IronAuth id never
/// contains either, and this exists so that stays a property of the ids rather than a dependency
/// of this function: an `externalId` that came from somewhere else must not be able to rewrite
/// the filter around it.
fn escape_filter_literal(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::{escape_filter_literal, patch_document};

    #[test]
    fn a_patch_document_drops_the_server_owned_fields() {
        let patch = patch_document(&serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "dsid-1",
            "meta": { "resourceType": "User" },
            "userName": "ada",
            "active": true,
        }));
        assert_eq!(
            patch["schemas"],
            serde_json::json!(["urn:ietf:params:scim:api:messages:2.0:PatchOp"])
        );
        let value = &patch["Operations"][0]["value"];
        // The three server-owned fields are gone, and the rest is intact. Asserting only that
        // `id` is absent would pass against a document that dropped everything.
        assert!(value.get("schemas").is_none());
        assert!(value.get("id").is_none());
        assert!(value.get("meta").is_none());
        assert_eq!(value["userName"], serde_json::json!("ada"));
        assert_eq!(value["active"], serde_json::json!(true));
    }

    #[test]
    fn a_filter_literal_cannot_terminate_itself() {
        // A value carrying a quote would otherwise close the literal and leave the rest of the
        // value as filter syntax.
        assert_eq!(escape_filter_literal("u-1"), "u-1");
        assert_eq!(
            escape_filter_literal("a\" or userName eq \"b"),
            "a\\\" or userName eq \\\"b"
        );
        // The backslash is escaped FIRST, so an input ending in one cannot escape the closing
        // quote the caller adds. Doing it the other way round is the classic ordering bug.
        assert_eq!(escape_filter_literal("trail\\"), "trail\\\\");
    }
}
