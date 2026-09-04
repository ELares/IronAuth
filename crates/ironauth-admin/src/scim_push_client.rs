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
    /// Write the resource back with `active: false`, keeping every other attribute.
    ///
    /// The safer default: a DELETE against a downstream directory is not reversible and an
    /// accidental scope change should not be.
    ///
    /// The body is the resource as the downstream currently holds it, not a two-key document.
    /// That is not a detail: `PUT` is a full replace (RFC 7644 section 3.5.1), so a partial body
    /// asks the downstream to erase `userName` and `externalId`, which a strict server refuses
    /// and a lenient one obeys, losing the identifier the next lookup matches on.
    ///
    /// Only meaningful where the schema HAS an `active` attribute. RFC 7643 section 4.2 gives
    /// Group none, so this policy is refused for groups rather than silently doing nothing.
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
        match error {
            // Retryable, including `Blocked`. A blocked destination needs an operator, but the
            // correct mechanical response is still to pause: consuming the event would drop a
            // directory change that nothing will replay once the URL is fixed.
            ScimTransportError::Blocked => {
                Self::Retryable("the destination is refused by the outbound policy".to_owned())
            }
            ScimTransportError::Timeout => Self::Retryable("the downstream timed out".to_owned()),
            ScimTransportError::Transport => {
                Self::Retryable("the downstream could not be reached".to_owned())
            }
            // NOT retryable, and separating it is the point of the variant. A base URL with a
            // query in it, or a credential that is not a legal header value, produces the same
            // failure on every attempt: retrying is a busy loop, and reporting it as a transport
            // failure makes a connection with a typo look exactly like a downstream outage. The
            // operator has to edit the connection, so the error has to say that.
            ScimTransportError::Configuration => Self::Permanent(
                "this connection cannot produce a request: check its base URL and the credential \
                 the secret holds"
                    .to_owned(),
            ),
        }
    }
}

/// A SCIM client pointed at one connection's downstream.
#[derive(Clone)]
pub struct ScimPushClient<T> {
    transport: T,
    base_url: String,
    bearer: String,
    write_mode: WriteMode,
}

/// Everything except the credential.
///
/// The derived `Debug` printed `bearer` in full, so one `tracing::debug!(?client, ...)` or one
/// `.expect()` on a `Result` holding a client wrote a downstream's bearer token into a log. The
/// token is the whole authority over somebody else's directory, and a log is the place a secret
/// is least likely to be noticed and most likely to be copied.
impl<T> std::fmt::Debug for ScimPushClient<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScimPushClient")
            .field("base_url", &self.base_url)
            .field("write_mode", &self.write_mode)
            .field("bearer", &"<redacted>")
            .finish_non_exhaustive()
    }
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
    /// An empty (or absent) `Resources` array is a miss, and it is the ONLY thing consulted:
    /// `totalResults` is not read at all. The two can disagree, and when they do the array is
    /// the one that can be indexed, so trusting the count is how a client panics or fabricates a
    /// match. An earlier version of this comment claimed both were read, which was never true.
    ///
    /// A resource that comes back carrying a DIFFERENT `externalId` is also not a match, and is
    /// refused permanently rather than used: see the body of this function for why a downstream
    /// that does not apply the filter cannot be allowed to choose the subject.
    ///
    /// A 400 `invalidFilter` is NOT a miss and must not be read as one: it means this downstream
    /// does not support the lookup, and treating it as "no match" would create a duplicate on
    /// every replay. It is permanent, and an operator needs to see it.
    async fn find_by_external_id(
        &self,
        collection: &str,
        external_id: &str,
    ) -> Result<Option<(String, Value)>, PushError> {
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
        let Some(found) = first else {
            return Ok(None);
        };
        // THE RESOURCE MUST CARRY THE externalId THAT WAS ASKED FOR.
        //
        // Taking `Resources[0]` on trust makes the client's correctness depend on the DOWNSTREAM
        // honouring a filter, and RFC 7644 section 3.4.2.2 support is patchy in the field: a
        // server that ignores an unsupported filter and returns its whole collection answers 200
        // with a perfectly well formed body. The client then believes an unrelated person is the
        // subject it is provisioning, and every later write addresses THEM: `converge` updates a
        // stranger's record with this subject's attributes, and `deprovision` deletes them.
        //
        // A filter this server did not apply is indistinguishable from one it did, EXCEPT by
        // reading the answer, so the answer is read.
        let carried = found.get("externalId").and_then(Value::as_str);
        if carried != Some(external_id) {
            return Err(PushError::Permanent(format!(
                "the downstream answered a lookup for externalId {external_id:?} with a resource \
                 carrying {carried:?}, so it is not applying the filter and its answers cannot be \
                 trusted to identify a subject"
            )));
        }
        let Some(id) = found.get("id").and_then(Value::as_str) else {
            return Err(PushError::Permanent(
                "the downstream answered a lookup with a resource that has no id".to_owned(),
            ));
        };
        Ok(Some((id.to_owned(), found.clone())))
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
        if let Some((id, current)) = self.find_by_external_id(collection, external_id).await? {
            self.update(collection, &id, resource, Some(&current))
                .await?;
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
            let Some((id, current)) = self.find_by_external_id(collection, external_id).await?
            else {
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
            self.update(collection, &id, resource, Some(&current))
                .await?;
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
    async fn update(
        &self,
        collection: &str,
        id: &str,
        resource: &Value,
        current: Option<&Value>,
    ) -> Result<(), PushError> {
        let path = format!("{collection}/{}", encode_path_segment(id));
        if self.write_mode == WriteMode::Patch {
            let document = patch_document(resource, current);
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
        known_downstream_id: Option<&str>,
    ) -> Result<Converged, PushError> {
        // WHICH RESOURCE, and how confident we are that it is absent, depend on whether the
        // caller already knows what the downstream called this subject.
        //
        // WITH a known id the lookup is skipped entirely. That is what makes the operation
        // correct under replica lag: a `GET`/`DELETE` addressed to a server-issued id is answered
        // by the server about that resource, while a FILTER is answered by whatever view the
        // downstream serves reads from, and a lagging replica answers "no such person" about
        // somebody it holds. The first version read that miss as success, so a terminated
        // employee stayed fully active downstream and the operator was told the offboarding had
        // happened. It is the worst failure this client can have, and addressing by id removes
        // the question rather than guessing at the answer.
        //
        // WITHOUT a known id, a miss really is absence in the only sense available: this
        // connection has no record of ever provisioning the subject, so there is nothing it can
        // be asked to remove. That keeps a replayed deprovision terminating instead of retrying
        // for ever.
        let found = match known_downstream_id {
            Some(id) => Some(id.to_owned()),
            None => self
                .find_by_external_id(collection, external_id)
                .await?
                .map(|(id, _)| id),
        };
        let Some(id) = found else {
            return Ok(Converged::AlreadyGone);
        };
        let path = format!("{collection}/{}", encode_path_segment(&id));
        match policy {
            DeletionPolicy::Delete => {
                let response = self.send(ScimRequest::delete(path)).await?;
                if response.status == http::StatusCode::NOT_FOUND {
                    // A 404 from the DELETE ITSELF is the evidence a query cannot give: the
                    // server is answering about a resource addressed by its own id. This is also
                    // what makes a REPLAYED deprovision terminate.
                    return Ok(Converged::AlreadyGone);
                }
                classify_write(&response, "a delete")?;
                Ok(Converged::AlreadyGone)
            }
            DeletionPolicy::Deactivate => {
                // THE DEACTIVATION IS THE WHOLE RESOURCE, not `{"active": false}`.
                //
                // The first version sent two keys and a hardcoded core User schema URN, and
                // `update` PUTs what it is given whenever the connection is `WriteMode::Put` or
                // the downstream refuses PATCH. RFC 7644 section 3.5.1 makes PUT a FULL REPLACE,
                // so that body asked the downstream to replace the person with a record having no
                // `userName` and no `externalId`. A strict server refuses it 400, so a
                // PATCH-incapable downstream could never deprovision at all, which is criterion 5
                // inverted; a lenient one accepts it, the resource loses the `externalId` the
                // next lookup matches on, and the following converge creates a SECOND record for
                // the same person.
                //
                // So the body starts from what the downstream currently holds: a complete
                // representation, whose `schemas` come from the resource rather than from a
                // literal that is only ever right for one collection.
                let read = self.send(ScimRequest::get(path)).await?;
                classify_write(&read, "a read before deactivating")?;
                let Some(current) = read.body else {
                    return Err(PushError::Permanent(
                        "the downstream answered a read with no body, so there is no \
                         representation to deactivate"
                            .to_owned(),
                    ));
                };
                let mut inactive = current.clone();
                let Some(object) = inactive.as_object_mut() else {
                    return Err(PushError::Permanent(
                        "the downstream answered a read with something that is not a resource"
                            .to_owned(),
                    ));
                };
                // RFC 7643 section 4.2 gives Group no `active` attribute, so there is no such
                // thing as an inactive group. The first version wrote one anyway: the downstream
                // stored an attribute outside the schema, kept every member, and answered 200, so
                // the group was reported deprovisioned and nothing had changed. A refusal an
                // operator can see beats a success that is not true.
                if !object.contains_key("active") && !collection.ends_with("Users") {
                    return Err(PushError::Permanent(format!(
                        "{collection} has no `active` attribute, so the deactivate policy cannot \
                         express a departure for it and this connection needs the delete policy"
                    )));
                }
                object.insert("active".to_owned(), Value::Bool(false));
                self.update(collection, &id, &inactive, Some(&current))
                    .await?;
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
    // 429 IS NOT A PERMANENT REFUSAL, and classifying it as one is how a busy downstream turns
    // into a dead letter. Every large SCIM provider throttles: Okta publishes per-org rate
    // limits and answers 429 with `Retry-After` when a bulk provision exceeds them. A backfill
    // of a large org is exactly the workload that meets them, so a permanent verdict here drops
    // the tail of the org on the floor and reports it as a refusal the operator must fix.
    if response.status == http::StatusCode::TOO_MANY_REQUESTS {
        return Err(PushError::Retryable(format!(
            "the downstream throttled {what}",
        )));
    }
    // A RESOURCE THAT VANISHED BETWEEN THE LOOKUP AND THE WRITE is a race, not a refusal. It
    // happens when somebody deletes downstream while a sync is in flight, and the answer is to
    // run the convergence again: the next pass misses on lookup and creates the resource. Called
    // permanent, the subject stays unprovisioned until a human notices.
    if response.status == http::StatusCode::NOT_FOUND {
        return Err(PushError::Retryable(format!(
            "the downstream answered 404 to {what}, so the resource was removed between the \
             lookup and the write and the next pass must create it again"
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
/// The `PatchOp` that converges a resource to `resource`, given what the downstream `current`ly
/// holds.
///
/// # Why the current representation is an argument
///
/// A pathless `replace` MERGES: RFC 7644 section 3.5.2.1 applies the object's members and leaves
/// every other attribute alone. `PUT` REPLACES: section 3.5.1 makes the request body the whole
/// resource, so an attribute the client stops sending is gone. Those are different end states
/// from the same desired document, and a connection's `write_mode` is an operator setting, so
/// the same directory pushed through two connections diverged: a user who dropped their
/// `nickName` kept it forever on the PATCH connection and lost it on the PUT one.
///
/// So the removals are made explicit. Every attribute the downstream holds that the desired
/// document does not carry gets its own `remove`, which is what makes PATCH reach the state PUT
/// reaches. Without `current` the client cannot know what to remove, and this returns the merge
/// it always did rather than guessing.
fn patch_document(resource: &Value, current: Option<&Value>) -> Value {
    let mut value = resource.clone();
    if let Some(object) = value.as_object_mut() {
        object.remove("schemas");
        object.remove("id");
        object.remove("meta");
    }
    let mut operations = vec![serde_json::json!({ "op": "replace", "value": value.clone() })];
    if let (Some(current), Some(desired)) = (current.and_then(Value::as_object), value.as_object())
    {
        let mut dropped: Vec<&String> = current
            .keys()
            // The server owns these three, so their absence from a desired document says nothing
            // about what the client wants and a `remove` for them is refused (`mutability`).
            .filter(|key| !matches!(key.as_str(), "id" | "meta" | "schemas"))
            .filter(|key| !desired.contains_key(key.as_str()))
            .collect();
        // Sorted so the request is the same on every run: an unordered map would make the wire
        // bytes vary between two converges that mean the same thing, which makes a recorded
        // request impossible to assert on and a downstream's audit log impossible to read.
        dropped.sort();
        for key in dropped {
            operations.push(serde_json::json!({ "op": "remove", "path": key }));
        }
    }
    serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": operations,
    })
}

/// Percent-encodes one path segment, so a downstream-issued id cannot restructure the URL.
///
/// RFC 7643 section 3.1 makes `id` opaque and SERVER issued, which means its bytes are chosen by
/// the downstream and not by IronAuth. Splicing it into a path raw lets an id containing `../`
/// address a different collection, one containing `?` turn the rest of the path into a query, and
/// one containing `#` truncate the request. A hostile or merely careless downstream therefore
/// chose which resource the next DELETE hit.
fn encode_path_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        match byte {
            // RFC 3986 section 2.3 unreserved, plus the sub-delims that are safe in a segment.
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(byte));
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
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
        let patch = patch_document(
            &serde_json::json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": "dsid-1",
            "meta": { "resourceType": "User" },
            "userName": "ada",
                "active": true,
            }),
            None,
        );
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
