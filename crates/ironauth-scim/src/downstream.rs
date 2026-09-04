// SPDX-License-Identifier: MIT OR Apache-2.0

//! A reference downstream SCIM server, for testing IronAuth as a SCIM CLIENT (issue #137).
//!
//! # Why this exists as its own implementation
//!
//! Issue #137's verification asks for "integration tests against an in-repo reference SCIM
//! server fixture". The temptation is to write a mock that answers whatever the outbound client
//! happens to send. That fixture proves nothing: the client and the mock come out of one head at
//! one sitting, so they agree by construction, and the first real downstream disagrees with both.
//!
//! This module is therefore written FIRST, from RFC 7644 and RFC 7643, BEFORE the outbound
//! client exists, and deliberately without consulting it. Where the RFC lets a server choose,
//! this one chooses the option that is HARDER for a client: it allocates its own `id` rather
//! than honouring a client-supplied one, it rejects a duplicate `externalId` with 409 rather
//! than silently upserting, and it can be switched to refuse PATCH the way a real
//! PATCH-incapable server does. A client that converges against this one has been made to do
//! the work the protocol actually requires.
//!
//! # What a green run against this fixture means, and what it does not
//!
//! It means the client speaks RFC-shaped SCIM and converges against a server that follows the
//! parts of the RFC implemented here. It does NOT mean it interoperates with Okta, Entra, or
//! any particular product, all of which have documented deviations. That gap is real and is the
//! same one `tests/fixtures/PROVENANCE.md` records for the inbound direction.
//!
//! # What is deliberately NOT implemented
//!
//! The filter surface is the narrow one RFC 7644 section 3.4.2 describes for a provisioning
//! client looking a resource up before creating it: `attr eq "literal"` on exactly the three
//! attributes below, and nothing else. A general filter engine is not needed to prove
//! idempotency and would only duplicate the inbound crate's parser. An unsupported filter is a
//! 400 with `scimType: invalidFilter`, which is what the RFC says and what a client must handle
//! anyway. Sorting, pagination, `attributes` projection and `/Me` are all absent for the same
//! reason: no criterion in #137 drives them.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::{Value, json};

use crate::schema::{GROUP_SCHEMA, USER_SCHEMA};

/// RFC 7644 section 3.5.2 gives the patch request its own schema URN.
///
/// `users.rs` and `groups.rs` each declare this privately for the INBOUND side; this is the
/// outbound reference server, and it is deliberately not sharing their constant. A fixture that
/// imported the implementation's idea of the URN would agree with the implementation by
/// construction, which is the failure mode this whole file exists to avoid.
const PATCH_OP_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

/// Whether this downstream honours `PATCH`, and how it refuses when it does not.
///
/// RFC 7644 section 3.5.2 makes PATCH OPTIONAL, and `ServiceProviderConfig` advertises whether a
/// server has it. Real servers that lack it answer 501, so a client that only ever meets a
/// PATCH-capable server never exercises its fallback. That is the whole point of this switch:
/// #137's criterion 5 is that "PATCH-incapable downstream servers converge via the PUT
/// fallback", and it cannot be tested without a downstream that genuinely refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchSupport {
    /// PATCH is honoured, and `ServiceProviderConfig` advertises it.
    Supported,
    /// PATCH is refused with 501, and `ServiceProviderConfig` advertises its absence.
    ///
    /// BOTH halves matter. A server that advertised support and then answered 501 would be
    /// testing a different thing (a lying downstream) than one that never claimed it.
    Unsupported,
}

/// What the downstream does with the next request, so a test can stage an outage.
///
/// #137's criterion 3 is that killing the downstream mid-sync and restoring it later converges
/// with no duplicates. "Killing" has to be expressible without tearing down the process, or the
/// test cannot assert on the state that survived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// Requests are served.
    Up,
    /// Every request this server ROUTES is answered 503, as a downstream behind a failing load
    /// balancer would be. The qualifier is load-bearing: a request to a path outside the SCIM
    /// routes never reaches a handler, so axum answers 404 and the switch does not see it. The
    /// switch does now cover a body this server cannot parse, which the first version left to an
    /// extractor running before the handler.
    ///
    /// The stored resources are UNTOUCHED, which is what makes the recovery assertion meaningful:
    /// a client replaying from its cursor must find its earlier writes still there and not
    /// duplicate them.
    Down,
}

/// One request this downstream received, in arrival order.
///
/// Recorded so a test can assert on what the client actually SENT, not merely on the state it
/// left behind. The two differ in exactly the case #137 cares about: a client that re-creates a
/// resource it should have looked up first reaches the same end state through more requests.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    /// The HTTP method, upper-case.
    pub method: String,
    /// The path, without the query string.
    pub path: String,
    /// The DECODED `filter` parameter of a collection query, empty on every other request.
    ///
    /// Named and documented for what it holds. It was called the raw query string, which it
    /// never was: only the two collection routes record anything, they record the decoded value
    /// of one parameter, and the other eleven routes pass an empty string whatever arrived. An
    /// assertion about an item request's query could not fail, and one about percent-encoding
    /// was reading a string the client never put on the wire.
    pub filter: String,
    /// The parsed request body, when there was one.
    pub body: Option<Value>,
}

#[derive(Debug)]
struct Inner {
    bearer: String,
    patch: PatchSupport,
    health: Health,
    stale_reads: bool,
    users: BTreeMap<String, Value>,
    groups: BTreeMap<String, Value>,
    next_id: u64,
    log: Vec<RecordedRequest>,
}

/// A running reference downstream, as an axum [`Router`] plus a handle onto its state.
#[derive(Debug, Clone)]
pub struct Downstream {
    inner: Arc<Mutex<Inner>>,
}

impl Downstream {
    /// A downstream that honours PATCH and accepts exactly this bearer token.
    #[must_use]
    pub fn new(bearer: &str) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                bearer: bearer.to_owned(),
                patch: PatchSupport::Supported,
                health: Health::Up,
                stale_reads: false,
                users: BTreeMap::new(),
                groups: BTreeMap::new(),
                next_id: 1,
                log: Vec::new(),
            })),
        }
    }

    /// The same, but refusing PATCH the way a PATCH-incapable server does.
    ///
    /// # Panics
    ///
    /// If a previous holder of the state lock panicked. A poisoned fixture cannot answer
    /// meaningfully, and a test that reached one has already failed for a better reason.
    #[must_use]
    pub fn without_patch(bearer: &str) -> Self {
        let this = Self::new(bearer);
        this.inner
            .lock()
            .expect("downstream state is not poisoned")
            .patch = PatchSupport::Unsupported;
        this
    }

    /// Answer every FILTERED QUERY as if it matched nothing, while writes keep working.
    ///
    /// # Why a downstream would do this, and why the client must survive it
    ///
    /// A downstream serving reads from a replica has read-after-write lag: a resource that was
    /// just created is not yet visible to a query. A provisioning client that looks up before
    /// creating then misses, POSTs, and meets the uniqueness constraint on a resource it created
    /// itself moments ago.
    ///
    /// That 409 is not a failure and it is the WHOLE REASON the recovery path exists, so it has
    /// to be reachable in a test. Without this switch a client could delete its 409 handling
    /// entirely and every test would still pass, because a fixture with a perfect read view
    /// never issues one.
    ///
    /// Reads only. A version that also failed writes would be an outage, which `Health` already
    /// models and which is a different thing.
    ///
    /// # Panics
    ///
    /// If a previous holder of the state lock panicked. A poisoned fixture cannot answer
    /// meaningfully, and a test that reached one has already failed for a better reason.
    pub fn set_stale_reads(&self, stale: bool) {
        self.inner
            .lock()
            .expect("downstream state is not poisoned")
            .stale_reads = stale;
    }

    /// Take the downstream down, or bring it back up.
    ///
    /// # Panics
    ///
    /// If a previous holder of the state lock panicked. A poisoned fixture cannot answer
    /// meaningfully, and a test that reached one has already failed for a better reason.
    pub fn set_health(&self, health: Health) {
        self.inner
            .lock()
            .expect("downstream state is not poisoned")
            .health = health;
    }

    /// Every request received so far, in arrival order.
    ///
    /// # Panics
    ///
    /// If a previous holder of the state lock panicked. A poisoned fixture cannot answer
    /// meaningfully, and a test that reached one has already failed for a better reason.
    #[must_use]
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.inner
            .lock()
            .expect("downstream state is not poisoned")
            .log
            .clone()
    }

    /// How many requests of this method reached this path prefix.
    ///
    /// The counter a duplicate-prevention assertion reads: a client that looks up before creating
    /// issues one POST per resource however many times it replays.
    ///
    /// # Panics
    ///
    /// If a previous holder of the state lock panicked. A poisoned fixture cannot answer
    /// meaningfully, and a test that reached one has already failed for a better reason.
    #[must_use]
    pub fn count(&self, method: &str, path_prefix: &str) -> usize {
        self.requests()
            .iter()
            .filter(|r| r.method == method && r.path.starts_with(path_prefix))
            .count()
    }

    /// Every user resource currently stored, by downstream id.
    ///
    /// # Panics
    ///
    /// If a previous holder of the state lock panicked. A poisoned fixture cannot answer
    /// meaningfully, and a test that reached one has already failed for a better reason.
    #[must_use]
    pub fn users(&self) -> BTreeMap<String, Value> {
        self.inner
            .lock()
            .expect("downstream state is not poisoned")
            .users
            .clone()
    }

    /// Every group resource currently stored, by downstream id.
    ///
    /// # Panics
    ///
    /// If a previous holder of the state lock panicked. A poisoned fixture cannot answer
    /// meaningfully, and a test that reached one has already failed for a better reason.
    #[must_use]
    pub fn groups(&self) -> BTreeMap<String, Value> {
        self.inner
            .lock()
            .expect("downstream state is not poisoned")
            .groups
            .clone()
    }

    /// The axum router serving this downstream.
    pub fn router(&self) -> Router {
        Router::new()
            .route(
                "/scim/v2/ServiceProviderConfig",
                get(service_provider_config),
            )
            .route("/scim/v2/Users", get(list_users).post(create_user))
            .route(
                "/scim/v2/Users/{id}",
                get(get_user)
                    .put(put_user)
                    .patch(patch_user)
                    .delete(delete_user),
            )
            .route("/scim/v2/Groups", get(list_groups).post(create_group))
            .route(
                "/scim/v2/Groups/{id}",
                get(get_group)
                    .put(put_group)
                    .patch(patch_group)
                    .delete(delete_group),
            )
            .with_state(self.clone())
    }
}

/// A SCIM error document (RFC 7644 section 3.12).
/// Answer with the SCIM media type RFC 7644 section 3.1 defines.
///
/// `axum::Json` sends `application/json`, so every response this fixture produced carried the
/// wrong type: a client that content-negotiates, or that asserts on what it received, was being
/// measured against a downstream that never sends what a real one does.
fn scim_json(status: StatusCode, body: &Value) -> Response {
    let mut response = (status, axum::Json(body.clone())).into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/scim+json"),
    );
    response
}

fn scim_error(status: StatusCode, scim_type: Option<&str>, detail: &str) -> Response {
    let mut body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "status": status.as_u16().to_string(),
        "detail": detail,
    });
    if let Some(t) = scim_type {
        body["scimType"] = json!(t);
    }
    scim_json(status, &body)
}

/// The bearer check and the outage switch, in the one place every route goes through.
///
/// Returns the refusal to send, or `None` to proceed. Deliberately ONE function rather than a
/// check per handler: a downstream with one unauthenticated route would silently weaken every
/// test that believes the client is authenticating.
fn gate(state: &Downstream, headers: &HeaderMap) -> Option<Response> {
    let inner = state
        .inner
        .lock()
        .expect("downstream state is not poisoned");
    if inner.health == Health::Down {
        return Some(scim_error(
            StatusCode::SERVICE_UNAVAILABLE,
            None,
            "the downstream is unavailable",
        ));
    }
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if presented != Some(inner.bearer.as_str()) {
        return Some(scim_error(
            StatusCode::UNAUTHORIZED,
            None,
            "a valid bearer token is required",
        ));
    }
    None
}

/// Reads a request body the way a SCIM server does, INSIDE the handler.
///
/// The first version took `axum::Json<Value>`, and an extractor runs BEFORE the handler: a body
/// axum could not decode was refused by axum, so the outage switch never ran, `record` never ran,
/// and the caller got axum's plain error instead of a SCIM error document. That is the wrong
/// behaviour in all three directions at once. A client retrying into a simulated outage saw 400
/// rather than 503 and stopped retrying; the request log -- the thing the outage tests read to
/// prove what the client did -- held nothing; and a client parsing the error document as SCIM
/// found no `scimType` to branch on.
///
/// Taking the raw bytes puts the decision back in the handler, which is why every refusal below
/// is a SCIM error document and why `record` sees the request first.
fn read_body(headers: &HeaderMap, body: &axum::body::Bytes) -> Result<Value, Box<Response>> {
    // RFC 7644 section 3.1: a SCIM client sends `application/scim+json`. Servers in the field
    // also take `application/json`, and the suffix form covers both without hard-coding a list.
    let Some(declared) = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    else {
        return Err(Box::new(scim_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            None,
            "a SCIM request body must declare application/scim+json",
        )));
    };
    let base = declared
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if base != "application/json" && !(base.starts_with("application/") && base.ends_with("+json"))
    {
        return Err(Box::new(scim_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            None,
            "a SCIM request body must declare application/scim+json",
        )));
    }
    serde_json::from_slice(body).map_err(|_| {
        Box::new(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidSyntax"),
            "the request body is not well formed JSON",
        ))
    })
}

fn record(state: &Downstream, method: &str, path: &str, filter: &str, body: Option<&Value>) {
    state
        .inner
        .lock()
        .expect("downstream state is not poisoned")
        .log
        .push(RecordedRequest {
            method: method.to_owned(),
            path: path.to_owned(),
            filter: filter.to_owned(),
            body: body.cloned(),
        });
}

/// `attr eq "literal"`, and nothing else. See the module header on why the surface is this narrow.
///
/// Returns the attribute and the literal. The attribute is lower-cased because RFC 7643 section
/// 2.1 makes attribute names case-insensitive, and a client that sends `externalID` is within
/// its rights.
fn parse_eq_filter(filter: &str) -> Option<(String, String)> {
    let trimmed = filter.trim();
    let (attr, rest) = trimmed.split_once(char::is_whitespace)?;
    let rest = rest.trim_start();
    // CASE INSENSITIVE, which RFC 7644 section 3.4.2.2 states outright and whose own worked
    // example is `userName Eq "john"`. The first version tested two literal spellings, `eq` and
    // `EQ`, so the RFC's own example was refused with `invalidFilter` and the debugging would
    // have gone into the client rather than here.
    let (token, rest) = match rest.find(char::is_whitespace) {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    if !token.eq_ignore_ascii_case("eq") {
        return None;
    }
    let literal = rest.trim();
    let literal = literal.strip_prefix('"')?.strip_suffix('"')?;
    if literal.contains('"') {
        return None;
    }
    Some((attr.to_ascii_lowercase(), literal.to_owned()))
}

/// The three attributes a provisioning client looks a resource up by.
fn filterable(attr: &str) -> Option<&'static str> {
    match attr {
        "externalid" => Some("externalId"),
        "username" => Some("userName"),
        "displayname" => Some("displayName"),
        _ => None,
    }
}

fn list_response(matches: &[Value]) -> Response {
    let total = matches.len();
    scim_json(
        StatusCode::OK,
        &json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": total,
            "itemsPerPage": total,
            "startIndex": 1,
            "Resources": matches,
        }),
    )
}

fn meta(resource_type: &str, id: &str) -> Value {
    json!({
        "resourceType": resource_type,
        "location": format!("/scim/v2/{resource_type}s/{id}"),
    })
}

/// `GET /ServiceProviderConfig` (RFC 7644 section 4).
///
/// Advertises PATCH support truthfully, so a client that reads the document before choosing
/// between PATCH and PUT is reading something that matches what the routes do.
async fn service_provider_config(State(state): State<Downstream>, headers: HeaderMap) -> Response {
    record(&state, "GET", "/scim/v2/ServiceProviderConfig", "", None);
    if let Some(refusal) = gate(&state, &headers) {
        return refusal;
    }
    let supported = state
        .inner
        .lock()
        .expect("downstream state is not poisoned")
        .patch
        == PatchSupport::Supported;
    scim_json(
        StatusCode::OK,
        &json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": { "supported": supported },
            "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
            // NO `maxResults`, which RFC 7643 section 5 makes optional. One was advertised and
            // nothing applied it: `list_in` caps nothing and `list_response` reports `startIndex: 1`
            // and the full count, so a client that paged BECAUSE a limit was advertised had its
            // paging silently ignored. Pagination is a stated non-goal of this fixture, and the
            // honest way to state it is to not claim a limit.
            "filter": { "supported": true },
            "changePassword": { "supported": false },
            "sort": { "supported": false },
            "etag": { "supported": false },
            "authenticationSchemes": [{
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "Authentication scheme using the OAuth Bearer Token Standard",
            }],
        }),
    )
}

/// Shared by both collections: the create half of RFC 7644 section 3.3.
///
/// The uniqueness refusal is the reason this fixture is worth having. A downstream that quietly
/// accepted a second resource with the same `externalId` would let a client that never looks up
/// before creating pass criterion 3, and then duplicate every user against a real server that
/// does enforce it.
/// The SHAPE every write must satisfy: a JSON object, declaring its schema, carrying its
/// required attribute.
///
/// Extracted from `create_in` because RFC 7644 section 3.5.1 makes PUT a FULL REPLACE, and a
/// real server validates a replace exactly as it validates a create. The first version checked
/// only that the id existed, so a client whose PUT fallback was built from its PATCH builder
/// sent `{"active": false}`, got 200, and had its `schemas`, `userName` and `externalId`
/// silently dropped. That client 400s against every conformant downstream, so the fixture was
/// certifying the exact defect criterion 5 exists to catch.
///
/// The OBJECT check leads, and it is not decoration: `body["id"] = ...` on a JSON array panics,
/// and the panic happens while the state lock is held, which poisons the fixture for every
/// remaining test in the file.
fn check_shape(body: &Value, required: &str, schema: &str) -> Option<Response> {
    if !body.is_object() {
        return Some(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "a resource must be a JSON object",
        ));
    }
    if !body
        .get("schemas")
        .and_then(Value::as_array)
        .is_some_and(|s| s.iter().any(|v| v.as_str() == Some(schema)))
    {
        return Some(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            &format!("the resource must declare the {schema} schema"),
        ));
    }
    if body.get(required).and_then(Value::as_str).is_none() {
        return Some(scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            &format!("{required} is required"),
        ));
    }
    None
}

/// Whether some OTHER stored resource already holds this body's unique values.
///
/// `exclude` is the id being written, so a replace that keeps its own `userName` does not clash
/// with itself. The first version enforced uniqueness on POST alone, so a replaying client with
/// a crossed mapping could PUT one subject's body over another and leave two resources sharing
/// an `externalId` -- exactly the state criterion 3 exists to prove impossible, reachable by a
/// different verb.
fn clashes(
    store: &BTreeMap<String, Value>,
    required: &str,
    body: &Value,
    exclude: Option<&str>,
) -> bool {
    let required_value = body.get(required).and_then(Value::as_str);
    let external = body.get("externalId").and_then(Value::as_str);
    store.iter().any(|(id, existing)| {
        if Some(id.as_str()) == exclude {
            return false;
        }
        (required_value.is_some()
            && existing.get(required).and_then(Value::as_str) == required_value)
            || (external.is_some()
                && existing.get("externalId").and_then(Value::as_str) == external)
    })
}

fn create_in(
    state: &Downstream,
    collection: &str,
    required: &str,
    schema: &str,
    mut body: Value,
) -> Response {
    if let Some(refusal) = check_shape(&body, required, schema) {
        return refusal;
    }

    let mut inner = state
        .inner
        .lock()
        .expect("downstream state is not poisoned");
    let store = if collection == "Users" {
        &inner.users
    } else {
        &inner.groups
    };
    if clashes(store, required, &body, None) {
        return scim_error(
            StatusCode::CONFLICT,
            Some("uniqueness"),
            "a resource with this identifier already exists",
        );
    }

    // The downstream allocates the id. RFC 7643 section 3.1 makes `id` server-issued and says a
    // client MUST NOT supply one, so anything the client sent under that key is DISCARDED rather
    // than honoured. A fixture that echoed it back would hide a client that invented ids.
    let id = format!("dsid-{}", inner.next_id);
    inner.next_id += 1;
    let resource_type = collection.trim_end_matches('s');
    body["id"] = json!(id);
    body["meta"] = meta(resource_type, &id);
    if collection == "Users" {
        inner.users.insert(id.clone(), body.clone());
    } else {
        inner.groups.insert(id.clone(), body.clone());
    }
    drop(inner);

    let mut response = scim_json(StatusCode::CREATED, &body);
    if let Ok(location) = format!("/scim/v2/{collection}/{id}").parse() {
        response
            .headers_mut()
            .insert(axum::http::header::LOCATION, location);
    }
    response
}

/// Shared by both collections: the filtered query of RFC 7644 section 3.4.2.
fn list_in(state: &Downstream, collection: &str, filter: Option<&str>) -> Response {
    let inner = state
        .inner
        .lock()
        .expect("downstream state is not poisoned");
    let store = if collection == "Users" {
        &inner.users
    } else {
        &inner.groups
    };
    let Some(filter) = filter else {
        return list_response(&store.values().cloned().collect::<Vec<_>>());
    };
    if inner.stale_reads {
        // The replica has not caught up. A valid, well-formed empty result, which is exactly
        // what makes it dangerous: it is indistinguishable from a genuine miss.
        return list_response(&[]);
    }
    let Some((attr, literal)) = parse_eq_filter(filter) else {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidFilter"),
            "only attr eq with a quoted literal is supported",
        );
    };
    let Some(canonical) = filterable(&attr) else {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidFilter"),
            "that attribute is not filterable on this server",
        );
    };
    let matches: Vec<Value> = store
        .values()
        .filter(|r| r.get(canonical).and_then(Value::as_str) == Some(literal.as_str()))
        .cloned()
        .collect();
    list_response(&matches)
}

/// Shared by both collections: the full replace of RFC 7644 section 3.5.1.
fn put_in(
    state: &Downstream,
    collection: &str,
    required: &str,
    schema: &str,
    id: &str,
    mut body: Value,
) -> Response {
    // A REPLACE IS VALIDATED LIKE A CREATE, because that is what a replace is. The first version
    // checked only that the id existed; see `check_shape` and `clashes` for the two defects that
    // let through, and why a fixture certifying them is worse than not having one.
    if let Some(refusal) = check_shape(&body, required, schema) {
        return refusal;
    }
    let mut inner = state
        .inner
        .lock()
        .expect("downstream state is not poisoned");
    let store = if collection == "Users" {
        &mut inner.users
    } else {
        &mut inner.groups
    };
    if !store.contains_key(id) {
        return scim_error(StatusCode::NOT_FOUND, None, "no such resource");
    }
    // EXCLUDING ITSELF: a replace that keeps its own userName is not a duplicate of itself.
    if clashes(store, required, &body, Some(id)) {
        return scim_error(
            StatusCode::CONFLICT,
            Some("uniqueness"),
            "another resource already holds this identifier",
        );
    }
    // `id` and `meta` are server-owned and survive a replace: RFC 7644 section 3.5.1 says the
    // server preserves immutable and read-only attributes whatever the client sent.
    body["id"] = json!(id);
    body["meta"] = meta(collection.trim_end_matches('s'), id);
    store.insert(id.to_owned(), body.clone());
    scim_json(StatusCode::OK, &body)
}

/// Shared by both collections: the partial modify of RFC 7644 section 3.5.2.
/// Applies one PATCH operation to a DRAFT, answering with the refusal if it cannot.
///
/// Split out of `patch_in` because that function outgrew the house line limit once the envelope
/// and atomicity checks arrived. The split is not cosmetic: taking `draft` rather than the stored
/// resource is what makes the caller's atomicity possible, and a helper that could only be handed
/// a draft is harder to misuse than a loop body that had the live store in scope.
fn apply_operation(draft: &mut Value, operation: &Value) -> Option<Response> {
    let op = operation
        .get("op")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let path = operation.get("path").and_then(Value::as_str);
    let value = operation.get("value");
    // SERVER-OWNED ATTRIBUTES ARE NOT PATCHABLE. `put_in` is careful to preserve `id` and
    // `meta` whatever the client sent, and PATCH assigned straight into the resource, so the
    // headline guarantee this fixture exists to enforce -- the SERVER allocates the id --
    // was bypassable by one operation. `schemas` goes with them: it describes the resource,
    // and servers variously ignore, reject or obey a request to overwrite it.
    if let Some(p) = path {
        if matches!(p, "id" | "meta" | "schemas") {
            return Some(scim_error(
                StatusCode::BAD_REQUEST,
                Some("mutability"),
                "id, meta and schemas are server owned and cannot be patched",
            ));
        }
        // ONE ATTRIBUTE, not a path expression. RFC 7644 section 3.5.2 paths can name a
        // sub-attribute (`name.givenName`) or carry a value filter
        // (`members[value eq "x"]`), and this server implements neither. Assigning the whole
        // string as a JSON key, which the first version did, does not refuse them: it
        // silently writes an attribute literally called `name.givenName`, and a client
        // relying on either would pass here and fail against a real downstream.
        if p.contains('.') || p.contains('[') {
            return Some(scim_error(
                StatusCode::BAD_REQUEST,
                Some("invalidPath"),
                "this server supports only a simple attribute path",
            ));
        }
    }
    match (op.as_str(), path) {
        // A pathless replace merges an object of attributes, which is how a provisioning
        // client sends a multi-attribute update.
        ("replace" | "add", None) => {
            let Some(object) = value.and_then(Value::as_object) else {
                return Some(scim_error(
                    StatusCode::BAD_REQUEST,
                    Some("invalidValue"),
                    "a pathless operation needs an object value",
                ));
            };
            if object
                .keys()
                .any(|k| matches!(k.as_str(), "id" | "meta" | "schemas"))
            {
                return Some(scim_error(
                    StatusCode::BAD_REQUEST,
                    Some("mutability"),
                    "id, meta and schemas are server owned and cannot be patched",
                ));
            }
            for (k, v) in object {
                draft[k.as_str()] = v.clone();
            }
        }
        ("replace", Some(p)) => {
            let Some(v) = value else {
                return Some(scim_error(
                    StatusCode::BAD_REQUEST,
                    Some("invalidValue"),
                    "this operation needs a value",
                ));
            };
            draft[p] = v.clone();
        }
        // ADD APPENDS TO A MULTI-VALUED ATTRIBUTE, which is what RFC 7644 section 3.5.2.1
        // says and what `members` needs. The first version collapsed `add` into `replace`,
        // so a client sending only the NEW member silently deleted the existing ones here
        // and a client sending the WHOLE list passed here and duplicated every member
        // against a conformant server. Group membership is a first-class outbound flow in
        // issue #137, so this is the operation that mattered most.
        ("add", Some(p)) => {
            let Some(v) = value else {
                return Some(scim_error(
                    StatusCode::BAD_REQUEST,
                    Some("invalidValue"),
                    "this operation needs a value",
                ));
            };
            match draft.get_mut(p).and_then(Value::as_array_mut) {
                Some(existing) => match v {
                    Value::Array(items) => existing.extend(items.iter().cloned()),
                    single => existing.push(single.clone()),
                },
                None => draft[p] = v.clone(),
            }
        }
        ("remove", Some(p)) => {
            if let Some(object) = draft.as_object_mut() {
                object.remove(p);
            }
        }
        // RFC 7644 section 3.5.2.2: a remove with no target is `noTarget`, which is a
        // different thing from syntax this server does not understand.
        ("remove", None) => {
            return Some(scim_error(
                StatusCode::BAD_REQUEST,
                Some("noTarget"),
                "a remove operation requires a path",
            ));
        }
        _ => {
            return Some(scim_error(
                StatusCode::BAD_REQUEST,
                Some("invalidSyntax"),
                "unsupported operation",
            ));
        }
    }
    None
}

fn patch_in(
    state: &Downstream,
    collection: &str,
    required: &str,
    id: &str,
    body: &Value,
) -> Response {
    let mut inner = state
        .inner
        .lock()
        .expect("downstream state is not poisoned");
    if inner.patch == PatchSupport::Unsupported {
        return scim_error(
            StatusCode::NOT_IMPLEMENTED,
            None,
            "this server does not support PATCH",
        );
    }
    let store = if collection == "Users" {
        &mut inner.users
    } else {
        &mut inner.groups
    };
    let Some(resource) = store.get(id).cloned() else {
        return scim_error(StatusCode::NOT_FOUND, None, "no such resource");
    };
    // THE ENVELOPE, which the first version never looked at. RFC 7644 section 3.5.2 gives the
    // PatchOp its own schema URN and its own required `Operations` member; a body declaring the
    // USER schema, or carrying an empty operation list, is not a patch request. Accepting both
    // meant a client that sent a resource where a PatchOp belonged got 200 here and a 400 from
    // every conformant downstream.
    if !body
        .get("schemas")
        .and_then(Value::as_array)
        .is_some_and(|s| s.iter().any(|v| v.as_str() == Some(PATCH_OP_SCHEMA)))
    {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "a patch request must declare the PatchOp schema",
        );
    }
    let Some(operations) = body.get("Operations").and_then(Value::as_array) else {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "Operations is required",
        );
    };
    if operations.is_empty() {
        return scim_error(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "Operations must not be empty",
        );
    }
    // APPLIED TO A COPY, committed only if EVERY operation succeeds. RFC 7644 section 3.5.2
    // requires a PATCH to be atomic ("if any operation fails, the service provider MUST fail
    // the entire request"), and the first version mutated the stored resource in place: an
    // unsupported third operation left the first two applied and answered 400, so a client that
    // retried met a resource already half-changed. That is the state a replay is supposed to be
    // safe against.
    let mut draft = resource;
    for operation in operations {
        if let Some(refusal) = apply_operation(&mut draft, operation) {
            return refusal;
        }
    }
    // UNIQUENESS AFTER THE OPERATIONS, for the reason `put_in` checks it: a patch that sets an
    // externalId another resource already holds leaves two resources sharing it, which is the
    // state criterion 3 exists to prove impossible.
    if clashes(store, required, &draft, Some(id)) {
        return scim_error(
            StatusCode::CONFLICT,
            Some("uniqueness"),
            "another resource already holds this identifier",
        );
    }
    let committed = draft.clone();
    store.insert(id.to_owned(), draft);
    scim_json(StatusCode::OK, &committed)
}

fn get_in(state: &Downstream, collection: &str, id: &str) -> Response {
    let inner = state
        .inner
        .lock()
        .expect("downstream state is not poisoned");
    let store = if collection == "Users" {
        &inner.users
    } else {
        &inner.groups
    };
    store.get(id).map_or_else(
        || scim_error(StatusCode::NOT_FOUND, None, "no such resource"),
        |r| scim_json(StatusCode::OK, r),
    )
}

fn delete_in(state: &Downstream, collection: &str, id: &str) -> Response {
    let mut inner = state
        .inner
        .lock()
        .expect("downstream state is not poisoned");
    let store = if collection == "Users" {
        &mut inner.users
    } else {
        &mut inner.groups
    };
    if store.remove(id).is_none() {
        return scim_error(StatusCode::NOT_FOUND, None, "no such resource");
    }
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Debug, serde::Deserialize)]
struct FilterQuery {
    filter: Option<String>,
}

async fn list_users(
    State(state): State<Downstream>,
    headers: HeaderMap,
    Query(q): Query<FilterQuery>,
) -> Response {
    record(
        &state,
        "GET",
        "/scim/v2/Users",
        q.filter.as_deref().unwrap_or_default(),
        None,
    );
    if let Some(refusal) = gate(&state, &headers) {
        return refusal;
    }
    list_in(&state, "Users", q.filter.as_deref())
}

async fn create_user(
    State(state): State<Downstream>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let parsed = read_body(&headers, &body);
    record(&state, "POST", "/scim/v2/Users", "", parsed.as_ref().ok());
    if let Some(refusal) = gate(&state, &headers) {
        return refusal;
    }
    let body = match parsed {
        Ok(body) => body,
        Err(refusal) => return *refusal,
    };
    create_in(&state, "Users", "userName", USER_SCHEMA, body)
}

async fn get_user(
    State(state): State<Downstream>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    record(&state, "GET", &format!("/scim/v2/Users/{id}"), "", None);
    if let Some(refusal) = gate(&state, &headers) {
        return refusal;
    }
    get_in(&state, "Users", &id)
}

async fn put_user(
    State(state): State<Downstream>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let parsed = read_body(&headers, &body);
    record(
        &state,
        "PUT",
        &format!("/scim/v2/Users/{id}"),
        "",
        parsed.as_ref().ok(),
    );
    if let Some(refusal) = gate(&state, &headers) {
        return refusal;
    }
    let body = match parsed {
        Ok(body) => body,
        Err(refusal) => return *refusal,
    };
    put_in(&state, "Users", "userName", USER_SCHEMA, &id, body)
}

async fn patch_user(
    State(state): State<Downstream>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let parsed = read_body(&headers, &body);
    record(
        &state,
        "PATCH",
        &format!("/scim/v2/Users/{id}"),
        "",
        parsed.as_ref().ok(),
    );
    if let Some(refusal) = gate(&state, &headers) {
        return refusal;
    }
    let body = match parsed {
        Ok(body) => body,
        Err(refusal) => return *refusal,
    };
    patch_in(&state, "Users", "userName", &id, &body)
}

async fn delete_user(
    State(state): State<Downstream>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    record(&state, "DELETE", &format!("/scim/v2/Users/{id}"), "", None);
    if let Some(refusal) = gate(&state, &headers) {
        return refusal;
    }
    delete_in(&state, "Users", &id)
}

async fn list_groups(
    State(state): State<Downstream>,
    headers: HeaderMap,
    Query(q): Query<FilterQuery>,
) -> Response {
    record(
        &state,
        "GET",
        "/scim/v2/Groups",
        q.filter.as_deref().unwrap_or_default(),
        None,
    );
    if let Some(refusal) = gate(&state, &headers) {
        return refusal;
    }
    list_in(&state, "Groups", q.filter.as_deref())
}

async fn create_group(
    State(state): State<Downstream>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let parsed = read_body(&headers, &body);
    record(&state, "POST", "/scim/v2/Groups", "", parsed.as_ref().ok());
    if let Some(refusal) = gate(&state, &headers) {
        return refusal;
    }
    let body = match parsed {
        Ok(body) => body,
        Err(refusal) => return *refusal,
    };
    create_in(&state, "Groups", "displayName", GROUP_SCHEMA, body)
}

async fn get_group(
    State(state): State<Downstream>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    record(&state, "GET", &format!("/scim/v2/Groups/{id}"), "", None);
    if let Some(refusal) = gate(&state, &headers) {
        return refusal;
    }
    get_in(&state, "Groups", &id)
}

async fn put_group(
    State(state): State<Downstream>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let parsed = read_body(&headers, &body);
    record(
        &state,
        "PUT",
        &format!("/scim/v2/Groups/{id}"),
        "",
        parsed.as_ref().ok(),
    );
    if let Some(refusal) = gate(&state, &headers) {
        return refusal;
    }
    let body = match parsed {
        Ok(body) => body,
        Err(refusal) => return *refusal,
    };
    put_in(&state, "Groups", "displayName", GROUP_SCHEMA, &id, body)
}

async fn patch_group(
    State(state): State<Downstream>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let parsed = read_body(&headers, &body);
    record(
        &state,
        "PATCH",
        &format!("/scim/v2/Groups/{id}"),
        "",
        parsed.as_ref().ok(),
    );
    if let Some(refusal) = gate(&state, &headers) {
        return refusal;
    }
    let body = match parsed {
        Ok(body) => body,
        Err(refusal) => return *refusal,
    };
    patch_in(&state, "Groups", "displayName", &id, &body)
}

async fn delete_group(
    State(state): State<Downstream>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    record(&state, "DELETE", &format!("/scim/v2/Groups/{id}"), "", None);
    if let Some(refusal) = gate(&state, &headers) {
        return refusal;
    }
    delete_in(&state, "Groups", &id)
}
