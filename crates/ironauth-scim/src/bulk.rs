// SPDX-License-Identifier: MIT OR Apache-2.0

//! SCIM bulk requests (RFC 7644 section 3.7, issue #135, criterion 4).
//!
//! The criterion is that bulk requests "respect advertised limits and return per-operation
//! results". Both halves matter and they fail differently.
//!
//! ADVERTISED LIMITS. A server publishes `maxOperations` and `maxPayloadSize` in its
//! `ServiceProviderConfig`, and a client sizes its batches from them. A server that advertises
//! a limit it does not enforce has published a promise an attacker reads as a budget; one
//! that enforces a limit it does not advertise breaks well-behaved clients at random. So
//! [`BulkLimits`] is ONE value: [`crate::ServiceProviderConfig`] renders that same struct
//! into the published document and this module enforces it, with no second constant for the
//! two to drift apart. The equality is TESTED there, by reading the number a client would
//! read out of the document and proving it is exactly where [`validate_bulk`] changes its
//! answer; the tests here pin the enforcement itself.
//!
//! PER-OPERATION RESULTS. A bulk request that fails as a unit tells a client nothing about
//! which of its fifty operations was the problem, and the client's only recovery is to retry
//! all fifty. Each operation therefore carries its own status, and one failing does not
//! discard the results of the others.
//!
//! # The bulk-smuggling shape
//!
//! Bulk is where an IDOR gets interesting, because it is a batch of paths inside one
//! authorized request. Every operation's path goes through [`crate::parse_resource_path`],
//! the same parser a single request uses: an operation is not a lesser kind of request that
//! earns a laxer reading of its path.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::path::{ResourceRef, parse_resource_path};

/// The bulk limits this server advertises AND enforces.
///
/// One value for both. See the module docs: two constants drift, and the drift is either a
/// promise an attacker reads as a budget or a limit that breaks honest clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BulkLimits {
    /// The maximum number of operations in one request.
    pub max_operations: usize,
    /// The maximum request payload size in bytes.
    pub max_payload_bytes: usize,
}

impl Default for BulkLimits {
    /// The advertised defaults.
    ///
    /// Chosen from what Okta and Entra actually send (tens of operations per batch), with
    /// room above it, and far below a batch that would hold a transaction open long enough
    /// to matter.
    fn default() -> Self {
        Self {
            max_operations: 1000,
            max_payload_bytes: 1_048_576,
        }
    }
}

/// One operation in a bulk request.
///
/// EVERY SCALAR FIELD IS A RAW `Value`, and that is the point rather than laxity. They were
/// `String`, so one operation with a missing or wrong-typed `method` failed the WHOLE envelope
/// parse: a review measured a two-operation batch whose first operation named no method
/// answering `400 the request body is not a SCIM bulk request`, with the valid sibling never
/// run and nothing saying which operation was bad. That is exactly the retry-all-fifty outcome
/// this module's header opens by condemning.
///
/// `Option<String>` was the first repair and it was HALF a repair: it tolerates ABSENT and
/// never WRONG-TYPED, so `"path": 5` still killed the envelope while the doc claimed
/// otherwise. A review measured that too, and measured that nothing in the suite noticed
/// either way. A raw `Value` is the only shape that cannot fail the envelope parse, so shape
/// problems are per-OPERATION refusals like every other one and a bad operation costs its own
/// slot and nothing else.
#[derive(Debug, Clone, Deserialize)]
pub struct BulkOperation {
    /// `POST`, `PUT`, `PATCH` or `DELETE`. Absent or not a string is this operation's own 400.
    pub method: Option<Value>,
    /// The resource path this operation addresses.
    pub path: Option<Value>,
    /// The client's correlation id for this operation.
    #[serde(rename = "bulkId")]
    pub bulk_id: Option<Value>,
    /// The resource body, for the methods that carry one.
    ///
    /// Kept as a raw `Value` and re-serialized when the operation is dispatched, rather than
    /// parsed into a `ScimUser` or `Group` here. Parsing it here would be a SECOND reader of
    /// the same wire format, and the whole argument of this module is that an operation in a
    /// batch is dispatched to the very handler a single request reaches -- including that
    /// handler's own parse, its own refusals, and its own error text.
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

/// A bulk request envelope.
#[derive(Debug, Clone, Deserialize)]
pub struct BulkRequest {
    /// The declared schema URNs.
    ///
    /// CHECKED, like `patch_user` checks the `PatchOp` URN. Without it a body of `{}` and a body
    /// with `"Operatons"` misspelled both parsed into an empty batch and answered `200` with an
    /// empty `Operations` array -- which this handler's own doc says is how a client tells a
    /// batch that RAN from one that was refused. Two doors in one crate answered the same
    /// question two ways.
    #[serde(default)]
    pub schemas: Vec<String>,
    /// The operations, in order.
    #[serde(rename = "Operations", default)]
    pub operations: Vec<BulkOperation>,
    /// After this many operations have failed, stop (RFC 7644 section 3.7.3).
    ///
    /// Absent means run every operation. The operations never attempted are simply absent from
    /// the response, which is why a client reads the results rather than assuming its batch
    /// ran to the end.
    #[serde(rename = "failOnErrors", default)]
    pub fail_on_errors: Option<usize>,
}

/// One operation's outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BulkOperationResult {
    /// Echoed so a client can match a result to what it sent.
    #[serde(rename = "bulkId", skip_serializing_if = "Option::is_none")]
    pub bulk_id: Option<String>,
    /// The method, echoed for the same reason.
    pub method: String,
    /// The HTTP status for this operation, as SCIM renders it: a string.
    pub status: String,
    /// Why it failed, when it did. Never echoes the client's input.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The created or addressed resource's location (RFC 7644 section 3.7.3).
    ///
    /// Present when the handler's own response carried the resource, which is what lets a
    /// client resolve its `bulkId` to a real id without a second request.
    ///
    /// ABSENT ON A SUCCESSFUL DELETE, and that is worth stating because the RFC's own example
    /// carries one there. It is read out of the handler's response document rather than built
    /// from the path this module parsed -- a create is the case that matters, since the client
    /// does not know the id it is about to get -- and a 204 has no document. Reporting a
    /// location assembled from the request path instead would be this module asserting where a
    /// resource is rather than reading where the handler put it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// The operation's own response body, for a FAILED operation.
    ///
    /// RFC 7644 section 3.7.3 says a failed operation carries the error response it would
    /// have received on its own. Carrying it means a client debugging one operation out of
    /// fifty reads the same SCIM error it would have read had it sent that one alone --
    /// rather than a status code and a sentence this module invented.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<serde_json::Value>,
}

/// Why a whole bulk request was refused before any operation ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BulkError {
    /// More operations than [`BulkLimits::max_operations`].
    TooManyOperations {
        /// The advertised limit, so a client can resize its batch without guessing.
        limit: usize,
    },
    /// A payload larger than [`BulkLimits::max_payload_bytes`].
    PayloadTooLarge {
        /// The advertised limit.
        limit: usize,
    },
}

/// The SCIM error document a 405 refusal carries.
///
/// Separate from [`scim_error_document`] only in its status and `scimType`: a method the path
/// does not offer is not an `invalidValue`.
#[must_use]
pub fn method_not_allowed_document(detail: &str) -> serde_json::Value {
    serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "detail": detail,
        "status": "405",
    })
}

/// One of the operation's scalar fields as a string, or `None` if it is absent OR not a string.
///
/// The two are deliberately the same answer here and different refusals at the call site: a
/// field that is present and wrong-typed is a client bug worth naming, and an absent one is a
/// different client bug worth naming, but neither may reach the envelope parse.
fn scalar(field: Option<&Value>) -> Option<&str> {
    field.and_then(Value::as_str)
}

/// Whether one of the operation's scalar fields is present but not a string.
fn wrong_typed(field: Option<&Value>) -> bool {
    field.is_some_and(|value| !value.is_string())
}

/// The SCIM error document a per-operation refusal carries.
///
/// The same shape `crate::server::scim_error` renders, built here because this module has no
/// `Response` to read back and the two must agree on what a client parses.
fn scim_error_document(detail: &str) -> serde_json::Value {
    serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "scimType": "invalidValue",
        "detail": detail,
        "status": "400",
    })
}

/// What one operation is, once its limits and path have been checked.
///
/// AN ENUM RATHER THAN A STATUS PLUS AN OPTION. The first version returned a
/// `(BulkOperationResult, Option<ResourceRef>)` per operation and gave a resolved operation the
/// status `"200"` -- which read as "this operation succeeded" while nothing had run yet. Any
/// caller that rendered those results without dispatching would have told a client that fifty
/// writes had landed. There is no such status here: a resolved operation carries no outcome,
/// because it does not have one until [`crate::server::bulk`] dispatches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BulkOutcome {
    /// The operation was refused before dispatch, and this is its final result.
    Refused(BulkOperationResult),
    /// The operation is well formed and addresses this resource. It has not run.
    Resolved {
        /// The client's correlation id, echoed on the eventual result.
        bulk_id: Option<String>,
        /// The uppercased method.
        method: String,
        /// Where it points, as the single-request path parser read it.
        resource: ResourceRef,
    },
}

/// Validate a bulk request against the advertised limits and resolve every operation's path.
///
/// Returns EITHER a whole-request refusal or one [`BulkOutcome`] per operation, in the order
/// they were sent. A refused operation does not abort the others: that is the half of the
/// criterion a fail-the-batch implementation silently drops.
///
/// This function does NOT execute anything. It cannot: it has no store, and the whole argument
/// of this module is that an operation is executed by the same handler a single request
/// reaches. [`crate::server::bulk`] is what dispatches a [`BulkOutcome::Resolved`].
///
/// # Errors
///
/// [`BulkError`] when the request exceeds an advertised limit, in which case no operation is
/// attempted: a limit enforced after doing the work is not a limit.
pub fn validate_bulk(
    request: &BulkRequest,
    payload_bytes: usize,
    limits: BulkLimits,
) -> Result<Vec<BulkOutcome>, BulkError> {
    // Checked BEFORE anything is parsed or executed. A limit applied per-operation as the
    // batch runs has already paid for the work it was meant to prevent.
    if payload_bytes > limits.max_payload_bytes {
        return Err(BulkError::PayloadTooLarge {
            limit: limits.max_payload_bytes,
        });
    }
    if request.operations.len() > limits.max_operations {
        return Err(BulkError::TooManyOperations {
            limit: limits.max_operations,
        });
    }

    Ok(request
        .operations
        .iter()
        .map(|operation| {
            // ECHOED AS THE CLIENT SPELLED IT, and matched EXACTLY. Both halves changed
            // together, and both were the same defect as the path beside them.
            //
            // The match used to uppercase first, so `post`, `Post` and `pOsT` all reached the
            // create handler while `post /scim/v2/Users` as a single request answers 405. HTTP
            // methods are case-sensitive (RFC 9110 section 9.1), RFC 7644 section 3.7.2 writes
            // them uppercase, and `path.rs` states the governing rule for the field next door:
            // accepting two spellings for one thing is a second interpretation for something
            // else to disagree with. A review measured the batch creating a user from `post`.
            //
            // And the ECHO is what the client sent rather than an uppercased or empty string,
            // because RFC 7644 section 3.7.3 requires the result to carry the operation's
            // method and a client matching results to what it sent needs its own spelling back.
            let method = scalar(operation.method.as_ref())
                .unwrap_or_default()
                .to_owned();
            let refuse = |detail: &str| {
                BulkOutcome::Refused(BulkOperationResult {
                    bulk_id: scalar(operation.bulk_id.as_ref()).map(str::to_owned),
                    method: method.clone(),
                    status: "400".to_owned(),
                    detail: Some(detail.to_owned()),
                    location: None,
                    // THE SAME SCIM ERROR DOCUMENT a dispatched failure carries, and in the
                    // same field. RFC 7644 section 3.7.3 defines `response` for the operation
                    // body and defines no operation-level `detail`, so a client written to the
                    // RFC read nothing at all for the refusals most likely to happen -- a bad
                    // path, an unsupported method, a bulkId reference. `detail` stays because
                    // it is what this server already emitted and dropping it would be a
                    // gratuitous break; `response` is what the spec-following client reads.
                    response: Some(scim_error_document(detail)),
                })
            };
            // WRONG-TYPED FIRST, and named as its own refusal. `"method": 5` and a missing
            // method are different client bugs, and telling them apart is the difference
            // between a client fixing its serializer and a client hunting a phantom.
            for (name, field) in [
                ("method", operation.method.as_ref()),
                ("path", operation.path.as_ref()),
                ("bulkId", operation.bulk_id.as_ref()),
            ] {
                if wrong_typed(field) {
                    return refuse(&format!("the operation's {name} is not a string"));
                }
            }
            if operation.method.is_none() {
                return refuse("the operation names no method");
            }
            if !matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
                return refuse("unsupported bulk method");
            }
            let Some(path) = scalar(operation.path.as_ref()) else {
                return refuse("the operation names no path");
            };
            // A `bulkId:` REFERENCE, which RFC 7644 section 3.7.2 lets a client use to point a
            // later operation at a resource an earlier one created. REFUSED, not resolved.
            //
            // Resolving it means this module maintaining its own map from correlation ids to
            // real ids and substituting into a path AFTER the parser read it -- which is a
            // second interpretation of a path, and a second interpretation of a path is the
            // exact shape of every IDOR this surface was written to close. Refusing is honest
            // and costs a client one extra round trip; neither Okta nor Entra sends one.
            if path.contains("bulkId:") {
                return refuse("bulkId references between operations are not supported");
            }
            // The SAME path parser a single request uses. An operation inside a batch is not
            // a lesser kind of request that earns a laxer reading of its path, and a batch is
            // exactly where an attacker would hope it were.
            match parse_resource_path(path) {
                Ok(resource) => BulkOutcome::Resolved {
                    bulk_id: scalar(operation.bulk_id.as_ref()).map(str::to_owned),
                    method,
                    resource,
                },
                Err(error) => refuse(&error.to_string()),
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(json: &str) -> BulkRequest {
        serde_json::from_str(json).expect("a bulk request")
    }

    #[test]
    fn every_operation_gets_its_own_result_and_one_failure_does_not_discard_the_rest() {
        // The half a fail-the-batch implementation drops. A client that is told only that
        // "the request failed" has to retry all fifty operations to find the one bad path.
        let parsed = request(
            r#"{"Operations":[
                 {"method":"POST","path":"/Users","bulkId":"a"},
                 {"method":"PATCH","path":"/Users/%2e%2e","bulkId":"b"},
                 {"method":"DELETE","path":"/Groups/grp_1","bulkId":"c"}
               ]}"#,
        );
        let results = validate_bulk(&parsed, 200, BulkLimits::default()).expect("within limits");
        assert_eq!(results.len(), 3);
        assert!(
            matches!(&results[0], BulkOutcome::Resolved { bulk_id, .. } if bulk_id.as_deref() == Some("a")),
            "{:?}",
            results[0]
        );
        assert!(
            matches!(&results[1], BulkOutcome::Refused(result) if result.status == "400"),
            "the traversal is refused: {:?}",
            results[1]
        );
        assert!(
            matches!(&results[2], BulkOutcome::Resolved { bulk_id, .. } if bulk_id.as_deref() == Some("c")),
            "and the operation AFTER the failure was still resolved: {:?}",
            results[2]
        );
    }

    #[test]
    fn a_bulk_operation_path_gets_no_laxer_reading_than_a_single_request() {
        // Bulk is where an IDOR gets interesting: a batch of paths inside one authorized
        // request. Every trick the single-request parser refuses is refused here too, because
        // it IS that parser.
        for hostile in [
            "/Users/%2e%2e",
            "/Users/%252e%252e",
            "/Users/../Groups/x",
            "/Users/a%00b",
            "/Users/a\\b",
        ] {
            let parsed = request(&format!(
                r#"{{"Operations":[{{"method":"PATCH","path":"{}","bulkId":"x"}}]}}"#,
                hostile.replace('\\', "\\\\")
            ));
            let results = validate_bulk(&parsed, 200, BulkLimits::default()).expect("limits ok");
            // `Refused` is the whole assertion: the enum has no variant that both carries a
            // refusal and points at a resource, so there is nothing left to dispatch.
            assert!(
                matches!(&results[0], BulkOutcome::Refused(result) if result.status == "400"),
                "must refuse {hostile:?}: {:?}",
                results[0]
            );
        }
    }

    #[test]
    fn the_refusal_names_the_limit_it_enforced() {
        // Named for what it actually checks. The advertised-equals-enforced property is a
        // claim about TWO artifacts and cannot be tested from inside one of them, so it lives
        // in `service_provider_config`, where the published document is available to read.
        // What this pins is the enforcement: the bound is where it says it is, it is
        // inclusive, and the error carries the number rather than a generic refusal.
        let limits = BulkLimits {
            max_operations: 2,
            max_payload_bytes: 100,
        };
        let three = request(
            r#"{"Operations":[
                 {"method":"POST","path":"/Users"},
                 {"method":"POST","path":"/Users"},
                 {"method":"POST","path":"/Users"}
               ]}"#,
        );
        assert_eq!(
            validate_bulk(&three, 50, limits),
            Err(BulkError::TooManyOperations { limit: 2 }),
            "and the refusal names the advertised limit, so a client can resize without guessing"
        );

        let one = request(r#"{"Operations":[{"method":"POST","path":"/Users"}]}"#);
        assert_eq!(
            validate_bulk(&one, 101, limits),
            Err(BulkError::PayloadTooLarge { limit: 100 })
        );
        assert!(
            validate_bulk(&one, 100, limits).is_ok(),
            "the bound is inclusive"
        );
    }

    #[test]
    fn a_limit_is_checked_before_any_operation_is_examined() {
        // A limit applied as the batch runs has already paid for the work it was meant to
        // prevent. An over-limit request whose operations are ALL malformed still refuses on
        // the limit, which is only true if the limit came first.
        let limits = BulkLimits {
            max_operations: 1,
            max_payload_bytes: 1000,
        };
        let junk = request(
            r#"{"Operations":[
                 {"method":"NOPE","path":"/Users/%2e%2e"},
                 {"method":"NOPE","path":"/Users/%2e%2e"}
               ]}"#,
        );
        assert_eq!(
            validate_bulk(&junk, 50, limits),
            Err(BulkError::TooManyOperations { limit: 1 })
        );
    }

    #[test]
    fn an_unsupported_method_is_one_operations_failure_rather_than_the_batchs() {
        let parsed = request(
            r#"{"Operations":[
                 {"method":"GET","path":"/Users","bulkId":"a"},
                 {"method":"POST","path":"/Users","bulkId":"b"}
               ]}"#,
        );
        let results = validate_bulk(&parsed, 100, BulkLimits::default()).expect("limits ok");
        assert!(
            matches!(&results[0], BulkOutcome::Refused(result) if result.status == "400"),
            "{:?}",
            results[0]
        );
        assert!(
            matches!(&results[1], BulkOutcome::Resolved { .. }),
            "the well-formed sibling still resolved: {:?}",
            results[1]
        );
    }

    #[test]
    fn a_bulk_id_reference_is_refused_rather_than_resolved() {
        // RFC 7644 section 3.7.2 lets a client point a later operation at a resource an
        // earlier one created, by `bulkId:` in the path. Resolving it means substituting into
        // a path AFTER the parser read it, which is a second interpretation of a path -- the
        // exact shape of every IDOR this surface closes. So it is refused, and the refusal
        // says what is unsupported rather than reading as a malformed path.
        let parsed = request(
            r#"{"Operations":[
                 {"method":"POST","path":"/Users","bulkId":"new"},
                 {"method":"PATCH","path":"/Groups/bulkId:new","bulkId":"b"}
               ]}"#,
        );
        let results = validate_bulk(&parsed, 200, BulkLimits::default()).expect("limits ok");
        let BulkOutcome::Refused(refused) = &results[1] else {
            panic!("a bulkId reference must be refused: {:?}", results[1]);
        };
        assert_eq!(refused.status, "400");
        assert_eq!(
            refused.detail.as_deref(),
            Some("bulkId references between operations are not supported"),
            "the refusal must name the unsupported feature rather than read as a bad path"
        );
        assert!(
            matches!(&results[0], BulkOutcome::Resolved { .. }),
            "and the operation that DEFINED the bulkId is untouched: {:?}",
            results[0]
        );
    }

    #[test]
    fn an_empty_batch_is_allowed_by_the_validator_and_refused_by_the_route() {
        // The control on the limit checks: they must not refuse an empty batch, which is what a
        // bound applied to `len()` would do if it were written the wrong way round.
        //
        // AND THE ROUTE REFUSES IT ANYWAY, one layer up. That is not a contradiction and the
        // asymmetry is deliberate: `#[serde(default)]` on `Operations` means a body of `{}` and
        // a body whose key is misspelled BOTH arrive here as an empty batch, and answering
        // `200 {"Operations":[]}` to a typo is how a client learns its batch ran when it did
        // not. RFC 7644 section 3.7 does not forbid an empty batch; it also gives a client no
        // reason to send one. So the validator stays honest about what it checks, and
        // `crate::server::bulk` owns the refusal --
        // `a_malformed_bulk_envelope_is_refused_rather_than_answered_as_an_empty_batch` drives
        // it. An earlier version of this comment said the opposite of what the server does.
        let parsed = request(r#"{"Operations":[]}"#);
        let results = validate_bulk(&parsed, 20, BulkLimits::default()).expect("within limits");
        assert!(results.is_empty());
    }
}
