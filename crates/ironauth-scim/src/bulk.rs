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
#[derive(Debug, Clone, Deserialize)]
pub struct BulkOperation {
    /// `POST`, `PUT`, `PATCH` or `DELETE`.
    pub method: String,
    /// The resource path this operation addresses.
    #[serde(default)]
    pub path: Option<String>,
    /// The client's correlation id for this operation.
    #[serde(rename = "bulkId", default)]
    pub bulk_id: Option<String>,
}

/// A bulk request envelope.
#[derive(Debug, Clone, Deserialize)]
pub struct BulkRequest {
    /// The operations, in order.
    #[serde(rename = "Operations", default)]
    pub operations: Vec<BulkOperation>,
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

/// Validate a bulk request against the advertised limits and resolve every operation's path.
///
/// Returns EITHER a whole-request refusal or a per-operation result for every operation. A
/// refused operation does not abort the others: that is the half of the criterion a
/// fail-the-batch implementation silently drops.
///
/// # Errors
///
/// [`BulkError`] when the request exceeds an advertised limit, in which case no operation is
/// attempted: a limit enforced after doing the work is not a limit.
pub fn validate_bulk(
    request: &BulkRequest,
    payload_bytes: usize,
    limits: BulkLimits,
) -> Result<Vec<(BulkOperationResult, Option<ResourceRef>)>, BulkError> {
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
            let method = operation.method.to_ascii_uppercase();
            if !matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
                return (
                    BulkOperationResult {
                        bulk_id: operation.bulk_id.clone(),
                        method,
                        status: "400".to_owned(),
                        detail: Some("unsupported bulk method".to_owned()),
                    },
                    None,
                );
            }
            let Some(path) = operation.path.as_deref() else {
                return (
                    BulkOperationResult {
                        bulk_id: operation.bulk_id.clone(),
                        method,
                        status: "400".to_owned(),
                        detail: Some("the operation names no path".to_owned()),
                    },
                    None,
                );
            };
            // The SAME path parser a single request uses. An operation inside a batch is not
            // a lesser kind of request that earns a laxer reading of its path, and a batch is
            // exactly where an attacker would hope it were.
            match parse_resource_path(path) {
                Ok(resource) => (
                    BulkOperationResult {
                        bulk_id: operation.bulk_id.clone(),
                        method,
                        status: "200".to_owned(),
                        detail: None,
                    },
                    Some(resource),
                ),
                Err(error) => (
                    BulkOperationResult {
                        bulk_id: operation.bulk_id.clone(),
                        method,
                        status: "400".to_owned(),
                        detail: Some(error.to_string()),
                    },
                    None,
                ),
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
        assert_eq!(results[0].0.status, "200");
        assert_eq!(results[1].0.status, "400", "the traversal is refused");
        assert_eq!(
            results[2].0.status, "200",
            "and the operation AFTER the failure still ran"
        );
        assert_eq!(results[0].0.bulk_id.as_deref(), Some("a"));
        assert_eq!(results[2].0.bulk_id.as_deref(), Some("c"));
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
            assert_eq!(results[0].0.status, "400", "must refuse {hostile:?}");
            assert!(results[0].1.is_none(), "and resolve no resource");
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
        assert_eq!(results[0].0.status, "400");
        assert_eq!(results[1].0.status, "200");
    }

    #[test]
    fn an_empty_batch_is_allowed_and_yields_no_results() {
        // The control on the limit checks: they must not refuse a legitimate empty batch,
        // which is what a client sends when it has nothing to do.
        let parsed = request(r#"{"Operations":[]}"#);
        assert!(
            validate_bulk(&parsed, 10, BulkLimits::default())
                .expect("allowed")
                .is_empty()
        );
    }
}
