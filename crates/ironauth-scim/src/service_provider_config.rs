// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `/ServiceProviderConfig` document (RFC 7644 section 4, issue #135, criterion 4).
//!
//! Criterion 4 says bulk requests "respect advertised limits". This module is the ADVERTISED
//! half, and it exists because without it that sentence is unfalsifiable: a limit nothing
//! publishes is not advertised, and a test asserting "advertised == enforced" against a
//! number that appears in exactly one place asserts that a value equals itself.
//!
//! So every number in this document is READ FROM [`ScimLimits`], the same value the enforcing
//! code takes. There is no second constant here for the two to drift apart, and the tests
//! below prove the equality by driving the enforcement rather than by comparing the struct to
//! itself: the advertised `maxOperations` is checked against the batch size
//! [`crate::validate_bulk`] actually refuses, not against `limits.max_operations`.
//!
//! A number is advertised here ONLY if something in this crate enforces it. That is the rule
//! the module is for. Publishing `maxResults` while paginating without a bound would be the
//! precise failure the bulk module's header warns about, one step to the left.

use serde::Serialize;

use crate::bulk::BulkLimits;

/// Every limit this server advertises, and therefore every limit it enforces.
///
/// One value, passed to both the renderer and the validators. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScimLimits {
    /// The bulk-request limits.
    pub bulk: BulkLimits,
    /// The maximum number of resources one page may return.
    ///
    /// SCIM lets a client choose `count`, so an unbounded value is a client-chosen amount of
    /// server work. This is the ceiling [`ScimLimits::clamp_count`] applies.
    pub max_results: usize,
    /// The most organization members one list request may examine.
    ///
    /// A filter this server cannot answer from an index is answered by examining members, and
    /// an unfiltered list of a large organization is the same work. Both are bounded here, and
    /// reaching the bound is REFUSED (RFC 7644 section 3.4.2.2 `tooMany`) rather than silently
    /// truncated: a short page that looked complete would make a provisioning client
    /// deprovision every member it did not see.
    ///
    /// READ IT THROUGH [`ScimLimits::scan_bound`], never directly. One store list call returns at
    /// most `MANAGEMENT_LIST_HARD_CAP + 1` rows (the repository clamps its limit to that, so a
    /// caller can always see ONE row past the cap and tell a full page from the last one), so a
    /// bound above `MANAGEMENT_LIST_HARD_CAP`
    /// makes the refusal UNREACHABLE and turns the bound into exactly the silent truncation
    /// the paragraph above says it prevents. That is not hypothetical: the first version of
    /// this field defaulted to 10 000, and a reviewer seeded 1100 members and got a 200 with
    /// `totalResults: 1001` and no indication the answer was partial.
    pub max_scan: usize,
}

impl Default for ScimLimits {
    fn default() -> Self {
        Self {
            bulk: BulkLimits::default(),
            // What Okta and Entra page at, and small enough that a hostile `count` buys
            // nothing over an honest one.
            max_results: 200,
            // The store's own list cap, which is the largest value that can ever be reached:
            // see the field's docs.
            max_scan: DEFAULT_MAX_SCAN,
        }
    }
}

/// The default scan bound: exactly what one store list call will return.
///
/// A `usize` conversion of an `i64` constant, done once here rather than at each use.
/// `MANAGEMENT_LIST_HARD_CAP` is a small positive literal, so the fallback is unreachable and
/// is a saturating floor rather than a panic.
const DEFAULT_MAX_SCAN: usize = {
    // `usize::try_from` is not const, so the conversion is written out. The negative guard is
    // a saturating floor rather than a panic; the cap is a small positive literal in the store,
    // so it is unreachable, and 0 refuses every scan rather than silently allowing an
    // unbounded one.
    //
    // There is deliberately NO upper guard. An earlier version had `cap > usize::MAX as i64`,
    // which is nonsense: that cast wraps to -1, so the comparison was always true and this
    // constant evaluated to 0 -- which would have made `scan_bound` return 0 and refuse every
    // list. Clippy found it, through `unnecessary_min_or_max` on the caller rather than here.
    let cap = ironauth_store::MANAGEMENT_LIST_HARD_CAP;
    if cap < 0 {
        0
    } else {
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        {
            cap as usize
        }
    }
};

impl ScimLimits {
    /// The scan bound actually enforced: the configured value, or the store's list cap if that
    /// is smaller.
    ///
    /// The `min` is the whole point. A caller can configure `max_scan` to anything, but the
    /// store returns at most `MANAGEMENT_LIST_HARD_CAP` rows per list call, so a larger
    /// configured value would leave `len() > bound` permanently false and the refusal
    /// permanently dead. Clamping here makes the bound reachable BY CONSTRUCTION rather than
    /// by whoever last edited the default.
    #[must_use]
    pub fn scan_bound(&self) -> usize {
        self.max_scan.min(DEFAULT_MAX_SCAN)
    }

    /// The page size to actually use for a client-requested `count`.
    ///
    /// Clamps rather than refuses: RFC 7644 section 3.4.2.4 says a provider MAY return fewer
    /// resources than requested, and a client asking for too many is ordinary rather than
    /// hostile. The clamp is the enforcement that makes the advertised `maxResults` true.
    #[must_use]
    pub fn clamp_count(&self, requested: Option<usize>) -> usize {
        match requested {
            // A count of zero is a metadata-only request in SCIM (`totalResults` with no
            // members), so it is passed through rather than raised to the default.
            Some(count) => count.min(self.max_results),
            None => self.max_results,
        }
    }
}

/// The `bulk` complex attribute of the config document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BulkConfig {
    /// Whether bulk is supported at all.
    pub supported: bool,
    /// The advertised maximum operation count.
    #[serde(rename = "maxOperations")]
    pub max_operations: usize,
    /// The advertised maximum payload size in bytes.
    #[serde(rename = "maxPayloadSize")]
    pub max_payload_size: usize,
}

/// The `filter` complex attribute of the config document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FilterConfig {
    /// Whether filtering is supported.
    pub supported: bool,
    /// The advertised maximum page size.
    #[serde(rename = "maxResults")]
    pub max_results: usize,
}

/// A config attribute that carries nothing but whether it is supported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Supported {
    /// Whether the feature is supported.
    pub supported: bool,
}

/// An authentication scheme entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthenticationScheme {
    /// The scheme type, for example `oauthbearertoken`.
    #[serde(rename = "type")]
    pub scheme_type: String,
    /// A short name.
    pub name: String,
    /// A description.
    pub description: String,
    /// Whether this is the primary scheme.
    pub primary: bool,
}

/// The `/ServiceProviderConfig` document.
///
/// Serializes to exactly the RFC 7644 section 4 shape, so a connector reads it without
/// special-casing this server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceProviderConfig {
    /// Always the `ServiceProviderConfig` schema URN.
    pub schemas: Vec<String>,
    /// PATCH support.
    pub patch: Supported,
    /// Bulk support and its limits.
    pub bulk: BulkConfig,
    /// Filter support and its page bound.
    pub filter: FilterConfig,
    /// Whether a password may be changed through SCIM.
    #[serde(rename = "changePassword")]
    pub change_password: Supported,
    /// Sort support.
    pub sort: Supported,
    /// `ETag` support.
    pub etag: Supported,
    /// How a client authenticates.
    #[serde(rename = "authenticationSchemes")]
    pub authentication_schemes: Vec<AuthenticationScheme>,
}

impl ServiceProviderConfig {
    /// Render the document for a set of limits.
    ///
    /// Every number comes from `limits`. A literal here would be the drift this module exists
    /// to prevent, and the tests below fail if one appears.
    #[must_use]
    pub fn new(limits: ScimLimits) -> Self {
        Self {
            schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig".to_owned()],
            // Supported because `parse_patch_path` exists and every operation goes through it.
            patch: Supported { supported: true },
            bulk: BulkConfig {
                // FALSE, and the reason is the whole point of this document.
                //
                // `validate_bulk` exists and the limits below are real, but there is NO
                // `/Bulk` ROUTE in `scim_router`. A client reading `supported: true` sends
                // `POST /scim/v2/Bulk` and gets axum's bare 404 -- not even a SCIM error --
                // and a provisioning run that batched its work would simply fail. An audit
                // caught this: the guard that was supposed to stop it asserted `supported ==
                // true` justified by the NAME of a parser, which is a fact about the crate
                // rather than about what a caller can reach.
                //
                // The limits stay populated because they are what the eventual route will
                // enforce, and RFC 7644 section 4 lets a provider advertise them either way.
                supported: false,
                max_operations: limits.bulk.max_operations,
                max_payload_size: limits.bulk.max_payload_bytes,
            },
            filter: FilterConfig {
                supported: true,
                max_results: limits.max_results,
            },
            // Deliberately false: nothing in IronAuth accepts a plaintext password through a
            // SCIM write, so advertising it would publish a capability a connector would then
            // fail against. Advertising less than you do costs a round trip; advertising more
            // than you do breaks the client.
            change_password: Supported { supported: false },
            sort: Supported { supported: false },
            // No resource version is stored, so an ETag would be invented per response and
            // would defeat the concurrency control it exists to provide.
            etag: Supported { supported: false },
            authentication_schemes: vec![AuthenticationScheme {
                scheme_type: "oauthbearertoken".to_owned(),
                name: "OAuth Bearer Token".to_owned(),
                description: "Authentication using an OAuth 2.0 bearer token".to_owned(),
                primary: true,
            }],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bulk::{BulkError, BulkRequest, validate_bulk};

    fn batch_of(count: usize) -> BulkRequest {
        let operations: Vec<String> = (0..count)
            .map(|_| r#"{"method":"POST","path":"/Users"}"#.to_owned())
            .collect();
        serde_json::from_str(&format!(r#"{{"Operations":[{}]}}"#, operations.join(",")))
            .expect("a bulk request")
    }

    fn rendered(limits: ScimLimits) -> serde_json::Value {
        serde_json::to_value(ServiceProviderConfig::new(limits)).expect("serializable")
    }

    #[test]
    fn the_advertised_bulk_limits_are_the_ones_actually_enforced() {
        // The point of the whole module. This does NOT compare the document to the struct it
        // was built from, which would be a tautology. It reads the number a CLIENT would read
        // out of the published document, and then proves that number is exactly where the
        // enforcement changes its answer.
        //
        // Several distinct limit sets, so a renderer that hard-coded any one of them fails.
        for limits in [
            ScimLimits::default(),
            ScimLimits {
                max_scan: ScimLimits::default().max_scan,
                bulk: BulkLimits {
                    max_operations: 3,
                    max_payload_bytes: 64,
                },
                max_results: 7,
            },
            ScimLimits {
                max_scan: ScimLimits::default().max_scan,
                bulk: BulkLimits {
                    max_operations: 1,
                    max_payload_bytes: 1,
                },
                max_results: 1,
            },
        ] {
            let document = rendered(limits);

            let advertised_operations = usize::try_from(
                document["bulk"]["maxOperations"]
                    .as_u64()
                    .expect("maxOperations is published as a number"),
            )
            .expect("a limit fits the platform word");
            let advertised_payload = usize::try_from(
                document["bulk"]["maxPayloadSize"]
                    .as_u64()
                    .expect("maxPayloadSize is published as a number"),
            )
            .expect("a limit fits the platform word");

            // At the advertised count: accepted. One over: refused, and the refusal names
            // the SAME number the document published.
            assert!(
                validate_bulk(&batch_of(advertised_operations), 0, limits.bulk).is_ok(),
                "a batch of exactly the advertised size must be accepted"
            );
            assert_eq!(
                validate_bulk(&batch_of(advertised_operations + 1), 0, limits.bulk),
                Err(BulkError::TooManyOperations {
                    limit: advertised_operations
                }),
                "one over the advertised size must be refused"
            );

            assert!(
                validate_bulk(&batch_of(0), advertised_payload, limits.bulk).is_ok(),
                "a payload of exactly the advertised size must be accepted"
            );
            assert_eq!(
                validate_bulk(&batch_of(0), advertised_payload + 1, limits.bulk),
                Err(BulkError::PayloadTooLarge {
                    limit: advertised_payload
                }),
                "one byte over the advertised size must be refused"
            );
        }
    }

    #[test]
    fn the_scan_bound_can_never_exceed_what_one_store_list_call_returns() {
        // THE PROPERTY THE CLAMP EXISTS FOR, and it cannot be driven through the HTTP surface:
        // a test at a small bound exercises a `min` that is a no-op there, and a test at a
        // large one would have to seed a thousand members. It is a pure function, so it is
        // asserted directly.
        //
        // The defect this closes: `max_scan` defaulted to 10 000 while
        // `OrgMembershipRepo::list_for_org` clamps its limit to `MANAGEMENT_LIST_HARD_CAP + 1`,
        // so `len() > max_scan` was permanently false, the `tooMany` refusal was dead code, and
        // 1100 seeded members answered 200 with `totalResults: 1001` and no sign the answer was
        // partial. An identity provider reads that as the complete member list.
        let cap = usize::try_from(ironauth_store::MANAGEMENT_LIST_HARD_CAP).expect("a small cap");
        for configured in [1, 10, cap - 1, cap, cap + 1, 10_000, usize::MAX] {
            let limits = ScimLimits {
                max_scan: configured,
                ..ScimLimits::default()
            };
            assert!(
                limits.scan_bound() <= cap,
                "a configured {configured} must not produce an unreachable bound"
            );
            // And it is a CLAMP, not a constant: a bound below the cap is honoured, or a
            // deployment could not narrow the scan at all.
            assert_eq!(limits.scan_bound(), configured.min(cap), "{configured}");
        }
        // The default is reachable, which is the case that actually ships.
        assert!(ScimLimits::default().scan_bound() <= cap);
        assert!(ScimLimits::default().scan_bound() > 0);
    }

    #[test]
    fn the_advertised_page_bound_is_the_one_actually_applied() {
        // Same shape for the other published number: read it out of the document, then prove
        // the clamp cannot be persuaded past it by any request.
        for limits in [
            ScimLimits::default(),
            ScimLimits {
                max_scan: ScimLimits::default().max_scan,
                bulk: BulkLimits::default(),
                max_results: 5,
            },
        ] {
            let advertised = usize::try_from(
                rendered(limits)["filter"]["maxResults"]
                    .as_u64()
                    .expect("maxResults is published as a number"),
            )
            .expect("a limit fits the platform word");

            assert_eq!(limits.clamp_count(Some(usize::MAX)), advertised);
            assert_eq!(limits.clamp_count(Some(advertised + 1)), advertised);
            assert_eq!(limits.clamp_count(None), advertised);
            // Below the bound the client's own choice is honoured, so the clamp is a ceiling
            // rather than a constant. Without this the test passes on `fn clamp_count() ->
            // max_results`, which would silently ignore every page size a client asked for.
            assert_eq!(limits.clamp_count(Some(1)), 1);
            assert_eq!(
                limits.clamp_count(Some(0)),
                0,
                "a count of zero is a metadata-only request, not an unset one"
            );
        }
    }

    #[test]
    fn nothing_is_advertised_that_this_crate_cannot_enforce() {
        // The rule the module states, asserted rather than promised. Each `supported: true`
        // names a capability with an implementation in this crate; each `false` names one
        // without. A future edit that flips a flag has to come back here and say which code
        // makes it true.
        let document = rendered(ScimLimits::default());
        // Each of these names the ROUTE that makes it true, not the parser that would serve
        // one. That distinction is the finding this test exists to have caught and did not:
        // it asserted `bulk: true` justified by `validate_bulk`, which is a function in this
        // crate, while `scim_router` mounts no `/Bulk` at all. A capability is what a caller
        // can REACH. `every_advertised_capability_is_reachable` in tests/surface.rs drives
        // them through the real router, which is the assertion this one cannot make.
        assert_eq!(
            document["patch"]["supported"], true,
            "PATCH /Users/{{id}} and /Groups/{{id}} are mounted"
        );
        assert_eq!(
            document["bulk"]["supported"], false,
            "no /Bulk route is mounted; validate_bulk is a parser, not a capability"
        );
        assert_eq!(
            document["filter"]["supported"], true,
            "GET /Users and /Groups accept ?filter="
        );
        assert_eq!(
            document["changePassword"]["supported"], false,
            "no SCIM write in this crate sets a password"
        );
        assert_eq!(document["sort"]["supported"], false, "no sort is parsed");
        assert_eq!(document["etag"]["supported"], false, "no version is stored");
    }

    #[test]
    fn the_document_is_the_shape_rfc_7644_section_4_describes() {
        // A connector reads this without special-casing the server, which means the field
        // names are the RFC's rather than Rust's.
        let document = rendered(ScimLimits::default());
        assert_eq!(
            document["schemas"][0],
            "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
        );
        for required in [
            "patch",
            "bulk",
            "filter",
            "changePassword",
            "sort",
            "etag",
            "authenticationSchemes",
        ] {
            assert!(
                document.get(required).is_some(),
                "the document must carry {required}"
            );
        }
        assert_eq!(
            document["authenticationSchemes"][0]["type"],
            "oauthbearertoken"
        );
    }
}
