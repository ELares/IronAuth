// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cursor (keyset) pagination for every list endpoint.
//!
//! There is no offset pagination anywhere. A list is ordered by the stable,
//! total key `(created_at, id)`, and a page's cursor is the opaque base64 of the
//! last row's key. The next page selects rows strictly after that key, so
//! insertions and deletions between pages never cause a row to be skipped or
//! returned twice. The page size is capped by config (a safe default, tunable
//! per deployment), never unbounded.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ironauth_store::{CursorPosition, MANAGEMENT_LIST_HARD_CAP};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::error::ApiError;

/// The query parameters common to every list endpoint.
///
/// `limit` is deserialized as a raw string and parsed in [`Pagination::resolve`]
/// (not as a typed `u32`) so a malformed value (`?limit=abc`, `?limit=-1`)
/// surfaces as our structured [`ApiError::BadRequest`] JSON body rather than
/// axum's plain-text query rejection. The OpenAPI schema still documents it as an
/// integer via `#[param(value_type = Option<u32>)]`.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListQuery {
    /// The desired page size, a positive integer. Clamped to
    /// `[1, max_page_size]`; defaults to the configured default when absent.
    #[param(value_type = Option<u32>)]
    pub limit: Option<String>,
    /// The opaque cursor from a previous page's `next_cursor`. Absent for the
    /// first page (keyset pagination; there is no offset).
    pub cursor: Option<String>,
}

/// A resolved pagination request: how many rows to fetch (page size plus one, so
/// the presence of a further page is detectable) and where to start.
#[derive(Debug, Clone)]
pub struct Pagination {
    /// The caller-facing page size (rows returned to the client).
    page_size: usize,
    /// The starting position, or `None` for the first page.
    after: Option<CursorPosition>,
}

impl Pagination {
    /// Resolve query parameters against the configured default and cap.
    ///
    /// The caller-facing page size is `min(requested_or_default, max, hard_cap)`:
    /// the configured `default`/`max` bound it, and the store's
    /// [`MANAGEMENT_LIST_HARD_CAP`] is a final ceiling (config load already
    /// rejects a `max` above the cap; clamping here is defense in depth).
    ///
    /// # Errors
    ///
    /// [`ApiError::BadRequest`] if `limit` is not a positive integer or the
    /// cursor is malformed.
    pub fn resolve(query: &ListQuery, default: u32, max: u32) -> Result<Self, ApiError> {
        let requested = match &query.limit {
            None => None,
            Some(raw) => Some(raw.parse::<u32>().map_err(|_| {
                ApiError::BadRequest("limit must be a positive integer".to_owned())
            })?),
        };
        let page_size = match requested {
            // Clamp the default to the max too (the config doc promises this).
            None => default.min(max),
            Some(0) => {
                return Err(ApiError::BadRequest("limit must be at least 1".to_owned()));
            }
            Some(value) => value.min(max),
        };
        let hard_cap = u32::try_from(MANAGEMENT_LIST_HARD_CAP).unwrap_or(u32::MAX);
        let page_size = page_size.min(hard_cap);
        let after = match &query.cursor {
            None => None,
            Some(raw) => Some(decode_cursor(raw)?),
        };
        Ok(Self {
            page_size: page_size as usize,
            after,
        })
    }

    /// The number of rows to fetch: one more than the page size, so a full extra
    /// row signals that a further page exists.
    #[must_use]
    pub fn fetch_limit(&self) -> i64 {
        // page_size comes from a u32 clamp, so +1 never overflows i64.
        i64::try_from(self.page_size).unwrap_or(i64::MAX - 1) + 1
    }

    /// The starting cursor position, for the repository query.
    #[must_use]
    pub fn after(&self) -> Option<&CursorPosition> {
        self.after.as_ref()
    }

    /// Trim an over-fetched result to the page size and derive the next cursor.
    ///
    /// `rows` is the raw query result (up to `fetch_limit` rows). `key` extracts
    /// the `(created_at_micros, id)` sort key from a row. Returns the rows to
    /// return and the opaque cursor for the next page (or `None` on the last
    /// page).
    #[must_use]
    pub fn finish<T>(
        &self,
        mut rows: Vec<T>,
        key: impl Fn(&T) -> (i64, String),
    ) -> (Vec<T>, Option<String>) {
        if rows.len() > self.page_size {
            rows.truncate(self.page_size);
            let next = rows.last().map(|last| {
                let (micros, id) = key(last);
                encode_cursor(micros, &id)
            });
            (rows, next)
        } else {
            (rows, None)
        }
    }
}

/// Encode a `(created_at_micros, id)` position into an opaque cursor.
fn encode_cursor(created_at_unix_micros: i64, id: &str) -> String {
    URL_SAFE_NO_PAD.encode(format!("{created_at_unix_micros}:{id}"))
}

/// Decode an opaque cursor, or reject it as a bad request.
fn decode_cursor(raw: &str) -> Result<CursorPosition, ApiError> {
    let bad = || ApiError::BadRequest("malformed pagination cursor".to_owned());
    let bytes = URL_SAFE_NO_PAD.decode(raw.as_bytes()).map_err(|_| bad())?;
    let text = String::from_utf8(bytes).map_err(|_| bad())?;
    let (micros, id) = text.split_once(':').ok_or_else(bad)?;
    let created_at_unix_micros = micros.parse::<i64>().map_err(|_| bad())?;
    if id.is_empty() {
        return Err(bad());
    }
    Ok(CursorPosition {
        created_at_unix_micros,
        id: id.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trips() {
        let encoded = encode_cursor(1_700_000_000_000_000, "ten_abc");
        let decoded = decode_cursor(&encoded).expect("round-trips");
        assert_eq!(decoded.created_at_unix_micros, 1_700_000_000_000_000);
        assert_eq!(decoded.id, "ten_abc");
    }

    #[test]
    fn malformed_cursor_is_rejected() {
        for raw in ["not-base64-!!", "", "bm90LWNvbG9u"] {
            assert!(
                matches!(decode_cursor(raw), Err(ApiError::BadRequest(_))),
                "{raw}"
            );
        }
    }

    fn query(limit: Option<&str>, cursor: Option<&str>) -> ListQuery {
        ListQuery {
            limit: limit.map(str::to_owned),
            cursor: cursor.map(str::to_owned),
        }
    }

    #[test]
    fn resolve_clamps_and_defaults() {
        let capped = Pagination::resolve(&query(Some("10000"), None), 50, 200).expect("valid");
        assert_eq!(capped.page_size, 200);
        assert_eq!(capped.fetch_limit(), 201);

        let defaulted = Pagination::resolve(&ListQuery::default(), 50, 200).expect("valid");
        assert_eq!(defaulted.page_size, 50);

        assert!(matches!(
            Pagination::resolve(&query(Some("0"), None), 50, 200),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn a_default_above_the_max_is_clamped_to_the_max() {
        // The config doc promises default_page_size is clamped to max_page_size;
        // the None arm must honor that even if a caller passes an unclamped pair.
        let resolved = Pagination::resolve(&ListQuery::default(), 500, 100).expect("valid");
        assert_eq!(resolved.page_size, 100, "default clamped down to the max");
    }

    #[test]
    fn a_malformed_limit_is_a_bad_request_not_a_plain_text_400() {
        for raw in ["abc", "-1", "", "3.5", "99999999999999999999"] {
            assert!(
                matches!(
                    Pagination::resolve(&query(Some(raw), None), 50, 200),
                    Err(ApiError::BadRequest(_))
                ),
                "limit={raw:?} must be a structured bad request"
            );
        }
    }

    #[test]
    fn the_page_size_never_exceeds_the_hard_cap() {
        let hard_cap = u32::try_from(MANAGEMENT_LIST_HARD_CAP).unwrap();
        // Even with an (out-of-policy) max above the cap, the returned page is
        // bounded by the hard cap so the store's sentinel row is never dropped.
        let resolved = Pagination::resolve(&query(Some("100000"), None), hard_cap, hard_cap + 5000)
            .expect("valid");
        assert_eq!(resolved.page_size, usize::try_from(hard_cap).expect("fits"));
    }

    #[test]
    fn the_config_and_store_hard_caps_agree() {
        // The store applies its own hard cap to every list fetch; config load
        // validates max_page_size against its mirror of the same value. They must
        // stay equal or config could permit a page the store then truncates.
        assert_eq!(
            i64::from(ironauth_config::MANAGEMENT_LIST_HARD_CAP),
            MANAGEMENT_LIST_HARD_CAP
        );
    }

    #[test]
    fn finish_trims_and_sets_next_cursor() {
        let page = Pagination {
            page_size: 2,
            after: None,
        };
        let (rows, next) = page.finish(vec![(1_i64, "a"), (2, "b"), (3, "c")], |(m, id)| {
            (*m, (*id).to_owned())
        });
        assert_eq!(rows.len(), 2, "trimmed to page size");
        assert!(next.is_some(), "a further page exists");
        let decoded = decode_cursor(&next.unwrap()).expect("cursor");
        assert_eq!(decoded.id, "b", "cursor is the last kept row");

        let last = Pagination {
            page_size: 5,
            after: None,
        };
        let (rows, next) = last.finish(vec![(1_i64, "a")], |(m, id)| (*m, (*id).to_owned()));
        assert_eq!(rows.len(), 1);
        assert!(next.is_none(), "last page has no cursor");
    }
}
