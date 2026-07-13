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
use ironauth_store::CursorPosition;
use serde::Deserialize;
use utoipa::IntoParams;

use crate::error::ApiError;

/// The query parameters common to every list endpoint.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListQuery {
    /// The desired page size. Clamped to `[1, max_page_size]`; defaults to the
    /// configured default when absent.
    pub limit: Option<u32>,
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
    /// # Errors
    ///
    /// [`ApiError::BadRequest`] if `limit` is zero or the cursor is malformed.
    pub fn resolve(query: &ListQuery, default: u32, max: u32) -> Result<Self, ApiError> {
        let page_size = match query.limit {
            None => default,
            Some(0) => {
                return Err(ApiError::BadRequest("limit must be at least 1".to_owned()));
            }
            Some(requested) => requested.min(max),
        };
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

    #[test]
    fn resolve_clamps_and_defaults() {
        let capped = Pagination::resolve(
            &ListQuery {
                limit: Some(10_000),
                cursor: None,
            },
            50,
            200,
        )
        .expect("valid");
        assert_eq!(capped.page_size, 200);
        assert_eq!(capped.fetch_limit(), 201);

        let defaulted = Pagination::resolve(&ListQuery::default(), 50, 200).expect("valid");
        assert_eq!(defaulted.page_size, 50);

        assert!(matches!(
            Pagination::resolve(
                &ListQuery {
                    limit: Some(0),
                    cursor: None
                },
                50,
                200
            ),
            Err(ApiError::BadRequest(_))
        ));
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
