// SPDX-License-Identifier: MIT OR Apache-2.0

//! The S3 side of the scheduled backup runner (issue #153): the object key layout, the
//! signed `ListObjectsV2` and `DeleteObject` requests, and the retention prune.
//!
//! # What lives here and what does not
//!
//! The SEAL lives in `ironauth-jose::backup` and the runner (which runs `pg_dump`, refuses
//! an RLS-subjected role or an empty dump, and PUTs the sealed bytes) lives in the binary.
//! This module is the pure S3 half: everything that must be testable without a database and
//! without a network - and it is, structurally, the same way the `SigV4` module is. The
//! end-to-end signature against a real S3-compatible endpoint belongs to the same
//! conformance run the log sink's PUT documents, because it cannot be verified here.

use std::time::{Duration, SystemTime};

use crate::sigv4::{
    CanonicalRequest, authorization_header, credential_scope, sha256_hex, sign, string_to_sign,
};

/// The S3 service name used in the credential scope, matching the log sink.
const SERVICE: &str = "s3";

/// The lower bound for `retention_secs`: an operator that wants "never delete" writes 0,
/// so every positive value here means a real prune window.
const MIN_RETENTION_SECS: u64 = 60;

/// The path of a backup object, derived from the instant it was produced.
///
/// `<prefix>/<yyyymmdd>/<yyyymmddThhmmssZ>.bin`. A day-ordered layout is what makes a
/// retention LIST cheap: the runner lists `{prefix}/{date}/` for the dates older than the
/// window and deletes every object it finds there, without listing the whole bucket.
/// A timestamped key means a retried run creates a second object - the accepted semantics
/// for backups (at least once with occasional duplicates), where the log sink's
/// batch-derived key would be the wrong shape because a NEW backup must never overwrite
/// an OLD one.
///
/// # Panics
///
/// Panics if `instant` is before the Unix epoch: a signing clock before the epoch is a
/// configuration error this module refuses to paper over.
#[must_use]
pub fn object_key(prefix: &str, instant: SystemTime) -> String {
    let (date, timestamp) = crate::log_shipper::sigv4_timestamps(instant)
        .expect("the signing clock is after the epoch");
    format!("{prefix}/{date}/{timestamp}.bin")
}

/// The retention decision is EXACT, not date-granular: every object key embeds its
/// production instant (`{prefix}/{yyyymmdd}/{yyyymmddThhmmssZ}.bin`), so the prune set is
/// the keys whose embedded timestamp is strictly older than the window. A backup taken
/// 23h59m ago under a 24h retention is kept, whatever its date directory says.
///
/// With a `retention_secs` of zero (keep forever) the caller never lists at all.
///
/// # The listing is one pass, and the prune self-bounds it
///
/// A `ListObjectsV2` response holds at most one thousand keys. A bucket held at the
/// retention window has at most `retention_days x backups_per_day` keys, so a single page
/// covers it; a backlog larger than a page takes a few passes, because every pass deletes
/// the old keys it found, and the next listing starts from the remainder. The runner
/// therefore issues ONE listing with no continuation token, and the prune converges.
#[must_use]
pub fn retention_list_prefix(prefix: &str) -> String {
    format!("{prefix}/")
}

/// The keys to delete from a listing: those whose embedded timestamp is strictly older
/// than the window.
///
/// # Panics
///
/// Panics if `now` is before the Unix epoch (see [`object_key`]).
#[must_use]
pub fn prune_set(
    keys: &[String],
    prefix: &str,
    now: SystemTime,
    retention_secs: u64,
) -> Vec<String> {
    if retention_secs == 0 {
        return Vec::new();
    }
    let cutoff = now
        .checked_sub(Duration::from_secs(retention_secs))
        .unwrap_or(SystemTime::UNIX_EPOCH)
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("the clock is after the epoch")
        .as_secs();
    keys.iter()
        .filter(|key| embedded_timestamp_secs(key, prefix).is_some_and(|seconds| seconds < cutoff))
        .cloned()
        .collect()
}

/// The production instant embedded in an object key, in unix seconds.
///
/// Returns `None` for a key that is not ours (a foreign object in the prefix) - foreign
/// objects are never pruned, because deleting what the layout does not own is how a prune
/// pass eats the bucket.
fn embedded_timestamp_secs(key: &str, prefix: &str) -> Option<u64> {
    let prefix_with_slash = format!("{prefix}/");
    let rest = key.strip_prefix(&prefix_with_slash)?;
    let (date, timestamp) = rest.split_once('/')?;
    if date.len() != 8 || !date.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let timestamp = timestamp.strip_suffix(".bin")?;
    if timestamp.len() != 16
        || timestamp.as_bytes().get(8) != Some(&b'T')
        || !timestamp.ends_with('Z')
    {
        return None;
    }
    let year: u32 = timestamp[0..4].parse().ok()?;
    let month: u32 = timestamp[4..6].parse().ok()?;
    let day: u32 = timestamp[6..8].parse().ok()?;
    let hour: u32 = timestamp[9..11].parse().ok()?;
    let minute: u32 = timestamp[11..13].parse().ok()?;
    let second: u32 = timestamp[13..15].parse().ok()?;
    let days = days_from_civil(i64::from(year), month, day)?;
    Some(
        u64::try_from(days).ok()? * 86_400
            + u64::from(hour) * 3600
            + u64::from(minute) * 60
            + u64::from(second),
    )
}

/// Days since the epoch for a civil date, the inverse of the shipper's `civil_from_days`
/// (Howard Hinnant's algorithm, both directions).
fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy =
        (153 * (i64::from(month) + if month > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

/// The keys to prune from a `ListObjectsV2` response body, given the prefix the listing
/// asked for.
///
/// The listing is for a date directory; everything it returns under that prefix is older
/// than the retention window by construction, so the response's keys ARE the prune set.
///
/// # What the parser accepts
///
/// The S3-compatible responses the runner targets all render `ListObjectsV2` as XML with
/// `<Contents><Key>...</Key></Contents>` entries. The parser matches the `Key` element
/// text inside `Contents`, and refuses a response with no `<Contents>` at all rather than
/// returning an empty prune set - an empty set from an actually-empty listing and an empty
/// set from an unparsed response are indistinguishable, and only one of them should
/// conclude a prune pass.
#[must_use]
pub fn keys_from_listing(body: &[u8]) -> Option<Vec<String>> {
    let text = std::str::from_utf8(body).ok()?;
    if !text.contains("<Contents>") {
        return None;
    }
    let mut keys = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("<Contents>") {
        let after_contents = &rest[start + "<Contents>".len()..];
        let key_start = after_contents.find("<Key>")?;
        let after_key = &after_contents[key_start + "<Key>".len()..];
        let key_end = after_key.find("</Key>")?;
        keys.push(after_key[..key_end].to_owned());
        rest = &after_contents[key_start + after_key[..key_end].len() + "<Key></Key>".len()..];
    }
    Some(keys)
}

/// The signed `ListObjectsV2` request for a prefix: (URL, headers).
///
/// The query is `list-type=2` and `prefix`, percent-encoded. The payload hash is the
/// SHA-256 of the empty string, which S3 expects for a bodyless GET.
#[must_use]
pub fn list_request(
    endpoint: &str,
    bucket: &str,
    prefix: &str,
    region: &str,
    credential: &str,
    now: SystemTime,
) -> (String, Vec<(&'static str, String)>) {
    let (access_key, secret) = split_credential(credential);
    let (date, timestamp) = sigv4_timestamps(now);
    let host = host_of(endpoint);
    let encoded_prefix = urlencode(prefix);
    let path = format!("/{bucket}");
    let query = vec![
        ("list-type".to_string(), "2".to_string()),
        ("prefix".to_string(), encoded_prefix),
    ];
    let payload_hash = sha256_hex(b"");
    let headers = vec![
        ("host".to_string(), host.clone()),
        ("x-amz-date".to_string(), timestamp.clone()),
    ];
    let canonical = CanonicalRequest {
        method: "GET",
        path: &path,
        query: &query,
        headers: headers.clone(),
        payload_hash: &payload_hash,
    };
    let scope = credential_scope(&date, region, SERVICE);
    let to_sign = string_to_sign(&timestamp, &scope, &canonical.render());
    let signature = sign(secret, &date, region, SERVICE, &to_sign);
    let authorization =
        authorization_header(access_key, &scope, &canonical.signed_headers(), &signature);
    (
        format!("{}{path}", endpoint.trim_end_matches('/')),
        vec![("x-amz-date", timestamp), ("authorization", authorization)],
    )
}

/// The signed `DeleteObject` request for one key: (URL, headers).
#[must_use]
pub fn delete_request(
    endpoint: &str,
    bucket: &str,
    key: &str,
    region: &str,
    credential: &str,
    now: SystemTime,
) -> (String, Vec<(&'static str, String)>) {
    let (access_key, secret) = split_credential(credential);
    let (date, timestamp) = sigv4_timestamps(now);
    let host = host_of(endpoint);
    let path = format!("/{bucket}/{key}");
    let payload_hash = sha256_hex(b"");
    let headers = vec![
        ("host".to_string(), host.clone()),
        ("x-amz-date".to_string(), timestamp.clone()),
    ];
    let canonical = CanonicalRequest {
        method: "DELETE",
        path: &path,
        query: &[],
        headers: headers.clone(),
        payload_hash: &payload_hash,
    };
    let scope = credential_scope(&date, region, SERVICE);
    let to_sign = string_to_sign(&timestamp, &scope, &canonical.render());
    let signature = sign(secret, &date, region, SERVICE, &to_sign);
    let authorization =
        authorization_header(access_key, &scope, &canonical.signed_headers(), &signature);
    (
        format!("{}{path}", endpoint.trim_end_matches('/')),
        vec![("x-amz-date", timestamp), ("authorization", authorization)],
    )
}

/// Split an `<access key>:<secret>` credential, the shape every S3 tool takes.
///
/// # Panics
///
/// Panics when the credential has no `:` - the caller validates before any request is
/// signed, so this is a programmer error.
fn split_credential(credential: &str) -> (&str, &str) {
    let (access, secret) = credential
        .split_once(':')
        .expect("an S3 credential is <access key id>:<secret access key>");
    (access, secret)
}

/// The signing timestamps, from the clock seam so a test can pin them.
///
/// # Panics
///
/// Panics if `instant` is before the Unix epoch (see [`object_key`]).
#[must_use]
pub fn sigv4_timestamps(instant: SystemTime) -> (String, String) {
    crate::log_shipper::sigv4_timestamps(instant).expect("the signing clock is after the epoch")
}

/// The `Host` header value: the endpoint with scheme and trailing slash removed.
fn host_of(endpoint: &str) -> String {
    endpoint
        .split("://")
        .nth(1)
        .unwrap_or(endpoint)
        .trim_end_matches('/')
        .to_owned()
}

/// Percent-encode a prefix for the query string: S3 expects the raw characters encoded.
fn urlencode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

/// The retention floor, so a positive-but-tiny window still means a real prune.
#[must_use]
pub const fn min_retention_secs() -> u64 {
    MIN_RETENTION_SECS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instant_at(seconds: u64) -> SystemTime {
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(seconds)
    }

    fn timestamp_of(seconds: u64) -> String {
        crate::log_shipper::sigv4_timestamps(
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(seconds),
        )
        .expect("after the epoch")
        .1
    }

    #[test]
    fn the_object_key_is_a_day_ordered_timestamped_path() {
        assert_eq!(
            object_key("ironauth-backups", instant_at(1_704_067_200)),
            "ironauth-backups/20240101/20240101T000000Z.bin"
        );
    }

    /// The retention prune is exact: a backup taken 23h59m ago under a 24h window is kept,
    /// and one taken a second past the window is deleted.
    #[test]
    fn retention_prunes_only_keys_strictly_older_than_the_window() {
        let noon_jan_1 = 1_704_067_200 + 43_200; // 2024-01-01T12:00:00Z
        let just_kept = format!(
            "ironauth-backups/20231231/{}.bin",
            timestamp_of(noon_jan_1 - 86_359)
        );
        let just_pruned = format!(
            "ironauth-backups/20231231/{}.bin",
            timestamp_of(noon_jan_1 - 86_401)
        );
        let keys = vec![just_kept.clone(), just_pruned.clone()];
        let prune = prune_set(&keys, "ironauth-backups", instant_at(noon_jan_1), 86_400);
        assert_eq!(prune, vec![just_pruned], "the 23h59m59s-old backup is kept");
    }

    #[test]
    fn retention_zero_means_keep_forever() {
        let keys = vec!["ironauth-backups/20230101/20230101T000000Z.bin".to_string()];
        assert_eq!(
            prune_set(&keys, "ironauth-backups", instant_at(1_704_067_200), 0),
            Vec::<String>::new()
        );
    }

    /// A foreign object in the prefix is never pruned: the prune deletes only what the
    /// key layout owns.
    #[test]
    fn a_foreign_key_is_never_pruned() {
        let keys = vec!["ironauth-backups/not-ours.txt".to_string()];
        assert_eq!(
            prune_set(
                &keys,
                "ironauth-backups",
                instant_at(1_704_067_200 + 9 * 86_400),
                86_400
            ),
            Vec::<String>::new()
        );
    }

    /// The parse of an embedded timestamp agrees with the object-key builder, both ways.
    #[test]
    fn the_embedded_timestamp_matches_the_object_key_builder() {
        let instant = instant_at(1_704_067_200);
        let key = object_key("ironauth-backups", instant);
        let seconds = key
            .strip_prefix("ironauth-backups/")
            .and_then(|_| embedded_timestamp_secs(key.as_str(), "ironauth-backups"))
            .expect("the builder's own key parses");
        assert_eq!(seconds, 1_704_067_200);
    }

    /// The listing parser returns the keys and refuses an unparseable body (an empty prune
    /// set from an unparsed response would silently stop retention).
    #[test]
    fn keys_from_listing_parses_the_contents_and_refuses_without_any() {
        let body = br#"<?xml version="1.0"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Contents><Key>ironauth-backups/20240101/20240101T000000Z.bin</Key></Contents>
  <Contents><Key>ironauth-backups/20240101/20240101T120000Z.bin</Key></Contents>
</ListBucketResult>"#;
        assert_eq!(
            keys_from_listing(body).expect("a real listing"),
            vec![
                "ironauth-backups/20240101/20240101T000000Z.bin".to_string(),
                "ironauth-backups/20240101/20240101T120000Z.bin".to_string(),
            ]
        );
        assert_eq!(
            keys_from_listing(b"<ListBucketResult></ListBucketResult>"),
            None,
            "a listing without Contents must not conclude a prune"
        );
    }

    /// The signed list request carries the sorted query and the S3 headers a PUT signs.
    #[test]
    fn the_list_request_sorts_the_query_and_signs_it() {
        let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_704_067_200);
        let (url, headers) = list_request(
            "https://s3.example.test",
            "bucket",
            "ironauth-backups/20240101/",
            "us-east-1",
            "AKID:secret",
            now,
        );
        assert_eq!(url, "https://s3.example.test/bucket");
        let timestamp = headers
            .iter()
            .find(|(name, _)| *name == "x-amz-date")
            .expect("the signing date header")
            .1
            .clone();
        assert_eq!(timestamp, "20240101T000000Z");
        let authorization = headers
            .iter()
            .find(|(name, _)| *name == "authorization")
            .expect("the authorization header")
            .1
            .clone();
        assert!(
            authorization
                .starts_with("AWS4-HMAC-SHA256 Credential=AKID/20240101/us-east-1/s3/aws4_request"),
            "{authorization}"
        );
        assert!(authorization.contains("SignedHeaders=host;x-amz-date"));
    }

    /// The delete request signs a bodyless DELETE against the exact object key.
    #[test]
    fn the_delete_request_targets_the_object_key() {
        let now = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_704_067_200);
        let (url, headers) = delete_request(
            "https://s3.example.test",
            "bucket",
            "ironauth-backups/20240101/20240101T000000Z.bin",
            "us-east-1",
            "AKID:secret",
            now,
        );
        assert_eq!(
            url,
            "https://s3.example.test/bucket/ironauth-backups/20240101/20240101T000000Z.bin"
        );
        let authorization = headers
            .iter()
            .find(|(name, _)| *name == "authorization")
            .expect("the authorization header");
        assert!(authorization.1.contains("SignedHeaders=host;x-amz-date"));
    }
}
