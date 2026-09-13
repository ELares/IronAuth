// SPDX-License-Identifier: MIT OR Apache-2.0

//! The access-review export: who holds which role, and by which path (issue #145).
//!
//! # What this is for
//!
//! #145's first acceptance criterion asks for an export answering "who has which role per
//! tenant/env/org", INCLUDING derived-assignment sources, in JSONL and CSV, ingestible by a
//! SailPoint-style consumer. The consumers are compliance tools: a SOC2 evidence pipeline
//! wants a point-in-time file it can diff between quarters, and an IGA tool wants to know not
//! just that someone holds a role but what to withdraw to take it away.
//!
//! # One definition of "effective", not a second one
//!
//! The rows are assembled from the effective-grant resolvers, once per member --
//! [`OrgGroupRepo::effective_role_grants`] for a person and
//! [`OrgGroupRepo::effective_role_grants_for_service_account`] for a machine -- rather than
//! from one SQL statement that joins the assignment tables itself. That is a deliberate trade
//! of queries for correctness.
//!
//! A second statement would be a SECOND ANSWER to "which roles does this person hold", and the
//! entire value of this export is that it agrees with the one the product uses. The existing
//! resolver already carries a bounded ancestor walk, liveness filtering on every table, the
//! organization's own lifecycle, and the DEFAULT role that has no row to join to at all. A
//! hand-written export join would reproduce none of those on its first day and would drift
//! from them afterwards, and the failure mode is an auditor's evidence file quietly
//! disagreeing with what tokens actually carry.
//!
//! # The multiset is preserved, and that is the point of the export
//!
//! A role reachable by several paths yields several rows, exactly as the resolver returns
//! several grants. Collapsing to one row per role would answer "does this person hold it" while
//! destroying "what do I withdraw to stop them holding it", and the second question is the one
//! an access review exists to answer. `effective_role_grants` documents the same reasoning for
//! the same decision.
//!
//! # The reader is strict where the writer is, and liberal about one thing
//!
//! [`parse_csv`] is a second implementation rather than the inverse of [`to_csv`], so it can
//! discover that the writer's quoting is unrecoverable rather than merely present. For that to
//! mean anything it has to REFUSE what a broken writer would emit: a bare quote inside an
//! unquoted field and a bare carriage return are both errors, because RFC 4180's `TEXTDATA`
//! excludes them. An earlier version accepted both as data, and three of the four quoting
//! characters could be dropped from the writer with the round trip still byte-identical.
//!
//! The single liberality is the record separator: a lone LF ends a record even though the
//! grammar says CRLF. A file that leaves this process gets normalized by ordinary things, and
//! the strict reading turned an LF-normalized export into ONE record that was consumed as the
//! header -- a successful parse reporting that nobody holds any role.

use crate::repository::{EffectiveRoleGrant, EffectiveRoleSource};

/// One PATH by which one member of one organization holds one role.
///
/// A member holding NOTHING still gets a row, with an empty `role_slug` and a `source` of
/// `none`. Omitting them made a person who holds no role indistinguishable from a person who
/// is not a member, and "this employee has no access" is a finding an access review exists to
/// report. It is also what a disabled organization now looks like -- every member present,
/// every one of them holding nothing -- rather than an empty file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessReviewRow {
    /// The organization the review is of (`org_...`).
    pub organization_id: String,
    /// Whether the member is a person or a machine: `user` or `service_account`.
    ///
    /// BOTH ARE MEMBERS. Service accounts have been first-class organization members since
    /// migration 0124 and resolve roles through the same closure, so an export of "who has
    /// which role" that listed only people would leave a machine identity holding
    /// `billing.admin` off the evidence entirely.
    pub principal_kind: &'static str,
    /// The membership the role reaches (`omb_...`).
    pub membership_id: String,
    /// The person or machine behind that membership (`usr_...` or `sva_...`).
    pub subject_id: String,
    /// The role's immutable slug, or empty on a `none` row.
    pub role_slug: String,
    /// Which kind of path this row records: `direct`, `group`, `default`, `time_boxed`,
    /// or `none`.
    pub source: &'static str,
    /// The group the role is inherited from, present only on a `group` row.
    ///
    /// A `default` row's emptiness is not an omission: the organization's default role has no
    /// assignment row anywhere, which is why the resolver has a variant for it, and an export
    /// that invented an id here would send a consumer looking for a row to withdraw that does
    /// not exist.
    pub via_group_id: Option<String>,
    /// The access request the role is held through, present only on a `time_boxed` row
    /// (issue #145 criterion 4, EXPLORATORY).
    ///
    /// Its OWN column rather than reusing `via_group_id`. The first version put the
    /// `agr_...` id there, and a consumer reading a column named for a group would have
    /// joined it against the group list and found nothing.
    pub via_request_id: Option<String>,
    /// When a `time_boxed` row stops granting, in epoch milliseconds.
    ///
    /// The only row kind that ends on its own. An auditor asking "and for how long" has no
    /// other column to read it from, and a review that showed the elevation without its end
    /// would report a standing grant.
    pub granted_until_unix_ms: Option<i64>,
}

impl AccessReviewRow {
    /// The rows one member contributes, in the order the resolver returned its grants.
    ///
    /// Never empty: a member with no grants contributes one `none` row, for the reason on the
    /// struct.
    #[must_use]
    pub fn from_grants(
        organization_id: &str,
        principal_kind: &'static str,
        membership_id: &str,
        subject_id: &str,
        grants: &[EffectiveRoleGrant],
    ) -> Vec<Self> {
        let row = |role_slug: String,
                   source: &'static str,
                   via_group_id: Option<String>,
                   via_request_id: Option<String>,
                   granted_until_unix_ms: Option<i64>| Self {
            organization_id: organization_id.to_owned(),
            principal_kind,
            membership_id: membership_id.to_owned(),
            subject_id: subject_id.to_owned(),
            role_slug,
            source,
            via_group_id,
            via_request_id,
            granted_until_unix_ms,
        };
        if grants.is_empty() {
            return vec![row(String::new(), "none", None, None, None)];
        }
        grants
            .iter()
            .map(|grant| {
                let (source, via_group_id, via_request_id, until) = match &grant.source {
                    EffectiveRoleSource::Direct => ("direct", None, None, None),
                    EffectiveRoleSource::Group(group) => {
                        ("group", Some(group.to_string()), None, None)
                    }
                    EffectiveRoleSource::Default => ("default", None, None, None),
                    // The request goes in its OWN column, not in `via_group_id`: a consumer
                    // reading a column named for a group would join an `agr_` id against
                    // the group list and find nothing.
                    EffectiveRoleSource::TimeBoxed {
                        request_id,
                        granted_until_micros,
                    } => (
                        "time_boxed",
                        None,
                        Some(request_id.clone()),
                        Some(granted_until_micros / 1000),
                    ),
                };
                row(
                    grant.slug.clone(),
                    source,
                    via_group_id,
                    via_request_id,
                    until,
                )
            })
            .collect()
    }
}

/// The column order both formats use, spelled once.
///
/// SHARED DELIBERATELY. Two lists would agree until somebody added a column to one, and a
/// consumer pinning the CSV header against the JSONL keys is exactly what a versioned contract
/// fixture does.
pub const ACCESS_REVIEW_COLUMNS: [&str; 9] = [
    "organization_id",
    "principal_kind",
    "membership_id",
    "subject_id",
    "role_slug",
    "source",
    "via_group_id",
    // APPENDED, never inserted: a consumer pinning by position keeps every column it had,
    // and one pinning by name is unaffected. Both are empty on every row unless the
    // exploratory access-request feature is acknowledged, but the HEADER carries them for
    // every deployment, which is the contract change this makes and the changelog states.
    "via_request_id",
    "granted_until_unix_ms",
];

/// The rows as JSON Lines: one object per line, trailing newline after the last.
///
/// A MISSING `via_group_id` IS NULL RATHER THAN ABSENT, so every line has the same key set and
/// a consumer reading a column-oriented frame does not have to guess a schema from the first
/// line it happens to see.
#[must_use]
pub fn to_jsonl(rows: &[AccessReviewRow]) -> String {
    let mut out = String::new();
    for row in rows {
        let value = serde_json::json!({
            "organization_id": row.organization_id,
            "principal_kind": row.principal_kind,
            "membership_id": row.membership_id,
            "subject_id": row.subject_id,
            "role_slug": row.role_slug,
            "source": row.source,
            "via_group_id": row.via_group_id,
            "via_request_id": row.via_request_id,
            "granted_until_unix_ms": row.granted_until_unix_ms,
        });
        out.push_str(&value.to_string());
        out.push('\n');
    }
    out
}

/// The rows as RFC 4180 CSV, header first, CRLF line endings.
///
/// CRLF BECAUSE RFC 4180 SAYS SO, and because the consumers here are spreadsheet and
/// evidence-pipeline tools rather than unix filters. A bare LF file is accepted by most of
/// them and rejected by some, and the ones that reject it are the ones an auditor uses.
#[must_use]
pub fn to_csv(rows: &[AccessReviewRow]) -> String {
    let mut out = String::new();
    out.push_str(&ACCESS_REVIEW_COLUMNS.join(","));
    out.push_str("\r\n");
    for row in rows {
        let fields = [
            row.organization_id.as_str(),
            row.principal_kind,
            row.membership_id.as_str(),
            row.subject_id.as_str(),
            row.role_slug.as_str(),
            row.source,
            row.via_group_id.as_deref().unwrap_or(""),
            row.via_request_id.as_deref().unwrap_or(""),
            // EMPTY rather than `0` when absent: a consumer reading a deadline out of a
            // row that never had one would schedule a revocation for a grant that does
            // not exist, which is the same mistake the event payload avoids.
            &row.granted_until_unix_ms
                .map(|at| at.to_string())
                .unwrap_or_default(),
        ];
        let encoded: Vec<String> = fields.iter().map(|field| csv_field(field)).collect();
        out.push_str(&encoded.join(","));
        out.push_str("\r\n");
    }
    out
}

/// One CSV field, quoted when RFC 4180 requires it.
///
/// QUOTED ON THE FOUR CHARACTERS THE GRAMMAR NAMES, not on the two that are obvious. A comma
/// or a quote is what everybody remembers; a bare CR or LF inside a field is what turns one
/// record into two in a reader that splits on newlines before it parses quotes, and that is
/// the failure that silently changes an access review's row count rather than erroring.
fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

/// A consumer's view of one exported row, parsed back from a file.
///
/// SEPARATE FROM [`AccessReviewRow`] ON PURPOSE. A round-trip test that parses into the
/// producer's own type with the producer's own field order proves the two halves of one
/// implementation agree, which they will whatever either of them does wrong. This is the
/// shape an outside consumer builds: fields looked up BY NAME off the header, values as
/// strings, nothing shared with the writer but the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedRow {
    /// Column name to value, sorted by column name.
    ///
    /// A `BTreeMap` rather than the file's order, because a consumer looks fields up BY NAME
    /// off the header -- which is the whole point of parsing the header -- and two files whose
    /// columns are ordered differently should compare equal.
    pub fields: std::collections::BTreeMap<String, String>,
}

/// Parse an RFC 4180 CSV export the way a compliance tool would: header first, fields by name.
///
/// Written as a second implementation rather than as the inverse of [`to_csv`], because a
/// parser sharing the writer's quoting decisions cannot discover that those decisions are
/// wrong. This one implements the grammar from the spec: a quoted field ends at a quote not
/// followed by another quote, and separators inside quotes are data.
///
/// # Errors
///
/// A message naming what was malformed, so a failing contract test says which record.
pub fn parse_csv(text: &str) -> Result<Vec<ConsumedRow>, String> {
    let mut records: Vec<Vec<String>> = Vec::new();
    let mut field = String::new();
    let mut record: Vec<String> = Vec::new();
    // Inside a quoted field.
    let mut quoted = false;
    // A quoted field just CLOSED. RFC 4180 allows only a comma or a record separator after
    // the closing quote, and tracking it is what stops `"abc"def` being absorbed as `abcdef`:
    // clearing `quoted` alone left the unquoted branch appending to the same buffer.
    let mut closed = false;
    // A field has BEGUN in this record. Without it the end-of-file flush cannot tell a record
    // whose only field is an empty quoted string from no record at all, and dropped it.
    let mut started = false;
    let mut chars = text.chars().peekable();
    let mut any = false;
    while let Some(ch) = chars.next() {
        any = true;
        if quoted {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    quoted = false;
                    closed = true;
                }
            } else {
                field.push(ch);
            }
            continue;
        }
        match ch {
            ',' => {
                record.push(std::mem::take(&mut field));
                closed = false;
                started = true;
            }
            // A BARE LF ENDS A RECORD, deliberately, though the grammar says CRLF. A file that
            // leaves this process is normalized by routine things -- an editor save,
            // core.autocrlf, a transport -- and treating a lone LF as field data collapsed an
            // LF-normalized export into ONE record, which was consumed as the header, so the
            // answer was Ok with zero rows: a successful parse reporting that nobody holds any
            // role. The reader is liberal about the separator and strict about everything else.
            '\r' | '\n' => {
                if ch == '\r' {
                    if chars.peek() != Some(&'\n') {
                        return Err(format!(
                            "record {} carries a bare carriage return outside a quoted field",
                            records.len()
                        ));
                    }
                    chars.next();
                }
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
                closed = false;
                started = false;
            }
            '"' => {
                // RFC 4180's TEXTDATA excludes DQUOTE, so a quote anywhere but the start of a
                // field is malformed. Accepting it as data made this parser unable to notice a
                // writer that had stopped quoting: the round trip came back byte-identical.
                if closed || !field.is_empty() {
                    return Err(format!(
                        "record {} has a bare quote inside an unquoted field",
                        records.len()
                    ));
                }
                quoted = true;
                started = true;
            }
            _ => {
                if closed {
                    return Err(format!(
                        "record {} has text after a closing quote",
                        records.len()
                    ));
                }
                field.push(ch);
                started = true;
            }
        }
    }
    if quoted {
        return Err("the file ends inside a quoted field".to_owned());
    }
    // `started` is what makes a final record of one empty quoted field survive: its field and
    // its record are both empty, and the earlier condition dropped it.
    if started || !field.is_empty() || !record.is_empty() {
        record.push(field);
        records.push(record);
    }
    if !any {
        return Err("the export is empty, not even a header".to_owned());
    }
    let mut rows = Vec::new();
    let mut records = records.into_iter();
    let header = records.next().ok_or("the export has no header")?;
    for (index, values) in records.enumerate() {
        if values.len() != header.len() {
            return Err(format!(
                "record {index} has {} fields against a header of {}",
                values.len(),
                header.len()
            ));
        }
        rows.push(ConsumedRow {
            fields: header.iter().cloned().zip(values).collect(),
        });
    }
    Ok(rows)
}

/// Parse a JSON Lines export the way a compliance tool would: one object per line, by name.
///
/// # Errors
///
/// A message naming the line that was not a flat JSON object.
pub fn parse_jsonl(text: &str) -> Result<Vec<ConsumedRow>, String> {
    let mut rows = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|e| format!("line {index} is not JSON: {e}"))?;
        let object = value
            .as_object()
            .ok_or_else(|| format!("line {index} is not a JSON object"))?;
        let mut fields = std::collections::BTreeMap::new();
        for (key, value) in object {
            // A NULL BECOMES THE EMPTY STRING, which is what the CSV carries for the same
            // absent value. The two formats have to land on one consumer-visible shape or a
            // tool pinning both sees two different access reviews.
            let rendered = match value {
                serde_json::Value::Null => String::new(),
                serde_json::Value::String(text) => text.clone(),
                other => other.to_string(),
            };
            fields.insert(key.clone(), rendered);
        }
        rows.push(ConsumedRow { fields });
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A row of the fourth source, with DISTINCT non-empty values in both new columns.
    ///
    /// Distinct on purpose: every other fixture leaves `via_request_id` and
    /// `granted_until_unix_ms` as `None`, so both render as the empty string and swapping the
    /// two entries in `to_csv`'s field list is invisible to the whole suite. Two values that
    /// cannot be mistaken for each other -- an `agr_` id and an integer -- make the positional
    /// mapping of the two appended columns measurable.
    fn time_boxed_row(request: &str, granted_until_unix_ms: i64) -> AccessReviewRow {
        AccessReviewRow {
            via_request_id: Some(request.to_owned()),
            granted_until_unix_ms: Some(granted_until_unix_ms),
            ..row("time_boxed", None)
        }
    }

    fn row(source: &'static str, via: Option<&str>) -> AccessReviewRow {
        AccessReviewRow {
            organization_id: "org_1".to_owned(),
            principal_kind: "user",
            membership_id: "omb_1".to_owned(),
            subject_id: "usr_1".to_owned(),
            role_slug: "admin".to_owned(),
            source,
            via_group_id: via.map(str::to_owned),
            via_request_id: None,
            granted_until_unix_ms: None,
        }
    }

    #[test]
    fn every_jsonl_line_carries_the_same_keys_whatever_the_source() {
        // A consumer that infers a schema from the first line must not meet a later line with
        // a key the first one lacked. The `group` row is the only one with a group id, so a
        // build that omitted the key on the others would differ line to line.
        let text = to_jsonl(&[
            row("direct", None),
            row("group", Some("grp_9")),
            row("default", None),
        ]);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "one line per row: {text}");
        let keys: Vec<Vec<String>> = lines
            .iter()
            .map(|line| {
                let parsed: serde_json::Value = serde_json::from_str(line).expect("a json object");
                let mut names: Vec<String> = parsed
                    .as_object()
                    .expect("an object")
                    .keys()
                    .cloned()
                    .collect();
                names.sort();
                names
            })
            .collect();
        assert_eq!(
            keys[0], keys[1],
            "the direct and group lines differ in shape"
        );
        assert_eq!(
            keys[1], keys[2],
            "the group and default lines differ in shape"
        );
        assert!(
            keys[0].contains(&"via_group_id".to_owned()),
            "the key has to be present even when empty: {keys:?}"
        );
    }

    #[test]
    fn a_default_row_names_no_group_and_a_group_row_names_its_own() {
        let text = to_jsonl(&[row("group", Some("grp_9")), row("default", None)]);
        let mut lines = text.lines();
        let group: serde_json::Value =
            serde_json::from_str(lines.next().expect("a group line")).expect("json");
        let default: serde_json::Value =
            serde_json::from_str(lines.next().expect("a default line")).expect("json");
        assert_eq!(group["via_group_id"], serde_json::json!("grp_9"));
        // NOT AN EMPTY STRING. A consumer filtering on "has a group to withdraw" tests for
        // null; an empty string is a value and passes that test.
        assert_eq!(default["via_group_id"], serde_json::Value::Null);
    }

    #[test]
    fn a_field_carrying_a_delimiter_cannot_split_the_record() {
        // The grammar's four characters, each in its own field, all in one row. A reader that
        // splits on newlines before parsing quotes turns this single record into three, which
        // changes an access review's row COUNT without erroring.
        let nasty = AccessReviewRow {
            organization_id: "org,1".to_owned(),
            principal_kind: "user",
            membership_id: "omb\"1".to_owned(),
            subject_id: "usr\r1".to_owned(),
            role_slug: "ad\nmin".to_owned(),
            source: "direct",
            via_group_id: None,
            via_request_id: None,
            granted_until_unix_ms: None,
        };
        let text = to_csv(&[nasty]);
        assert!(text.contains("\"org,1\""), "a comma must be quoted: {text}");
        assert!(
            text.contains("\"omb\"\"1\""),
            "a quote must be doubled and the field quoted: {text}"
        );
        assert!(text.contains("\"usr\r1\""), "a CR must be quoted: {text}");
        assert!(text.contains("\"ad\nmin\""), "an LF must be quoted: {text}");
        // AND THE RECORD IS STILL ONE RECORD. Splitting on the record separator gives the
        // header, the row, and the trailing empty -- not five pieces.
        let records: Vec<&str> = text.split("\r\n").collect();
        assert_eq!(
            records.len(),
            3,
            "the embedded separators split the record: {records:?}"
        );
    }

    #[test]
    fn the_csv_header_is_the_shared_column_list_in_order() {
        let text = to_csv(&[]);
        assert_eq!(
            text,
            format!("{}\r\n", ACCESS_REVIEW_COLUMNS.join(",")),
            "an empty review is a header and nothing else"
        );
    }

    #[test]
    fn a_consumer_reads_the_same_review_from_either_format() {
        // #145 criterion 1's consumer fixture. The two files are the SAME access review or a
        // tool pinning both sees two, and the only way to find that out is to parse them with
        // something that shares nothing with the writer.
        let rows = [
            row("direct", None),
            row("group", Some("grp_9")),
            row("default", None),
            time_boxed_row("agr_9", 1_767_225_600_000),
        ];
        let from_csv = parse_csv(&to_csv(&rows)).expect("the CSV parses");
        let from_jsonl = parse_jsonl(&to_jsonl(&rows)).expect("the JSONL parses");
        assert_eq!(
            from_csv, from_jsonl,
            "the two exports of one review do not describe the same thing"
        );
        assert_eq!(from_csv.len(), 4, "one consumed row per exported row");
        assert_eq!(
            from_csv[1].fields.get("via_group_id").map(String::as_str),
            Some("grp_9"),
            "the consumer must reach the withdrawable group by name: {:?}",
            from_csv[1]
        );
        // WHICH COLUMN each value lands in, which the equality above cannot see: the JSONL
        // writer is key-based and the CSV writer is position-based, so a swapped pair in the
        // CSV field list makes the two formats DISAGREE and the comparison catches it -- but
        // only if the two values differ. Named separately so a failure says which column.
        assert_eq!(
            from_csv[3].fields.get("via_request_id").map(String::as_str),
            Some("agr_9"),
            "the request id landed in the wrong column: {:?}",
            from_csv[3]
        );
        assert_eq!(
            from_csv[3]
                .fields
                .get("granted_until_unix_ms")
                .map(String::as_str),
            Some("1767225600000"),
            "the deadline landed in the wrong column: {:?}",
            from_csv[3]
        );
        // And the three OTHER sources leave both empty, which is what makes the pair above a
        // measurement of this row rather than of the header.
        for (index, consumed) in from_csv.iter().take(3).enumerate() {
            assert_eq!(
                consumed.fields.get("via_request_id").map(String::as_str),
                Some(""),
                "row {index} is not time-boxed and must name no request"
            );
            assert_eq!(
                consumed
                    .fields
                    .get("granted_until_unix_ms")
                    .map(String::as_str),
                Some(""),
                "row {index} is not time-boxed and must carry no deadline"
            );
        }
    }

    #[test]
    fn a_consumer_recovers_a_value_that_carries_a_delimiter() {
        // The writer quotes; this proves the quoting is RECOVERABLE rather than merely
        // present. A writer that escaped in a way no RFC 4180 reader undoes produces a file
        // that looks right and imports wrong, and the earlier CSV test cannot see that
        // because it only inspects the text the writer produced.
        let nasty = AccessReviewRow {
            organization_id: "org,1".to_owned(),
            principal_kind: "user",
            membership_id: "omb\"1".to_owned(),
            subject_id: "usr\r1".to_owned(),
            role_slug: "ad\nmin".to_owned(),
            source: "direct",
            via_group_id: None,
            via_request_id: None,
            granted_until_unix_ms: None,
        };
        let consumed = parse_csv(&to_csv(std::slice::from_ref(&nasty))).expect("the CSV parses");
        assert_eq!(consumed.len(), 1, "the record split: {consumed:?}");
        let fields = &consumed[0].fields;
        assert_eq!(
            fields.get("organization_id").map(String::as_str),
            Some("org,1")
        );
        assert_eq!(
            fields.get("membership_id").map(String::as_str),
            Some("omb\"1")
        );
        assert_eq!(fields.get("subject_id").map(String::as_str), Some("usr\r1"));
        assert_eq!(fields.get("role_slug").map(String::as_str), Some("ad\nmin"));
    }

    #[test]
    fn an_lf_normalized_export_is_read_rather_than_reported_empty() {
        // A file that leaves this process gets its line endings rewritten by ordinary things.
        // The reader used to treat a lone LF as field data, so the whole export collapsed into
        // one record, that record was consumed as the header, and the answer was Ok with zero
        // rows -- "nobody in this organization holds any role", indistinguishable from a
        // genuinely empty review.
        let rows = [row("direct", None), row("group", Some("grp_9"))];
        let crlf = to_csv(&rows);
        let lf = crlf.replace("\r\n", "\n");
        let from_crlf = parse_csv(&crlf).expect("the CRLF export parses");
        let from_lf = parse_csv(&lf).expect("the LF-normalized export parses");
        assert_eq!(
            from_lf.len(),
            2,
            "the LF file lost its records: {from_lf:?}"
        );
        assert_eq!(
            from_crlf, from_lf,
            "normalizing the line endings changed what the file says"
        );
    }

    /// One legal record whose THIRD field is `body`, with as many fields as the header has
    /// columns however many that becomes.
    ///
    /// The arity is DERIVED rather than written out, and that is the whole reason this helper
    /// exists. The refusal tests below were first written with seven fields spelled out; when
    /// this commit appended two columns, `parse_csv` began refusing every one of those fixtures
    /// on arity before it ever reached the byte rule under test, and all six assertions passed
    /// for a reason that had nothing to do with what they claim to measure. A helper keyed on
    /// `ACCESS_REVIEW_COLUMNS` cannot drift that way again.
    fn one_record_whose_third_field_is(body: &str) -> String {
        let header = ACCESS_REVIEW_COLUMNS.join(",");
        let mut fields: Vec<String> = vec![String::new(); ACCESS_REVIEW_COLUMNS.len()];
        fields[0] = "org_1".to_string();
        fields[1] = "user".to_string();
        fields[2] = body.to_string();
        fields[3] = "usr_1".to_string();
        fields[4] = "admin".to_string();
        fields[5] = "direct".to_string();
        format!("{header}\r\n{}\r\n", fields.join(","))
    }

    #[test]
    fn the_fixture_the_refusal_tests_mutate_is_itself_accepted() {
        // THE CONTROL, and the reason it is a test of its own rather than a line inside each
        // case below. Every refusal assertion is of the form `is_err()`, which a fixture that
        // is malformed for some OTHER reason satisfies just as well. This pins that the only
        // thing wrong with each fixture below is the byte the case is named for: strip that
        // byte and the record parses, so a refusal is attributable to the rule under test.
        let clean = one_record_whose_third_field_is("omb_1");
        let rows = parse_csv(&clean).expect("the unmutated fixture has to parse");
        assert_eq!(rows.len(), 1, "the control fixture is one record");
        assert_eq!(
            rows[0].fields.get("membership_id").map(String::as_str),
            Some("omb_1"),
            "the mutated field is the one the cases below reach"
        );
    }

    #[test]
    fn the_reader_refuses_what_a_writer_that_stopped_quoting_would_emit() {
        // THE POINT OF A SECOND IMPLEMENTATION, and the previous reader failed it for three
        // of the four characters: it accepted a bare quote and a bare CR as data, so a writer
        // that had stopped quoting them round-tripped byte-identical and the mutation lived.
        //
        // Each case below is a line the writer could never legally produce, and differs from
        // the control fixture in exactly one byte.
        let bare_quote = one_record_whose_third_field_is("omb\"1");
        assert!(
            parse_csv(&bare_quote).is_err(),
            "a bare quote in an unquoted field has to be refused, not read as data"
        );

        let bare_cr = one_record_whose_third_field_is("omb\r1");
        assert!(
            parse_csv(&bare_cr).is_err(),
            "a bare carriage return has to be refused, not read as data"
        );

        // The comma and the LF are caught by ARITY rather than by a byte rule: each splits the
        // record, and the field count stops agreeing with the header. Stated because it means
        // these two, unlike the pair above, would still pass against a reader with no byte
        // rules at all -- they measure the arity check, which is a different guarantee.
        let bare_comma = one_record_whose_third_field_is("omb,1");
        assert!(
            parse_csv(&bare_comma).is_err(),
            "an unquoted comma adds a field and has to be refused"
        );
        let bare_lf = one_record_whose_third_field_is("omb\n1");
        assert!(
            parse_csv(&bare_lf).is_err(),
            "an unquoted newline splits the record and has to be refused"
        );
    }

    #[test]
    fn text_after_a_closing_quote_is_refused_rather_than_absorbed() {
        // RFC 4180 allows only a comma or a record separator after a closing quote. Clearing
        // the quoted flag without recording that the field HAD been quoted let the unquoted
        // branch keep appending to the same buffer, so `"abc"def` came back as `abcdef` --
        // a value no writer could produce, silently concatenated and handed to the consumer.
        //
        // Both cases keep the control's arity, so `is_err()` can only be the closing-quote
        // rule: absorbing the trailing text would yield one field and one record, which the
        // control proves parses.
        for bad in [
            one_record_whose_third_field_is("\"omb\"junk"),
            one_record_whose_third_field_is("\"\"xyz"),
        ] {
            assert!(
                parse_csv(&bad).is_err(),
                "text after a closing quote was absorbed instead of refused: {bad}"
            );
        }
    }

    #[test]
    fn a_final_record_of_one_empty_quoted_field_is_not_dropped() {
        // The end-of-file flush asked whether the field or the record held anything. A record
        // whose only field is an empty QUOTED string satisfies neither, so the last line of
        // such a file vanished and the parse reported success with one row fewer.
        let one_column = "only\r\n\"\"";
        let rows = parse_csv(one_column).expect("the file parses");
        assert_eq!(rows.len(), 1, "the final record was dropped: {rows:?}");
        assert_eq!(rows[0].fields.get("only").map(String::as_str), Some(""));
    }

    #[test]
    fn the_two_formats_carry_the_same_columns() {
        // The pair a consumer pins. A column added to one format and not the other is the
        // defect this catches, and it is the one a shared list exists to prevent.
        let rows = [row("group", Some("grp_9"))];
        let json: serde_json::Value =
            serde_json::from_str(to_jsonl(&rows).lines().next().expect("a line")).expect("json");
        let mut json_keys: Vec<String> = json
            .as_object()
            .expect("an object")
            .keys()
            .cloned()
            .collect();
        json_keys.sort();
        let mut columns: Vec<String> = ACCESS_REVIEW_COLUMNS
            .iter()
            .map(|c| (*c).to_owned())
            .collect();
        columns.sort();
        assert_eq!(
            json_keys, columns,
            "the JSONL keys and the CSV header disagree"
        );
    }
}
