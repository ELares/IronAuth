// SPDX-License-Identifier: MIT OR Apache-2.0

//! The pre-upgrade data preflight behind `ironauth doctor` (issue #148).
//!
//! A migration that adds a constraint can fail against data that is already in the
//! database. When it does, it fails PART WAY THROUGH AN UPGRADE, with the new binary
//! rolling out and the schema refusing to move, which is the worst moment to discover
//! it. This module asks the question beforehand, against the live rows: for every
//! migration this build has that the database has not applied, would any row prevent
//! it from applying?
//!
//! # The probe is derived from the constraint, never written beside it
//!
//! A hand-written "does any row violate migration 0231?" check is a second copy of the
//! constraint, free to disagree with the first. Here the probe's predicate IS the
//! migration's predicate, lifted out of the statement that will run. A CHECK's probe
//! searches for rows where that CHECK's own expression is FALSE. A SET NOT NULL probe
//! searches for NULLs in that column. There is no expected value to keep in sync,
//! because there is no second statement of the rule: the only input is the migration
//! text, and the only expectation is "no rows".
//!
//! # What it examines, and what it says when it cannot
//!
//! Five statement kinds can strand existing data, and [`derive`] builds a probe for
//! each:
//!
//! | statement | stranded by |
//! |---|---|
//! | `ALTER TABLE t ALTER COLUMN c SET NOT NULL` | an existing NULL in `c` |
//! | `ALTER TABLE t ADD CONSTRAINT n CHECK (e)` | a row where `e` is FALSE |
//! | `ALTER TABLE t ADD COLUMN c ... NOT NULL` (no DEFAULT) | any existing row |
//! | `CREATE UNIQUE INDEX n ON t (cols)` | a duplicate over `cols` |
//! | `ALTER TABLE t ADD CONSTRAINT n FOREIGN KEY (c) REFERENCES p (k)` | an orphan `c` |
//! | `ALTER TABLE t ADD PRIMARY KEY (cols)` | a NULL in any column, or a duplicate |
//! | `ALTER TABLE t VALIDATE CONSTRAINT n` | a row the deferred constraint rejects |
//!
//! # Silence means one thing
//!
//! A preflight whose silence means BOTH "no row is at risk" and "I did not understand
//! this statement" is not a preflight. So the verdict is three-way: a statement is a
//! hazard, or it is CLEARED by a decision written down here, or it is UNREAD -- and
//! unread is reported by name in [`Derivation::unexamined`] and BLOCKS.
//!
//! The clearing decisions are allow lists ([`RELAXING_COLUMN_ACTIONS`],
//! [`RELAXING_TABLE_ACTIONS`], a nullable or defaulted new column, `NOT VALID`), never a
//! fall-through. An earlier version inverted that -- anything unmatched was cleared --
//! and it handed a clean bill to `ALTER COLUMN ... TYPE` (which rewrites the table and
//! re-casts every row, so an over-long value rejects it) and parsed
//! `ADD PRIMARY KEY (id)` as a column named `PRIMARY`. An inverted list turns every
//! construct nobody thought of into a pass, including the ones added after it is written.
//!
//! # Scope
//!
//! This runs read-only, against live data, before the upgrade. It does not apply
//! anything and holds no locks. It answers one question (would a pending migration be
//! rejected by the rows that are already there) and deliberately not the other two:
//! whether the NEW BINARY can read the OLD rows is `scripts/expand-phase-ddl.sh`, and
//! whether an APPLIED migration's text has changed is the checksum in
//! [`crate::MigrationRunner`].

use std::collections::BTreeMap;

use sqlx::{PgPool, Row};

use crate::migrate::{Migration, MigrationError};

/// One way a pending migration can be rejected by rows that already exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hazard {
    /// `ALTER TABLE t ALTER COLUMN c SET NOT NULL` against an existing NULL.
    NotNull {
        /// The table the column belongs to, as written.
        table: String,
        /// The column being made mandatory, as written.
        column: String,
    },
    /// `ADD CONSTRAINT n CHECK (e)` against a row for which `e` is FALSE.
    Check {
        /// The table the constraint is added to, as written.
        table: String,
        /// The constraint's name, as written.
        constraint: String,
        /// The CHECK expression, lifted verbatim from the migration.
        expression: String,
    },
    /// `ADD COLUMN c ... NOT NULL` with no DEFAULT, against any existing row.
    MandatoryNewColumn {
        /// The table gaining the column, as written.
        table: String,
        /// The new column's name, as written.
        column: String,
    },
    /// `CREATE UNIQUE INDEX n ON t (cols)` against an existing duplicate.
    UniqueIndex {
        /// The table being indexed, as written.
        table: String,
        /// The index's name, as written.
        index: String,
        /// The indexed column list, lifted verbatim.
        columns: String,
        /// The partial-index predicate, if the index has a WHERE clause.
        predicate: Option<String>,
    },
    /// `VALIDATE CONSTRAINT n` against a row the deferred constraint rejects.
    ///
    /// This is the other half of the `NOT VALID` escape. `ADD CONSTRAINT ... NOT VALID`
    /// is cleared because Postgres does not scan for it, and the scan it skipped happens
    /// HERE. Clearing both would mean such a constraint is never checked by this preflight
    /// at all: two defensible decisions adding up to a blind spot.
    ValidateConstraint {
        /// The table the constraint is on, as written.
        table: String,
        /// The constraint's name, as written.
        constraint: String,
        /// The CHECK expression, when a pending migration in this run adds it NOT VALID.
        /// `None` when an already-applied migration added it, in which case the probe
        /// resolves it from `pg_constraint` instead.
        expression: Option<String>,
    },
    /// `ADD CONSTRAINT n FOREIGN KEY (c) REFERENCES p (k)` against an orphan.
    ForeignKey {
        /// The referencing table, as written.
        table: String,
        /// The constraint's name, as written.
        constraint: String,
        /// The referencing column list, lifted verbatim.
        columns: String,
        /// The referenced table, as written.
        parent: String,
        /// The referenced column list, lifted verbatim.
        parent_columns: String,
    },
}

impl Hazard {
    /// The read-only query that counts the rows this hazard would strand.
    ///
    /// The predicate is the migration's own, inverted. Note the NULL handling in each
    /// case, because it is where the naive form is wrong:
    ///
    /// - A CHECK constraint is satisfied when its expression is NULL (unknown), and
    ///   violated only when it is FALSE. `WHERE NOT (e)` is therefore too broad, since
    ///   it misses nothing but also matches nothing for a NULL `e`; `WHERE (e) IS FALSE`
    ///   is the exact complement and is what Postgres itself applies.
    /// - A unique index treats NULLs as DISTINCT by default, so a group of NULL rows is
    ///   not a duplicate. The row-wise `(cols) IS NOT NULL` (true only when EVERY column
    ///   is non-null) drops exactly the rows the index would not compare.
    /// - A foreign key permits a NULL referencing column, so orphan detection skips
    ///   rows whose referencing columns are NULL.
    #[must_use]
    pub fn probe_sql(&self) -> String {
        match self {
            Hazard::NotNull { table, column } => {
                format!("SELECT count(*) AS n FROM {table} WHERE {column} IS NULL")
            }
            Hazard::Check {
                table, expression, ..
            } => {
                format!("SELECT count(*) AS n FROM {table} WHERE ({expression}) IS FALSE")
            }
            Hazard::MandatoryNewColumn { table, .. } => {
                format!("SELECT count(*) AS n FROM {table}")
            }
            Hazard::UniqueIndex {
                table,
                columns,
                predicate,
                ..
            } => {
                let where_clause = predicate.as_ref().map_or_else(
                    || format!("WHERE ({columns}) IS NOT NULL"),
                    |p| format!("WHERE ({columns}) IS NOT NULL AND ({p})"),
                );
                format!(
                    "SELECT count(*) AS n FROM (SELECT 1 FROM {table} {where_clause} \
                     GROUP BY {columns} HAVING count(*) > 1) AS duplicated"
                )
            }
            Hazard::ValidateConstraint {
                table, expression, ..
            } => {
                // Only reachable with the expression resolved: probe() looks it up in
                // pg_constraint first when it is None, and reports the statement
                // unanswered if it cannot be found.
                let predicate = expression.clone().unwrap_or_else(|| "true".to_owned());
                format!("SELECT count(*) AS n FROM {table} WHERE ({predicate}) IS FALSE")
            }
            Hazard::ForeignKey {
                table,
                columns,
                parent,
                parent_columns,
                ..
            } => {
                let child: Vec<&str> = columns.split(',').map(str::trim).collect();
                let referenced: Vec<&str> = parent_columns.split(',').map(str::trim).collect();
                let join = child
                    .iter()
                    .zip(referenced.iter())
                    .map(|(c, k)| format!("parent.{k} = child.{c}"))
                    .collect::<Vec<_>>()
                    .join(" AND ");
                let present = child
                    .iter()
                    .map(|c| format!("child.{c} IS NOT NULL"))
                    .collect::<Vec<_>>()
                    .join(" AND ");
                format!(
                    "SELECT count(*) AS n FROM {table} AS child WHERE {present} \
                     AND NOT EXISTS (SELECT 1 FROM {parent} AS parent WHERE {join})"
                )
            }
        }
    }

    /// The table this hazard is about, for grouping a report by table.
    #[must_use]
    pub fn table(&self) -> &str {
        match self {
            Hazard::NotNull { table, .. }
            | Hazard::Check { table, .. }
            | Hazard::MandatoryNewColumn { table, .. }
            | Hazard::ValidateConstraint { table, .. }
            | Hazard::UniqueIndex { table, .. }
            | Hazard::ForeignKey { table, .. } => table,
        }
    }

    /// A one-line operator-facing description of what would be rejected and why.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Hazard::NotNull { table, column } => {
                format!("{table}.{column} becomes mandatory, and these rows have no value for it")
            }
            Hazard::Check {
                table, constraint, ..
            } => format!("{table} gains CHECK {constraint}, and these rows do not satisfy it"),
            Hazard::MandatoryNewColumn { table, column } => format!(
                "{table} gains mandatory column {column} with no default, \
                 so every existing row would have no value for it"
            ),
            Hazard::UniqueIndex {
                table,
                index,
                columns,
                ..
            } => format!(
                "{table} gains UNIQUE {index} on ({columns}), and these groups are duplicated"
            ),
            Hazard::ValidateConstraint {
                table, constraint, ..
            } => format!(
                "{table} validates the deferred constraint {constraint}, \
                 and these rows do not satisfy it"
            ),
            Hazard::ForeignKey {
                table,
                constraint,
                parent,
                ..
            } => format!(
                "{table} gains FOREIGN KEY {constraint} into {parent}, \
                 and these rows reference a row that is not there"
            ),
        }
    }
}

/// What [`derive`] made of one migration: the probes it built, and the statements it
/// recognised as constraint-shaped but could not build a probe for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Derivation {
    /// One hazard per constraint-imposing statement the parser understood.
    pub hazards: Vec<Hazard>,
    /// Statements containing a constraint phrase that produced no hazard. These are
    /// NOT a pass: they are the parser saying it did not read this one, and the
    /// operator-facing report prints them separately from the findings.
    pub unexamined: Vec<String>,
}

/// Split SQL into statements on top-level semicolons.
///
/// A semicolon inside a string literal, a quoted identifier, a dollar-quoted body, or
/// a comment is not a statement boundary, and every IronAuth migration that defines a
/// trigger function contains all four. Comments are replaced by a single space rather
/// than removed, so two tokens separated only by a comment do not fuse.
#[must_use]
pub fn split_statements(sql: &str) -> Vec<String> {
    let chars: Vec<char> = sql.chars().collect();
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];

        // A line comment runs to the newline, which is itself kept as the separator.
        if c == '-' && chars.get(i + 1) == Some(&'-') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            current.push(' ');
            continue;
        }

        // Block comments nest in Postgres, so track the depth rather than scanning
        // for the first close.
        if c == '/' && chars.get(i + 1) == Some(&'*') {
            let mut depth = 1usize;
            i += 2;
            while i < chars.len() && depth > 0 {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            current.push(' ');
            continue;
        }

        // A string literal or a quoted identifier, each doubling its own quote to
        // escape it.
        if c == '\'' || c == '"' {
            current.push(c);
            i += 1;
            while i < chars.len() {
                if chars[i] == c {
                    if chars.get(i + 1) == Some(&c) {
                        current.push(c);
                        current.push(c);
                        i += 2;
                        continue;
                    }
                    current.push(c);
                    i += 1;
                    break;
                }
                current.push(chars[i]);
                i += 1;
            }
            continue;
        }

        // A dollar-quoted body: $tag$ ... $tag$, where tag may be empty.
        if c == '$' {
            if let Some(tag) = dollar_tag(&chars, i) {
                current.push_str(&tag);
                i += tag.chars().count();
                let tag_chars: Vec<char> = tag.chars().collect();
                while i < chars.len() {
                    if chars[i] == '$' && chars[i..].starts_with(tag_chars.as_slice()) {
                        current.push_str(&tag);
                        i += tag_chars.len();
                        break;
                    }
                    current.push(chars[i]);
                    i += 1;
                }
                continue;
            }
        }

        if c == ';' {
            statements.push(current.clone());
            current.clear();
            i += 1;
            continue;
        }

        current.push(c);
        i += 1;
    }
    statements.push(current);

    statements
        .into_iter()
        .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|s| !s.is_empty())
        .collect()
}

/// If a `$` at `at` opens a dollar quote, the full opening tag (`$$` or `$name$`).
fn dollar_tag(chars: &[char], at: usize) -> Option<String> {
    let mut end = at + 1;
    while end < chars.len() && (chars[end].is_alphanumeric() || chars[end] == '_') {
        end += 1;
    }
    if chars.get(end) == Some(&'$') {
        Some(chars[at..=end].iter().collect())
    } else {
        None
    }
}

/// Take one identifier (optionally quoted, optionally schema-qualified) off the front.
fn take_ident(input: &str) -> Option<(String, &str)> {
    let mut rest = input.trim_start();
    let mut out = String::new();
    loop {
        let (part, remainder) = take_ident_part(rest)?;
        out.push_str(&part);
        rest = remainder;
        if let Some(after_dot) = rest.strip_prefix('.') {
            out.push('.');
            rest = after_dot;
        } else {
            return Some((out, rest));
        }
    }
}

fn take_ident_part(input: &str) -> Option<(String, &str)> {
    let chars: Vec<char> = input.chars().collect();
    if chars.first() == Some(&'"') {
        let mut i = 1;
        while i < chars.len() {
            if chars[i] == '"' {
                if chars.get(i + 1) == Some(&'"') {
                    i += 2;
                    continue;
                }
                let consumed: usize = chars[..=i].iter().map(|c| c.len_utf8()).sum();
                return Some((chars[..=i].iter().collect(), &input[consumed..]));
            }
            i += 1;
        }
        return None;
    }
    let end = input
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(input.len());
    if end == 0 {
        None
    } else {
        Some((input[..end].to_owned(), &input[end..]))
    }
}

/// Take a balanced parenthesised group off the front, returning its contents.
fn take_parens(input: &str) -> Option<(String, &str)> {
    let trimmed = input.trim_start();
    if !trimmed.starts_with('(') {
        return None;
    }
    let chars: Vec<char> = trimmed.chars().collect();
    let mut depth = 0usize;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' || c == '"' {
            i += 1;
            while i < chars.len() {
                if chars[i] == c {
                    if chars.get(i + 1) == Some(&c) {
                        i += 2;
                        continue;
                    }
                    break;
                }
                i += 1;
            }
            i += 1;
            continue;
        }
        if c == '(' {
            depth += 1;
        } else if c == ')' {
            depth -= 1;
            if depth == 0 {
                let consumed: usize = chars[..=i].iter().map(|c| c.len_utf8()).sum();
                let inner: String = chars[1..i].iter().collect();
                return Some((inner.trim().to_owned(), &trimmed[consumed..]));
            }
        }
        i += 1;
    }
    None
}

/// Split on commas that are not inside parentheses or quotes.
fn split_top_level_commas(input: &str) -> Vec<String> {
    let chars: Vec<char> = input.chars().collect();
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' || c == '"' {
            current.push(c);
            i += 1;
            while i < chars.len() {
                current.push(chars[i]);
                if chars[i] == c {
                    if chars.get(i + 1) == Some(&c) {
                        current.push(c);
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(current.trim().to_owned());
                current.clear();
                i += 1;
                continue;
            }
            _ => {}
        }
        current.push(c);
        i += 1;
    }
    parts.push(current.trim().to_owned());
    parts.into_iter().filter(|p| !p.is_empty()).collect()
}

/// Case-insensitive keyword match at a WORD BOUNDARY, returning the remainder.
///
/// The boundary is the point. A bare prefix match splits an identifier that merely starts
/// with a keyword (`ALTER COLUMN uniqueness ...` matching `UNIQUE`), and the wrong parse
/// that follows produces a probe naming a column that does not exist, which the database
/// answers with `undefined_column` -- the one error this module used to excuse. A parser
/// bug would have been laundered into a clean verdict.
fn eat(input: &str, keyword: &str) -> Option<String> {
    let trimmed = input.trim_start();
    if trimmed.len() < keyword.len() || !trimmed[..keyword.len()].eq_ignore_ascii_case(keyword) {
        return None;
    }
    let rest = &trimmed[keyword.len()..];
    // A keyword ending in a non-word character (none here today) needs no boundary; one
    // ending in a word character must not be followed by another.
    let ends_word = keyword
        .chars()
        .last()
        .is_some_and(|c| c.is_alphanumeric() || c == '_');
    let continues_word = rest
        .chars()
        .next()
        .is_some_and(|c| c.is_alphanumeric() || c == '_');
    if ends_word && continues_word {
        return None;
    }
    Some(rest.to_owned())
}

/// Whether `needle` occurs in `haystack` as a standalone keyword, outside any string
/// literal or quoted identifier.
///
/// `haystack.to_ascii_uppercase().contains(needle)` is the shape this replaces, and it is
/// wrong twice over: it matches inside a quoted value (a DEFAULT of `'NOT VALID'`, a
/// constraint named `not_valid_yet`) and it matches a fragment of a longer word. Both
/// turn into a statement cleared on the strength of text that was never a keyword.
fn contains_keyword(haystack: &str, needle: &str) -> bool {
    let upper_needle = needle.to_ascii_uppercase();
    let chars: Vec<char> = haystack.chars().collect();
    let mut i = 0;
    let mut plain = String::with_capacity(haystack.len());
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' || c == '"' {
            // Replace the whole literal with a space: its contents are data, not syntax.
            i += 1;
            while i < chars.len() {
                if chars[i] == c {
                    if chars.get(i + 1) == Some(&c) {
                        i += 2;
                        continue;
                    }
                    break;
                }
                i += 1;
            }
            i += 1;
            plain.push(' ');
            continue;
        }
        plain.push(c.to_ascii_uppercase());
        i += 1;
    }
    let bytes = plain.as_bytes();
    let needle_bytes = upper_needle.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut from = 0;
    while let Some(found) = plain[from..].find(&upper_needle) {
        let start = from + found;
        let end = start + needle_bytes.len();
        let before_ok = start == 0 || !is_word(bytes[start - 1]);
        let after_ok = end == bytes.len() || !is_word(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

/// Whether a statement contains a phrase that can impose a constraint on existing
/// rows. Used only to decide whether silence means "additive" or "not read".
fn looks_constraint_shaped(statement: &str) -> bool {
    // Only reached for statements that are NOT `ALTER TABLE` (whose actions are each
    // judged individually and reported whenever unread) and not `CREATE UNIQUE INDEX`.
    // The two arms that tested for "ALTER TABLE" alongside an action keyword used to be
    // applied to the comma-split ACTION, which never contains that text, so they could
    // not fire; they are gone rather than rewritten, because the action path no longer
    // filters at all.
    [
        "SET NOT NULL",
        "ADD CONSTRAINT",
        "CREATE UNIQUE INDEX",
        "VALIDATE CONSTRAINT",
        "SET DATA TYPE",
    ]
    .iter()
    .any(|keyword| contains_keyword(statement, keyword))
        || (contains_keyword(statement, "ADD COLUMN") && contains_keyword(statement, "NOT NULL"))
}

/// Read one migration and build a probe for every statement that could be rejected by
/// rows already in the database.
///
/// See the module header for the five statement kinds this understands and for why a
/// statement it does not understand is reported rather than passed.
#[must_use]
pub fn derive(migration: &Migration) -> Derivation {
    let mut derivation = Derivation::default();
    let statements = split_statements(migration.sql);
    // A migration may add a constraint NOT VALID and validate it in the same file, so the
    // expression a later VALIDATE will scan for is in this text. Collect those first.
    let deferred = deferred_check_constraints(&statements);
    for statement in statements {
        if let Some(rest) = eat(&statement, "ALTER TABLE") {
            derive_alter_table(&rest, &statement, &deferred, &mut derivation);
        } else if let Some(hazard) = derive_create_unique_index(&statement) {
            derivation.hazards.push(hazard);
        } else if looks_constraint_shaped(&statement) {
            derivation.unexamined.push(statement);
        }
    }
    derivation
}

/// `ALTER TABLE [ONLY] [IF EXISTS] t <action> [, <action> ...]`.
///
/// Each action is examined on its own, so a statement whose first action parses and
/// whose second does not still reports the second as unexamined. A statement that
/// reports one hazard is not evidence that its other actions were read.
/// Constraint name to CHECK expression, for every `ADD CONSTRAINT ... CHECK (...) NOT
/// VALID` in this migration.
///
/// The NOT VALID escape and the VALIDATE that redeems it can sit in one file, and when they
/// do, the constraint is in neither the catalog nor any earlier migration at preflight
/// time. Reading it out of the text is the only way the pair can be checked at all.
fn deferred_check_constraints(statements: &[String]) -> BTreeMap<String, String> {
    let mut deferred = BTreeMap::new();
    for statement in statements {
        let Some(rest) = eat(statement, "ALTER TABLE") else {
            continue;
        };
        let mut rest = rest;
        for modifier in ["IF EXISTS", "ONLY"] {
            if let Some(stripped) = eat(&rest, modifier) {
                rest = stripped;
            }
        }
        let Some((_table, actions)) = take_ident(&rest) else {
            continue;
        };
        for action in split_top_level_commas(actions) {
            if !contains_keyword(&action, "NOT VALID") {
                continue;
            }
            let Some(after_add) = eat(&action, "ADD") else {
                continue;
            };
            let Some(after_constraint) = eat(&after_add, "CONSTRAINT") else {
                continue;
            };
            let Some((name, body)) = take_ident(&after_constraint) else {
                continue;
            };
            let Some(after_check) = eat(body, "CHECK") else {
                continue;
            };
            if let Some((expression, _)) = take_parens(&after_check) {
                deferred.insert(name, expression);
            }
        }
    }
    deferred
}

fn derive_alter_table(
    after_keyword: &str,
    whole: &str,
    deferred: &BTreeMap<String, String>,
    derivation: &mut Derivation,
) {
    let mut rest = after_keyword.to_owned();
    for modifier in ["IF EXISTS", "ONLY"] {
        if let Some(stripped) = eat(&rest, modifier) {
            rest = stripped;
        }
    }
    let Some((table, actions)) = take_ident(&rest) else {
        if looks_constraint_shaped(whole) {
            derivation.unexamined.push(whole.to_owned());
        }
        return;
    };

    for action in split_top_level_commas(actions) {
        match derive_action(&table, &action, deferred) {
            Verdict::Hazards(hazards) => derivation.hazards.extend(hazards),
            Verdict::Safe => {}
            // Every unread ALTER TABLE action is reported, with no shape filter.
            //
            // The filter that used to be here could not fire: it was handed the
            // comma-split ACTION, and two of its arms tested for the text "ALTER TABLE",
            // which an action fragment never contains by construction. Any action that
            // only matched those arms was dropped instead of reported. It is also no
            // longer needed: Safe is now an affirmative recognition rather than a
            // fall-through, so Unread means the parser genuinely did not read it, and
            // that is worth printing whatever the statement looks like.
            Verdict::Unread => derivation
                .unexamined
                .push(format!("ALTER TABLE {table} {action}")),
        }
    }
}

/// What the parser made of one ALTER TABLE action.
///
/// The distinction between [`Verdict::Safe`] and [`Verdict::Unread`] is the whole point
/// of the type. Both produce no hazard, and collapsing them is how a preflight comes to
/// report a clean bill for a statement it never understood. `Safe` is a decision about
/// the statement ("this ADD COLUMN carries a DEFAULT, so no existing row is stranded");
/// `Unread` is the absence of one.
enum Verdict {
    /// Existing rows can reject this statement, and here are the probes that find them.
    ///
    /// A list, not one hazard: `PRIMARY KEY (a, b)` imposes TWO rules at once, that
    /// neither column is NULL and that the pair is unique, and a verdict that could carry
    /// only one of them would check half the constraint and report the half it checked.
    Hazards(Vec<Hazard>),
    /// The parser read this statement and determined no existing row can reject it.
    Safe,
    /// The parser did not recognise this statement. Never a pass.
    Unread,
}

impl Verdict {
    /// A verdict carrying exactly one hazard.
    fn one(hazard: Hazard) -> Self {
        Verdict::Hazards(vec![hazard])
    }
}

/// Table-level `ALTER TABLE` actions that no existing row can reject.
///
/// Every one of these either removes a rule, removes data, or changes metadata that rows
/// do not have to satisfy, so Postgres never scans for them. Each is a DECISION, written
/// down, and the list is checked against the shipped chain: these five account for all 348
/// table-level actions in it, and anything outside the list is Unread rather than assumed.
///
/// VALIDATE CONSTRAINT is deliberately NOT here. It is the one table-level action that
/// does scan.
const RELAXING_TABLE_ACTIONS: &[&str] = &[
    "ENABLE ROW LEVEL SECURITY",
    "DISABLE ROW LEVEL SECURITY",
    "FORCE ROW LEVEL SECURITY",
    "NO FORCE ROW LEVEL SECURITY",
    "DROP CONSTRAINT",
    "DROP COLUMN",
    "ENABLE TRIGGER",
    "DISABLE TRIGGER",
    "OWNER TO",
    "SET SCHEMA",
    "CLUSTER ON",
    "SET WITHOUT CLUSTER",
    "INHERIT",
    "NO INHERIT",
];

fn derive_action(table: &str, action: &str, deferred: &BTreeMap<String, String>) -> Verdict {
    // Checked BEFORE the NOT VALID escape below: an action that both validates and
    // mentions NOT VALID would otherwise be cleared by the escape.
    if let Some(rest) = eat(action, "VALIDATE CONSTRAINT") {
        let Some((constraint, _)) = take_ident(&rest) else {
            return Verdict::Unread;
        };
        let expression = deferred.get(&constraint).cloned();
        return Verdict::one(Hazard::ValidateConstraint {
            table: table.to_owned(),
            constraint,
            expression,
        });
    }
    // NOT VALID defers the scan, so Postgres accepts the statement against any data and
    // nothing is stranded when it applies. Validating it later is a separate operator
    // step, outside this preflight. This is a decision about the statement, not a
    // failure to read it.
    //
    // Matched as a keyword outside string literals: a CHECK whose DEFAULT or comparison
    // value is the TEXT 'NOT VALID' would otherwise clear a constraint Postgres fully
    // validates.
    if contains_keyword(action, "NOT VALID") {
        return Verdict::Safe;
    }
    if let Some(rest) = eat(action, "ALTER") {
        return derive_alter_column(table, &rest);
    }
    if let Some(rest) = eat(action, "ADD") {
        return derive_add(table, &rest);
    }
    if RELAXING_TABLE_ACTIONS
        .iter()
        .any(|relaxing| eat(action, relaxing).is_some())
    {
        return Verdict::Safe;
    }
    Verdict::Unread
}

/// `ALTER [COLUMN] c SET NOT NULL`. The `COLUMN` keyword is optional in Postgres.
/// The `ALTER [COLUMN] c <action>` forms that provably cannot be rejected by an existing
/// row, because each one only relaxes a rule or changes metadata the rows do not have to
/// satisfy.
///
/// This is an ALLOW LIST on purpose. The first version inverted it -- anything that was
/// not `SET NOT NULL` was declared safe -- and that handed a clean bill to
/// `ALTER COLUMN ... TYPE`, which rewrites the table, re-casts every row, and is rejected
/// by data that does not fit (an over-long varchar, a failed USING cast, a numeric
/// overflow). An inverted list makes every action nobody thought of into a pass.
const RELAXING_COLUMN_ACTIONS: &[&str] = &[
    "DROP NOT NULL",
    "SET DEFAULT",
    "DROP DEFAULT",
    "DROP EXPRESSION",
    "DROP IDENTITY",
    "SET STATISTICS",
    "SET STORAGE",
    "SET COMPRESSION",
    "RESET",
];

fn derive_alter_column(table: &str, after_alter: &str) -> Verdict {
    let rest = eat(after_alter, "COLUMN").unwrap_or_else(|| after_alter.to_owned());
    let Some((column, tail)) = take_ident(&rest) else {
        return Verdict::Unread;
    };
    if eat(tail, "SET NOT NULL").is_some() {
        return Verdict::one(Hazard::NotNull {
            table: table.to_owned(),
            column,
        });
    }
    if RELAXING_COLUMN_ACTIONS
        .iter()
        .any(|action| eat(tail, action).is_some())
    {
        return Verdict::Safe;
    }
    // TYPE, SET DATA TYPE, ADD GENERATED, SET GENERATED, and anything new: not read.
    Verdict::Unread
}

/// `ADD CONSTRAINT n ...`, `ADD COLUMN c ...`, and the unnamed `ADD UNIQUE (...)`.
/// The table-constraint keywords an `ADD` action can open with. A constraint may be
/// written with or without a `CONSTRAINT name` prefix, and the unnamed form is the one
/// that used to be mistaken for a column.
const TABLE_CONSTRAINT_KEYWORDS: &[&str] =
    &["CHECK", "UNIQUE", "PRIMARY KEY", "FOREIGN KEY", "EXCLUDE"];

/// `ADD CONSTRAINT n ...`, the unnamed `ADD <constraint> ...`, and `ADD [COLUMN] c ...`.
///
/// The ordering here is load-bearing. The first version tried CONSTRAINT, then UNIQUE,
/// then fell through to "this must be an ADD COLUMN", which parsed `ADD PRIMARY KEY (id)`
/// as a column named `PRIMARY`, found no NOT NULL in the remainder, and returned Safe.
/// Four statements in the shipped chain take that path (two `ADD PRIMARY KEY` in 0168, two
/// `ADD FOREIGN KEY` in 0150), and because the misparse produced Safe rather than Unread,
/// the chain-wide "everything is read" test passed BECAUSE of it. A fall-through to the
/// permissive branch is how an unrecognised statement becomes a pass.
fn derive_add(table: &str, after_add: &str) -> Verdict {
    if let Some(rest) = eat(after_add, "CONSTRAINT") {
        let Some((constraint, body)) = take_ident(&rest) else {
            return Verdict::Unread;
        };
        return derive_constraint_body(table, &constraint, body);
    }
    // An unnamed table constraint. Postgres names it for you; the preflight cares only
    // about which rows it would reject.
    for keyword in TABLE_CONSTRAINT_KEYWORDS {
        if eat(after_add, keyword).is_some() {
            let name = format!("(unnamed {keyword} on {table})");
            return derive_constraint_body(table, &name, after_add);
        }
    }
    // Only now is this an ADD COLUMN. `COLUMN` is optional in Postgres, so a bare
    // identifier reaches here too, but every constraint keyword has been ruled out above.
    let rest = eat(after_add, "COLUMN").unwrap_or_else(|| after_add.to_owned());
    let rest = eat(&rest, "IF NOT EXISTS").unwrap_or(rest);
    let Some((column, tail)) = take_ident(&rest) else {
        return Verdict::Unread;
    };
    if !contains_keyword(tail, "NOT NULL") {
        // A nullable new column strands nothing: every existing row gets NULL.
        return Verdict::Safe;
    }
    // A new mandatory column strands every existing row ONLY when it has no default to
    // fill them with. A volatile default is still a default: Postgres evaluates it per
    // row, so the column is never null and no row is stranded. That is a decision about
    // the statement, so it is Safe and not Unread: 45 of the chain's ADD COLUMNs take
    // this branch, and reporting them as unread would bury the real signal.
    //
    // Both keywords are matched OUTSIDE string literals. `DEFAULT 'NOT NULL'` and a
    // default whose text contains the word DEFAULT would otherwise decide this.
    if contains_keyword(tail, "DEFAULT") {
        return Verdict::Safe;
    }
    Verdict::one(Hazard::MandatoryNewColumn {
        table: table.to_owned(),
        column,
    })
}

fn derive_constraint_body(table: &str, constraint: &str, body: &str) -> Verdict {
    if let Some(rest) = eat(body, "CHECK") {
        let Some((expression, _)) = take_parens(&rest) else {
            return Verdict::Unread;
        };
        return Verdict::one(Hazard::Check {
            table: table.to_owned(),
            constraint: constraint.to_owned(),
            expression,
        });
    }
    if let Some(rest) = eat(body, "UNIQUE") {
        // NULLS NOT DISTINCT (Postgres 15+) inverts the NULL handling probe_sql assumes,
        // so this is Unread rather than probed with the wrong predicate.
        if contains_keyword(&rest, "NULLS NOT DISTINCT") {
            return Verdict::Unread;
        }
        let Some((columns, _)) = take_parens(&rest) else {
            return Verdict::Unread;
        };
        return Verdict::one(Hazard::UniqueIndex {
            table: table.to_owned(),
            index: constraint.to_owned(),
            columns,
            predicate: None,
        });
    }
    if let Some(rest) = eat(body, "PRIMARY KEY") {
        // ADD PRIMARY KEY ... USING INDEX adopts an existing index, so the columns are not
        // in this statement at all and cannot be read from it. Unread.
        if contains_keyword(&rest, "USING INDEX") {
            return Verdict::Unread;
        }
        let Some((columns, _)) = take_parens(&rest) else {
            return Verdict::Unread;
        };
        // A primary key is two rules, and both can be rejected by existing rows: every
        // column mandatory, and the tuple unique. Probing only one would report a clean
        // bill on the strength of the half that happened to pass.
        let mut hazards: Vec<Hazard> = columns
            .split(',')
            .map(|column| Hazard::NotNull {
                table: table.to_owned(),
                column: column.trim().to_owned(),
            })
            .collect();
        hazards.push(Hazard::UniqueIndex {
            table: table.to_owned(),
            index: constraint.to_owned(),
            columns: columns.clone(),
            predicate: None,
        });
        return Verdict::Hazards(hazards);
    }
    if let Some(rest) = eat(body, "FOREIGN KEY") {
        // MATCH FULL inverts the NULL rule probe_sql assumes. Under the default MATCH
        // SIMPLE a row is exempt if ANY referencing column is NULL, which is the `AND` of
        // IS NOT NULL the probe builds. MATCH FULL exempts a row only if EVERY one is
        // NULL, so a partially-NULL row IS checked and can be an orphan -- exactly the
        // rows the probe's `AND` excludes. Probing it would under-report, so it is Unread.
        if contains_keyword(body, "MATCH FULL") {
            return Verdict::Unread;
        }
        let Some((columns, after_columns)) = take_parens(&rest) else {
            return Verdict::Unread;
        };
        let Some(after_references) = eat(after_columns, "REFERENCES") else {
            return Verdict::Unread;
        };
        let Some((parent, after_parent)) = take_ident(&after_references) else {
            return Verdict::Unread;
        };
        // The referenced column list is optional: omitting it means the parent's primary
        // key, which this parser cannot resolve from the migration text alone. Unread,
        // so the report says so rather than skipping the foreign key silently.
        let Some((parent_columns, _)) = take_parens(after_parent) else {
            return Verdict::Unread;
        };
        return Verdict::one(Hazard::ForeignKey {
            table: table.to_owned(),
            constraint: constraint.to_owned(),
            columns,
            parent,
            parent_columns,
        });
    }
    // PRIMARY KEY, EXCLUDE, and anything else: not read, so not cleared.
    Verdict::Unread
}

/// `CREATE UNIQUE INDEX [CONCURRENTLY] [IF NOT EXISTS] n ON t (cols) [WHERE p]`.
fn derive_create_unique_index(statement: &str) -> Option<Hazard> {
    let mut rest = eat(statement, "CREATE UNIQUE INDEX")?;
    for modifier in ["CONCURRENTLY", "IF NOT EXISTS"] {
        if let Some(stripped) = eat(&rest, modifier) {
            rest = stripped;
        }
    }
    if contains_keyword(&rest, "NULLS NOT DISTINCT") {
        return None;
    }
    let (index, after_index) = take_ident(&rest)?;
    let after_on = eat(after_index, "ON")?;
    let (table, after_table) = take_ident(&after_on)?;
    // An index method or a storage clause may sit between the table and the columns.
    let after_using = match eat(after_table, "USING") {
        Some(after) => {
            let past_method = take_ident(&after).map(|(_method, tail)| tail.to_owned());
            past_method.unwrap_or(after)
        }
        None => after_table.to_owned(),
    };
    let (columns, after_columns) = take_parens(&after_using)?;
    // The predicate has to be read exactly or not at all. INCLUDE (...), WITH (...),
    // TABLESPACE x and NULLS NOT DISTINCT may all sit between the column list and WHERE,
    // and `eat` only matches at the front, so a clause in between used to make the
    // predicate silently None -- widening the probe from the partial index's row set to
    // the WHOLE TABLE and reporting duplicates the index would never compare. Anything
    // other than a bare WHERE or nothing at all is Unread.
    let tail = after_columns.trim();
    let predicate = match (tail.is_empty(), eat(tail, "WHERE")) {
        (true, _) => None,
        (false, Some(rest)) => Some(rest.trim().to_owned()),
        // A clause this parser does not read sits before the predicate. Returning None
        // here makes the whole statement Unread, which is the point: a half-read partial
        // index probed as if it covered every row reports duplicates that would never
        // collide.
        (false, None) => return None,
    };
    Some(Hazard::UniqueIndex {
        table,
        index,
        columns,
        predicate,
    })
}

/// One pending migration statement that live rows would reject, and how many rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The pending migration's version.
    pub version: i64,
    /// The pending migration's name.
    pub name: String,
    /// What would be rejected.
    pub hazard: Hazard,
    /// How many rows (or duplicate groups) are in the way. Always greater than zero.
    pub rows: i64,
}

/// A statement whose probe could not be answered, which is not the same as a clean one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unanswered {
    /// The pending migration's version.
    pub version: i64,
    /// The statement or probe at issue, for the operator to read.
    pub detail: String,
    /// Why there is no answer: the parser did not read the statement, or the probe
    /// itself failed against the database.
    pub reason: UnansweredReason,
}

/// Why a pending statement produced no verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnansweredReason {
    /// [`derive`] recognised the statement as constraint-shaped and could not parse it.
    NotRead,
    /// The probe ran and the database rejected it for a reason other than the subject
    /// not existing yet.
    ProbeFailed,
}

/// The outcome of [`run`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Report {
    /// The pending migrations, ascending: those this build has that the database has
    /// not applied.
    pub pending: Vec<(i64, String)>,
    /// How many probes were executed against live data.
    pub probes_run: usize,
    /// How many probes named a table or column that does not exist yet, because an
    /// earlier pending migration creates it. Nothing can be stranded in a table that is
    /// not there, so these are clean; they are counted so the probe total is honest
    /// about how much of it actually touched rows.
    pub probes_not_yet_applicable: usize,
    /// Rows that would reject a pending migration. Empty is the good case.
    pub findings: Vec<Finding>,
    /// Statements with no verdict. Also blocks: see [`Report::blocks`].
    pub unanswered: Vec<Unanswered>,
}

impl Report {
    /// Whether `ironauth doctor` should refuse the upgrade.
    ///
    /// A finding blocks, and so does an unanswered statement. The second half is the
    /// point: a preflight that passes what it could not evaluate tells an operator the
    /// upgrade is safe on the strength of a statement it never read.
    #[must_use]
    pub fn blocks(&self) -> bool {
        !self.findings.is_empty() || !self.unanswered.is_empty()
    }
}

/// How long any one probe may run before the preflight gives up on it.
///
/// A probe is a sequential scan of a production table, so on a large deployment it is
/// the slowest thing here. A timeout surfaces as an unanswered probe, which blocks: an
/// operator who wants to proceed past a table too large to scan is making a decision,
/// and should make it explicitly rather than have a silent skip make it for them.
pub const PROBE_TIMEOUT_MS: i32 = 30_000;

/// Run the preflight: probe live data against every pending migration's constraints.
///
/// Read-only. Each probe runs in its own read-only transaction with a statement
/// timeout, and the transaction is rolled back; nothing here writes, and nothing here
/// applies a migration.
///
/// # Errors
///
/// [`MigrationError::Database`] if the ledger itself cannot be read. An individual
/// probe failing is a [`Report`] entry, not an error: the preflight's job is to report
/// on all of them, not to stop at the first.
#[allow(clippy::too_many_lines)]
pub async fn run(pool: &PgPool, chain: &[Migration]) -> Result<Report, MigrationError> {
    let mut report = Report::default();

    // A database with no ledger has had nothing applied, so every migration is pending.
    // That is a fresh install, where every probe finds an absent table and the verdict
    // is clean, which is the right answer.
    let applied: Vec<i64> =
        match sqlx::query("SELECT version FROM _schema_migrations ORDER BY version")
            .fetch_all(pool)
            .await
        {
            Ok(rows) => rows.iter().map(|row| row.get("version")).collect(),
            Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some("42P01") => {
                Vec::new()
            }
            Err(error) => return Err(error.into()),
        };

    // What this run will bring into existence, read before any probe: it is what makes an
    // absent table or column decidable rather than merely excused.
    let pending: Vec<&Migration> = chain
        .iter()
        .filter(|migration| !applied.contains(&migration.version))
        .collect();
    let shape = pending_shape(&pending);

    for migration in chain {
        if applied.contains(&migration.version) {
            continue;
        }
        report
            .pending
            .push((migration.version, migration.name.to_owned()));

        let derivation = derive(migration);
        for statement in derivation.unexamined {
            report.unanswered.push(Unanswered {
                version: migration.version,
                detail: statement,
                reason: UnansweredReason::NotRead,
            });
        }
        for hazard in derivation.hazards {
            // A VALIDATE whose constraint an APPLIED migration added carries no expression
            // from the text; the catalog has it. Without resolving it the probe would read
            // `WHERE (true) IS FALSE`, which matches nothing and reports clean.
            let hazard = if let Hazard::ValidateConstraint {
                table,
                constraint,
                expression: None,
            } = &hazard
            {
                let Some(expression) = constraint_expression(pool, constraint).await else {
                    report.unanswered.push(Unanswered {
                        version: migration.version,
                        detail: format!(
                            "VALIDATE CONSTRAINT {constraint} on {table}: the constraint is in \
                             neither this run's migrations nor pg_constraint, so the rows it \
                             will scan cannot be determined"
                        ),
                        reason: UnansweredReason::ProbeFailed,
                    });
                    continue;
                };
                Hazard::ValidateConstraint {
                    table: table.clone(),
                    constraint: constraint.clone(),
                    expression: Some(expression),
                }
            } else {
                hazard
            };
            match probe(pool, &hazard).await {
                ProbeOutcome::Rows(0) => report.probes_run += 1,
                ProbeOutcome::Rows(rows) => {
                    report.probes_run += 1;
                    report.findings.push(Finding {
                        version: migration.version,
                        name: migration.name.to_owned(),
                        hazard,
                        rows,
                    });
                }
                ProbeOutcome::SubjectAbsent => match absent_subject_verdict(&hazard, &shape) {
                    AbsentVerdict::CreatedByThisRun => report.probes_not_yet_applicable += 1,
                    AbsentVerdict::EveryRowStranded => {
                        // The column arrives NULL on every row the table already holds, so
                        // a SET NOT NULL on it is rejected by all of them. Count the rows
                        // rather than call it "not applicable".
                        let count_rows = Hazard::MandatoryNewColumn {
                            table: hazard.table().to_owned(),
                            column: String::new(),
                        };
                        match probe(pool, &count_rows).await {
                            ProbeOutcome::Rows(0) => report.probes_run += 1,
                            ProbeOutcome::Rows(rows) => {
                                report.probes_run += 1;
                                report.findings.push(Finding {
                                    version: migration.version,
                                    name: migration.name.to_owned(),
                                    hazard,
                                    rows,
                                });
                            }
                            _ => report.unanswered.push(Unanswered {
                                version: migration.version,
                                detail: format!(
                                    "{}: this run adds the column with no default, so every \
                                     existing row would be NULL, and the row count could not \
                                     be read",
                                    hazard.describe()
                                ),
                                reason: UnansweredReason::ProbeFailed,
                            }),
                        }
                    }
                    AbsentVerdict::Undecidable(why) => report.unanswered.push(Unanswered {
                        version: migration.version,
                        detail: format!("{} -- {why}: {}", hazard.describe(), hazard.probe_sql()),
                        reason: UnansweredReason::ProbeFailed,
                    }),
                },
                ProbeOutcome::Failed(message) => {
                    report.probes_run += 1;
                    report.unanswered.push(Unanswered {
                        version: migration.version,
                        detail: format!("{} -- probe failed: {message}", hazard.probe_sql()),
                        reason: UnansweredReason::ProbeFailed,
                    });
                }
            }
        }
    }

    Ok(report)
}

enum ProbeOutcome {
    Rows(i64),
    /// The probe named a table or column the database does not have. Whether that is
    /// harmless is NOT decided here: [`absent_subject_verdict`] asks whether this run
    /// creates the subject before deciding, because "a pending migration makes it" and
    /// "the parser named something that does not exist" arrive as the same error.
    SubjectAbsent,
    Failed(String),
}

/// What this pending run will bring into existence before its constraints apply.
///
/// Needed because "the database has never heard of this column" has two very different
/// causes. If a pending migration creates it, nothing can be stranded there and the probe
/// is genuinely not applicable. If nothing creates it, the probe named something that does
/// not exist, which is a PARSER ERROR, and excusing it turns a bug in this file into a
/// clean bill of health for the upgrade.
#[derive(Debug, Default)]
struct PendingShape {
    tables: std::collections::BTreeSet<String>,
    /// (table, column) for every column a pending migration adds WITHOUT a default. Such
    /// a column arrives NULL on every row the table already holds.
    nullable_new_columns: std::collections::BTreeSet<(String, String)>,
    /// (table, column) for every column a pending migration adds WITH a default.
    defaulted_new_columns: std::collections::BTreeSet<(String, String)>,
}

impl PendingShape {
    fn creates_table(&self, table: &str) -> bool {
        let bare = table.rsplit('.').next().unwrap_or(table);
        self.tables.contains(bare)
    }

    fn creates_column(&self, table: &str, column: &str) -> Option<bool> {
        let bare = table.rsplit('.').next().unwrap_or(table).to_owned();
        let key = (bare, column.to_owned());
        if self.nullable_new_columns.contains(&key) {
            return Some(false);
        }
        if self.defaulted_new_columns.contains(&key) {
            return Some(true);
        }
        None
    }
}

/// Read the tables and columns the pending migrations will create.
fn pending_shape(pending: &[&Migration]) -> PendingShape {
    let mut shape = PendingShape::default();
    for migration in pending {
        for statement in split_statements(migration.sql) {
            if let Some(rest) = eat(&statement, "CREATE TABLE") {
                let rest = eat(&rest, "IF NOT EXISTS").unwrap_or(rest);
                if let Some((table, _)) = take_ident(&rest) {
                    let bare = table.rsplit('.').next().unwrap_or(&table).to_owned();
                    shape.tables.insert(bare);
                }
                continue;
            }
            let Some(rest) = eat(&statement, "ALTER TABLE") else {
                continue;
            };
            let mut rest = rest;
            for modifier in ["IF EXISTS", "ONLY"] {
                if let Some(stripped) = eat(&rest, modifier) {
                    rest = stripped;
                }
            }
            let Some((table, actions)) = take_ident(&rest) else {
                continue;
            };
            let bare = table.rsplit('.').next().unwrap_or(&table).to_owned();
            for action in split_top_level_commas(actions) {
                let Some(after_add) = eat(&action, "ADD") else {
                    continue;
                };
                // Only a genuine ADD COLUMN: the constraint keywords are ruled out first,
                // exactly as derive_add does, so `ADD PRIMARY KEY (id)` is not recorded as
                // a column named PRIMARY.
                if eat(&after_add, "CONSTRAINT").is_some()
                    || TABLE_CONSTRAINT_KEYWORDS
                        .iter()
                        .any(|keyword| eat(&after_add, keyword).is_some())
                {
                    continue;
                }
                let after_column = eat(&after_add, "COLUMN").unwrap_or(after_add);
                let after_column = eat(&after_column, "IF NOT EXISTS").unwrap_or(after_column);
                if let Some((column, tail)) = take_ident(&after_column) {
                    let key = (bare.clone(), column);
                    if contains_keyword(tail, "DEFAULT") {
                        shape.defaulted_new_columns.insert(key);
                    } else {
                        shape.nullable_new_columns.insert(key);
                    }
                }
            }
        }
    }
    shape
}

/// What an absent table or column means for one hazard.
enum AbsentVerdict {
    /// A pending migration creates the subject. Nothing can be stranded in a table or
    /// column that does not exist yet.
    CreatedByThisRun,
    /// The column is added by this run WITHOUT a default, so it arrives NULL on every row
    /// the table already holds, and a rule that forbids NULL is rejected by all of them.
    EveryRowStranded,
    /// Not decidable from the migration text. Blocks, with this as the reason.
    Undecidable(&'static str),
}

/// Decide what an absent subject means, rather than assuming it is harmless.
///
/// The version this replaces mapped both `undefined_table` and `undefined_column` to
/// "clean", on the reasoning that an earlier pending migration must be about to create
/// them. That reasoning is right for a TABLE and wrong for a COLUMN, in a way that
/// produced a false pass on an ordinary migration:
///
/// ```sql
/// ALTER TABLE widgets ADD COLUMN region text;
/// ALTER TABLE widgets ALTER COLUMN region SET NOT NULL;
/// ```
///
/// The `SET NOT NULL` probe asks for NULLs in a column that does not exist yet, gets
/// `undefined_column`, and was reported clean -- while in fact the column arrives NULL on
/// every existing row and the migration fails on the first one. It also excused a probe
/// naming a column NOTHING creates, which is this file's own parser being wrong, laundered
/// into a clean bill for the upgrade.
fn absent_subject_verdict(hazard: &Hazard, shape: &PendingShape) -> AbsentVerdict {
    let table = hazard.table();
    if shape.creates_table(table) {
        return AbsentVerdict::CreatedByThisRun;
    }
    match hazard {
        // The one case where an absent column has a determinate answer: the column is
        // about to exist, all-NULL, and the rule forbids NULL.
        Hazard::NotNull { column, .. } => match shape.creates_column(table, column) {
            Some(false) => AbsentVerdict::EveryRowStranded,
            // Added WITH a default: the rows get that default, and whether it satisfies
            // the rule is not readable from the text (a DEFAULT NULL satisfies nothing).
            Some(true) => AbsentVerdict::Undecidable(
                "this run adds the column with a default, so whether the filled value \
                 satisfies the constraint cannot be read from the migration",
            ),
            None => AbsentVerdict::Undecidable(
                "the probe names a column that neither exists nor is created by any \
                 pending migration, so the probe itself is wrong",
            ),
        },
        // A unique index and a foreign key both ignore rows with a NULL key, and an
        // all-NULL new column makes EVERY row such a row, whatever the other columns
        // hold. So these are clean, determinately.
        Hazard::UniqueIndex { columns, .. } | Hazard::ForeignKey { columns, .. } => {
            let any_arrives_null = columns
                .split(',')
                .any(|column| shape.creates_column(table, column.trim()) == Some(false));
            if any_arrives_null {
                AbsentVerdict::CreatedByThisRun
            } else {
                AbsentVerdict::Undecidable(
                    "the probe names a column that neither exists nor is created without a \
                     default by any pending migration",
                )
            }
        }
        // A CHECK over an absent column is NOT determinate: its expression may reference
        // other columns, so an all-NULL new column does not make the whole expression
        // NULL. Blocking here is the honest answer.
        Hazard::Check { .. } | Hazard::ValidateConstraint { .. } => AbsentVerdict::Undecidable(
            "the constraint references a column this run creates, and whether its \
             expression accepts the filled rows cannot be read from the migration",
        ),
        Hazard::MandatoryNewColumn { .. } => {
            AbsentVerdict::Undecidable("the table is not there and no pending migration creates it")
        }
    }
}

async fn probe(pool: &PgPool, hazard: &Hazard) -> ProbeOutcome {
    let sql = hazard.probe_sql();
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(error) => return ProbeOutcome::Failed(error.to_string()),
    };
    // Read-only and time-boxed: this runs against a live production database during an
    // upgrade window, so it must not be able to write and must not be able to hang.
    for setup in [
        format!("SET LOCAL statement_timeout = {PROBE_TIMEOUT_MS}"),
        "SET LOCAL transaction_read_only = on".to_owned(),
    ] {
        if let Err(error) = sqlx::query(&setup).execute(&mut *tx).await {
            return ProbeOutcome::Failed(error.to_string());
        }
    }
    let outcome = match sqlx::query(&sql).fetch_one(&mut *tx).await {
        Ok(row) => ProbeOutcome::Rows(row.get::<i64, _>("n")),
        // The caller decides what an absent subject means. This module used to excuse
        // 42P01 and 42703 here, which excused a parser error just as readily as a table an
        // earlier pending migration creates.
        Err(sqlx::Error::Database(error)) => match error.code().as_deref() {
            // undefined_table, undefined_column.
            Some("42P01" | "42703") => ProbeOutcome::SubjectAbsent,
            _ => ProbeOutcome::Failed(error.to_string()),
        },
        Err(error) => ProbeOutcome::Failed(error.to_string()),
    };
    drop(tx);
    outcome
}

/// Resolve a `VALIDATE CONSTRAINT`'s expression from the catalog.
///
/// Used when the constraint was added NOT VALID by an already-applied migration, so its
/// text is in `pg_constraint` rather than in any migration this run is about to apply.
async fn constraint_expression(pool: &PgPool, constraint: &str) -> Option<String> {
    let row = sqlx::query(
        "SELECT pg_get_constraintdef(oid) AS definition FROM pg_constraint WHERE conname = $1",
    )
    .bind(constraint)
    .fetch_optional(pool)
    .await
    .ok()??;
    let definition: String = row.get("definition");
    // "CHECK ((expr))" -- take what is inside the outermost parentheses after CHECK.
    let after_check = eat(&definition, "CHECK")?;
    take_parens(&after_check).map(|(expression, _)| expression)
}

/// Render a [`Report`] as the operator-facing text `ironauth doctor` prints.
///
/// Every finding names the migration, the constraint, the row count, and the probe that
/// found them, so the operator can run the same query and see the rows themselves. A
/// report that blocks without saying which rows is not actionable.
#[must_use]
pub fn render(report: &Report) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();

    if report.pending.is_empty() {
        out.push_str(
            "doctor: the database is at this build's schema version; nothing is pending.\n",
        );
        return out;
    }

    let _ = writeln!(
        out,
        "doctor: {} pending migration(s): {}",
        report.pending.len(),
        report
            .pending
            .iter()
            .map(|(version, name)| format!("{version} ({name})"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let _ = writeln!(
        out,
        "doctor: {} probe(s) run against live data, {} skipped as not yet applicable",
        report.probes_run, report.probes_not_yet_applicable
    );

    if !report.findings.is_empty() {
        let _ = writeln!(
            out,
            "\ndoctor: {} pending constraint(s) would be REJECTED by data already in this database:",
            report.findings.len()
        );
        for finding in &report.findings {
            let _ = writeln!(
                out,
                "\n  migration {} ({})\n    {}\n    {} row(s) in the way\n    see them with: {}",
                finding.version,
                finding.name,
                finding.hazard.describe(),
                finding.rows,
                finding.hazard.probe_sql()
            );
        }
    }

    if !report.unanswered.is_empty() {
        let _ = writeln!(
            out,
            "\ndoctor: {} pending statement(s) could NOT be checked. This is not a pass:",
            report.unanswered.len()
        );
        for item in &report.unanswered {
            let reason = match item.reason {
                UnansweredReason::NotRead => "the preflight does not read this statement kind",
                UnansweredReason::ProbeFailed => "the probe could not be answered",
            };
            let _ = writeln!(
                out,
                "\n  migration {} -- {reason}\n    {}",
                item.version, item.detail
            );
        }
    }

    if report.blocks() {
        out.push_str(
            "\ndoctor: UPGRADE BLOCKED. Resolve the rows above, or correct the pending\n             migration, and run doctor again.\n",
        );
    } else {
        let _ = writeln!(
            out,
            "\ndoctor: no row in this database would reject a pending migration."
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{Hazard, derive, split_statements};
    use crate::migrate::{Migration, Phase};

    fn migration(sql: &'static str) -> Migration {
        Migration {
            version: 1,
            name: "probe",
            phase: Phase::Expand,
            sql,
        }
    }

    fn only_hazard(sql: &'static str) -> Hazard {
        let derivation = derive(&migration(sql));
        assert!(
            derivation.unexamined.is_empty(),
            "unexpectedly unread: {:?}",
            derivation.unexamined
        );
        assert_eq!(
            derivation.hazards.len(),
            1,
            "expected one hazard from {sql}"
        );
        derivation.hazards.into_iter().next().expect("just checked")
    }

    #[test]
    fn a_column_made_mandatory_probes_that_column_for_nulls() {
        let hazard = only_hazard("ALTER TABLE widgets ALTER COLUMN state SET NOT NULL;");
        assert_eq!(
            hazard.probe_sql(),
            "SELECT count(*) AS n FROM widgets WHERE state IS NULL"
        );
    }

    #[test]
    fn the_column_keyword_is_optional_as_it_is_in_postgres() {
        let hazard = only_hazard("ALTER TABLE widgets ALTER state SET NOT NULL;");
        assert_eq!(
            hazard.probe_sql(),
            "SELECT count(*) AS n FROM widgets WHERE state IS NULL"
        );
    }

    /// A CHECK is violated only when its expression is FALSE, never when it is NULL.
    /// `WHERE NOT (expression)` would agree on every non-null row and is therefore the
    /// shape that looks right and is not: it silently reclassifies a row Postgres would
    /// ACCEPT. The probe must say IS FALSE.
    #[test]
    fn a_check_probes_for_rows_where_the_expression_is_false_not_merely_not_true() {
        let hazard = only_hazard(
            "ALTER TABLE widgets ADD CONSTRAINT users_state_valid CHECK (state IN ('active'));",
        );
        assert_eq!(
            hazard.probe_sql(),
            "SELECT count(*) AS n FROM widgets WHERE (state IN ('active')) IS FALSE"
        );
    }

    #[test]
    fn a_check_expression_keeps_its_own_parentheses_and_commas() {
        let hazard = only_hazard(
            "ALTER TABLE t ADD CONSTRAINT c CHECK ((a > 0 AND b IN (1, 2)) OR c IS NULL);",
        );
        let Hazard::Check { expression, .. } = &hazard else {
            panic!("expected a CHECK hazard, got {hazard:?}");
        };
        assert_eq!(expression, "(a > 0 AND b IN (1, 2)) OR c IS NULL");
    }

    #[test]
    fn a_new_mandatory_column_without_a_default_strands_every_existing_row() {
        let hazard = only_hazard("ALTER TABLE widgets ADD COLUMN region text NOT NULL;");
        assert_eq!(hazard.probe_sql(), "SELECT count(*) AS n FROM widgets");
    }

    /// The same statement WITH a default strands nothing, and must be reported as read
    /// and cleared rather than as unread. 45 statements in the shipped chain take this
    /// branch; reporting them as unread would bury every real signal under them.
    #[test]
    fn a_new_mandatory_column_with_a_default_is_cleared_not_merely_unreported() {
        let derivation = derive(&migration(
            "ALTER TABLE widgets ADD COLUMN region text NOT NULL DEFAULT 'eu';",
        ));
        assert!(derivation.hazards.is_empty());
        assert!(
            derivation.unexamined.is_empty(),
            "a cleared statement must not be reported as unread: {:?}",
            derivation.unexamined
        );
    }

    /// A unique index treats NULLs as distinct, so a group of NULL rows is not a
    /// duplicate. Without the row-wise IS NOT NULL the probe invents duplicates that
    /// would not block the migration, and blocks an upgrade that was fine.
    #[test]
    fn a_unique_index_probe_excludes_the_rows_the_index_would_not_compare() {
        let hazard =
            only_hazard("CREATE UNIQUE INDEX users_email_key ON widgets (tenant_id, email);");
        assert_eq!(
            hazard.probe_sql(),
            "SELECT count(*) AS n FROM (SELECT 1 FROM widgets WHERE (tenant_id, email) IS NOT NULL \
             GROUP BY tenant_id, email HAVING count(*) > 1) AS duplicated"
        );
    }

    #[test]
    fn a_partial_unique_index_carries_its_predicate_into_the_probe() {
        let hazard =
            only_hazard("CREATE UNIQUE INDEX u ON widgets (email) WHERE deleted_at IS NULL;");
        assert_eq!(
            hazard.probe_sql(),
            "SELECT count(*) AS n FROM (SELECT 1 FROM widgets WHERE (email) IS NOT NULL \
             AND (deleted_at IS NULL) GROUP BY email HAVING count(*) > 1) AS duplicated"
        );
    }

    #[test]
    fn a_foreign_key_probes_for_orphans_and_permits_a_null_reference() {
        let hazard = only_hazard(
            "ALTER TABLE gizmos ADD CONSTRAINT m_user_fk \
             FOREIGN KEY (user_id) REFERENCES widgets (id);",
        );
        assert_eq!(
            hazard.probe_sql(),
            "SELECT count(*) AS n FROM gizmos AS child WHERE child.user_id IS NOT NULL \
             AND NOT EXISTS (SELECT 1 FROM widgets AS parent WHERE parent.id = child.user_id)"
        );
    }

    /// NOT VALID tells Postgres not to scan, so the statement applies against any data.
    /// Cleared, not unread.
    #[test]
    fn a_not_valid_constraint_is_cleared_because_postgres_does_not_scan_for_it() {
        let derivation = derive(&migration(
            "ALTER TABLE t ADD CONSTRAINT c CHECK (a > 0) NOT VALID;",
        ));
        assert!(derivation.hazards.is_empty());
        assert!(derivation.unexamined.is_empty());
    }

    /// The honesty valve. Each of these IS constraint-shaped and this parser does not read
    /// it, so it must surface rather than pass. If one ever fails because the parser
    /// learned to read it, the fix is to assert the hazard, never to delete the case --
    /// which is exactly what happened to PRIMARY KEY, now covered below.
    #[test]
    fn a_constraint_kind_the_parser_does_not_read_is_reported_not_passed() {
        for sql in [
            // Adopts an existing index, so the columns are not in the statement at all.
            "ALTER TABLE t ADD CONSTRAINT p PRIMARY KEY USING INDEX t_idx;",
            // Inverts the NULL rule the unique probe assumes.
            "ALTER TABLE t ADD CONSTRAINT u UNIQUE NULLS NOT DISTINCT (a, b);",
            // Inverts the NULL rule the foreign-key probe assumes.
            "ALTER TABLE t ADD CONSTRAINT f FOREIGN KEY (a, b) REFERENCES p (x, y) MATCH FULL;",
            // Rewrites the table and re-casts every row.
            "ALTER TABLE t ALTER COLUMN c TYPE bigint;",
            "ALTER TABLE t ALTER COLUMN c SET DATA TYPE varchar(8);",
            // Not a constraint this parser models.
            "ALTER TABLE t ADD CONSTRAINT e EXCLUDE USING gist (c WITH &&);",
        ] {
            let derivation = derive(&migration(sql));
            assert!(
                derivation.hazards.is_empty(),
                "{sql} should not produce a hazard"
            );
            assert_eq!(
                derivation.unexamined.len(),
                1,
                "{sql} must be reported as unread, not silently cleared"
            );
        }
    }

    /// A type change is the case that motivated turning the ALTER COLUMN branch into an
    /// allow list. It cannot be probed from the migration text, so it must block; the
    /// thing it must NOT do is read as safe because it is not `SET NOT NULL`.
    #[test]
    fn a_narrowing_type_change_is_never_cleared() {
        let derivation = derive(&migration(
            "ALTER TABLE widgets ALTER COLUMN name TYPE varchar(64);",
        ));
        assert!(derivation.hazards.is_empty());
        assert_eq!(derivation.unexamined.len(), 1);
        assert!(derivation.unexamined[0].contains("TYPE"));
    }

    /// The actions that genuinely cannot be rejected by a row stay cleared, so the
    /// allow list above does not simply block everything.
    #[test]
    fn a_relaxing_column_action_is_cleared() {
        for sql in [
            "ALTER TABLE t ALTER COLUMN c DROP NOT NULL;",
            "ALTER TABLE t ALTER COLUMN c SET DEFAULT 'x';",
            "ALTER TABLE t ALTER COLUMN c DROP DEFAULT;",
            "ALTER TABLE t ENABLE ROW LEVEL SECURITY;",
            "ALTER TABLE t FORCE ROW LEVEL SECURITY;",
            "ALTER TABLE t DROP CONSTRAINT c;",
            "ALTER TABLE t DROP COLUMN c;",
        ] {
            let derivation = derive(&migration(sql));
            assert!(derivation.hazards.is_empty(), "{sql}");
            assert!(
                derivation.unexamined.is_empty(),
                "{sql} is a decision, not an absence of one: {:?}",
                derivation.unexamined
            );
        }
    }

    /// A PRIMARY KEY is two rules at once, and probing one would report a clean bill on
    /// the strength of the half that happened to pass.
    #[test]
    fn a_primary_key_probes_both_mandatory_columns_and_uniqueness() {
        let derivation = derive(&migration(
            "ALTER TABLE t ADD CONSTRAINT t_pkey PRIMARY KEY (tenant_id, id);",
        ));
        assert!(derivation.unexamined.is_empty());
        let probes: Vec<String> = derivation.hazards.iter().map(Hazard::probe_sql).collect();
        assert_eq!(
            probes.len(),
            3,
            "two NOT NULLs and one uniqueness: {probes:?}"
        );
        assert!(probes.contains(&"SELECT count(*) AS n FROM t WHERE tenant_id IS NULL".to_owned()));
        assert!(probes.contains(&"SELECT count(*) AS n FROM t WHERE id IS NULL".to_owned()));
        assert!(
            probes.iter().any(|p| p.contains("GROUP BY tenant_id, id")),
            "{probes:?}"
        );
    }

    /// The four statements in the shipped chain that used to be parsed as a column named
    /// `PRIMARY` or `FOREIGN`. An unnamed constraint is a constraint.
    #[test]
    fn an_unnamed_table_constraint_is_read_as_a_constraint_not_a_column() {
        let unnamed = derive(&migration(
            "ALTER TABLE t ADD FOREIGN KEY (env_id, tenant_id) REFERENCES e (id, tenant_id);",
        ));
        assert!(unnamed.unexamined.is_empty(), "{:?}", unnamed.unexamined);
        assert_eq!(unnamed.hazards.len(), 1);
        assert!(unnamed.hazards[0].probe_sql().contains("NOT EXISTS"));

        let check = derive(&migration("ALTER TABLE t ADD CHECK (a > 0);"));
        assert_eq!(check.hazards.len(), 1);
        assert!(check.hazards[0].probe_sql().contains("(a > 0) IS FALSE"));

        let unique = derive(&migration("ALTER TABLE t ADD UNIQUE (a, b);"));
        assert_eq!(unique.hazards.len(), 1);
        assert!(unique.hazards[0].probe_sql().contains("GROUP BY a, b"));
    }

    /// `DEFAULT` and `NOT VALID` decide whether a statement is cleared, so neither may be
    /// matched inside a value. A column whose default is the TEXT 'NOT NULL' is still a
    /// defaulted column; a constraint compared against the TEXT 'NOT VALID' is still
    /// validated.
    #[test]
    fn a_keyword_inside_a_string_literal_does_not_decide_a_statement() {
        // The word DEFAULT appears only inside the literal, so this column is mandatory
        // with NO default and every existing row is stranded.
        let mandatory = derive(&migration(
            "ALTER TABLE t ADD COLUMN mode text NOT NULL COLLATE \"en_US\" CHECK (mode <> 'DEFAULT');",
        ));
        assert_eq!(
            mandatory.hazards.len(),
            1,
            "DEFAULT inside a literal must not clear a mandatory column: {mandatory:?}"
        );

        // NOT VALID appears only inside the literal, so this constraint IS validated.
        let validated = derive(&migration(
            "ALTER TABLE t ADD CONSTRAINT c CHECK (status <> 'NOT VALID');",
        ));
        assert_eq!(
            validated.hazards.len(),
            1,
            "NOT VALID inside a literal must not defer the scan: {validated:?}"
        );
    }

    /// A keyword match without a word boundary splits an identifier that starts with one.
    ///
    /// `COLUMN` is optional in `ADD [COLUMN] c ...`, so a bare column name is matched
    /// against the constraint keywords first -- and a column called `checksum` or
    /// `uniqueness_score` begins with one. Without the boundary, `eat` consumes the
    /// prefix, the action is taken for an unnamed CHECK or UNIQUE, and a genuinely
    /// mandatory new column is filed as unread instead of as the hazard it is.
    ///
    /// The earlier version of this test used `ADD CONSTRAINT uniqueness_rule CHECK (...)`,
    /// where the CONSTRAINT branch is taken before any keyword loop runs, so the boundary
    /// was never consulted: deleting it left the test green. These cases discriminate.
    #[test]
    fn a_keyword_match_respects_word_boundaries() {
        for (sql, column) in [
            ("ALTER TABLE t ADD checksum text NOT NULL;", "checksum"),
            (
                "ALTER TABLE t ADD uniqueness_score int NOT NULL;",
                "uniqueness_score",
            ),
        ] {
            let derivation = derive(&migration(sql));
            assert!(
                derivation.unexamined.is_empty(),
                "{sql} names a column, not a constraint: {:?}",
                derivation.unexamined
            );
            assert_eq!(derivation.hazards.len(), 1, "{sql}");
            let Hazard::MandatoryNewColumn { column: got, .. } = &derivation.hazards[0] else {
                panic!(
                    "{sql} should be a mandatory new column, got {:?}",
                    derivation.hazards[0]
                );
            };
            assert_eq!(got, column, "{sql}");
        }

        // And the named form still parses, so the boundary did not break the common case.
        let named = derive(&migration(
            "ALTER TABLE t ADD CONSTRAINT uniqueness_rule CHECK (uniqueness > 0);",
        ));
        assert_eq!(named.hazards.len(), 1);
        assert_eq!(
            named.hazards[0].probe_sql(),
            "SELECT count(*) AS n FROM t WHERE (uniqueness > 0) IS FALSE"
        );
    }

    /// A clause between the column list and WHERE used to make the predicate silently
    /// None, widening the probe from the partial index's rows to the whole table.
    #[test]
    fn a_unique_index_whose_predicate_cannot_be_read_exactly_is_unread() {
        let derivation = derive(&migration(
            "CREATE UNIQUE INDEX u ON t (a) INCLUDE (b) WHERE deleted_at IS NULL;",
        ));
        assert!(
            derivation.hazards.is_empty(),
            "a half-read partial index must not be probed as if it covered every row: {:?}",
            derivation.hazards
        );
        assert_eq!(derivation.unexamined.len(), 1);
    }

    /// NOT VALID defers the scan to a later VALIDATE, so clearing both would mean the
    /// constraint is never checked. When the pair sits in one migration the expression is
    /// in the text, and the VALIDATE is probed with it.
    #[test]
    fn a_deferred_constraint_is_probed_when_its_validate_runs() {
        let derivation = derive(&migration(
            "ALTER TABLE t ADD CONSTRAINT c CHECK (n >= 0) NOT VALID;\n\
             ALTER TABLE t VALIDATE CONSTRAINT c;",
        ));
        assert!(
            derivation.unexamined.is_empty(),
            "{:?}",
            derivation.unexamined
        );
        assert_eq!(
            derivation.hazards.len(),
            1,
            "the ADD is deferred, the VALIDATE is not"
        );
        assert_eq!(
            derivation.hazards[0].probe_sql(),
            "SELECT count(*) AS n FROM t WHERE (n >= 0) IS FALSE"
        );
    }

    /// One statement, two actions, one of each. A statement that yields a hazard is not
    /// evidence that its other actions were read.
    #[test]
    fn an_unread_action_surfaces_even_beside_one_that_parsed() {
        let derivation = derive(&migration(
            "ALTER TABLE t ADD CONSTRAINT c CHECK (a > 0), ALTER COLUMN b TYPE bigint;",
        ));
        assert_eq!(derivation.hazards.len(), 1);
        assert_eq!(derivation.unexamined.len(), 1);
        assert!(derivation.unexamined[0].contains("TYPE"));
    }

    #[test]
    fn a_semicolon_inside_a_dollar_quoted_body_is_not_a_statement_boundary() {
        let statements = split_statements(
            "CREATE FUNCTION f() RETURNS trigger AS $$ BEGIN RETURN NEW; END; $$ LANGUAGE plpgsql;\n\
             ALTER TABLE t ALTER COLUMN c SET NOT NULL;",
        );
        assert_eq!(statements.len(), 2, "got {statements:?}");
        assert!(statements[1].contains("SET NOT NULL"));
    }

    #[test]
    fn a_semicolon_inside_a_string_or_a_comment_is_not_a_statement_boundary() {
        let statements = split_statements(
            "INSERT INTO t (v) VALUES ('a;b'); -- a trailing; comment\n\
             ALTER TABLE t ALTER COLUMN c SET NOT NULL;",
        );
        assert_eq!(statements.len(), 2, "got {statements:?}");
        assert!(statements[0].contains("'a;b'"));
        assert!(statements[1].contains("SET NOT NULL"));
    }

    /// The whole shipped chain is readable by this parser.
    ///
    /// This guard was ONCE VACUOUS and is worth the warning. It inspects only
    /// `unexamined`, and in the first version an unrecognised `ADD` action fell through to
    /// the ADD COLUMN branch and returned `Verdict::Safe` -- which puts nothing in
    /// `unexamined`. Four statements in the chain took that path (two `ADD PRIMARY KEY` in
    /// 0168, two `ADD FOREIGN KEY` in 0150), so the test passed BECAUSE of the misparse it
    /// was written to catch. It only means something now that `Safe` requires an
    /// affirmative decision and every unread action is reported.
    ///
    /// The hazard floor is the other half. Without it a parser that stopped reading
    /// anything at all would satisfy the `unread.is_empty()` half perfectly.
    #[test]
    fn every_constraint_in_the_shipped_chain_is_read() {
        let mut unread = Vec::new();
        let mut hazards = 0usize;
        let mut kinds = (0usize, 0usize, 0usize, 0usize, 0usize);
        for migration in &crate::migrate::chain() {
            let derivation = derive(migration);
            hazards += derivation.hazards.len();
            for hazard in &derivation.hazards {
                match hazard {
                    Hazard::NotNull { .. } | Hazard::MandatoryNewColumn { .. } => kinds.0 += 1,
                    Hazard::Check { .. } => kinds.1 += 1,
                    Hazard::UniqueIndex { .. } => kinds.2 += 1,
                    Hazard::ForeignKey { .. } => kinds.3 += 1,
                    Hazard::ValidateConstraint { .. } => kinds.4 += 1,
                }
            }
            for statement in derivation.unexamined {
                unread.push(format!("{}: {statement}", migration.version));
            }
        }
        assert!(
            unread.is_empty(),
            "the preflight cannot read {} constraint statement(s) in the shipped chain, so \
             `ironauth doctor` would not check them: {unread:#?}",
            unread.len()
        );
        assert!(
            hazards > 150,
            "only {hazards} probes derived from the whole chain, which means the parser \
             stopped reading it rather than that the chain stopped constraining"
        );
        // Every kind the parser can probe is actually exercised by the chain, so none of
        // the five arms is dead code that nothing would notice breaking.
        for (kind, count) in [
            ("NOT NULL", kinds.0),
            ("CHECK", kinds.1),
            ("UNIQUE", kinds.2),
            ("FOREIGN KEY", kinds.3),
            ("VALIDATE", kinds.4),
        ] {
            assert!(
                count > 0,
                "the chain exercises no {kind} probe, so its arm is untested here"
            );
        }
    }
}
