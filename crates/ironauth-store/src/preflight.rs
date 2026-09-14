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
//!
//! Everything else in a migration is additive against existing rows, or it is
//! `NOT VALID` (which Postgres accepts without scanning), or it is a kind this parser
//! does not recognise. That last case is the one that matters: a preflight whose
//! silence means BOTH "no row is at risk" and "I did not understand this statement" is
//! not a preflight. So any statement that LOOKS constraint-shaped (it contains one of
//! the phrases above) and that [`derive`] could not turn into a probe is reported by
//! name in [`Derivation::unexamined`], and `ironauth doctor` prints those separately
//! from its findings rather than folding them into a clean verdict.
//!
//! # Scope
//!
//! This runs read-only, against live data, before the upgrade. It does not apply
//! anything and holds no locks. It answers one question (would a pending migration be
//! rejected by the rows that are already there) and deliberately not the other two:
//! whether the NEW BINARY can read the OLD rows is `scripts/expand-phase-ddl.sh`, and
//! whether an APPLIED migration's text has changed is the checksum in
//! [`crate::MigrationRunner`].

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

/// Case-insensitive prefix match, returning the remainder.
fn eat(input: &str, keyword: &str) -> Option<String> {
    let trimmed = input.trim_start();
    if trimmed.len() >= keyword.len() && trimmed[..keyword.len()].eq_ignore_ascii_case(keyword) {
        Some(trimmed[keyword.len()..].to_owned())
    } else {
        None
    }
}

/// Whether a statement contains a phrase that can impose a constraint on existing
/// rows. Used only to decide whether silence means "additive" or "not read".
fn looks_constraint_shaped(statement: &str) -> bool {
    let upper = statement.to_ascii_uppercase();
    upper.contains("SET NOT NULL")
        || upper.contains("ADD CONSTRAINT")
        || upper.contains("CREATE UNIQUE INDEX")
        || (upper.contains("ADD COLUMN") && upper.contains("NOT NULL"))
        || (upper.contains("ALTER TABLE") && upper.contains("ADD UNIQUE"))
        || (upper.contains("ALTER TABLE") && upper.contains("ADD PRIMARY KEY"))
}

/// Read one migration and build a probe for every statement that could be rejected by
/// rows already in the database.
///
/// See the module header for the five statement kinds this understands and for why a
/// statement it does not understand is reported rather than passed.
#[must_use]
pub fn derive(migration: &Migration) -> Derivation {
    let mut derivation = Derivation::default();
    for statement in split_statements(migration.sql) {
        if let Some(rest) = eat(&statement, "ALTER TABLE") {
            derive_alter_table(&rest, &statement, &mut derivation);
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
fn derive_alter_table(after_keyword: &str, whole: &str, derivation: &mut Derivation) {
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
        match derive_action(&table, &action) {
            Verdict::Hazard(hazard) => derivation.hazards.push(hazard),
            Verdict::Safe => {}
            Verdict::Unread => {
                if looks_constraint_shaped(&action) {
                    derivation
                        .unexamined
                        .push(format!("ALTER TABLE {table} {action}"));
                }
            }
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
    /// Existing rows can reject this statement, and here is the probe that finds them.
    Hazard(Hazard),
    /// The parser read this statement and determined no existing row can reject it.
    Safe,
    /// The parser did not recognise this statement. Never a pass.
    Unread,
}

fn derive_action(table: &str, action: &str) -> Verdict {
    // NOT VALID defers the scan, so Postgres accepts the statement against any data and
    // nothing is stranded when it applies. Validating it later is a separate operator
    // step, outside this preflight. This is a decision about the statement, not a
    // failure to read it.
    if action.to_ascii_uppercase().contains("NOT VALID") {
        return Verdict::Safe;
    }
    if let Some(rest) = eat(action, "ALTER") {
        return derive_alter_column(table, &rest);
    }
    if let Some(rest) = eat(action, "ADD") {
        return derive_add(table, &rest);
    }
    Verdict::Unread
}

/// `ALTER [COLUMN] c SET NOT NULL`. The `COLUMN` keyword is optional in Postgres.
fn derive_alter_column(table: &str, after_alter: &str) -> Verdict {
    let rest = eat(after_alter, "COLUMN").unwrap_or_else(|| after_alter.to_owned());
    let Some((column, tail)) = take_ident(&rest) else {
        return Verdict::Unread;
    };
    if eat(tail, "SET NOT NULL").is_none() {
        // Every other ALTER COLUMN action (DROP NOT NULL, SET DEFAULT, TYPE) relaxes or
        // retypes rather than constrains, so no existing row is rejected by it.
        return Verdict::Safe;
    }
    Verdict::Hazard(Hazard::NotNull {
        table: table.to_owned(),
        column,
    })
}

/// `ADD CONSTRAINT n ...`, `ADD COLUMN c ...`, and the unnamed `ADD UNIQUE (...)`.
fn derive_add(table: &str, after_add: &str) -> Verdict {
    if let Some(rest) = eat(after_add, "CONSTRAINT") {
        let Some((constraint, body)) = take_ident(&rest) else {
            return Verdict::Unread;
        };
        return derive_constraint_body(table, &constraint, body);
    }
    if let Some(rest) = eat(after_add, "UNIQUE") {
        let Some((columns, _)) = take_parens(&rest) else {
            return Verdict::Unread;
        };
        return Verdict::Hazard(Hazard::UniqueIndex {
            table: table.to_owned(),
            index: format!("(unnamed UNIQUE on {table})"),
            columns,
            predicate: None,
        });
    }
    let rest = eat(after_add, "COLUMN").unwrap_or_else(|| after_add.to_owned());
    let rest = eat(&rest, "IF NOT EXISTS").unwrap_or(rest);
    let Some((column, tail)) = take_ident(&rest) else {
        return Verdict::Unread;
    };
    let upper = tail.to_ascii_uppercase();
    // A new mandatory column strands every existing row ONLY when it has no default to
    // fill them with. A volatile default is still a default: Postgres evaluates it per
    // row, so the column is never null and no row is stranded. That is a decision about
    // the statement, so it is Safe and not Unread: 45 of the chain's ADD COLUMNs take
    // this branch, and reporting them as unread would bury the real signal.
    if upper.contains("NOT NULL") && !upper.contains("DEFAULT") {
        return Verdict::Hazard(Hazard::MandatoryNewColumn {
            table: table.to_owned(),
            column,
        });
    }
    Verdict::Safe
}

fn derive_constraint_body(table: &str, constraint: &str, body: &str) -> Verdict {
    if let Some(rest) = eat(body, "CHECK") {
        let Some((expression, _)) = take_parens(&rest) else {
            return Verdict::Unread;
        };
        return Verdict::Hazard(Hazard::Check {
            table: table.to_owned(),
            constraint: constraint.to_owned(),
            expression,
        });
    }
    if let Some(rest) = eat(body, "UNIQUE") {
        // NULLS NOT DISTINCT (Postgres 15+) inverts the NULL handling probe_sql assumes,
        // so this is Unread rather than probed with the wrong predicate.
        if rest.to_ascii_uppercase().contains("NULLS NOT DISTINCT") {
            return Verdict::Unread;
        }
        let Some((columns, _)) = take_parens(&rest) else {
            return Verdict::Unread;
        };
        return Verdict::Hazard(Hazard::UniqueIndex {
            table: table.to_owned(),
            index: constraint.to_owned(),
            columns,
            predicate: None,
        });
    }
    if let Some(rest) = eat(body, "FOREIGN KEY") {
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
        return Verdict::Hazard(Hazard::ForeignKey {
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
    if rest.to_ascii_uppercase().contains("NULLS NOT DISTINCT") {
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
    let predicate = eat(after_columns, "WHERE").map(|p| p.trim().to_owned());
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
                ProbeOutcome::NotYetApplicable => report.probes_not_yet_applicable += 1,
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
    /// The table or column is not there yet, because an earlier pending migration
    /// creates it. No existing row can be stranded in a table that does not exist.
    NotYetApplicable,
    Failed(String),
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
        Err(sqlx::Error::Database(error)) => match error.code().as_deref() {
            // undefined_table, undefined_column: created by an earlier pending migration.
            Some("42P01" | "42703") => ProbeOutcome::NotYetApplicable,
            _ => ProbeOutcome::Failed(error.to_string()),
        },
        Err(error) => ProbeOutcome::Failed(error.to_string()),
    };
    drop(tx);
    outcome
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

    /// The honesty valve. These two ARE constraint-shaped and this parser does not read
    /// them, so they must surface rather than pass. If this test ever fails because the
    /// parser learned to read them, the fix is to assert the hazard, never to delete the
    /// case.
    #[test]
    fn a_constraint_kind_the_parser_does_not_read_is_reported_not_passed() {
        for sql in [
            "ALTER TABLE t ADD CONSTRAINT t_pkey PRIMARY KEY (id);",
            "ALTER TABLE t ADD CONSTRAINT u UNIQUE NULLS NOT DISTINCT (a, b);",
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

    /// One statement, two actions, one of each. A statement that yields a hazard is not
    /// evidence that its other actions were read.
    #[test]
    fn an_unread_action_surfaces_even_beside_one_that_parsed() {
        let derivation = derive(&migration(
            "ALTER TABLE t ADD CONSTRAINT c CHECK (a > 0), ADD CONSTRAINT p PRIMARY KEY (id);",
        ));
        assert_eq!(derivation.hazards.len(), 1);
        assert_eq!(derivation.unexamined.len(), 1);
        assert!(derivation.unexamined[0].contains("PRIMARY KEY"));
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

    /// The whole shipped chain is readable by this parser. Not a restatement of the
    /// parser's output: it asserts a property (nothing constraint-shaped went unread)
    /// that fails the moment a new migration uses a constraint kind this cannot probe,
    /// which is exactly when the doctor would start being quietly incomplete.
    #[test]
    fn every_constraint_in_the_shipped_chain_is_read() {
        let mut unread = Vec::new();
        let mut hazards = 0usize;
        for migration in &crate::migrate::chain() {
            let derivation = derive(migration);
            hazards += derivation.hazards.len();
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
            hazards > 100,
            "only {hazards} probes derived from the whole chain, which means the parser \
             stopped reading it rather than that the chain stopped constraining"
        );
    }
}
