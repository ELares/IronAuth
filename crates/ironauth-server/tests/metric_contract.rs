// SPDX-License-Identifier: MIT OR Apache-2.0

//! The metric contract, checked against the EMIT SITES (issue #152 criterion 1).
//!
//! # What the criterion asks
//!
//! > Every metric in the documented contract is exported and carries the documented labels; a
//! > CI contract test fails on drift in either direction.
//!
//! # Two directions, and they are checked by different tests
//!
//! `every_contract_metric_has_an_emit_site` is CONTRACT -> CODE: a metric promised and never
//! emitted is a graph that renders empty and an alert that never fires.
//!
//! `every_emit_site_matches_the_contract_it_is_declared_under` is CODE -> CONTRACT: a series
//! emitted and undocumented is how cardinality arrives unreviewed, and a site whose labels or
//! kind disagree with the contract breaks whatever query was written against it.
//!
//! ONLY THE SECOND EXISTED AT FIRST. Both tests iterated the wrong collection -- one over the
//! sites, one over the declared constants, neither over `CONTRACT` -- so "every metric in the
//! contract is exported", which the criterion names FIRST, had no assertion behind it while two
//! files claimed it did. Adding a contract entry nothing emits passed. My own mutants missed it
//! because all three mutated the direction I had built rather than the one I had promised.
//!
//! # Why not a scrape
//!
//! An earlier version emitted every metric by READING THE CONTRACT for its kind and labels,
//! scraped, and compared. That is circular: the expected value travelled with the thing under
//! test, so it proved the Prometheus exporter renders what it is handed. A contract claiming a
//! label no site emits passed it.
//!
//! What has to be compared is the CALL SITES, because they are what runs.

use ironauth_server::metrics::{self, MetricKind};

/// Every emit site in the server crate: which macro, which metric constant, which labels.
///
/// # A TEXT SCAN, and what it therefore cannot see
///
/// It reads `counter!(CONST, "a" => .., "b" => ..)` and the gauge and histogram forms out of the
/// crate's own source. It does NOT see a call assembled from a variable, a label list built at
/// runtime, or an emit inside another crate. So a passing scan is not proof that no site
/// disagrees; it is proof that no site it can read disagrees, which is the honest claim and is
/// still the one that catches the change a person actually makes.
fn emit_sites() -> Vec<(String, String, Vec<String>)> {
    let mut sites = Vec::new();
    // READ AT RUNTIME, NOT `include_str!`, because the outbox and log-stream metrics are emitted
    // from the BINARY crate and a macro path cannot reach a sibling crate without a brittle
    // relative literal. Finding that out was the scan telling me its file list was incomplete:
    // the first version listed three files in this crate and reported that no site sets
    // `consumer`, which was true of the files it read and false of the workspace.
    for source in workspace_sources() {
        for macro_name in ["counter", "gauge", "histogram"] {
            let needle = format!("{macro_name}!(");
            let mut from = 0;
            while let Some(at) = source[from..].find(&needle) {
                let start = from + at;
                let open = start + needle.len();
                // ANCHORED. A bare `find` for "gauge!(" also matches inside "describe_gauge!(",
                // and eleven of the seventy sites the first version found were describe_ calls,
                // which register HELP and TYPE and emit no series at all. That made the scan's
                // own definition of "emitted" wrong in the unsafe direction: a metric whose real
                // emits were deleted still had a "site", so it looked exported when it was not.
                if start > 0
                    && source[..start]
                        .chars()
                        .next_back()
                        .is_some_and(|c| c.is_alphanumeric() || c == '_')
                {
                    from = open;
                    continue;
                }
                // The macro's arguments, to the matching close paren. Nesting is shallow here
                // (a call like `reason_label(reason)` appears as a label VALUE), so a depth
                // counter is enough and a full parser is not.
                let mut depth = 1usize;
                let mut close = open;
                for (offset, ch) in source[open..].char_indices() {
                    match ch {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                close = open + offset;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let args = &source[open..close];
                from = close.max(open + 1);

                // The first argument is the metric: a bare constant, or `metrics::CONST`.
                let Some(first) = args.split(',').next() else {
                    continue;
                };
                let ident = first.trim().rsplit("::").next().unwrap_or("").trim();
                if ident.is_empty() || !ident.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
                    continue;
                }
                // A label is the token immediately BEFORE each `=>`. Taking the last
                // comma-separated piece of the text before the arrow skips the previous
                // label's VALUE, which may itself contain commas (a function call).
                let pieces: Vec<&str> = args.split("=>").collect();
                let labels: Vec<String> = pieces[..pieces.len().saturating_sub(1)]
                    .iter()
                    .filter_map(|before| {
                        before
                            .rsplit(',')
                            .next()
                            .map(|raw| raw.trim().trim_matches('"').to_owned())
                    })
                    .filter(|label| !label.is_empty() && !label.contains('('))
                    .collect();
                sites.push((ident.to_owned(), macro_name.to_owned(), labels));
            }
        }
    }
    sites
}

/// Every Rust source in the workspace that could emit a metric.
///
/// Walks the tree from this crate's manifest directory rather than taking a list, so a metric
/// emitted from a crate nobody thought of is still seen. Target directories are skipped: they
/// hold generated code and vendored sources, which are not emit sites anybody edits.
fn workspace_sources() -> Vec<String> {
    fn walk(dir: &std::path::Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                // A TEST EMIT IS NOT AN EXPORT, and this walk did not enforce that.
                //
                // `cfg_test_spans` below closes the in-`src` door: an emit inside
                // `#[cfg(test)] mod tests` does not count. The OTHER door was open. Integration
                // tests live in `tests/` and need no `cfg(test)` attribute, because the whole
                // file is already a test target, so `cfg_test_spans` finds nothing to exclude
                // and every line of them counted as a production emit site.
                //
                // That is the same hole the `ironauth_up` incident in `cfg_test_spans`'s doc
                // describes, reached through a different directory: a contract metric emitted
                // ONLY from a test would satisfy "every contract metric has an emit site"
                // while the process never set it.
                let skip = matches!(
                    name.as_ref(),
                    "target" | "tests" | "benches" | "examples" | "fuzz"
                );
                if !skip && !name.starts_with('.') {
                    walk(&path, out);
                }
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    out.push(text);
                }
            }
        }
    }
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate directory has a parent")
        .to_path_buf();
    let mut out = Vec::new();
    walk(&crates, &mut out);
    assert!(
        out.len() > 50,
        "the walk found {} sources, too few to be reading the workspace",
        out.len()
    );
    out
}

/// Byte ranges of every `#[cfg(test)]` item in `source`.
///
/// A TEST EMIT IS NOT AN EXPORT, and this file already believed that: `workspace_sources`
/// exists to read the whole tree, and the intent was always that tests do not count. But in
/// this repository tests live in two places, and only `tests/` directories were excluded.
/// An emit inside `#[cfg(test)] mod tests` in a `src/` file counted as production.
///
/// A review deleted BOTH production emits of `ironauth_up` -- the process no longer set its
/// liveness gauge at all -- and every check stayed green, propped up by a single emit inside
/// a test module. An `absent(ironauth_up)` alert would never have fired.
fn cfg_test_spans(source: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut from = 0;
    while let Some(at) = source[from..].find("#[cfg(test)]") {
        let start = from + at;
        // Find the item's opening brace, then its matching close.
        let Some(open_offset) = source[start..].find('{') else {
            break;
        };
        let open = start + open_offset;
        let mut depth = 0usize;
        let mut close = open;
        for (offset, ch) in source[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = open + offset;
                        break;
                    }
                }
                _ => {}
            }
        }
        spans.push((start, close));
        from = close.max(start + 1);
    }
    spans
}

/// Every `pub const NAME: &str = "ironauth_..."` ANYWHERE in the workspace.
///
/// The sibling `value_of` reads only this crate's metrics module, which is correct for the
/// constants declared there and blind to the ones other crates declare. A metric named by a
/// constant in `ironauth-fetch` was invisible to every check here.
fn workspace_metric_consts() -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    for source in workspace_sources() {
        // SPAN-BASED, not line-based. `pub const NAME: &str =` wraps onto the next line when
        // the value is long, and a line-based read missed exactly those: the first version of
        // this scan could not see
        // `ironauth_lazy_migration_breaker_transitions_total`, whose declaration wraps.
        let mut from = 0;
        while let Some(at) = source[from..].find("const ") {
            let start = from + at;
            from = start + "const ".len();
            let Some(rest) = source.get(from..) else {
                break;
            };
            let Some((ident, tail)) = rest.split_once(':') else {
                continue;
            };
            let ident = ident.trim();
            if ident.is_empty()
                || !ident
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            {
                continue;
            }
            // The value must follow within this declaration, so stop at the terminating
            // semicolon rather than running on into the next item.
            let Some((decl, _)) = tail.split_once(';') else {
                continue;
            };
            // Split on the `=` and then take the first string, rather than matching `= "`:
            // a long value wraps onto the next line, putting a newline between them. That is
            // exactly how `ironauth_lazy_migration_breaker_transitions_total` is written, and
            // it was the last metric this scan could not see.
            let Some((_, value)) = decl.split_once('=') else {
                continue;
            };
            let Some((_, value)) = value.split_once('"') else {
                continue;
            };
            let Some((value, _)) = value.split_once('"') else {
                continue;
            };
            if value.starts_with("ironauth_") {
                out.insert(ident.to_owned(), value.to_owned());
            }
        }
    }
    out
}

/// Every metric name the workspace emits from PRODUCTION code.
///
/// Accepts both spellings of the first macro argument: a bare string literal and a constant.
/// The sibling `emit_sites` accepts only an all-uppercase identifier, so every
/// literal-named metric was skipped -- which is why the contract covered eleven of the
/// thirty-eight this workspace emits.
fn workspace_emitted_metrics() -> std::collections::BTreeSet<String> {
    let consts = workspace_metric_consts();
    let mut names = std::collections::BTreeSet::new();
    for source in workspace_sources() {
        let skip = cfg_test_spans(&source);
        for macro_name in ["counter", "gauge", "histogram"] {
            let needle = format!("{macro_name}!(");
            let mut from = 0;
            while let Some(at) = source[from..].find(&needle) {
                let start = from + at;
                let open = start + needle.len();
                from = open;
                // Anchored, so `describe_gauge!(` does not read as `gauge!(`.
                if start > 0
                    && source[..start]
                        .chars()
                        .next_back()
                        .is_some_and(|c| c.is_alphanumeric() || c == '_')
                {
                    continue;
                }
                if skip.iter().any(|(lo, hi)| start >= *lo && start <= *hi) {
                    continue;
                }
                let Some(first) = source[open..]
                    .split(',')
                    .next()
                    .and_then(|first| first.split(')').next())
                else {
                    continue;
                };
                let first = first.trim();
                let name = if let Some(literal) = first
                    .strip_prefix('"')
                    .and_then(|rest| rest.split('"').next())
                {
                    literal.to_owned()
                } else {
                    let ident = first.rsplit("::").next().unwrap_or("").trim();
                    match consts.get(ident) {
                        Some(value) => value.clone(),
                        None => continue,
                    }
                };
                if name.starts_with("ironauth_") {
                    names.insert(name);
                }
            }
        }
    }
    names
}

/// THE OTHER BOUNDARY: every metric the WORKSPACE emits is in the contract.
///
/// `the_contract_covers_every_metric_this_module_declares` covers what this module declares,
/// which was eleven. The workspace emits thirty-eight, so twenty-seven were promised to
/// nobody and checked by nothing: not their kind, not their labels, not whether they still
/// exist. A dashboard built on one of them had no contract behind it at all.
#[test]
fn the_contract_covers_every_metric_the_workspace_emits() {
    let emitted = workspace_emitted_metrics();
    assert!(
        emitted.len() >= 30,
        "the scan found {} emitted metrics, too few to be reading the workspace; the \
         assertion below would pass by covering almost nothing",
        emitted.len()
    );

    let promised: std::collections::HashSet<&str> =
        metrics::CONTRACT.iter().map(|spec| spec.name).collect();
    let missing: Vec<&String> = emitted
        .iter()
        .filter(|name| !promised.contains(name.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "these metrics are emitted and not in the contract, so nothing checks their kind, \
         their labels, or whether they still exist: {missing:?}"
    );
}

/// The value of a `pub const NAME: &str = "..."` in the metrics module.
fn value_of(ident: &str) -> Option<String> {
    include_str!("../src/metrics.rs")
        .split_once(&format!("pub const {ident}: &str = \""))
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(value, _)| value.to_owned())
}

#[test]
fn every_emit_site_matches_the_contract_it_is_declared_under() {
    // THE CHECK THAT IS NOT CIRCULAR, and the first version of this file did not have it.
    //
    // That version emitted every metric by READING THE CONTRACT for its kind and labels, then
    // scraped and asserted the scrape matched the contract. It passed against a contract
    // claiming a label no call site emits, and against one declaring the wrong kind, because
    // the expected value travelled with the thing under test: it proved the exporter renders
    // what it is given.
    //
    // What has to be compared is the CALL SITES against the contract, because they are what
    // actually runs.
    let sites = emit_sites();
    assert!(
        sites.len() >= 4,
        "the scan found {} emit sites, too few to be reading the crate",
        sites.len()
    );

    for (ident, macro_name, labels) in &sites {
        let Some(name) = value_of(ident) else {
            continue;
        };
        let Some(spec) = metrics::CONTRACT.iter().find(|spec| spec.name == name) else {
            panic!("{ident} ({name}) is emitted and is in no contract entry");
        };

        let declared_macro = match spec.kind {
            MetricKind::Counter => "counter",
            MetricKind::Gauge => "gauge",
            MetricKind::Histogram => "histogram",
        };
        assert_eq!(
            macro_name, declared_macro,
            "{name} is emitted with {macro_name}! and the contract declares it a {declared_macro}"
        );

        for label in labels {
            assert!(
                spec.labels.contains(&label.as_str()),
                "{name} is emitted with the label {label:?}, which the contract does not list.
                 Contract: {:?}",
                spec.labels
            );
        }
        // AND EVERY DECLARED LABEL IS EMITTED SOMEWHERE. A contract that lists a label no site
        // sets is a promise to a query that will never match.
        //
        // Checked across ALL of a metric's sites rather than each one, because a metric can
        // legitimately be emitted from several places, and one of them setting a subset is not
        // a defect -- a label missing from EVERY site is.
        let all_labels: std::collections::HashSet<&str> = sites
            .iter()
            .filter(|(other, _, _)| value_of(other).as_deref() == Some(spec.name))
            .flat_map(|(_, _, labels)| labels.iter().map(String::as_str))
            .collect();
        for declared in spec.labels {
            assert!(
                all_labels.contains(declared),
                "the contract says {name} carries {declared:?}, and no emit site this scan can \
                 read sets it"
            );
        }
    }
}

#[test]
fn every_contract_metric_has_an_emit_site() {
    // THE DIRECTION THE CRITERION NAMES FIRST, and the one this file did not have. Both other
    // tests use CONTRACT as a lookup or a membership set; neither iterates it, so a promise with
    // nothing behind it was invisible to both.
    //
    // WHAT THIS CAN AND CANNOT SAY. A site that exists is not a site that RUNS: a metric emitted
    // only from a branch nothing reaches is still, in practice, not exported. Establishing that
    // needs the metric to be produced by exercising the server, which is the integration shape
    // rather than this one. What this rules out is the case that actually happens -- a contract
    // entry whose emits were deleted, renamed, or never written.
    // WIDENED (issue #152 criterion 1). This resolved names only through this module's own
    // constants, so it could not see a literal-named metric or one named by a constant in
    // another crate -- which is every one of the twenty-seven the contract did not cover. It
    // would have passed over them in silence.
    let emitted = workspace_emitted_metrics();
    assert!(
        emitted.len() >= 30,
        "the scan found {} emitted metrics, too few to be reading the workspace; the \
         assertion below would pass by covering almost nothing",
        emitted.len()
    );

    for spec in metrics::CONTRACT {
        assert!(
            emitted.contains(spec.name),
            "the contract promises {}, and no PRODUCTION emit site produces it.\n\
             A promised metric nobody emits is a dashboard that renders empty and an alert \
             that never fires. Emitted: {:?}",
            spec.name,
            emitted
        );
    }
}

#[test]
fn the_contract_covers_every_metric_this_module_declares() {
    // THE BOUNDARY. The scrape test above can only see what `emit_everything` emitted, and that
    // reads the contract -- so a constant declared in the module and left out of the contract is
    // invisible to it. This reads the SOURCE, which is the only thing that knows what was
    // declared.
    let source = include_str!("../src/metrics.rs");
    let declared: Vec<&str> = source
        .lines()
        .filter_map(|line| line.trim().strip_prefix("pub const "))
        .filter(|rest| rest.contains(": &str = \"ironauth_"))
        .filter_map(|rest| rest.split(':').next())
        .collect();
    assert!(
        declared.len() >= 10,
        "the parse found {} declarations, too few to be reading this module",
        declared.len()
    );

    let promised: std::collections::HashSet<&str> =
        metrics::CONTRACT.iter().map(|spec| spec.name).collect();
    for ident in &declared {
        let Some((value, _)) = source
            .split_once(&format!("pub const {ident}: &str = \""))
            .and_then(|(_, rest)| rest.split_once('"'))
        else {
            panic!("could not read the value of {ident}")
        };
        assert!(
            promised.contains(value),
            "{ident} ({value}) is declared in this module and is in no contract entry, so \
             nothing checks that it is exported or what labels it carries"
        );
    }
}

/// The cardinality bound `docs/METRICS.md` publishes: no series is keyed by a principal.
///
/// # What the bound is
///
/// A label whose value is a tenant, a client, a user or an environment multiplies every series
/// it appears on by the number of distinct values a DEPLOYMENT has. That number is unbounded
/// from this repository's side, so the bound cannot be a threshold on a count; it has to be a
/// refusal of the label itself. It is also the label class that puts identifiers on a scrape
/// surface, which is usually protected less carefully than the database holding the same
/// identifiers.
///
/// # Why it is a test rather than a sentence
///
/// The published page states the bound, and a statement about the code held in a different
/// artifact is the thing this repository keeps having to retract. The expectation lives HERE --
/// the list below is the test's, not the contract's -- and the observation is read from
/// `CONTRACT`, so the two cannot be the same edit. Adding `tenant` to a metric turns the page's
/// paragraph false and fails this test in the same commit.
///
/// The `_id` suffix rule is what makes it hold for names nobody has thought of yet. A label
/// ending in `_id` is per-entity by construction, whatever the entity turns out to be called,
/// so a future `workspace_id` fails without anyone having to remember to extend the list.
#[test]
fn no_contract_metric_carries_a_per_principal_label() {
    const PER_PRINCIPAL: &[&str] = &[
        "tenant",
        "client",
        "environment",
        "env",
        "user",
        "subject",
        "sub",
        "account",
        "org",
        "organization",
        "email",
        "username",
        "session",
        "ip",
        "remote_addr",
    ];

    for spec in metrics::CONTRACT {
        for label in spec.labels {
            assert!(
                !PER_PRINCIPAL.contains(label),
                "{} carries the label `{label}`, which is one value per principal: it multiplies \
                 that metric's series by a count this build does not bound, and docs/METRICS.md \
                 publishes the opposite. The per-tenant view belongs on the events and usage \
                 API, which is authenticated and paginated",
                spec.name
            );
            assert!(
                !label.ends_with("_id"),
                "{} carries the label `{label}`, and a label ending in `_id` is one value per \
                 entity by construction. See the cardinality section of docs/METRICS.md",
                spec.name
            );
        }
    }
}
