// SPDX-License-Identifier: MIT OR Apache-2.0

//! The golden-path replay harness (issue #92, PR 7): compile every committed journey and replay
//! its recorded transcripts against it, so behavioral drift between flow versions fails a CI gate.
//! Consumed by scripts/journey-replay.sh, which runs it from the repository root.
//!
//! The corpus lives under a per-journey directory: each subdirectory of the corpus root holds one
//! `journey.json` (the journey artifact) and one or more `*.json` transcripts that replay against
//! it. In the default CHECK mode the harness runs every transcript and exits non-zero on any
//! divergence, naming the exact hop that drifted. In `--regenerate` mode it recomputes each
//! transcript's expected outcomes from the compiled routing and rewrites the files, so an author
//! who deliberately changes routing updates the goldens by a reviewable diff; regeneration is
//! idempotent, so a corpus with no drift rewrites to byte-identical files.
//!
//! This example does the file I/O the pure library forbids; the routing logic it invokes
//! ([`ironauth_journey::replay::run`]) is the same pure walk the flow engine drives.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ironauth_journey::replay::{self, JourneyTranscript, ReplayReport};
use ironauth_journey::{Journey, compile};

/// The default corpus root, relative to the repository root the CI script runs from.
const DEFAULT_CORPUS: &str = "docs/journey-transcripts";

/// The artifact file name every per-journey directory carries.
const JOURNEY_FILE: &str = "journey.json";

fn main() -> ExitCode {
    let mut regenerate = false;
    let mut corpus: Option<PathBuf> = None;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--regenerate" => regenerate = true,
            other if other.starts_with("--") => {
                eprintln!("journey-replay: unknown flag {other}");
                return ExitCode::FAILURE;
            }
            other => corpus = Some(PathBuf::from(other)),
        }
    }
    let corpus = corpus.unwrap_or_else(|| PathBuf::from(DEFAULT_CORPUS));

    match run_corpus(&corpus, regenerate) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(message) => {
            eprintln!("journey-replay: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Replay (or regenerate) every transcript under the corpus root. Returns `Ok(true)` when every
/// transcript matched (or was regenerated), `Ok(false)` when a divergence was reported, and an
/// `Err` for a harness-level failure (a missing corpus, an unreadable file, a compile failure, or
/// a transcript paired with the wrong artifact).
fn run_corpus(corpus: &Path, regenerate: bool) -> Result<bool, String> {
    let mut journey_dirs: Vec<PathBuf> = fs::read_dir(corpus)
        .map_err(|error| format!("cannot read corpus directory {}: {error}", corpus.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    journey_dirs.sort();

    let mut all_ok = true;
    let mut transcript_count = 0_usize;
    for dir in &journey_dirs {
        let (journey, compiled) = load_journey(dir)?;
        let mut transcripts: Vec<PathBuf> = fs::read_dir(dir)
            .map_err(|error| format!("cannot read {}: {error}", dir.display()))?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| is_transcript(path))
            .collect();
        transcripts.sort();

        for path in &transcripts {
            transcript_count += 1;
            let transcript = load_transcript(path)?;
            check_pairing(path, &journey, &transcript)?;
            if regenerate {
                regenerate_one(path, &compiled, &transcript)?;
            } else if !check_one(path, &compiled, &transcript) {
                all_ok = false;
            }
        }
    }

    if transcript_count == 0 {
        return Err(format!("no transcripts found under {}", corpus.display()));
    }
    if regenerate {
        println!("journey-replay: regenerated {transcript_count} transcript(s)");
    } else if all_ok {
        println!("journey-replay: {transcript_count} transcript(s) replayed clean");
    }
    Ok(all_ok)
}

/// Load and compile a per-journey directory's `journey.json` artifact.
fn load_journey(dir: &Path) -> Result<(Journey, ironauth_journey::CompiledJourney), String> {
    let path = dir.join(JOURNEY_FILE);
    let text = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let journey: Journey = serde_json::from_str(&text).map_err(|error| {
        format!(
            "{} is not a valid journey artifact: {error}",
            path.display()
        )
    })?;
    let compiled = compile(&journey).map_err(|errors| {
        let rendered: Vec<String> = errors.iter().map(|error| format!("{error:?}")).collect();
        format!(
            "{} does not compile: {}",
            path.display(),
            rendered.join("; ")
        )
    })?;
    Ok((journey, compiled))
}

/// Parse a transcript file.
fn load_transcript(path: &Path) -> Result<JourneyTranscript, String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    serde_json::from_str(&text)
        .map_err(|error| format!("{} is not a valid transcript: {error}", path.display()))
}

/// Refuse a transcript paired with the wrong artifact (a harness-level error, not a drift): the
/// transcript's declared journey id and engine version must match the artifact it sits beside.
fn check_pairing(
    path: &Path,
    journey: &Journey,
    transcript: &JourneyTranscript,
) -> Result<(), String> {
    if transcript.journey_id != journey.id {
        return Err(format!(
            "{}: transcript journey_id {:?} does not match the artifact id {:?}",
            path.display(),
            transcript.journey_id,
            journey.id
        ));
    }
    if transcript.engine_version != journey.engine_version {
        return Err(format!(
            "{}: transcript engine_version {} does not match the artifact engine_version {}",
            path.display(),
            transcript.engine_version,
            journey.engine_version
        ));
    }
    Ok(())
}

/// Replay one transcript, printing the outcome. Returns whether it matched.
fn check_one(
    path: &Path,
    compiled: &ironauth_journey::CompiledJourney,
    transcript: &JourneyTranscript,
) -> bool {
    match replay::run(compiled, transcript) {
        ReplayReport::Match => {
            println!("  ok   {}", path.display());
            true
        }
        ReplayReport::Divergence(divergence) => {
            println!("  DRIFT {}: {divergence}", path.display());
            false
        }
    }
}

/// Regenerate one transcript's expected outcomes and rewrite the file if it changed.
fn regenerate_one(
    path: &Path,
    compiled: &ironauth_journey::CompiledJourney,
    transcript: &JourneyTranscript,
) -> Result<(), String> {
    let regenerated = transcript
        .regenerated(compiled)
        .map_err(|error| format!("{}: cannot regenerate: {error}", path.display()))?;
    write_transcript(path, &regenerated)
}

/// Write a transcript back to disk in the canonical form: pretty JSON with a trailing newline, so
/// a regenerated corpus is byte-stable and a drift shows as a git diff.
fn write_transcript(path: &Path, transcript: &JourneyTranscript) -> Result<(), String> {
    let mut json = serde_json::to_string_pretty(transcript)
        .map_err(|error| format!("{}: cannot serialize: {error}", path.display()))?;
    json.push('\n');
    fs::write(path, json).map_err(|error| format!("cannot write {}: {error}", path.display()))
}

/// Whether a path is a transcript file (a `.json` file that is not the artifact).
fn is_transcript(path: &Path) -> bool {
    path.is_file()
        && path.extension().is_some_and(|ext| ext == "json")
        && path.file_name().is_some_and(|name| name != JOURNEY_FILE)
}
