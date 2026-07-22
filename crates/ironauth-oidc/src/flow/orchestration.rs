// SPDX-License-Identifier: MIT OR Apache-2.0

//! The custom-journey table-driven engine path (issue #92, PR 4): the FIRST engine-touching,
//! ADDITIVE parallel path. A [`Journey::Custom`](super::model::Journey) flow is driven by a
//! compiled transition table ([`ironauth_journey::CompiledJourney`]) rather than one of the six
//! hardcoded built-in drivers, but it reuses the EXACT SAME already-factored executor cores the
//! built-ins call: [`login::advance_login`](super::login), the MFA challenge / enroll ceremonies
//! ([`super::mfa`]), and progressive profiling ([`super::profiling`]). No security decision is
//! re-derived here; the table only chooses which executor core runs and how routing threads
//! between them.
//!
//! ## Why a parallel path (behavior preservation)
//!
//! The built-in `drive_*` functions in [`super`] are UNTOUCHED. The duplication is confined to
//! the thin orchestration shell below (resolve the current step, run its executor, then either
//! re-render or walk the compiled transitions), so the built-in default path stays byte-identical
//! and a custom journey never perturbs it. A later PR converges the built-ins onto the table
//! under a byte-equivalence gate.
//!
//! ## The routing loop
//!
//! On each submission the engine resolves the current step (the persisted `custom_step`, or the
//! compiled entry on the first submission), runs its executor, and:
//!
//! - a RENDER outcome persists the flow ON the same step and re-renders (a validation error, or
//!   the uniform authentication failure), staying OPEN;
//! - an ADVANCE outcome assembles the typed [`EvalContext`](ironauth_journey::EvalContext) from
//!   real state and walks the current step's guarded edges IN DOCUMENT ORDER, taking the first
//!   whose guard is absent or evaluates true. A TERMINAL target completes (the single mint with
//!   the honest amr the flow earned); a DECISION target routes onward IN-CALL with no client
//!   round trip; a render-kind target transitions into that step and renders it. In-call routing
//!   hops are bounded by the step count (a mis-compile defense).

#[cfg(any(test, feature = "testing"))]
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ironauth_journey::{
    CompiledJourney, CompiledStep, EvalContext, OutcomeSignal, SignalSet, StepKind, evaluate,
};
use ironauth_store::{FlowId, FlowRecord, NewFlow, Scope, Store, UserId};

use super::builtin_artifacts::builtin_compiled;
use super::eval_ctx::assemble_eval_context;
use super::message::{self, Message};
use super::model::{CONTRACT_VERSION, Flow, FlowStateTag, Journey, Node, Transport};
use super::wire_identity::{render_override_states, wire_state_for};
use super::{
    Continuation, FlowError, PersistedState, Submission, build_flow, consume_and_complete,
    generate_submit_token, login, login_follow_through, method_tokens, mfa,
    normalize_transient_payload, persist_and_render, profiling, recovery, registration,
};
use crate::authn::{AuthMethod, AuthenticationEvent};
use crate::interaction;
use crate::state::OidcState;
use crate::util::epoch_micros;

/// A boxed resolve future (issue #92): a store-backed source AWAITS its scoped, RLS-forced
/// `flow_versions` read and then compiles; the embedded test source resolves immediately. Boxed so
/// [`CompiledJourneySource`] stays object-safe behind `Arc<dyn ...>` (the codebase's async-trait
/// convention, matching the pow / migration-hook seams) without an async-trait dependency.
pub type ResolveFuture<'a> =
    Pin<Box<dyn Future<Output = Option<Arc<CompiledJourney>>> + Send + 'a>>;

/// A boxed creation-resolve future (issue #92): resolves an author-facing `journey_id` to the
/// PINNED version id to stamp on a new flow row and the compiled table to drive it.
pub type ResolveForCreationFuture<'a> =
    Pin<Box<dyn Future<Output = Option<(String, Arc<CompiledJourney>)>> + Send + 'a>>;

/// The seam that resolves a compiled custom journey (issue #92): the boundary between the engine
/// (which drives a compiled table) and the store (which persists and version-pins the journey
/// documents). PR 4 shipped the test-only [`EmbeddedJourneySource`] behind this trait; PR 5 wires
/// the [`FlowVersionJourneySource`] production implementation (RLS-scoped `flow_versions`, admin
/// authoring, and pin resolution, with a compile cache keyed by version id), so the trait boundary
/// is the exact PR 4 / PR 5 seam. Resolution is async so a store-backed source can await its
/// scoped DB read. A live custom flow re-resolves the SAME table across submissions from the
/// version id stamped on its row, so the journey it started under cannot change mid-flow even after
/// the pin moves.
pub trait CompiledJourneySource: Send + Sync {
    /// Resolve the compiled journey for a stamped `flow_version_id` (the pin a live flow carries),
    /// or [`None`] when it names no known version in this scope.
    fn resolve<'a>(&'a self, scope: Scope, flow_version_id: &str) -> ResolveFuture<'a>;

    /// Resolve the CURRENT version for an author-facing `journey_id` at creation, returning the
    /// version id to PIN on the new flow row and the compiled table to drive it, or [`None`] when
    /// the journey is unknown (or unpinned) in this scope.
    fn resolve_for_creation<'a>(
        &'a self,
        scope: Scope,
        journey_id: &str,
    ) -> ResolveForCreationFuture<'a>;
}

/// The production compiled-journey source (issue #92, PR 5): a [`Store`]-backed implementation of
/// [`CompiledJourneySource`] that resolves a pinned journey through the RLS-scoped `flow_versions`
/// registry and CACHES the compiled table keyed by `flow_version_id`. A version's artifact is
/// immutable (append-only registry), so a compiled table keyed by its version id is a sound cache:
/// compilation is a pure, load-time lowering, so caching it never observes a stale artifact.
///
/// The pinning guarantee flows from the version id: creation resolves the journey's PINNED version
/// and stamps its id on the flow row; every later submission re-resolves the SAME version id (never
/// the current pin), so a live flow keeps running the version it started under even after the pin
/// moves to a newer version.
pub struct FlowVersionJourneySource {
    store: Store,
    /// The compile cache, keyed by (tenant, environment, version id) -> its compiled table. The
    /// key includes the SCOPE so a cache hit can never serve one environment's compiled table for
    /// another's lookup: the scope-forced `get_by_id` returns None for a cross-scope id, and this
    /// key preserves that isolation on a hit (a `flv_` id embeds scope + entropy, so a collision is
    /// already unreachable, but the key is scope-safe by construction). Guarded by a plain mutex;
    /// the lock is held only for the brief sync get / insert, never across the store read or
    /// compilation.
    cache: Mutex<HashMap<String, Arc<CompiledJourney>>>,
}

impl FlowVersionJourneySource {
    /// Build a store-backed source over `store` (a cheap handle clone sharing the pool). The
    /// compile cache starts empty and fills lazily on first resolution of each version.
    #[must_use]
    pub fn new(store: Store) -> Self {
        Self {
            store,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The compiled table for `flow_version_id` in `scope`: a cache hit, or a scoped read of the
    /// stored artifact compiled once and cached. [`None`] when the version is absent in scope or
    /// its stored artifact does not compile (a corrupt row; a uniform not-found, never an oracle).
    async fn resolve_version(
        &self,
        scope: Scope,
        flow_version_id: &str,
    ) -> Option<Arc<CompiledJourney>> {
        if let Some(hit) = self.cached(scope, flow_version_id) {
            return Some(hit);
        }
        let record = self
            .store
            .scoped(scope)
            .flow_versions()
            .get_by_id(flow_version_id)
            .await
            .ok()??;
        let compiled = Arc::new(compile_stored_artifact(&record.artifact_json)?);
        self.insert(scope, flow_version_id, &compiled);
        Some(compiled)
    }

    /// The pinned version id and compiled table for an author-facing `journey_id` in `scope`, or
    /// [`None`] when the journey has no pin (an unknown or unpinned journey names no creatable
    /// custom flow). Reuses the compile cache keyed by the (scope, resolved version id).
    async fn resolve_pinned(
        &self,
        scope: Scope,
        journey_id: &str,
    ) -> Option<(String, Arc<CompiledJourney>)> {
        let record = self
            .store
            .scoped(scope)
            .flow_versions()
            .get_pinned(journey_id)
            .await
            .ok()??;
        let version_id = record.id;
        if let Some(hit) = self.cached(scope, &version_id) {
            return Some((version_id, hit));
        }
        let compiled = Arc::new(compile_stored_artifact(&record.artifact_json)?);
        self.insert(scope, &version_id, &compiled);
        Some((version_id, compiled))
    }

    /// The scope-safe cache key: (tenant, environment, version id), so a lookup in one scope can
    /// never hit an entry cached for another.
    fn cache_key(scope: Scope, flow_version_id: &str) -> String {
        format!(
            "{}:{}:{}",
            scope.tenant(),
            scope.environment(),
            flow_version_id
        )
    }

    /// A cache hit for `(scope, flow_version_id)`, holding the lock only for the sync lookup.
    fn cached(&self, scope: Scope, flow_version_id: &str) -> Option<Arc<CompiledJourney>> {
        let key = Self::cache_key(scope, flow_version_id);
        let cache = self.cache.lock().expect("compile cache mutex not poisoned");
        cache.get(&key).cloned()
    }

    /// Insert a compiled table into the cache under the scope-safe key, holding the lock only for
    /// the sync insert.
    fn insert(&self, scope: Scope, flow_version_id: &str, compiled: &Arc<CompiledJourney>) {
        let key = Self::cache_key(scope, flow_version_id);
        let mut cache = self.cache.lock().expect("compile cache mutex not poisoned");
        cache.insert(key, compiled.clone());
    }
}

impl CompiledJourneySource for FlowVersionJourneySource {
    fn resolve<'a>(&'a self, scope: Scope, flow_version_id: &str) -> ResolveFuture<'a> {
        let id = flow_version_id.to_owned();
        Box::pin(async move { self.resolve_version(scope, &id).await })
    }

    fn resolve_for_creation<'a>(
        &'a self,
        scope: Scope,
        journey_id: &str,
    ) -> ResolveForCreationFuture<'a> {
        let journey = journey_id.to_owned();
        Box::pin(async move { self.resolve_pinned(scope, &journey).await })
    }
}

/// Compile a stored journey artifact into a table (issue #92, PR 5). A stored artifact is
/// LOAD-VALID by construction (the store validated it on write), so this never fails on a real
/// row; [`None`] means a corrupt or forward-versioned row, treated as a uniform not-found rather
/// than an oracle. Compilation is pure, so a cached result is safe.
fn compile_stored_artifact(artifact_json: &str) -> Option<CompiledJourney> {
    let journey: ironauth_journey::Journey = serde_json::from_str(artifact_json).ok()?;
    ironauth_journey::compile(&journey).ok()
}

/// A test-only, in-memory compiled-journey source (issue #92, PR 4): the AC1 fixture compiled
/// once and keyed by a synthetic version id. It ignores the scope (a single-tenant test source);
/// PR 5's store-backed implementation is RLS-scoped. Behind the [`CompiledJourneySource`] seam so
/// the engine wiring is identical whether the source is embedded (PR 4) or store-backed (PR 5).
#[cfg(any(test, feature = "testing"))]
pub struct EmbeddedJourneySource {
    by_version: BTreeMap<String, Arc<CompiledJourney>>,
    by_journey: BTreeMap<String, String>,
}

#[cfg(any(test, feature = "testing"))]
impl EmbeddedJourneySource {
    /// A single-journey embedded source: the compiled journey keyed by both its author-facing
    /// `journey_id` and its synthetic `version_id`.
    #[must_use]
    pub fn single(journey_id: &str, version_id: &str, compiled: CompiledJourney) -> Self {
        let mut by_version = BTreeMap::new();
        by_version.insert(version_id.to_owned(), Arc::new(compiled));
        let mut by_journey = BTreeMap::new();
        by_journey.insert(journey_id.to_owned(), version_id.to_owned());
        Self {
            by_version,
            by_journey,
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl CompiledJourneySource for EmbeddedJourneySource {
    fn resolve<'a>(&'a self, _scope: Scope, flow_version_id: &str) -> ResolveFuture<'a> {
        // The lookup is sync (an in-memory map); the source resolves immediately with a
        // ready future so the engine wiring is identical to the store-backed source.
        let result = self.by_version.get(flow_version_id).cloned();
        Box::pin(async move { result })
    }

    fn resolve_for_creation<'a>(
        &'a self,
        _scope: Scope,
        journey_id: &str,
    ) -> ResolveForCreationFuture<'a> {
        let result = self.by_journey.get(journey_id).and_then(|version| {
            self.by_version
                .get(version)
                .map(|compiled| (version.clone(), compiled.clone()))
        });
        Box::pin(async move { result })
    }
}

/// The outcome of running one custom step's executor (issue #92, PR 4).
enum StepOutcome {
    /// Stay on the current step and re-render (a validation error or the uniform authentication
    /// failure). The flow stays OPEN, so a re-render is never a completion oracle.
    Render {
        /// The nodes to render (already carrying their node-level messages).
        nodes: Vec<Node>,
        /// The flow-level messages.
        messages: Vec<Message>,
        /// An optional WIRE-STATE override for this render (issue #92, PR 8a). Normally a re-render
        /// stays on the flow's current wire state (the flat [`FlowStateTag::Custom`], or the
        /// built-in per-step state once a journey converges). A mint-family executor whose render is
        /// a NON-TERMINAL acknowledgment on a DIFFERENT wire state (registration's uniform
        /// [`FlowStateTag::RegistrationAck`], shown while the flow stays OPEN) sets it here, so the
        /// re-render advances the wire position without completing. [`None`] keeps the current
        /// state. Behavior-neutral in PR 8a: no built-in drives through this path yet, so every
        /// executor sets [`None`] and the wire state is unchanged.
        state_override: Option<FlowStateTag>,
    },
    /// The step is done: route onward. The signals the executor emitted drive the guarded
    /// transitions, and the persisted scratch (subject, method tokens, enroll credential) has been
    /// updated in place.
    Advance {
        /// The boolean routing signals this executor emitted.
        signals: SignalSet,
        /// An optional post-mint counter reset to thread to the terminal (issue #92, PR 8d): the
        /// recovery verify executor carries the recovery-path abuse context here, so a genuine
        /// completion relaxes the SAME counters the built-in `drive_recovery` does through
        /// `reset_after_success`. [`None`] for every other Advance producer (login / mfa / profiling
        /// / registration run no post-mint reset). Threaded pure in-memory (never persisted to
        /// `flows.state`): the verify executor advances and the walk hits the terminal in the SAME
        /// drive call, consuming the flow.
        post_reset: Option<crate::abuse::AttemptContext>,
    },
}

/// The polymorphic completion a mint-family step performs at a terminal (issue #92, PR 8a): the
/// generalization of the custom engine's session mint so the converging built-in journeys
/// (login/mfa/profiling, registration, recovery) can complete through the ONE choke point with
/// their own per-journey fenced re-render and post-mint side effects.
///
/// Only [`CompletionKind::SessionMint`] exists: the five converging journeys are the MINT-FAMILY,
/// so the mechanism carries no redirect or consent-decision variant (federation and consent stay
/// thin single-step drivers and never run through the table drive). The enum shape is kept so a
/// later need can extend it without a breaking change.
enum CompletionKind {
    /// Mint the session through the existing [`consume_and_complete`] choke point.
    SessionMint {
        /// The nodes to re-render UNIFORMLY on the rare central-fence TOCTOU after the completion
        /// latch tripped (login's uniform-incorrect render, MFA's challenge form, registration's
        /// details form, recovery's ack form). Empty for a genuine custom journey, whose wire state
        /// carries no built-in fallback form.
        fenced_nodes: Vec<Node>,
        /// An optional post-mint counter reset to run on a genuine completion (issue #92, PR 8a):
        /// recovery relaxes its path abuse counters after a genuine mint, exactly as the built-in
        /// `drive_recovery` does through `reset_after_success`. [`None`] for login/mfa/profiling and
        /// for a genuine custom journey, which run no post-mint reset. Behavior-neutral in PR 8a:
        /// the only live producer (the custom Terminal path) sets [`None`].
        post_reset: Option<crate::abuse::AttemptContext>,
    },
}

/// Create a new custom-journey flow (issue #92, PR 4): resolve the author-facing `journey_id` to
/// a pinned compiled table via the source, seed the entry step, persist the row (stamping the
/// resolved `flow_version_id` so every later submission re-resolves the SAME table), and return
/// the id, submit token, and initial flow object. Mirrors [`super::create_flow`] for the built-in
/// journeys, but seeds the FLAT [`FlowStateTag::Custom`] wire state with the concrete entry step
/// held server side.
///
/// # Errors
///
/// [`FlowError::NotFound`] when no custom journey source is configured or the `journey_id` is
/// unknown; [`FlowError::InvalidSubmission`] when the resume target is present but not a local
/// same-scope `/authorize` target, or when the entry step is not a creation-renderable kind;
/// [`FlowError::MalformedTransientPayload`] on a bad transient payload; [`FlowError::Store`] on a
/// persistence fault.
pub(super) async fn create_custom_flow(
    state: &OidcState,
    scope: Scope,
    transport: Transport,
    journey_id: &str,
    return_to: Option<&str>,
    transient_payload: Option<&serde_json::Value>,
) -> Result<(FlowId, String, Flow), FlowError> {
    let source = state.custom_journey_source().ok_or(FlowError::NotFound)?;
    let (flow_version_id, compiled) = source
        .resolve_for_creation(scope, journey_id)
        .await
        .ok_or(FlowError::NotFound)?;

    // A present resume target is validated the SAME way the built-in creation path validates it:
    // it must be a LOCAL `/authorize?...` target resolving into THIS flow's scope.
    if let Some(raw) = return_to {
        match interaction::parse_resume(Some(raw)) {
            Some(resume) if resume.scope == scope => {}
            _ => return Err(FlowError::InvalidSubmission),
        }
    }

    let transient = normalize_transient_payload(transient_payload)?;
    let flow_id = FlowId::generate(state.env(), &scope);

    // Seed the entry step. The entry carries no subject or method tokens yet (the primary factor
    // proves them), so the scratch starts empty with the flat Custom position on the entry step.
    let entry_step_id = compiled.entry.clone();
    let entry = compiled.step(&entry_step_id).ok_or(FlowError::NotFound)?;
    let mut scratch = custom_scratch_empty(&entry_step_id);
    let nodes = enter_step_nodes(
        state,
        scope,
        &flow_id.to_string(),
        return_to,
        transport,
        entry,
        &mut scratch,
    )
    .await?;

    let submit_token = generate_submit_token(state);
    let now = state.now();
    let expires_at_micros = epoch_micros(
        now.checked_add(Duration::from_secs(super::FLOW_TTL_SECS))
            .unwrap_or(now),
    );
    let state_json = serde_json::to_string(&scratch).map_err(|_| FlowError::Store)?;

    state
        .store()
        .scoped(scope)
        .flows()
        .create(
            &flow_id,
            NewFlow {
                journey: Journey::Custom.as_str(),
                transport: transport.as_str(),
                state: &state_json,
                submit_token: &submit_token,
                transient_payload: transient.as_deref(),
                return_to,
                contract_version: i32::try_from(CONTRACT_VERSION).unwrap_or(1),
                flow_version_id: Some(&flow_version_id),
                expires_at_unix_micros: expires_at_micros,
            },
        )
        .await
        .map_err(|_| FlowError::Store)?;

    let record = FlowRecord {
        id: flow_id.to_string(),
        journey: Journey::Custom.as_str().to_owned(),
        transport: transport.as_str().to_owned(),
        state: state_json,
        submit_token: submit_token.clone(),
        transient_payload: transient,
        return_to: return_to.map(str::to_owned),
        contract_version: i32::try_from(CONTRACT_VERSION).unwrap_or(1),
        flow_version_id: Some(flow_version_id),
        consumed_at_unix_micros: None,
        expires_at_unix_micros: expires_at_micros,
    };
    let flow = build_flow(
        scope,
        &record,
        transport,
        Journey::Custom,
        FlowStateTag::Custom,
        nodes,
        Vec::new(),
    );
    Ok((flow_id, submit_token, flow))
}

/// A resolved compiled-table handle for one drive (issue #92, PR 8b): a genuine custom journey's
/// table arrives as an [`Arc`] (from the store-backed source's compile cache), a converged built-in
/// journey's as a `'static` reference (from the embedded [`builtin_compiled`] registry). The handle
/// owns the reference for the whole drive, so the borrowed [`CompiledJourney`] outlives the walk.
enum TableRef {
    /// A genuine custom journey's pinned table.
    Custom(Arc<CompiledJourney>),
    /// A converged built-in journey's embedded artifact.
    Builtin(&'static CompiledJourney),
}

impl TableRef {
    /// The borrowed compiled table, whichever source it came from.
    fn get(&self) -> &CompiledJourney {
        match self {
            TableRef::Custom(compiled) => compiled,
            TableRef::Builtin(compiled) => compiled,
        }
    }
}

/// Resolve the compiled table for a table-driven flow (issue #92, PR 8b): a genuine custom journey
/// resolves its PINNED table from the store-backed source keyed by the version id stamped on its
/// row (so a live flow keeps the version it started under even after the pin moves); a converged
/// built-in journey resolves its embedded artifact from [`builtin_compiled`].
///
/// # Errors
///
/// [`FlowError::NotFound`] when no source is configured, the pin or version cannot resolve, or the
/// journey has no embedded artifact (a corrupt row, a uniform not found, never an oracle).
async fn resolve_table(
    state: &OidcState,
    scope: Scope,
    record: &FlowRecord,
    journey: Journey,
) -> Result<TableRef, FlowError> {
    match journey {
        Journey::Custom => {
            let flow_version_id = record
                .flow_version_id
                .as_deref()
                .ok_or(FlowError::NotFound)?;
            let source = state.custom_journey_source().ok_or(FlowError::NotFound)?;
            let compiled = source
                .resolve(scope, flow_version_id)
                .await
                .ok_or(FlowError::NotFound)?;
            Ok(TableRef::Custom(compiled))
        }
        _ => builtin_compiled(journey)
            .map(TableRef::Builtin)
            .ok_or(FlowError::NotFound),
    }
}

/// Drive one submission of a TABLE-DRIVEN flow through the compiled engine (issue #92, PR 4;
/// generalized PR 8b). This is the ONE compiled-table drive, serving BOTH a genuine
/// [`Journey::Custom`] flow (its pinned table resolved from the store-backed source) and a converged
/// BUILT-IN journey (its embedded artifact from [`builtin_compiled`], starting with
/// [`Journey::Login`] in PR 8b). Resolve the compiled table and the current step, run that step's
/// executor, and either re-render or walk the guarded transitions to the next render step, a
/// decision (routed in-call), or a terminal completion.
///
/// The one difference between the two is the WIRE identity, and it is the whole point of the
/// convergence: a built-in journey emits its own [`Journey`] and the built-in per-step
/// [`FlowStateTag`] ([`wire_state_for`]), resolving the current step by REVERSE-mapping the
/// persisted tag and writing NO `custom_step`, so a built-in row's serialized `flows.state` and its
/// rendered [`Flow`] stay byte-identical to the imperative driver. A genuine custom journey keeps
/// the flat [`FlowStateTag::Custom`] wire state with the concrete step held in `custom_step`,
/// exactly as before.
///
/// # Errors
///
/// [`FlowError::NotFound`] when the source, the pin, the artifact, the current step, or a routing
/// target cannot resolve (a corrupt row or a mis-compiled table, never an oracle); the executor
/// cores' own typed errors otherwise.
// The routing walk is one linear pass (resolve, run the executor, then a bounded transition loop
// with one short arm per StepKind); a flat body reads best and the length reflects the kind count,
// not any real branching complexity.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) async fn drive_via_table(
    state: &OidcState,
    scope: Scope,
    flow_id: &FlowId,
    transport: Transport,
    record: &FlowRecord,
    persisted: &PersistedState,
    submission: &Submission,
    headers: &axum::http::HeaderMap,
    now_micros: i64,
    journey: Journey,
) -> Result<Continuation, FlowError> {
    let table = resolve_table(state, scope, record, journey).await?;
    let compiled = table.get();

    // Resolve the current compiled step. A custom flow holds the concrete step id in `custom_step`
    // (or the entry on the first submission); a built-in flow REVERSE-maps its persisted per-step
    // wire tag to the unique compiled step whose `wire_state_for` renders as it, so no `custom_step`
    // is ever written for a built-in row.
    let current_step_id: String = match journey {
        Journey::Custom => persisted
            .custom_step
            .clone()
            .unwrap_or_else(|| compiled.entry.clone()),
        _ => builtin_step_for(journey, compiled, persisted.step)
            .ok_or(FlowError::NotFound)?
            .to_owned(),
    };
    let current = compiled.step(&current_step_id).ok_or(FlowError::NotFound)?;

    // The scratch carries the subject and proven method tokens across submissions; the executor
    // updates it on an advance.
    let mut scratch = persisted.clone();

    // The advancing executor yields the routing signals plus an optional post-mint counter reset to
    // thread to the terminal (issue #92, PR 8d): recovery's verify carries its recovery-path abuse
    // context here so a genuine mint relaxes the SAME counters. Pure in-memory: the flow is consumed
    // in this same drive call, so the ctx is never persisted to `flows.state`. Every other executor
    // yields None.
    let (signals, post_reset) = match run_step_executor(
        state,
        scope,
        record,
        current,
        &current_step_id,
        submission,
        headers,
        &mut scratch,
    )
    .await?
    {
        StepOutcome::Render {
            nodes,
            messages,
            state_override,
        } => {
            // A re-render stays on the current step's wire state (the flat Custom for a custom
            // journey, or the built-in per-step state for a converged one). A mint-family executor
            // whose render advances the wire position (registration's non-terminal Ack, PR 8c) sets
            // a state override; login sets `None`, so a login re-render stays on its real per-step
            // tag, byte-identical to the imperative driver.
            let mut next = table_state(journey, &scratch, &current.kind, &current_step_id);
            if let Some(tag) = state_override {
                next.step = tag;
            }
            return persist_and_render(
                state, scope, flow_id, transport, journey, record, &next, nodes, messages,
                now_micros,
            )
            .await;
        }
        StepOutcome::Advance {
            signals,
            post_reset,
        } => (signals, post_reset),
    };

    // Walk the compiled transitions. Only a decision step continues the walk in-call; a render
    // step or a terminal ends this submission. The hop bound defends against a mis-compiled table
    // (a well-compiled one always reaches a render or terminal within `steps.len()` hops).
    let mut cursor = current_step_id;
    for _ in 0..=compiled.steps.len() {
        let ctx = assemble_eval_context(state, scope, &cursor, &scratch, &signals).await;
        let next_id = choose_edge(compiled, &cursor, &ctx).ok_or(FlowError::NotFound)?;
        let next_step = compiled.step(&next_id).ok_or(FlowError::NotFound)?;
        match &next_step.kind {
            StepKind::Terminal => {
                // The pre-terminal step is the cursor (no state is persisted for the terminal), and
                // it fixes the per-journey fenced re-render for the rare central-fence TOCTOU. The
                // built-in fenced nodes reproduce the imperative driver's fence exactly; a custom
                // journey's fence is empty. `post_reset` is the ctx the advancing executor threaded
                // (Some only for recovery's verify, PR 8d, which relaxes its counters post-mint;
                // None for login / registration / a custom journey), so this stays byte-identical to
                // the pre-8b mint for a custom journey.
                let from_kind = compiled
                    .step(&cursor)
                    .map(|step| step.kind.clone())
                    .ok_or(FlowError::NotFound)?;
                let fenced_nodes = builtin_fenced_nodes(
                    state,
                    scope,
                    journey,
                    &from_kind,
                    transport,
                    &record.id,
                    record.return_to.as_deref(),
                    &scratch,
                )
                .await;
                let completion = CompletionKind::SessionMint {
                    fenced_nodes,
                    post_reset,
                };
                return complete_via_table(
                    state, scope, flow_id, transport, journey, record, &scratch, completion,
                    headers, now_micros,
                )
                .await;
            }
            // A decision is pure routing: continue the walk from it in-call, with no render and
            // no client round trip. Its own guarded edges route onward.
            StepKind::Decision => {
                cursor = next_id;
            }
            StepKind::IdentifierPassword
            | StepKind::MfaChallenge
            | StepKind::MfaEnroll
            | StepKind::ProgressiveProfiling => {
                let nodes = enter_step_nodes(
                    state,
                    scope,
                    &record.id,
                    record.return_to.as_deref(),
                    transport,
                    next_step,
                    &mut scratch,
                )
                .await?;
                let next = table_state(journey, &scratch, &next_step.kind, &next_id);
                return persist_and_render(
                    state,
                    scope,
                    flow_id,
                    transport,
                    journey,
                    record,
                    &next,
                    nodes,
                    Vec::new(),
                    now_micros,
                )
                .await;
            }
            // Entering the recovery VERIFY step (issue #92, PR 8d) is the uniform acknowledgment plus
            // code entry, which unlike the login MFA / profiling entries above MUST carry the
            // flow-level `RECOVERY_ACK` message, byte-identical to the imperative `drive_recovery`
            // Ack render (its `ack_nodes(false)` + `[RECOVERY_ACK]`). The generic enter path passes
            // empty messages, so recovery routes through this dedicated arm rather than
            // `enter_step_nodes`. `table_state` persists on `RecoveryAck` with NO `custom_step`,
            // carrying the stored `identifier` forward, so the row is byte-identical to the
            // imperative `PersistedState::step(RecoveryAck){identifier}`.
            StepKind::RecoveryVerify => {
                let nodes = recovery::ack_nodes(transport, &record.id, false);
                let next = table_state(journey, &scratch, &next_step.kind, &next_id);
                return persist_and_render(
                    state,
                    scope,
                    flow_id,
                    transport,
                    journey,
                    record,
                    &next,
                    nodes,
                    vec![Message::of(message::RECOVERY_ACK)],
                    now_micros,
                )
                .await;
            }
            // The remaining mint-family kinds (issue #92) are BUILT-IN-ONLY and not wired to their
            // render-into entry: registration's Ack is a render-override (never routed into), and
            // recovery's `start` entry is never routed INTO (it is the creation seed). The login
            // artifact and every custom artifact cannot route into one, so the walk never reaches one
            // on a live flow. A subflow_call is inlined away at compile time and an unknown kind never
            // compiles. Any of these on a live table is a corrupt table: a uniform not found, never
            // an oracle.
            StepKind::Registration
            | StepKind::RecoveryStart
            | StepKind::SubflowCall
            | StepKind::Unknown(_) => return Err(FlowError::NotFound),
        }
    }
    Err(FlowError::NotFound)
}

/// Drive one submission of a genuine custom-journey flow (issue #92, PR 4; a thin wrapper since PR
/// 8b): a [`Journey::Custom`] flow drives through the generalized [`drive_via_table`] engine,
/// preserving every custom-journey behavior byte-identically.
///
/// # Errors
///
/// The same typed errors [`drive_via_table`] reports.
#[allow(clippy::too_many_arguments)]
pub(super) async fn drive_custom(
    state: &OidcState,
    scope: Scope,
    flow_id: &FlowId,
    transport: Transport,
    record: &FlowRecord,
    persisted: &PersistedState,
    submission: &Submission,
    headers: &axum::http::HeaderMap,
    now_micros: i64,
) -> Result<Continuation, FlowError> {
    drive_via_table(
        state,
        scope,
        flow_id,
        transport,
        record,
        persisted,
        submission,
        headers,
        now_micros,
        Journey::Custom,
    )
    .await
}

/// Run one custom step's executor on a submission (issue #92, PR 4), reusing the SAME already
/// factored built-in cores. Updates `scratch` (subject, method tokens, enroll credential) on an
/// advance and returns the routing signals; a render leaves the flow on the current step.
///
// One arm per renderable StepKind, each a short call into the shared executor core plus its
// signal mapping; a flat match reads best and the length only reflects the kind count.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_step_executor(
    state: &OidcState,
    scope: Scope,
    record: &FlowRecord,
    step: &CompiledStep,
    _step_id: &str,
    submission: &Submission,
    headers: &axum::http::HeaderMap,
    scratch: &mut PersistedState,
) -> Result<StepOutcome, FlowError> {
    match &step.kind {
        StepKind::IdentifierPassword => {
            match login::advance_login(state, scope, record, submission, headers).await? {
                login::LoginStep::Render { nodes } => Ok(StepOutcome::Render {
                    nodes,
                    messages: Vec::new(),
                    state_override: None,
                }),
                login::LoginStep::Complete(success) => {
                    // The primary factor genuinely verified: run the SAME post-success follow
                    // through the built-in login driver runs (relax counters, foreign rehash, risk
                    // record), record the subject and the honest primary method token, and emit the
                    // routing signals from the SAME step-up + profiling planners.
                    //
                    // Placement residual (issue #359, resolved when the imperative driver retires in
                    // PR8e): the follow through runs here, at primary success, exactly once on every
                    // path. On a multi step path (challenge / enroll / profiling) that matches the
                    // imperative driver, which also runs it before the next step. On a DIRECT
                    // complete it runs before the session mint rather than after it, and if the mint
                    // is then refused at the rare central fence TOCTOU (the account turns non
                    // authenticatable between verify and mint) the follow through has already fired
                    // for a login that does not complete. Both effects are best effort, feed nothing
                    // into establish_session, and are invisible to the rendered flow, so they are
                    // outside the byte equivalence gate.
                    login_follow_through(state, scope, &success, headers).await;
                    let primary_methods = [AuthMethod::Password];
                    scratch.subject = Some(success.subject.clone());
                    scratch.methods = method_tokens(&primary_methods);
                    scratch.enroll_credential = None;
                    let plan =
                        mfa::plan_after_primary(state, scope, &success.user_id, &primary_methods)
                            .await;
                    let profiling_pending = profiling::plan(
                        state,
                        scope,
                        &success.user_id,
                        record.return_to.as_deref(),
                    )
                    .await
                    .is_some();
                    let signals = SignalSet::new()
                        .with(OutcomeSignal::PrimaryVerified, true)
                        .with(
                            OutcomeSignal::MfaRequired,
                            matches!(plan, mfa::MfaPlan::Challenge),
                        )
                        .with(
                            OutcomeSignal::EnrollRequired,
                            matches!(plan, mfa::MfaPlan::Enroll),
                        )
                        .with(OutcomeSignal::ProfilingPending, profiling_pending);
                    Ok(StepOutcome::Advance {
                        signals,
                        post_reset: None,
                    })
                }
            }
        }
        StepKind::MfaChallenge => {
            let (subject_id, _) = super::mfa_context(scope, scratch)?;
            match mfa::advance_challenge(state, scope, record, &subject_id, submission, headers)
                .await?
            {
                mfa::MfaStep::Render { nodes, messages } => Ok(StepOutcome::Render {
                    nodes,
                    messages,
                    state_override: None,
                }),
                mfa::MfaStep::Complete { new_method } => {
                    add_method(scratch, new_method);
                    let signals =
                        signals_after_second_factor(state, scope, record, &subject_id).await;
                    Ok(StepOutcome::Advance {
                        signals,
                        post_reset: None,
                    })
                }
            }
        }
        StepKind::MfaEnroll => {
            let (subject_id, _) = super::mfa_context(scope, scratch)?;
            let credential_id = scratch
                .enroll_credential
                .clone()
                .ok_or(FlowError::NotFound)?;
            match mfa::advance_enroll(
                state,
                scope,
                record,
                &subject_id,
                &credential_id,
                submission,
            )
            .await?
            {
                mfa::MfaStep::Render { nodes, messages } => Ok(StepOutcome::Render {
                    nodes,
                    messages,
                    state_override: None,
                }),
                mfa::MfaStep::Complete { new_method } => {
                    add_method(scratch, new_method);
                    scratch.enroll_credential = None;
                    let signals =
                        signals_after_second_factor(state, scope, record, &subject_id).await;
                    Ok(StepOutcome::Advance {
                        signals,
                        post_reset: None,
                    })
                }
            }
        }
        StepKind::ProgressiveProfiling => {
            let (subject_id, _) = super::mfa_context(scope, scratch)?;
            match profiling::advance(state, scope, record, &subject_id, submission).await? {
                profiling::ProfilingStep::Render { nodes, messages } => Ok(StepOutcome::Render {
                    nodes,
                    messages,
                    state_override: None,
                }),
                profiling::ProfilingStep::Complete => {
                    let signals = SignalSet::new()
                        .with(OutcomeSignal::PrimaryVerified, true)
                        .with(OutcomeSignal::MfaRequired, false)
                        .with(OutcomeSignal::EnrollRequired, false)
                        .with(OutcomeSignal::ProfilingPending, false);
                    Ok(StepOutcome::Advance {
                        signals,
                        post_reset: None,
                    })
                }
            }
        }
        // The REGISTRATION journey (issue #92, PR 8c): the SAME `advance_registration` executor the
        // imperative `drive_registration` runs, reusing every #64/#80/#82 defense unchanged. Its
        // three outcomes map onto the table engine's vocabulary:
        //
        // - `Render` (a validation error / throttle / open-mode duplicate) stays on the details
        //   state with NO override, byte-identical to the imperative re-render;
        // - `Ack` (the closed-mode anti-enumeration acknowledgment, or the waitlist pending notice)
        //   renders EMPTY nodes plus the one flow-level ack message and OVERRIDES the wire state to
        //   the interstitial RegistrationAck, so the flow advances its wire position while staying
        //   OPEN (no consume);
        // - `Complete` (a genuine account create) records the subject and the honest `pwd` primary
        //   method token and ADVANCES: the single unguarded `register -> done` edge routes to the
        //   terminal, where `complete_via_table` mints the first session. `success.event` and
        //   `success.actor` are DROPPED (as login drops `LoginStep::Complete`'s event):
        //   `complete_via_table` rebuilds `AuthenticationEvent::from_methods(&[Password], ...)` and
        //   `interaction::user_actor`, identical in every rendered field.
        StepKind::Registration => {
            match registration::advance_registration(state, scope, record, submission, headers)
                .await?
            {
                registration::RegistrationStep::Render { nodes, messages } => {
                    Ok(StepOutcome::Render {
                        nodes,
                        messages,
                        state_override: None,
                    })
                }
                registration::RegistrationStep::Ack { message_id } => Ok(StepOutcome::Render {
                    nodes: registration::ack_nodes(),
                    messages: vec![Message::of(message_id)],
                    state_override: Some(FlowStateTag::RegistrationAck),
                }),
                registration::RegistrationStep::Complete(success) => {
                    scratch.subject = Some(success.subject.clone());
                    scratch.methods = method_tokens(&[AuthMethod::Password]);
                    scratch.enroll_credential = None;
                    Ok(StepOutcome::Advance {
                        signals: SignalSet::new(),
                        post_reset: None,
                    })
                }
            }
        }
        // The RECOVERY journey (issue #92, PR 8d): the SAME `advance_start` / `advance_verify`
        // executors the imperative `drive_recovery` runs, reusing every #64/#80/#81/#84 defense
        // unchanged. A passwordless email-OTP identity proof: request a code, enter it, mint an
        // email-factor session (`amr = [otp]`).
        //
        // - `RecoveryStart` (`Render` -> stay on the identifier form on an empty identifier;
        //   `Ack` -> store the identifier server-side and ADVANCE: the single unguarded
        //   `start -> verify` edge routes to the verify step, whose dedicated walk arm renders the
        //   ack + code entry with the flow-level `RECOVERY_ACK` message);
        // - `RecoveryVerify` (reads the stored identifier or a uniform not found; `Render` -> stay
        //   on the ack + code entry on an empty / wrong code; `Complete` -> record the subject and
        //   the honest `email_otp` method token and ADVANCE with the recovery-path abuse context as
        //   `post_reset`, so a genuine mint relaxes the SAME counters `drive_recovery` does through
        //   `reset_after_success`). `success.event` / `success.actor` are DROPPED (as login /
        //   registration drop theirs): `complete_via_table` rebuilds
        //   `AuthenticationEvent::from_methods(&[EmailOtp], ...)` (== `email_otp()` field-for-field)
        //   and `interaction::user_actor`.
        StepKind::RecoveryStart => {
            match recovery::advance_start(state, scope, record, submission, headers).await? {
                recovery::RecoveryStartStep::Render { nodes } => Ok(StepOutcome::Render {
                    nodes,
                    messages: Vec::new(),
                    state_override: None,
                }),
                recovery::RecoveryStartStep::Ack { identifier } => {
                    scratch.identifier = Some(identifier);
                    Ok(StepOutcome::Advance {
                        signals: SignalSet::new(),
                        post_reset: None,
                    })
                }
            }
        }
        StepKind::RecoveryVerify => {
            let identifier = scratch.identifier.clone().ok_or(FlowError::NotFound)?;
            match recovery::advance_verify(state, scope, record, &identifier, submission, headers)
                .await?
            {
                recovery::RecoveryVerifyStep::Render { nodes, messages } => {
                    Ok(StepOutcome::Render {
                        nodes,
                        messages,
                        state_override: None,
                    })
                }
                recovery::RecoveryVerifyStep::Complete(success) => {
                    scratch.subject = Some(success.subject.clone());
                    scratch.methods = method_tokens(&[AuthMethod::EmailOtp]);
                    scratch.enroll_credential = None;
                    Ok(StepOutcome::Advance {
                        signals: SignalSet::new(),
                        post_reset: Some(success.ctx),
                    })
                }
            }
        }
        // A decision, terminal, or subflow_call step is never a client-submittable render: the
        // engine routes THROUGH it, it does not advance it by a submission. A uniform not found,
        // never an oracle.
        StepKind::Decision | StepKind::Terminal | StepKind::SubflowCall | StepKind::Unknown(_) => {
            Err(FlowError::NotFound)
        }
    }
}

/// The routing signals after a genuine second factor (issue #92, PR 4): the primary and the second
/// factor are proven, so `mfa_required` and `enroll_required` clear; `profiling_pending` is
/// recomputed LIVE (a held profiling step may still be due), exactly as the built-in
/// `complete_with_second_factor` consults the profiling planner before minting.
async fn signals_after_second_factor(
    state: &OidcState,
    scope: Scope,
    record: &FlowRecord,
    subject_id: &UserId,
) -> SignalSet {
    let profiling_pending = profiling::plan(state, scope, subject_id, record.return_to.as_deref())
        .await
        .is_some();
    SignalSet::new()
        .with(OutcomeSignal::PrimaryVerified, true)
        .with(OutcomeSignal::MfaRequired, false)
        .with(OutcomeSignal::EnrollRequired, false)
        .with(OutcomeSignal::ProfilingPending, profiling_pending)
}

/// Push a genuinely proven second-factor method token onto the scratch (deduplicated), so the
/// final mint's amr honestly reflects every factor that ran.
fn add_method(scratch: &mut PersistedState, method: AuthMethod) {
    let token = method.as_token().to_owned();
    if !scratch.methods.contains(&token) {
        scratch.methods.push(token);
    }
}

/// Build the nodes for TRANSITIONING INTO a render-kind step (issue #92, PR 4), reusing the SAME
/// pure node builders the built-in engine and the golden corpus call. The MFA enroll step mints a
/// pending factor through the shared ceremony and stamps its credential id on the scratch; the
/// profiling step renders the live held-field plan. A step whose kind renders nothing (decision,
/// terminal, `subflow_call`) is never entered here.
async fn enter_step_nodes(
    state: &OidcState,
    scope: Scope,
    flow_id: &str,
    return_to: Option<&str>,
    transport: Transport,
    step: &CompiledStep,
    scratch: &mut PersistedState,
) -> Result<Vec<Node>, FlowError> {
    match &step.kind {
        StepKind::IdentifierPassword => Ok(login::start_nodes(transport, flow_id)),
        StepKind::MfaChallenge => Ok(mfa::challenge_start_nodes(transport, flow_id)),
        StepKind::MfaEnroll => {
            let subject_id = scratch_subject(scope, scratch)?;
            let begin = mfa::begin_enroll(state, scope, &subject_id).await?;
            scratch.enroll_credential = Some(begin.credential_id.clone());
            Ok(mfa::enroll_nodes(transport, flow_id, &begin, false))
        }
        StepKind::ProgressiveProfiling => {
            let subject_id = scratch_subject(scope, scratch)?;
            match profiling::plan(state, scope, &subject_id, return_to).await {
                Some(plan) => Ok(profiling::start_nodes(transport, flow_id, &plan)),
                // Nothing left to collect (a mis-routed profiling step): render nothing rather
                // than fabricate a form. A well-compiled journey only routes here on
                // profiling_pending, so this stays inert.
                None => Ok(Vec::new()),
            }
        }
        // The mint-family kinds (issue #92, PR 8a) render their entry nodes (registration's details
        // form, recovery's start / ack forms) once the per-journey convergence PRs (8c, 8d) wire
        // them; until then no live table routes into one. A decision, terminal, or subflow_call step
        // renders nothing here. Any of these is a uniform not found, never an oracle.
        StepKind::Registration
        | StepKind::RecoveryStart
        | StepKind::RecoveryVerify
        | StepKind::Decision
        | StepKind::Terminal
        | StepKind::SubflowCall
        | StepKind::Unknown(_) => Err(FlowError::NotFound),
    }
}

/// Complete a table-driven flow at a terminal step (issue #92, PR 4; generalized PR 8a/8b): mint
/// the session through the ONE choke point with the honest amr the flow earned (the primary factor
/// plus any genuinely proven second factor, carried on the scratch method tokens), executing the
/// polymorphic [`CompletionKind::SessionMint`] for the flow's real `journey` (login since PR 8b, or
/// a genuine custom journey).
///
/// The completion carries the per-journey fenced re-render nodes (login's uniform-incorrect / MFA
/// challenge / profiling forms, empty for a genuine custom journey) and an optional post-mint
/// counter reset (issue #92, PR 8a): recovery relaxes its path abuse counters on a GENUINE mint (PR
/// 8d), exactly as the built-in `drive_recovery` does; login and a custom journey pass [`None`].
#[allow(clippy::too_many_arguments)]
async fn complete_via_table(
    state: &OidcState,
    scope: Scope,
    flow_id: &FlowId,
    transport: Transport,
    journey: Journey,
    record: &FlowRecord,
    scratch: &PersistedState,
    completion: CompletionKind,
    headers: &axum::http::HeaderMap,
    now_micros: i64,
) -> Result<Continuation, FlowError> {
    let CompletionKind::SessionMint {
        fenced_nodes,
        post_reset,
    } = completion;
    let subject = scratch.subject.clone().ok_or(FlowError::NotFound)?;
    let subject_id = UserId::parse_in_scope(&subject, &scope).map_err(|_| FlowError::NotFound)?;
    let methods: Vec<AuthMethod> = scratch
        .methods
        .iter()
        .filter_map(|token| AuthMethod::from_token(token))
        .collect();
    // auth_time is now_micros (the drive entry instant), which is what the imperative step up and
    // profiling completions already used. It unifies the direct complete path onto the same clock;
    // the imperative direct complete alone read a post verify instant, so a no MFA login now stamps
    // auth_time a password verify latency earlier. Same request, sub second, and not a rendered
    // value, so it is outside the byte equivalence gate (issue #359).
    let event = AuthenticationEvent::from_methods(&methods, now_micros);
    let actor = interaction::user_actor(&subject_id);
    let continuation = consume_and_complete(
        state,
        scope,
        flow_id,
        transport,
        journey,
        record,
        &subject,
        actor,
        &event,
        fenced_nodes,
        headers,
        now_micros,
    )
    .await?;
    // A post-mint counter reset runs only on a GENUINE completion (never on the rare central-fence
    // re-render), exactly as the built-in recovery driver relaxes its counters after a real mint.
    if let Some(ctx) = post_reset {
        if matches!(continuation, Continuation::Complete { .. }) {
            state.reset_after_success(&ctx).await;
        }
    }
    Ok(continuation)
}

/// Choose the first guarded edge that applies from `from` (issue #92, PR 4): document order, first
/// whose guard is absent or evaluates true. An evaluation error (only the depth guard, which a
/// type-checked predicate never hits) is treated as a non-match, never fail-open.
fn choose_edge(compiled: &CompiledJourney, from: &str, ctx: &EvalContext) -> Option<String> {
    for edge in compiled.edges(from) {
        // An eval error counts as "guard did not match" so a corrupt guard cannot force a route.
        // SAFETY INVARIANT for a built-in artifact: a POSITIVE guard whose false skips a security
        // requirement (for example /mfa_required gating the challenge edge) must never be able to
        // error, or "false on error" would relax that requirement. Today the built-in login guards
        // are depth 1 Cmp predicates that only ever error on MAX_PREDICATE_DEPTH, which they cannot
        // hit, so this holds; a future built-in guard must preserve it (issue #359).
        let taken = match &edge.guard {
            None => true,
            Some(guard) => evaluate(guard, ctx).unwrap_or(false),
        };
        if taken {
            return Some(edge.to.clone());
        }
    }
    None
}

/// The persisted state for a table-driven flow ON a given compiled step (issue #92, PR 4;
/// generalized PR 8b), carrying the scratch's subject and method tokens forward.
///
/// For a genuine custom journey the wire `step` is the FLAT [`FlowStateTag::Custom`] with the
/// concrete step id held server side in `custom_step`. For a converged built-in journey the wire
/// `step` is the journey's REAL per-step [`FlowStateTag`] ([`wire_state_for`]) and NO `custom_step`
/// is written, so the serialized `flows.state` is BYTE-IDENTICAL to the imperative driver's row (a
/// built-in row never carried a `custom_step`, and `skip_serializing_if` omits the [`None`]).
fn table_state(
    journey: Journey,
    scratch: &PersistedState,
    kind: &StepKind,
    step_id: &str,
) -> PersistedState {
    let mut next = scratch.clone();
    next.step = wire_state_for(journey, kind);
    next.custom_step = match journey {
        Journey::Custom => Some(step_id.to_owned()),
        _ => None,
    };
    next
}

/// The compiled step a converged built-in journey's persisted wire tag names (issue #92, PR 8b):
/// the REVERSE of [`wire_state_for`]. Each renderable step kind of a built-in artifact maps to a
/// distinct per-step [`FlowStateTag`], so a persisted tag names exactly one compiled step (a
/// bijection over the renderable kinds); the first submission's `IdentifierPassword` tag resolves
/// to the login entry step. Returns [`None`] when no compiled step renders as `tag` (a corrupt row,
/// a uniform not found, never an oracle). A genuine custom journey never uses this (it holds the
/// concrete step in `custom_step`).
///
/// A step also reverse-maps from any RENDER-OVERRIDE wire state it can emit (issue #92, PR 8c):
/// registration persists on [`FlowStateTag::RegistrationAck`] after an Ack render while the flow
/// stays OPEN, so a resubmit re-enters with `persisted.step == RegistrationAck` and must fold back
/// to the `register` step, re-running `advance_registration` exactly as the imperative
/// `drive_registration` (which ignores the persisted step) does. [`render_override_states`] supplies
/// those states, so the fold is single-sourced with the projection.
///
/// Sharp edge that stays fail closed: [`wire_state_for`] folds a built-in Terminal to the flat
/// `FlowStateTag::Custom`, so a tampered login row carrying `step = custom` reverse-maps to the
/// Terminal step rather than an immediate not found. The Terminal step has no runnable executor, so
/// the drive still refuses it with [`FlowError::NotFound`] and mints nothing (proven by the
/// `flow_login_flip_adversarial` forged-custom-tag probe).
fn builtin_step_for(
    journey: Journey,
    compiled: &CompiledJourney,
    tag: FlowStateTag,
) -> Option<&str> {
    compiled
        .steps
        .iter()
        .find(|(_, step)| {
            wire_state_for(journey, &step.kind) == tag
                || render_override_states(journey, &step.kind).contains(&tag)
        })
        .map(|(id, _)| id.as_str())
}

/// The per-journey fenced re-render nodes for a table-driven terminal (issue #92, PR 8b): the
/// UNIFORM nodes to re-render on the rare central-fence TOCTOU after the completion latch tripped,
/// keyed on the PRE-TERMINAL step kind, reproducing the imperative login driver's fence EXACTLY. A
/// direct primary complete re-renders the uniform-incorrect primary form; a complete after a second
/// factor re-renders the MFA challenge form; a complete after profiling re-renders the held-field
/// form (or nothing, when the plan has emptied by the mint). A genuine custom journey carries no
/// built-in fallback form, so its fence is empty. This path is a rare TOCTOU that is NOT in the
/// golden corpus, so it is not byte-gated; it is reproduced for fidelity regardless.
#[allow(clippy::too_many_arguments)]
async fn builtin_fenced_nodes(
    state: &OidcState,
    scope: Scope,
    journey: Journey,
    from_kind: &StepKind,
    transport: Transport,
    flow_id: &str,
    return_to: Option<&str>,
    scratch: &PersistedState,
) -> Vec<Node> {
    match (journey, from_kind) {
        (Journey::Login, StepKind::IdentifierPassword) => {
            login::uniform_incorrect_render(transport, flow_id)
        }
        (Journey::Login, StepKind::MfaChallenge | StepKind::MfaEnroll) => {
            mfa::challenge_start_nodes(transport, flow_id)
        }
        (Journey::Login, StepKind::ProgressiveProfiling) => {
            // The held-field plan may have emptied by the mint; an empty fenced set is then correct,
            // exactly as the imperative `drive_profiling` fence recomputes it. A missing subject (a
            // corrupt row that could never have reached here) folds to empty rather than fault: the
            // flow is already consumed and this is a best-effort re-render, never an oracle.
            match scratch_subject(scope, scratch) {
                Ok(subject_id) => match profiling::plan(state, scope, &subject_id, return_to).await
                {
                    Some(plan) => profiling::start_nodes(transport, flow_id, &plan),
                    None => Vec::new(),
                },
                Err(_) => Vec::new(),
            }
        }
        // Registration's pre-terminal step is the `register` details step (issue #92, PR 8c): the
        // imperative `drive_registration` fences the details form on the rare central-fence TOCTOU,
        // so reproduce it exactly. Registration runs NO post-mint reset (`post_reset` stays None).
        (Journey::Registration, StepKind::Registration) => {
            registration::start_nodes(transport, flow_id)
        }
        // Recovery's pre-terminal step is the `verify` code-entry step (issue #92, PR 8d): the
        // imperative `drive_recovery` fences `ack_nodes(false)` on the rare central-fence TOCTOU, so
        // reproduce it exactly. The genuine mint relaxes the recovery-path counters through the
        // threaded `post_reset`, not here.
        (Journey::Recovery, StepKind::RecoveryVerify) => {
            recovery::ack_nodes(transport, flow_id, false)
        }
        // A genuine custom journey (and any not-yet-converged built-in) carries no built-in
        // fallback form: its wire state renders from its own nodes, so the fence is empty.
        _ => Vec::new(),
    }
}

/// A fresh custom scratch seated on the entry step (no subject or method tokens yet).
fn custom_scratch_empty(entry_step_id: &str) -> PersistedState {
    let mut scratch = PersistedState::step(FlowStateTag::Custom);
    scratch.custom_step = Some(entry_step_id.to_owned());
    scratch
}

/// Resolve the typed subject id carried on the scratch, or a uniform not found when a step that
/// needs a subject is reached without one (a corrupt table, never an oracle).
fn scratch_subject(scope: Scope, scratch: &PersistedState) -> Result<UserId, FlowError> {
    let subject = scratch.subject.as_deref().ok_or(FlowError::NotFound)?;
    UserId::parse_in_scope(subject, &scope).map_err(|_| FlowError::NotFound)
}
