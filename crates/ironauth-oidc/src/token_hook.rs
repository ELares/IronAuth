// SPDX-License-Identifier: MIT OR Apache-2.0
//! Running a deployed WASM hook when a token is minted (issue #114, issue #113 criterion 1).
//!
//! M11's exit criterion is "a WASM hook customizes token claims in microseconds under capability
//! sandboxing". Everything but the last four words shipped: the engine, the deny-by-default
//! sandbox, the four resource bounds, the WIT interface, and a benchmark proving the microsecond
//! claim. `LoadedHook::customize` had ZERO callers, so no hook had ever customized a token.
//!
//! This is the caller. It sits at the same seam the declarative mapping uses, immediately after
//! it, and that order is deliberate: the mapping is configuration an operator writes as data,
//! the hook is code, and code should see what configuration produced rather than race it.
//!
//! # Everything a hook returns goes through the fence
//!
//! `claims_mapping::filter_hook_claims` exists for this and had no caller either. A hook is
//! arbitrary guest code: it can return `sub`, a thousand claims, a name of a megabyte, or a name
//! that is entirely whitespace. The fence refuses each by NAME and reports what it refused,
//! bounded, so a hook that returns ten thousand bad claims produces a bounded log line rather
//! than ten thousand.
//!
//! It runs on the hook's output and not on its input, which is the direction that matters:
//! what a hook READS is the mint's business, what it WRITES is the token's.
//!
//! # Every failure is fail-CLOSED, and that is the opposite of the enrichment beside it
//!
//! `merge_enriched_claims` is deliberately fail-open: an FGA that is down costs a deployment
//! some claims and never a login. A hook is not an enrichment for the same reason a mapping is
//! not: it can REMOVE a claim as easily as add one, so ignoring a hook that failed issues more
//! than the operator deployed.
//!
//! And there is a second reason that applies only here. A hook that traps, exhausts its fuel or
//! passes its deadline is code behaving in a way its author did not intend. Continuing past that
//! with a half-shaped token means issuing a credential whose shape nobody chose.
//!
//! # Compilation is CACHED, and that is what makes the criterion true
//!
//! M11's exit criterion says "in microseconds". Compiling a component is not microseconds:
//! measured on the shipped fixture, `precompile_component` is a median of 34 ms and
//! `Component::new` 33 ms. The first version of this module compiled on every issuance, on a
//! reactor thread, so the shipped path cost 34 ms per login and the claim was false -- and the
//! latency benchmark could not see it, because that benchmark measures deserialize + instantiate
//! + call, which is the path the dispatch did not take.
//!
//! So a loaded component is held per (scope, client, component digest). The digest is in the
//! key rather than a version counter: it is the artifact's own identity, so a redeploy of
//! different bytes is a different key by construction and a redeploy of identical bytes
//! correctly reuses the entry. Nothing has to remember to invalidate.
//!
//! # WHAT A CACHE HIT ACTUALLY COSTS, which is more than the wasm
//!
//! Saying "a cache hit is instantiate + call" would be the same error this module was built to
//! fix, one layer up. A hit is:
//!
//! 1. a STORE READ of the `token_hooks` row, ~378 microseconds, paid on EVERY hooked login
//!    because that read is how the server learns a hook is deployed at all
//! 2. SHA-256 over the bytes it returned, which the 8 MiB `token_hooks_component_bounded` CHECK
//!    is what keeps finite
//! 3. a hash lookup, then instantiate + call -- the tens of microseconds the benchmark measures
//!
//! Step 3 is the part "in microseconds" is a claim about, and it holds. Steps 1 and 2 dominate
//! it, and the honest statement of the criterion is that the HOOK is microseconds while the
//! dispatch around it is a database round trip. Cutting that would mean keying the cache on a
//! version column so a hit never reads the bytes, which is a schema change and not this issue.
//!
//! # It is not on a tokio worker
//!
//! `LoadedHook::customize` blocks, and wasmtime's `in_tokio` PANICS on a tokio worker thread.
//! Measured on this runtime: the same hook that returns in 1.16 ms under `spawn_blocking` panics
//! when called directly. So the invocation goes through `spawn_blocking`, and so does the
//! COMPILE on a cache miss -- 33 ms of cranelift is not something to run on a reactor either,
//! which the first version did.
//!
//! There is no `unsafe` here. It used the AOT pair -- `precompile_component` then the `unsafe`
//! `Component::deserialize` -- on the reasoning that AOT is what a deployment pays at deploy
//! time. Measured, that pair is 34.0 ms against 32.8 ms for the safe `Component::new`: it was
//! SLOWER and it was the only `unsafe` block in this crate. The reason AOT exists is to move
//! compilation off the request path, and a cache does that without machine code in a database
//! or an `unsafe` deserialize of it.

use std::collections::BTreeMap;
use std::sync::Arc;

use ironauth_hooks::{HookEngine, HookError, Limits, LoadedHook, Request};
use ironauth_store::{Scope, Store};

use crate::claims_mapping;

/// Why an issuance could not run this client's hook.
///
/// Deliberately not carrying the underlying error: the caller turns this into a `server_error`,
/// and the detail belongs in the log rather than in anything a client reads. A client learning
/// which resource bound a hook exhausted learns about the hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookFault {
    /// The store could not answer.
    Unavailable,
    /// The stored component could not be compiled or instantiated.
    ///
    /// Distinct from [`Self::Aborted`] because they point at different people: this is the
    /// deployed artifact being wrong, which is the operator's, while an abort is the hook's code
    /// misbehaving at runtime, which is its author's.
    Unloadable,
    /// The hook ran and exhausted a bound, trapped, or declined.
    Aborted,
    /// The hook was built against a payload version this server does not emit.
    ///
    /// Issue #113 criterion 6: the version is explicit in every invocation. A hook compiled
    /// against version 1 and handed a version 2 payload reads fields that moved, and the only
    /// honest answer is to refuse rather than to hand it a shape it cannot parse.
    PayloadVersion,
}

/// The payload version this server emits (issue #113 criterion 6).
///
/// A hook's stored `payload_version` must equal it. Not "must be at most": a hook built against
/// a LATER version than the server emits is as wrong as one built against an earlier one, and
/// silently accepting either is how a field that moved gets read from the wrong place.
///
/// AN ALIAS, not a copy. It read `= 1` and was a THIRD independent declaration of the version,
/// beside `TOKEN_CUSTOMIZE_VERSION` and the migration's CHECK. Two of those three were tied
/// (by `the_emitted_payload_version_is_the_one_the_table_admits` below) and the registry was
/// not, so bumping the schema and registering version 2 would have left this dispatch emitting
/// 1 with nothing red -- which is criterion 6's failure exactly:
///
/// > Event payload version is explicit in every hook invocation; emitting an unregistered
/// > version fails CI.
///
/// `token_customize` already proves `TOKEN_CUSTOMIZE_VERSION` is in `REGISTERED_VERSIONS` and
/// that an unregistered version cannot validate. Aliasing makes the emitted version THE
/// registered one by construction, so "emitting an unregistered version" stops being a thing a
/// gate has to catch.
pub const PAYLOAD_VERSION: u32 = ironauth_store::token_customize::TOKEN_CUSTOMIZE_VERSION;

/// The loaded components this process holds, keyed by scope, client, and component DIGEST.
///
/// The digest and not a version counter, because it is the artifact's own identity: a redeploy
/// of different bytes is a different key by construction, and a redeploy of identical bytes
/// correctly reuses the entry. Nothing has to remember to invalidate, which is the failure mode
/// a counter has.
///
/// A `Mutex` rather than an `RwLock`: the critical section is a hash lookup and an `Arc` clone,
/// so the contention a reader-writer lock would relieve does not exist, and `RwLock` would add a
/// second poisoning story for nothing. The COMPILE happens outside the lock -- two logins
/// racing a cold client each compile and one insert wins, which costs one duplicate compile and
/// is strictly better than holding a lock across 33 ms of cranelift.
///
/// BOUNDED, and the bound is not defensive. An entry is a compiled component: tens of megabytes
/// of host memory for a large one, and the key space is (scope, client), which an operator with
/// many clients can grow without limit. Past the bound the cache stops ADMITTING rather than
/// evicting, because eviction under a login flood is a thundering-herd recompile and the honest
/// answer is that a deployment past this many distinct hooks needs a real cache rather than a
/// bigger map.
type HookCache = std::sync::Mutex<std::collections::HashMap<HookKey, Arc<LoadedHook>>>;

/// The engine and its compilation cache, as ONE installable thing.
///
/// Together rather than separately because they are only correct together: the cache's keys are
/// meaningless against a different engine, and an engine without a cache compiles 33 ms on every
/// issuance. Two `with_*` calls on the state would be two chances to install one and forget the
/// other, and the failure that produces is a latency regression nothing red announces.
pub struct HookRuntime {
    engine: Arc<HookEngine>,
    cache: Arc<HookCache>,
}

/// Hand-written because `HookEngine` has no `Debug`, and because the CACHE SIZE is the field
/// worth seeing: it is the difference between a deployment paying tens of microseconds of wasm
/// per hooked login and one paying tens of milliseconds of cranelift. The components themselves are machine code
/// and would render as nothing useful.
impl std::fmt::Debug for HookRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cached = self.cache.lock().ok().map(|map| map.len());
        f.debug_struct("HookRuntime")
            .field("cached_components", &cached)
            .finish_non_exhaustive()
    }
}

impl HookRuntime {
    /// Build a runtime around `engine`, with an empty cache.
    #[must_use]
    pub fn new(engine: Arc<HookEngine>) -> Self {
        Self {
            engine,
            cache: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// The engine, for the epoch driver.
    ///
    /// A deployment must advance the epoch or the deadline never arrives, which is the backstop
    /// against a hook that blocks -- see `HookEngine::tick`.
    #[must_use]
    pub fn engine(&self) -> &Arc<HookEngine> {
        &self.engine
    }
}

/// (tenant, environment, client, component digest).
type HookKey = (String, String, String, [u8; 32]);

/// The most distinct hooks one process holds compiled at once.
///
/// Two hundred and fifty-six. A claim-shaping component compiles to a few tens of megabytes of
/// host memory, so this is a bound in the low gigabytes at the extreme -- deliberately generous,
/// because the cost of being too small is recompiling 33 ms on a login and the cost of being too
/// large is memory a deployment can measure.
const MAX_CACHED_HOOKS: usize = 256;

/// What a hook contributed, after the fence.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HookClaims {
    /// Accepted ID-token claims.
    pub id_token: BTreeMap<String, serde_json::Value>,
    /// Accepted access-token claims.
    pub access_token: BTreeMap<String, serde_json::Value>,
}

/// One invocation's inputs.
///
/// A struct rather than six parameters, and not only for the arity lint: `grant_type` and
/// `client_id` are both `&str`, as are the two claim maps' element types, so a positional call
/// with two of them swapped compiles. Naming them at the call site is what makes a door that
/// passes the ACCESS-token claims as the ID-token ones a diff a reviewer sees.
#[derive(Debug, Clone, Copy)]
pub struct Invocation<'a> {
    /// The scope the tokens belong to.
    pub scope: Scope,
    /// The client the tokens are for, and the key the hook is deployed under.
    pub client_id: &'a str,
    /// The wire `grant_type`, so a hook can shape a refresh differently from a code exchange.
    pub grant_type: &'a str,
    /// The subject, absent for a grant with no user.
    pub subject: Option<&'a str>,
    /// The ID-token claims as the mint has them so far.
    pub id_token_claims: &'a serde_json::Map<String, serde_json::Value>,
    /// The access-token claims as the mint has them so far.
    pub access_token_claims: &'a serde_json::Map<String, serde_json::Value>,
}

/// Read, compile and run this client's hook, returning what it contributed.
///
/// [`None`] when the client has no hook deployed, which is every client until an operator
/// deploys one. That is distinct from a hook that ran and returned nothing.
///
/// # Errors
///
/// [`HookFault`] on any failure. Every one fails the issuance; see the module header.
pub async fn run(
    store: &Store,
    runtime: &HookRuntime,
    invocation: &Invocation<'_>,
) -> Result<Option<HookClaims>, HookFault> {
    let (engine, cache) = (&runtime.engine, &runtime.cache);
    let Invocation {
        scope,
        client_id,
        grant_type,
        subject,
        id_token_claims,
        access_token_claims,
    } = *invocation;
    let record = store
        .scoped(scope)
        .token_hooks()
        .get(client_id)
        .await
        .map_err(|error| {
            tracing::error!(
                target: "ironauth.hooks",
                tenant = %scope.tenant(),
                client_id,
                ?error,
                "a token issuance could not read the client's hook"
            );
            HookFault::Unavailable
        })?;
    let Some(record) = record else {
        return Ok(None);
    };

    // THE VERSION, before the component is even compiled. Refusing here rather than after means
    // a mismatched hook costs nothing and, more importantly, is never INVOKED with a payload it
    // cannot read.
    let deployed_version = u32::try_from(record.payload_version).unwrap_or(u32::MAX);
    if deployed_version != PAYLOAD_VERSION {
        tracing::error!(
            target: "ironauth.hooks",
            tenant = %scope.tenant(),
            client_id,
            deployed_version,
            emitted_version = PAYLOAD_VERSION,
            "the deployed hook was built against a payload version this server does not emit"
        );
        return Err(HookFault::PayloadVersion);
    }

    let loaded = loaded_hook(engine, cache, scope, client_id, &record.component)
        .await
        .map_err(|error| {
            tracing::error!(
                target: "ironauth.hooks",
                tenant = %scope.tenant(),
                client_id,
                ?error,
                "the deployed hook component could not be compiled"
            );
            HookFault::Unloadable
        })?;

    let request = Request {
        payload_version: PAYLOAD_VERSION,
        grant_type: grant_type.to_owned(),
        client_id: client_id.to_owned(),
        subject: subject.map(str::to_owned),
        id_token_claims: as_pairs(id_token_claims),
        access_token_claims: as_pairs(access_token_claims),
    };

    let customization = invoke(Arc::clone(engine), loaded, request)
        .await
        .map_err(|error| {
            tracing::error!(
                target: "ironauth.hooks",
                tenant = %scope.tenant(),
                client_id,
                ?error,
                "the deployed hook did not complete"
            );
            HookFault::Aborted
        })?;

    Ok(Some(HookClaims {
        id_token: fence(
            &customization.id_token_claims,
            id_token_claims,
            scope,
            client_id,
            "id_token",
        ),
        access_token: fence(
            &customization.access_token_claims,
            access_token_claims,
            scope,
            client_id,
            "access_token",
        ),
    }))
}

/// The loaded component for this client's bytes, compiling it only on a miss.
///
/// The whole reason this function exists is that compiling is 33 ms and instantiating is tens of
/// microseconds. A cache hit is what makes "in microseconds" true of the WASM WORK on the
/// shipped path rather than of a benchmark measuring a different one. It does not make the
/// dispatch microseconds: the caller has already paid a store read to get `component` here, and
/// the digest below hashes it. See the module header for the full cost of a hit.
///
/// The compile runs on `spawn_blocking` for the same reason the invocation does, and one more:
/// 33 ms of cranelift on a reactor thread stalls every other request on that thread, and the
/// first version of this module did exactly that on every issuance.
async fn loaded_hook(
    engine: &Arc<HookEngine>,
    cache: &Arc<HookCache>,
    scope: Scope,
    client_id: &str,
    component: &[u8],
) -> Result<Arc<LoadedHook>, HookError> {
    let key: HookKey = (
        scope.tenant().to_string(),
        scope.environment().to_string(),
        client_id.to_owned(),
        digest(component),
    );

    // The lock is held across a hash lookup and an `Arc` clone, and nothing else. Poisoning is
    // treated as an empty cache rather than a panic: a poisoned cache is a correctness-neutral
    // loss of a performance structure, and failing a login over it would turn one panicking
    // request into an outage.
    if let Some(hit) = cache.lock().ok().and_then(|map| map.get(&key).cloned()) {
        return Ok(hit);
    }

    let compiling = Arc::clone(engine);
    let bytes = component.to_vec();
    let loaded = Arc::new(
        tokio::task::spawn_blocking(move || compiling.load(&bytes))
            .await
            .unwrap_or_else(|join| {
                Err(HookError::Declined(format!(
                    "the compile task did not complete: {join}"
                )))
            })?,
    );

    if let Ok(mut map) = cache.lock() {
        // STOPS ADMITTING at the bound rather than evicting. Eviction under a login flood is a
        // thundering-herd recompile, and a deployment past this many distinct hooks needs a real
        // cache rather than a bigger map. The already-loaded component is still returned, so the
        // login succeeds; what is lost is the reuse.
        if map.len() < MAX_CACHED_HOOKS {
            map.insert(key, Arc::clone(&loaded));
        } else {
            tracing::warn!(
                target: "ironauth.hooks",
                cached = map.len(),
                "the hook cache is full, so this component was compiled and not retained; \
                 every issuance for it will recompile until a process restart"
            );
        }
    }
    Ok(loaded)
}

/// A component's identity, for the cache key.
///
/// SHA-256 rather than a cheaper hash, because a collision here would run one client's code for
/// another's token. That is not a performance question.
fn digest(component: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(component);
    hasher.finalize().into()
}

/// Run the hook OFF the reactor.
///
/// `spawn_blocking` for two reasons, and the first is not tuning: `LoadedHook::customize` reaches
/// wasmtime's `in_tokio`, which PANICS on a tokio worker thread. The second is that a hook is
/// permitted to spin for its entire fuel budget, and that belongs on a blocking pool rather than
/// on a reactor thread other requests are waiting on.
async fn invoke(
    engine: Arc<HookEngine>,
    hook: Arc<LoadedHook>,
    request: Request,
) -> Result<ironauth_hooks::Customization, HookError> {
    tokio::task::spawn_blocking(move || hook.customize(&engine, &limits(), &request))
        .await
        .unwrap_or_else(|join| {
            // A panic INSIDE the guest cannot reach here -- wasmtime turns a guest trap into an
            // error -- so a join failure is the host panicking or the task being cancelled. Both
            // are aborts as far as the issuance is concerned, and both must fail closed.
            Err(HookError::Declined(format!(
                "the hook task did not complete: {join}"
            )))
        })
}

/// How often the epoch advances.
///
/// EXPORTED, and the server's ticker reads it rather than declaring its own. It was a
/// `from_millis(10)` literal in `ironauth/src/main.rs` and another in the integration harness,
/// and the harness's was 1 ms -- ten times harsher than production. That is not a stricter
/// test, it is a DIFFERENT one, and it made a guest doing microseconds of work fail an issuance
/// on a busy machine while the server it was standing in for would not have.
///
/// A tick interval and a tick COUNT are only a duration together, so they cannot live in
/// separate files and be trusted to agree.
pub const EPOCH_TICK: std::time::Duration = std::time::Duration::from_millis(10);

/// The number of whole epoch ticks a hook is guaranteed, plus the partial one it starts in.
///
/// With [`EPOCH_TICK`] that is a floor of ONE SECOND of wall clock, which
/// `the_epoch_deadline_clears_any_plausible_scheduling_delay` computes rather than restates.
///
/// # Why the bound is sized for the SCHEDULER and not for the work
///
/// A claim-shaping hook does tens of microseconds of work, so a wall-clock bound sized for the
/// work would be a fraction of a millisecond. That was the mistake. FUEL counts executed
/// instructions and is deterministic: the same guest on the same input burns the same fuel on
/// an idle laptop and a saturated server, and `claim_shaping`'s 50M is the real CPU bound. An
/// EPOCH DEADLINE counts ticks of a wall clock, so a guest the scheduler descheduled trips it
/// exactly as a runaway guest does, and wasmtime cannot tell the two apart.
///
/// So this bound has to clear the worst SCHEDULING delay, not the worst work. It was 2 ticks
/// (10 to 20 ms), and review measured what that costs: with 24 spinners on 14 cores, 2 of 6
/// full runs of the hook suite failed with `server_error` from a guest doing microseconds of
/// work. A CI runner with 2 vCPUs, or a host under a traffic spike, is that machine.
///
/// One second cannot be reached by scheduling delay on a machine that is serving requests at
/// all, and it is still a hard stop: fuel already bounds CPU, so what remains for the deadline
/// to catch is a guest that executes without burning fuel, which no shipped hook does. A login
/// tolerates a second far better than it tolerates a random 500.
///
/// # What this is NOT
///
/// A guarantee. It is a bound sized so that tripping it means something is genuinely wrong,
/// rather than that the machine was busy. Making it configurable is the honest end state (the
/// tunability rule: an environment-dependent tradeoff belongs in settings with a safe default),
/// and it is not in this change.
const EPOCH_TICKS_PER_HOOK: u64 = 101;

/// The bounds one invocation runs under.
///
/// `Limits::claim_shaping` with the epoch deadline raised, for the reason on
/// [`EPOCH_TICKS_PER_HOOK`]. Everything else is the shipped preset, which
/// `only_the_deadline_departs_from_the_shipped_preset` pins.
///
/// The delta is at least 2 for a second, arithmetic reason: wasmtime sets the deadline to
/// `current_epoch + delta`, so a store created at an arbitrary point inside a tick gets
/// whatever remains of it. A delta of 1 is therefore uniform in (0, one tick] -- measured
/// against a 10 ms ticker, a hook doing 78 microseconds of work trapped on 0.40% of
/// invocations and one doing 544 microseconds on 4.15%. Any delta of 2 or more guarantees at
/// least `delta - 1` WHOLE ticks, which is a bound rather than a lottery.
///
/// `Limits::claim_shaping`'s own doc says a limit that trips during ordinary work teaches
/// operators to raise it without reading it. A limit that trips at random is worse: there is
/// nothing to read.
fn limits() -> Limits {
    Limits {
        epoch_deadline: EPOCH_TICKS_PER_HOOK,
        ..Limits::claim_shaping()
    }
}

/// Put a hook's returned claims through the protected-claim fence, and log what it refused.
///
/// The refusals are logged rather than returned, because a caller cannot act on them: the token
/// is issued without those claims either way. What an OPERATOR can act on is the log line, which
/// is why it names the claim and the reason.
fn fence(
    returned: &[(String, String)],
    handed: &serde_json::Map<String, serde_json::Value>,
    scope: Scope,
    client_id: &str,
    token: &'static str,
) -> BTreeMap<String, serde_json::Value> {
    // EVERY returned claim is parsed and handed to the fence, and the reason is that truncating
    // here defeats two things `filter_hook_claims` promises. Its doc says "which claims overflow
    // is decided in claim-name order, so it is the same set on every invocation" and "the
    // overflow is refused into `refused` rather than dropped, so the audit records that claims
    // were lost". A `.take()` in wire order keeps whichever 64 the guest happened to emit first,
    // with no log, no refusal, and no count -- so both promises were false while this function
    // claimed to be applying them.
    //
    // The cost of not truncating is bounded by what already happened: `from_wit` in the engine
    // has materialised the whole returned list before this function is called, so the map is
    // the smaller allocation, not the larger one. Bounding the GUEST's output belongs at the
    // ABI boundary where the list is built, and is filed rather than pretended at here.
    //
    // A claim whose value is not JSON is DROPPED rather than refused by name: the fence answers
    // "may a hook write this NAME", and an unparseable value is a different failure with a
    // different reason, counted separately below.
    let mut parsed: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let mut unparseable = 0_usize;
    for (name, value_json) in returned {
        match serde_json::from_str(value_json) {
            Ok(value) => {
                parsed.insert(name.clone(), value);
            }
            Err(_) => unparseable += 1,
        }
    }
    if unparseable > 0 {
        tracing::warn!(
            target: "ironauth.hooks",
            tenant = %scope.tenant(),
            client_id,
            token,
            unparseable,
            "the hook returned claims whose values are not JSON; they are dropped"
        );
    }

    // THE CAP BOUNDS WHAT A HOOK CONTRIBUTES, NOT WHAT THE TOKEN CARRIES, and separating the
    // two is not a refinement -- it is a data-loss bug review found in the round-2 fix.
    //
    // `MAX_HOOK_CLAIMS` is 32 and exists so "a hook returning a hundred thousand claims" cannot
    // fold them all into a token. Under the MERGE this dispatch used to do, the mint's own
    // claims survived that cap because they were never in the hook's output. Under REPLACE they
    // are: the shipped `good` guest ECHOES its input, so a deployment with more than 32 extra
    // claims -- `conform_id_token_claims` plus issue #100 enrichment reaches that -- would
    // deploy the documented well-behaved hook and get a token silently missing everything past
    // the alphabetically-first 32. The issuance would SUCCEED.
    //
    // So the fence sees the DELTA: a claim the hook handed back unchanged is not something it
    // contributed, it is something it kept, and keeping is how a replace contract expresses "do
    // not touch this". What the cap still bounds is exactly what it was written for -- names
    // the hook ADDED or CHANGED.
    let (echoed, contributed): (BTreeMap<_, _>, BTreeMap<_, _>) = parsed
        .into_iter()
        .partition(|(name, value)| handed.get(name) == Some(value));
    let outcome = claims_mapping::filter_hook_claims(&contributed);
    for (name, reason) in &outcome.refused {
        tracing::warn!(
            target: "ironauth.hooks",
            tenant = %scope.tenant(),
            client_id,
            token,
            claim = %name,
            reason = ?reason,
            "the hook tried to write a claim it may not"
        );
    }
    if outcome.refusals_not_reported > 0 {
        tracing::warn!(
            target: "ironauth.hooks",
            tenant = %scope.tenant(),
            client_id,
            token,
            not_reported = outcome.refusals_not_reported,
            "and further refusals were not reported individually"
        );
    }
    // Echoes first, then the accepted contributions, so a hook that both echoes a name and
    // changes it -- which it cannot, since a list has one entry per name after parsing -- could
    // not use the ordering to smuggle anything past the fence.
    let mut kept = echoed;
    kept.extend(outcome.accepted);
    kept
}

/// The wire shape the guest ABI takes: a name and its value as JSON TEXT.
fn as_pairs(claims: &serde_json::Map<String, serde_json::Value>) -> Vec<(String, String)> {
    claims
        .iter()
        .map(|(name, value)| (name.clone(), value.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{PAYLOAD_VERSION, limits, loaded_hook};

    /// The epoch deadline is at least TWO ticks, and the reason is arithmetic.
    ///
    /// wasmtime sets `deadline = current_epoch + delta`, and a store is created at an arbitrary
    /// point inside a tick, so `delta = 1` grants whatever remains of the current one -- uniform
    /// in (0, T]. Measured against a 10 ms ticker: a hook doing 78 microseconds of work trapped
    /// on 0.40% of invocations and one doing 544 microseconds on 4.15%. Every abort fails the
    /// issuance, so that is a random `server_error` on roughly one hooked login in a hundred.
    ///
    /// `delta = 2` guarantees at least one WHOLE tick, so the bound becomes [T, 2T].
    ///
    /// # Why this is a unit test and not an integration one
    ///
    /// The behavioural difference cannot be made deterministic. `delta = 1` traps only when the
    /// remaining slice is shorter than the work, so a guest that ALWAYS trips it needs work
    /// longer than a whole tick -- and that work also trips `delta = 2`. There is no guest that
    /// distinguishes the two every time, which is the finding restated: at `delta = 1` the bound
    /// is a lottery, and a lottery is exactly what a test cannot pin.
    ///
    /// So the pin is on the value, and it stops a silent revert. What it cannot do is notice
    /// somebody removing the ticker, which is why the harness now runs one.
    #[test]
    fn the_epoch_deadline_clears_any_plausible_scheduling_delay() {
        // COMPUTED from the tick interval, not restated. A test asserting `== 101` would pass
        // for any tick length, including a 1 ms one that puts the guarantee back at 100 ms.
        let guaranteed = super::EPOCH_TICK
            * u32::try_from(limits().epoch_deadline - 1).expect("the deadline fits a u32 of ticks");
        assert!(
            guaranteed >= std::time::Duration::from_secs(1),
            "a hook is guaranteed {guaranteed:?}, which is not enough to survive a scheduler \
             that descheduled it. The deadline bounds WALL time while fuel bounds CPU, so this \
             number has to clear the worst scheduling delay and not the worst work: review \
             measured 2 of 6 suite runs failing with `server_error` at a 20 ms ceiling under \
             24 spinners on 14 cores."
        );
        assert!(
            limits().epoch_deadline >= 2,
            "a deadline of one tick is whatever remains of the current one, which fails a \
             fraction of ordinary logins at random"
        );
    }

    /// The dispatch's limits are `claim_shaping`'s EXCEPT the deadline.
    ///
    /// Without this the assertion above passes for a `limits()` that invented every bound from
    /// nothing -- fuel, memory and the host-resource cap included -- which would silently
    /// unbound the three things the sandbox suite is written against.
    #[test]
    fn only_the_deadline_departs_from_the_shipped_preset() {
        let shipped = ironauth_hooks::Limits::claim_shaping();
        let ours = limits();
        assert_eq!(ours.fuel, shipped.fuel);
        assert_eq!(ours.memory_bytes, shipped.memory_bytes);
        assert_eq!(ours.max_host_resources, shipped.max_host_resources);
        assert_ne!(
            ours.epoch_deadline, shipped.epoch_deadline,
            "and the deadline DOES depart, or the reason above has been reverted"
        );
    }

    /// The payload version this server emits is the one the table admits.
    ///
    /// THREE artifacts declare the version and only two of the three can be tied by code.
    ///
    /// `TOKEN_CUSTOMIZE_VERSION` (the schema registry) and `PAYLOAD_VERSION` (what this
    /// dispatch emits) are now ONE constant, because the second is an alias of the first. That
    /// pair cannot drift.
    ///
    /// The third is `token_hooks_payload_version_known` in migration 0162, which is SQL text in
    /// a file that is frozen once shipped, so it cannot be an alias of anything. This is the
    /// tie for it, and it is a text scan for that reason. A migration admitting 2 while the
    /// server emits 1 would let a hook be deployed that the dispatch then refuses at every
    /// login.
    #[test]
    fn the_emitted_payload_version_is_the_one_the_table_admits() {
        let migration = include_str!("../../ironauth-store/migrations/0162_token_hooks.sql");
        assert!(
            migration.contains(&format!("payload_version = {PAYLOAD_VERSION}")),
            "migration 0162 must admit exactly the version this server emits"
        );
    }

    /// COMPILING A HOOK MUST NOT RUN ON THE REACTOR, and this measures it rather than saying it.
    ///
    /// `Component::new` is cranelift: 33 ms of pure CPU on the release build, and seconds on a
    /// debug one. Run inline on an async task it holds a runtime worker for that whole time, so
    /// every other request assigned to that worker waits -- one client's first login after a
    /// deploy stalling other tenants' logins, which is the thing `spawn_blocking` exists to stop.
    ///
    /// Nothing pinned it: the 12 integration tests all pass with the `spawn_blocking` removed,
    /// because a multi-worker runtime with an idle worker beside it looks identical from the
    /// outside.
    ///
    /// # Why a CURRENT-THREAD runtime is the discriminator
    ///
    /// It has exactly ONE task-running thread, so "held the reactor" and "nothing else ran" are
    /// the same statement, and it needs no timing margin to tell them apart: an inline compile
    /// leaves the ticker below at ZERO. `spawn_blocking` moves the work to the blocking pool,
    /// which is a different thread on any flavor, so the reactor keeps driving the timer.
    ///
    /// The assertion is `> 0` and not a tick count, because the count is a function of how slow
    /// the compile is on this machine and that is not what is being pinned.
    #[test]
    fn compiling_a_hook_does_not_hold_the_reactor() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime");

        runtime.block_on(async {
            let ticks = std::sync::Arc::new(AtomicU64::new(0));
            let counting = std::sync::Arc::clone(&ticks);
            let ticker = tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    counting.fetch_add(1, Ordering::Relaxed);
                }
            });
            // Let the ticker reach its first await, so a zero below means blocked and not
            // never-scheduled.
            tokio::task::yield_now().await;

            let engine =
                std::sync::Arc::new(ironauth_hooks::HookEngine::new().expect("build the engine"));
            let cache: std::sync::Arc<super::HookCache> =
                std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
            let scope = ironauth_store::Scope::new(
                ironauth_store::TenantId::from_seed_bytes([7_u8; 16]),
                ironauth_store::EnvironmentId::from_seed_bytes([9_u8; 16]),
            );

            loaded_hook(
                &engine,
                &cache,
                scope,
                "a-client",
                ironauth_hooks::fixtures::GOOD,
            )
            .await
            .expect("the shipped fixture compiles");

            let observed = ticks.load(Ordering::Relaxed);
            ticker.abort();
            assert!(
                observed > 0,
                "the reactor drove another task while the hook compiled; zero means the compile \
                 ran inline on the only thread this runtime has, which is a stall every other \
                 request on that worker pays"
            );
        });
    }
}
