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
//! # It is not on a tokio worker
//!
//! `LoadedHook::customize` blocks, and wasmtime's `in_tokio` PANICS on a tokio worker thread.
//! Measured on this runtime: the same hook that returns in 1.16 ms under `spawn_blocking` panics
//! when called directly. So the invocation goes through `spawn_blocking`, which also keeps a
//! hook that spins for its whole fuel budget off the reactor.

use std::collections::BTreeMap;
use std::sync::Arc;

use ironauth_hooks::{HookEngine, HookError, Limits, Request};
use ironauth_store::{Scope, Store};

use crate::claims_mapping::{self, MAX_HOOK_CLAIMS};

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
pub const PAYLOAD_VERSION: u32 = 1;

/// A compiled hook, ready to invoke.
///
/// Held so a caller can compile once and invoke many times. Compilation is the expensive half --
/// the benchmark in `ironauth-hooks` measures the split -- and doing it per issuance would put
/// the whole cost on every login rather than on deploy.
pub struct CompiledHook {
    engine: Arc<HookEngine>,
    artifact: Arc<Vec<u8>>,
    payload_version: u32,
}

impl std::fmt::Debug for CompiledHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledHook")
            .field("artifact_bytes", &self.artifact.len())
            .field("payload_version", &self.payload_version)
            .finish_non_exhaustive()
    }
}

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
    engine: &Arc<HookEngine>,
    invocation: &Invocation<'_>,
) -> Result<Option<HookClaims>, HookFault> {
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

    let compiled = compile(engine, &record.component).map_err(|error| {
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

    let customization = invoke(compiled, request).await.map_err(|error| {
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
        id_token: fence(&customization.id_token_claims, scope, client_id, "id_token"),
        access_token: fence(
            &customization.access_token_claims,
            scope,
            client_id,
            "access_token",
        ),
    }))
}

/// Compile a stored component into something invocable.
///
/// Separate so the expensive half is nameable: a caller that wants to compile at deploy time
/// rather than at issuance calls this and holds the result.
fn compile(engine: &Arc<HookEngine>, component: &[u8]) -> Result<CompiledHook, HookError> {
    Ok(CompiledHook {
        engine: Arc::clone(engine),
        artifact: Arc::new(engine.compile(component)?),
        payload_version: PAYLOAD_VERSION,
    })
}

/// Run the hook OFF the reactor.
///
/// `spawn_blocking` for two reasons, and the first is not tuning: `LoadedHook::customize` reaches
/// wasmtime's `in_tokio`, which PANICS on a tokio worker thread. The second is that a hook is
/// permitted to spin for its entire fuel budget, and that belongs on a blocking pool rather than
/// on a reactor thread other requests are waiting on.
async fn invoke(
    compiled: CompiledHook,
    request: Request,
) -> Result<ironauth_hooks::Customization, HookError> {
    tokio::task::spawn_blocking(move || {
        // SAFETY: `artifact` is the output of `engine.compile` on THIS engine, in this process,
        // moments ago -- `compile` above produced both together and neither has left this
        // function. That is exactly the provenance `load_precompiled` requires, and it is why
        // the durable form in `token_hooks` is the portable component rather than this.
        #[expect(
            unsafe_code,
            reason = "the artifact was produced by the same engine in this process; see above"
        )]
        let hook = unsafe { compiled.engine.load_precompiled(&compiled.artifact) }?;
        hook.customize(&compiled.engine, &Limits::claim_shaping(), &request)
    })
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

/// Put a hook's returned claims through the protected-claim fence, and log what it refused.
///
/// The refusals are logged rather than returned, because a caller cannot act on them: the token
/// is issued without those claims either way. What an OPERATOR can act on is the log line, which
/// is why it names the claim and the reason.
fn fence(
    returned: &[(String, String)],
    scope: Scope,
    client_id: &str,
    token: &'static str,
) -> BTreeMap<String, serde_json::Value> {
    // Parsed here, and a claim whose value is not JSON is DROPPED rather than refused by name:
    // the fence answers "may a hook write this NAME", and an unparseable value is a different
    // failure. Bounded by the same `MAX_HOOK_CLAIMS` the fence applies, so a hook returning a
    // million claims does not build a million-entry map before the fence sees it.
    let mut parsed: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let mut unparseable = 0_usize;
    for (name, value_json) in returned.iter().take(MAX_HOOK_CLAIMS.saturating_mul(2)) {
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

    let outcome = claims_mapping::filter_hook_claims(&parsed);
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
    outcome.accepted
}

/// The wire shape the guest ABI takes: a name and its value as JSON TEXT.
fn as_pairs(claims: &serde_json::Map<String, serde_json::Value>) -> Vec<(String, String)> {
    claims
        .iter()
        .map(|(name, value)| (name.clone(), value.to_string()))
        .collect()
}
