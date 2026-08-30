// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deployed WASM token hooks (issue #114).
//!
//! The persistence shape only. What a hook DOES lives in `ironauth-hooks`, which this crate
//! cannot depend on and does not need to: from here a hook is bytes and a version number.
//!
//! # Why the component travels as bytes rather than a precompiled artifact
//!
//! `HookEngine::compile` produces machine code for the exact engine, wasmtime version, CPU
//! features and flags that produced it, and `load_precompiled` is `unsafe` because nothing
//! checks that. A precompiled artifact in a shared database is a portability hazard with a
//! memory-safety failure mode: a replica on a different CPU deserializes machine code built for
//! something else. So the durable form is the portable one, and each process compiles what it
//! loads.

/// What the dispatch does when a client's hook does not complete (issue #114 criterion 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookFailurePolicy {
    /// A hook that does not complete REFUSES the issuance. The default, and the only safe
    /// answer when nobody has told the server what the hook is for.
    ///
    /// A hook's answer REPLACES the claim set rather than merging into it, so a hook deployed
    /// to STRIP a claim actually strips it. Ignoring one that failed therefore issues MORE
    /// than the operator deployed -- a token carrying the claim they removed -- which is why
    /// this is the default rather than the graceful-sounding alternative.
    FailClosed,
    /// A hook that does not complete is SKIPPED, and the token is minted without its
    /// contribution.
    ///
    /// Correct only where the operator knows their hook only ADDS claims, which is a fact
    /// about their deployment that this server cannot check. Opt in per client.
    FailOpen,
}

impl HookFailurePolicy {
    /// The stored spelling, which is also the wire spelling on the management API.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::FailOpen => "fail_open",
        }
    }

    /// Parse a stored or wire spelling.
    ///
    /// Returns `None` for anything else rather than defaulting: a row naming an unknown policy
    /// is one no dispatch can honour, and silently reading it as fail-closed would hide a
    /// migration or an API that had started writing a third value.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "fail_closed" => Some(Self::FailClosed),
            "fail_open" => Some(Self::FailOpen),
            _ => None,
        }
    }
}

/// One deployed hook: the component, and the payload version its guest was built against.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenHookRecord {
    /// The OAuth client whose tokens this hook shapes.
    ///
    /// NOT unique per scope any more, and the doc used to say it was. Since migration 0168 a
    /// client may hold several hooks, so the identity is `(scope, client_id, name)` and this
    /// field alone no longer picks out a row.
    pub client_id: String,
    /// WHICH of the client's hooks this is, and the handle an admin route addresses.
    ///
    /// Every hook that existed before ordering is `DEFAULT_HOOK_NAME`, which is what migration
    /// 0167 backfilled them to.
    pub name: String,
    /// WHERE in the client's chain this hook runs, ascending, or [`None`] for a record that
    /// has no position.
    ///
    /// Unique per client, so the order is total: two hooks at one position have no order
    /// between them, and a chain that ran them would produce a token depending on which row
    /// came back first.
    ///
    /// OPTIONAL BECAUSE A HISTORICAL VERSION HAS NO POSITION. This type carries both the ACTIVE
    /// row and a row read out of the version history, and position is a property of the current
    /// arrangement rather than of an archived component: version 3 of a hook was at whatever
    /// position the hook occupied then, which nothing records and nothing needs. An earlier
    /// draft made this a plain `i32` filled from `try_get(..).unwrap_or(0)`, which is the same
    /// shape as a silent default -- a historical version would have read as "runs first", and a
    /// query that forgot to project the column would have collapsed a whole client's order to
    /// position zero without failing.
    pub ordinal: Option<i32>,
    /// The WASM component.
    pub component: Vec<u8>,
    /// The payload version the guest expects (issue #113 criterion 6).
    pub payload_version: i32,
    /// What the dispatch does when this hook does not complete.
    pub failure_policy: HookFailurePolicy,
    /// The environment secrets this hook has been GRANTED, by name (issue #114 criterion 5).
    ///
    /// NAMES ONLY. The values stay sealed in `environment_secrets` and the dispatch resolves
    /// them just before the guest runs; carrying them here would put a secret in every log line
    /// that formats a record.
    ///
    /// EMPTY ON A HISTORICAL VERSION, and not because it is unknown: a grant belongs to the
    /// deployed HOOK rather than to a version of its code, so version 3 of a hook has no grants
    /// of its own to report. It is a `Vec` rather than an `Option` because the two cases a
    /// caller must tell apart are "granted nothing" and "granted these", and both are lists --
    /// an `Option` would add a third state nothing means.
    ///
    /// FILLED BY THE CHAIN READ, in the same statement, which is the point: resolving grants
    /// with a query per hook would add a database round trip to every issuance that runs a
    /// hook, including the overwhelming majority that are granted nothing.
    pub granted_secrets: Vec<String>,
}

/// WHERE a deploy puts a hook in its client's chain: which hook it is, and in what position.
///
/// A pair rather than two parameters, and the reason is the one `Invocation`'s doc gives one
/// layer down: `name` is a `&str` and so is the client id already in that signature, so a
/// positional call with two of them swapped compiles. It also keeps the two halves of one
/// decision together -- a caller that supplies a name has to say where it goes.
#[derive(Debug, Clone, Copy)]
pub struct HookPlacement<'a> {
    /// The hook's stable handle, unique per client.
    pub name: &'a str,
    /// Its position in the chain, unique per client and ascending.
    pub ordinal: i32,
}

impl HookPlacement<'_> {
    /// The one hook a client had before ordering existed: `default`, first.
    ///
    /// What the pre-ordering deploy path means, spelled out. Migration 0167 backfilled every
    /// existing row to exactly this, so a deploy through the unnamed path keeps addressing the
    /// row it always addressed.
    #[must_use]
    pub const fn default_hook() -> Self {
        Self {
            name: crate::repository::DEFAULT_HOOK_NAME,
            ordinal: 0,
        }
    }
}

/// WHAT a deploy installs: the component, the contract it was built against, what to do when it
/// fails, and where it goes.
///
/// A struct rather than four more parameters, and the arity lint is the symptom rather than the
/// reason. `component` and the numbers travel together on every call and mean nothing apart --
/// a component without its payload version is bytes nobody can invoke -- and bundling them is
/// the same argument [`HookPlacement`] makes for its own two halves.
#[derive(Debug, Clone, Copy)]
pub struct HookDeployment<'a> {
    /// The WASM component to install.
    pub component: &'a [u8],
    /// The `token.customize` payload version the guest was built against (issue #113
    /// criterion 6).
    pub payload_version: i32,
    /// What the dispatch does when this hook does not complete.
    pub failure_policy: HookFailurePolicy,
    /// Which hook this is and where in the chain it runs.
    pub placement: HookPlacement<'a>,
}

/// Hand-written, and the component is rendered as a LENGTH.
///
/// A derived `Debug` would put megabytes of WASM into any log line that formats a record, and
/// the bytes are the one field nobody reading a log wants. What a reader needs is which client,
/// which version, and whether the component is the size they deployed.
impl std::fmt::Debug for TokenHookRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenHookRecord")
            .field("client_id", &self.client_id)
            // WHICH hook and WHERE it runs, both of which a log line about a chain needs: two
            // records for one client are otherwise indistinguishable in the output.
            .field("name", &self.name)
            .field("ordinal", &self.ordinal)
            // THE GRANTED NAMES, never a value: the values are not on this type at all, and
            // this field is the list of what the hook MAY read. A log line that formats a
            // record therefore says which secrets are in play without saying what they hold.
            .field("granted_secrets", &self.granted_secrets)
            .field("component_bytes", &self.component.len())
            .field("payload_version", &self.payload_version)
            .field("failure_policy", &self.failure_policy)
            .finish()
    }
}

/// A deployed hook's metadata, without the component (issue #114).
///
/// The management read reports a LENGTH, so it reads a length: `TokenHookRecord` carries up to
/// sixteen megabytes that this surface would immediately discard -- and that is the bound after
/// #114 criterion 1 doubled it, because the shipped TypeScript hook is over ten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenHookMetadata {
    /// The OAuth client whose tokens this hook shapes.
    pub client_id: String,
    /// WHICH of the client's hooks this is: the handle the admin surface addresses.
    pub name: String,
    /// WHERE in the client's chain it runs, ascending.
    pub ordinal: i32,
    /// How many bytes the deployed component is.
    pub component_bytes: i32,
    /// The payload version the guest expects.
    pub payload_version: i32,
    /// What the dispatch does when this hook does not complete.
    pub failure_policy: HookFailurePolicy,
}

/// One historical deploy of a client's hook (issue #114 criterion 5).
///
/// METADATA, never the component. A version list answers "what did I deploy and when", which a
/// length and a timestamp answer; returning the bytes would make listing five versions a
/// forty-megabyte response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenHookVersion {
    /// Monotonic per client, starting at 1.
    pub version: i32,
    /// How many bytes that deploy's component was.
    pub component_bytes: i32,
    /// The payload version its guest was built against.
    pub payload_version: i32,
    /// The failure policy it was deployed with.
    pub failure_policy: HookFailurePolicy,
    /// When it was deployed, as epoch microseconds.
    pub created_at_unix_micros: i64,
}
