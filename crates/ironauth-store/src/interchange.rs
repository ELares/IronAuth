// SPDX-License-Identifier: MIT OR Apache-2.0

//! The signed journey interchange archive (issue #347): the `.iaj` bundle that carries a journey
//! artifact, its sub-flows, and a safety manifest across an ORGANIZATION boundary, plus the
//! import gate that decides whether the importing environment will run it.
//!
//! This is a PURE value module, exactly like [`crate::flow_version`]: no SQL, no entropy, and no
//! I/O. Time enters only as the [`Clock`] the JOSE verifier evaluates `exp` and `iat` against,
//! through the determinism seam. Those two and no others: `PAYLOAD_MEMBERS` admits exactly seven
//! members and `nbf` is not one of them, so an archive can never carry a not-before claim for the
//! verifier to evaluate, however general the verifier itself is.
//!
//! ## The one thing that makes this real: the manifest is a CHECKED CLAIM
//!
//! The exporter is the UNTRUSTED party. Cross-organization sharing means the bundle arrives from
//! someone the importer does not control, so a manifest that the importer BELIEVED would be
//! decoration: a bundle that simply under-declared its `required_capabilities` would walk straight
//! past the capability check and the whole feature would be theatre.
//!
//! So the importer never reads a capability out of the manifest and acts on it. It RE-DERIVES the
//! capability set from the artifact and its sub-flows ([`derive_capabilities`]) and then:
//!
//! 1. compares the DERIVED set against the manifest's declaration, refusing an under-declaring
//!    manifest with [`InterchangeError::CapabilityUnderDeclared`] and an over-declaring one with
//!    [`InterchangeError::CapabilityOverDeclared`]; and
//! 2. checks the DERIVED set (never the declared one) against what the importing environment has
//!    granted, refusing with [`InterchangeError::CapabilityNotGranted`].
//!
//! Step 2 is the security gate and it does not consult the manifest at all, so even a manifest
//! check that was deleted tomorrow could not admit an ungranted capability. Step 1 exists so the
//! operator reading the manifest before granting is reading the truth.
//!
//! That second sentence is MEASURED, and it takes a specific test shape to measure it at all.
//! Step 1 enforces two-sided set equality, so by the time step 2 runs the derived set and the
//! declared set are always the same value and a step 2 that read the declaration would behave
//! identically. The acceptance case
//! `a_capability_that_is_both_under_declared_and_ungranted_is_refused_by_either_check_alone`
//! breaks that tie: one capability is neither declared nor granted, and the case asserts only that
//! the import is REFUSED without pinning the variant, so it stays green when step 1 is deleted and
//! fails only when step 2 is ALSO made to read the manifest. Pinning the error variant there would
//! destroy the property, which is why it does not.
//!
//! Over-declaration is refused as well, and that is a judgement worth stating. It is not a
//! security hole: an over-declaring manifest asks for MORE than the artifact needs, so the grant
//! check can only get stricter. It is refused because the manifest is the human-facing safety
//! summary an operator reads to decide what to grant, and a manifest naming capabilities the
//! artifact never exercises inflates that decision. Requiring exact equality also makes the
//! manifest a deterministic function of the payload, so [`export_archive`] is reproducible and a
//! mismatch is reported as a precise, two-sided diff. The two failures carry DIFFERENT errors, so
//! the security-relevant direction is never confused with the integrity-relevant one.
//!
//! ## Why the verified bytes and the parsed bytes cannot diverge
//!
//! Signing "the canonical bytes" of a JSON structure is a classic signature-bypass surface: if
//! the bytes that were verified are one derivation and the object that is acted on is another,
//! any disagreement between the two is the attack. This module forecloses that by construction
//! rather than by agreement:
//!
//! - The archive is the RFC 7515 section 7.2.2 FLATTENED JWS JSON serialization,
//!   `{protected, payload, signature}`, three base64url strings and nothing else
//!   (`deny_unknown_fields`, so a fourth member is a refusal, not something ignored).
//! - Import joins those three RECEIVED strings with `.` into the compact form and hands it to
//!   [`ironauth_jose::verify`], the crate's single verification choke point. The signing input is
//!   therefore literally the received bytes.
//! - [`ironauth_jose::verify`] decodes the payload segment ONCE, after the signature check, and
//!   parses it. The artifact, the sub-flows, and the manifest are read out of THAT parse. There is
//!   no second byte-level parse anywhere on the import path, so there is nothing for a second
//!   reading to disagree with, whatever the parse decided.
//!
//! ## How far the duplicate-key rejection reaches, MEASURED
//!
//! `ironauth-jose`'s parser rejects a duplicate key, and it is worth being exact about where,
//! because "parsed with a duplicate-key-rejecting parser" overstates it. Measured by
//! `a_duplicate_key_is_refused_at_the_container_and_the_payload_top_level_but_not_below_it`:
//!
//! - a duplicate member in the CONTAINER is refused ([`InterchangeError::ArchiveMalformed`]);
//! - a duplicate TOP-LEVEL payload key is refused (uniformly, as a verification failure, since
//!   `parse_unique_object` runs inside the verifier); but
//! - a duplicate key NESTED inside `artifact` is ACCEPTED, last value winning, because
//!   `parse_unique_object` (`ironauth-jose/src/json.rs`) enforces uniqueness only in its own
//!   `visit_map` and every object below the top level is an ordinary `serde_json::Value`.
//!
//! That last one is NOT a signature bypass, and the reason is the bullet above: there is one parse
//! and `project` reads that same tree, so the value checked is the value acted on. The residual
//! exposure is narrower: a signed `.iaj` carrying such a duplicate is AMBIGUOUS to a THIRD-PARTY
//! inspector, which may read the first value where IronAuth reads the last. Making the parse
//! recurse would change how every token in the system is parsed, which is out of proportion to
//! that, so the limitation is recorded and locked by the test rather than closed here.
//! - Import never canonicalizes. Canonicalization is an EXPORT-side determinism property only
//!   ([`export_archive`] reuses [`crate::snapshot`]'s one canonical JSON writer). Re-canonicalizing
//!   at import and comparing would reintroduce exactly the second derivation this design removes.
//!
//! ## What is enforced and what is refused rather than ignored
//!
//! [`LaunchConstraints`] mixes checkable and declared facts, and each is handled explicitly:
//!
//! - `min_engine_version` is DERIVED from the artifact and checked for equality against the
//!   declaration, then checked against [`ironauth_journey::JOURNEY_ENGINE_VERSION`].
//! - `requires_sandbox` is a PROJECTION of the derived capability set (whether it contains
//!   [`FixedCapability::DECISION_SANDBOX`]) and is checked for equality against the declaration.
//!   The engine withholds that capability today, so a bundle that needs the M11 decision sandbox
//!   is refused at load until M11 grants it.
//! - `allowed_transports` is NOT derivable: it is author intent about where the journey may be
//!   launched. It is ENFORCED rather than ignored, in the only direction that fails closed: every
//!   transport the importing environment OFFERS must appear in the allowed set, because nothing in
//!   the engine can pin a stored journey to a subset of an environment's transports, so an
//!   environment that would serve the journey over a transport the author excluded cannot honor
//!   the constraint and refuses the import instead. An environment offering NOTHING would satisfy
//!   that universally quantified rule for free, so it is refused with
//!   [`InterchangeError::EnvironmentServesNoTransport`] rather than passing vacuously.
//!
//! ## Trust
//!
//! [`import_archive`] takes the [`TrustedExporter`] as an ARGUMENT. Nothing in the archive selects
//! a key: there is no `jku`, no bundle-named JWKS URL, and no key material in the payload, so the
//! importer never fetches anything an attacker names and the SSRF surface of this path is empty by
//! construction. The operator's act of naming the exporter IS the trust decision, and the
//! verification then pins the exporter's issuer exactly.
//!
//! What does NOT exist yet is a HOME for that decision. See [`TrustedExporter`] for the measured
//! gap.

use std::collections::BTreeSet;
use std::fmt;
use std::fmt::Write as _;

use ironauth_env::Clock;
use ironauth_jose::{
    EmissionOptions, ExpectedTyp, JwsAlgorithm, RejectReason, SigningKey, TokenTyp, TrustedKey,
    VerificationCaps, VerificationPolicy, sign_jws, trusted_keys_from_jwks, verify,
};
use ironauth_journey::{
    CmpOp, CompiledJourney, DecisionSpec, FieldSource, JOURNEY_ENGINE_VERSION, Journey,
    JourneyError, Literal, MemberSet, NODE_GROUPS, Predicate, Step, StepKind, Subflow, SubflowRef,
    SubflowSource, Transition, builtin_subflows, compile,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The `aud` every interchange archive carries.
///
/// An archive is a BROADCAST artifact: the exporter signs it once and does not know which
/// organizations will import it, so there is no single intended recipient to name. The audience
/// therefore names the interchange PROFILE rather than a recipient. Recipient-specific trust is
/// carried by the two things that actually bind the relationship: the operator's decision to trust
/// this exporter at all, and the exact issuer pin that decision comes with. Making `aud` the
/// importer's own issuer instead would turn every archive into a point-to-point message and defeat
/// the cross-organization sharing this exists for.
pub const INTERCHANGE_AUDIENCE: &str = "urn:ironauth:journey-interchange";

/// The largest `.iaj` archive document [`import_archive`] will look at, checked BEFORE the JSON
/// parse so a hostile archive cannot force a large parse. Generous for any real journey (the
/// composed-step ceiling is [`ironauth_journey::MAX_COMPOSED_STEPS`]) and far below anything that
/// could be a memory problem.
pub const MAX_ARCHIVE_BYTES: usize = 1 << 20;

/// The largest DECODED payload the JOSE caps admit for an archive.
///
/// The JOSE defaults ([`VerificationCaps::DEFAULT`]) bound a payload at 16 KiB, which is right for
/// a token and far too small for a document: a journey artifact with its sub-flows is routinely
/// larger. This raises exactly that one cap, and nothing else: the structural rejections (no
/// `alg: none`, no embedded key material, no `crit`, no compression, no PBES2) are not numbers and
/// are unaffected.
const MAX_PAYLOAD_BYTES: usize = 512 * 1024;

/// The exact set of top-level payload members an archive may carry.
///
/// An archive whose payload carries any other member, or omits one of these, is refused. That
/// forecloses a bundle carrying a second copy of something the importer does not read, and it
/// means a member a NEWER importer would honor cannot be silently ignored by this one.
const PAYLOAD_MEMBERS: [&str; 7] = [
    "artifact", "aud", "exp", "iat", "iss", "manifest", "subflows",
];

// ---------------------------------------------------------------------------
// The capability vocabulary
// ---------------------------------------------------------------------------

// The vocabulary lives in a PRIVATE submodule, and the walkers below deliberately do NOT.
//
// `FixedCapability`'s fields are private, but Rust privacy is per MODULE, not per type, so while
// the struct and the walkers shared one module every walker could construct one. That was measured:
// `Capability::fixed(FixedCapability { wire: "forged.by.a.walker", engine_grants: true })` inside
// `walk_predicate` COMPILED CLEANLY, which made "a walker cannot sidestep the list by writing a
// bare string literal" a claim the compiler was not enforcing. Putting the declaration one module
// down puts every walker OUTSIDE its privacy scope, so the same line is now an E0451 private-field
// error and the sentence is true of the compiler rather than of the reader.
mod vocabulary {
    /// Map the grant word a [`fixed_capabilities`] entry must spell to its boolean.
    ///
    /// Only these two words match, so a new entry cannot omit the decision or spell it approximately:
    /// anything else is a macro expansion error.
    macro_rules! grant_flag {
        (ENGINE_GRANTS) => {
            true
        };
        (ENGINE_WITHHOLDS) => {
            false
        };
    }

    /// Declare the FIXED capability vocabulary ONCE: the constant, its documentation, its wire token,
    /// and whether the engine as shipped grants it.
    ///
    /// From that one list this generates the [`FixedCapability`] constants and
    /// [`FixedCapability::ALL`], whose length is COUNTED from the same list.
    ///
    /// This is the `ironauth_jose`'s `token_profiles!` pattern applied to the capability vocabulary,
    /// and it is here for the same reason. A hand-written list beside a structural source is the
    /// defect this whole feature exists to avoid, so the deriver must not have one. The walkers below
    /// match EXHAUSTIVELY on the journey crate's [`Predicate`], [`CmpOp`], [`FieldSource`],
    /// [`MemberSet`], [`Literal`], and [`DecisionSpec`] enums, so a new variant in the journey format
    /// stops this file compiling until it names a capability; the only way to name one is a constant
    /// generated here; and the only way to generate one is to add an entry to this list, which also
    /// puts it in `ALL` and forces the grant decision to be written down. There is therefore no
    /// reachable state in which a feature is exercisable but invisible to the deriver, and none in
    /// which a new feature is granted by default because someone forgot to think about it.
    ///
    /// [`FixedCapability`]'s fields are private and it has no constructor, and this declaration
    /// sits in a submodule the walkers are OUTSIDE of, so no code that derives a capability can
    /// sidestep the list by writing a bare string literal: it is an E0451 private-field error, not
    /// a convention. Rust privacy is per MODULE rather than per type, so the submodule is what
    /// makes that true; while the struct and the walkers shared one module a forged literal
    /// compiled cleanly.
    macro_rules! fixed_capabilities {
        ($( $(#[$doc:meta])* $name:ident => $wire:literal, $grant:ident );+ $(;)?) => {
            /// One capability from the CLOSED vocabulary, as opposed to the open-ended ones whose name
            /// carries a document-supplied identifier (a step kind, a node group, a built-in subflow
            /// name).
            ///
            /// Generated by the `fixed_capabilities!` declaration list. The fields are private and
            /// there is no constructor, so every value of this type came from that list.
            #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
            pub struct FixedCapability {
                wire: &'static str,
                engine_grants: bool,
            }

            impl FixedCapability {
                $( $(#[$doc])* pub const $name: FixedCapability = FixedCapability {
                    wire: $wire,
                    engine_grants: grant_flag!($grant),
                }; )+

                /// EVERY fixed capability, generated from the same declaration list as the constants,
                /// so this array cannot fall behind them.
                pub const ALL: [FixedCapability; 0 $( + { let _ = stringify!($name); 1 } )+] =
                    [ $( FixedCapability::$name, )+ ];

                /// The wire token this capability appears as in a manifest.
                #[must_use]
                pub const fn as_wire(self) -> &'static str {
                    self.wire
                }

                /// Whether the engine AS SHIPPED grants this capability, the value
                /// [`super::GrantedCapabilities::engine_default`] reads.
                ///
                /// Declared per entry rather than computed as "everything except a short deny list",
                /// because a deny list gets the failure direction backwards: a capability added to the
                /// vocabulary and forgotten would be granted by default. Here forgetting is impossible,
                /// because the declaration does not parse without the word.
                #[must_use]
                pub const fn engine_grants(self) -> bool {
                    self.engine_grants
                }
            }
        };
    }

    fixed_capabilities! {
        /// A comparison of a field against a literal ([`ironauth_journey::Predicate::Cmp`]).
        PREDICATE_CMP => "predicate.cmp", ENGINE_GRANTS;
        /// A closed-set membership test over literals ([`ironauth_journey::Predicate::In`]).
        PREDICATE_IN => "predicate.in", ENGINE_GRANTS;
        /// A subject group or scope membership test ([`ironauth_journey::Predicate::Member`]).
        ///
        /// WITHHELD, and MEASURED rather than assumed. `typecheck_member`
        /// (`crates/ironauth-journey/src/eval.rs:845`) requires a `member` predicate's field to read
        /// `subject_groups` or `subject_scopes`, and `source_is_engine_live` (`eval.rs:590`) marks BOTH
        /// of those NOT-LIVE, so the shipped engine refuses every `member` predicate at load. Granting
        /// it here would be a grant for something no artifact can reach: the honest state is withheld,
        /// and it flips to granted in the same edit that lights the sources up.
        PREDICATE_MEMBER => "predicate.member", ENGINE_WITHHOLDS;
        /// A conjunction ([`ironauth_journey::Predicate::And`]).
        PREDICATE_AND => "predicate.and", ENGINE_GRANTS;
        /// A disjunction ([`ironauth_journey::Predicate::Or`]).
        PREDICATE_OR => "predicate.or", ENGINE_GRANTS;
        /// A negation ([`ironauth_journey::Predicate::Not`]).
        PREDICATE_NOT => "predicate.not", ENGINE_GRANTS;
        /// The constant true predicate ([`ironauth_journey::Predicate::Always`]).
        PREDICATE_ALWAYS => "predicate.always", ENGINE_GRANTS;
        /// The constant false predicate ([`ironauth_journey::Predicate::Never`]).
        PREDICATE_NEVER => "predicate.never", ENGINE_GRANTS;

        /// The equality comparison operator ([`ironauth_journey::CmpOp::Eq`]).
        OP_EQ => "predicate.op.eq", ENGINE_GRANTS;
        /// The inequality comparison operator ([`ironauth_journey::CmpOp::Ne`]).
        OP_NE => "predicate.op.ne", ENGINE_GRANTS;
        /// The less-than comparison operator ([`ironauth_journey::CmpOp::Lt`]).
        OP_LT => "predicate.op.lt", ENGINE_GRANTS;
        /// The less-or-equal comparison operator ([`ironauth_journey::CmpOp::Le`]).
        OP_LE => "predicate.op.le", ENGINE_GRANTS;
        /// The greater-than comparison operator ([`ironauth_journey::CmpOp::Gt`]).
        OP_GT => "predicate.op.gt", ENGINE_GRANTS;
        /// The greater-or-equal comparison operator ([`ironauth_journey::CmpOp::Ge`]).
        OP_GE => "predicate.op.ge", ENGINE_GRANTS;

        /// Reads flow-local state ([`ironauth_journey::FieldSource::Flow`]).
        FIELD_FLOW => "predicate.field.flow", ENGINE_GRANTS;
        /// Reads step outcome signals ([`ironauth_journey::FieldSource::Signals`]).
        FIELD_SIGNALS => "predicate.field.signals", ENGINE_GRANTS;
        /// Reads the subject's sealed identity traits ([`ironauth_journey::FieldSource::SubjectTraits`]).
        FIELD_SUBJECT_TRAITS => "predicate.field.subject_traits", ENGINE_GRANTS;
        /// Reads the subject's group memberships ([`ironauth_journey::FieldSource::SubjectGroups`]).
        ///
        /// WITHHELD: `source_is_engine_live` (`crates/ironauth-journey/src/eval.rs:590`) marks this
        /// source NOT-LIVE, so the load-time type check refuses any predicate reading it.
        FIELD_SUBJECT_GROUPS => "predicate.field.subject_groups", ENGINE_WITHHOLDS;
        /// Reads the subject's granted scopes ([`ironauth_journey::FieldSource::SubjectScopes`]).
        ///
        /// WITHHELD for the same measured reason as [`FixedCapability::FIELD_SUBJECT_GROUPS`].
        FIELD_SUBJECT_SCOPES => "predicate.field.subject_scopes", ENGINE_WITHHOLDS;
        /// Reads the risk decision ([`ironauth_journey::FieldSource::Risk`]).
        ///
        /// Granted: `source_is_engine_live` (`crates/ironauth-journey/src/eval.rs:590`) serves this
        /// source at the `/level` pointer. The capability is per SOURCE, not per pointer, because a
        /// pointer is data (see [`super::derive_capabilities`]); the load-time type check is what refuses a
        /// pointer the source does not serve.
        FIELD_RISK => "predicate.field.risk", ENGINE_GRANTS;

        /// Tests membership of a named subject GROUP ([`ironauth_journey::MemberSet::Group`]).
        ///
        /// WITHHELD: it is reachable only through a `member` predicate over the not-live
        /// `subject_groups` source. See [`FixedCapability::PREDICATE_MEMBER`].
        MEMBER_GROUP => "predicate.member.group", ENGINE_WITHHOLDS;
        /// Tests membership of a named subject SCOPE ([`ironauth_journey::MemberSet::Scope`]).
        ///
        /// WITHHELD for the same measured reason as [`FixedCapability::MEMBER_GROUP`].
        MEMBER_SCOPE => "predicate.member.scope", ENGINE_WITHHOLDS;

        /// Compares against a JSON null literal ([`ironauth_journey::Literal::Null`]).
        LITERAL_NULL => "predicate.literal.null", ENGINE_GRANTS;
        /// Compares against a boolean literal ([`ironauth_journey::Literal::Bool`]).
        LITERAL_BOOL => "predicate.literal.bool", ENGINE_GRANTS;
        /// Compares against a numeric literal ([`ironauth_journey::Literal::Number`]).
        LITERAL_NUMBER => "predicate.literal.number", ENGINE_GRANTS;
        /// Compares against a string literal ([`ironauth_journey::Literal::String`]).
        LITERAL_STRING => "predicate.literal.string", ENGINE_GRANTS;

        /// Routes on a GUARDED transition (a [`ironauth_journey::Transition`] carrying a predicate). An artifact whose
        /// every transition is unguarded does not exercise this.
        TRANSITION_GUARD => "transition.guard", ENGINE_GRANTS;

        /// A decision step carries a PREDICATE decision spec
        /// ([`ironauth_journey::DecisionSpec::Predicate`]).
        ///
        /// WITHHELD, by the same standard that withholds [`FixedCapability::PREDICATE_MEMBER`]:
        /// a grant for something no artifact can reach is not an honest grant. `walk_decision`
        /// inserts [`FixedCapability::DECISION_SANDBOX`] unconditionally BEFORE it matches the spec
        /// form, and `DecisionSpec` has exactly one variant, so this capability cannot be derived
        /// without the sandbox being derived alongside it and the sandbox is withheld. Granting
        /// this one would therefore have been a grant that changes no outcome, while reading as
        /// though the engine executes a decision predicate. It does not: the attachment is
        /// validated and type checked at load and never consulted by the built-in edge-guard
        /// routing. Both entries flip to granted in the same edit that implements M11.
        DECISION_PREDICATE => "decision.predicate", ENGINE_WITHHOLDS;

        /// A step carries a `decision` attachment at all: the RESERVED outcome-based routing seam
        /// (issue #351) that the M11 sandbox will drive.
        ///
        /// WITHHELD by the shipped engine. The attachment is validated and type checked at load but is
        /// not consulted by the built-in edge-guard routing, so a bundle that carries one is asking for
        /// behavior this engine does not implement. That is precisely the case the issue names: it is
        /// refused at load until M11 grants the capability, rather than imported and silently
        /// half-honored.
        DECISION_SANDBOX => "decision.sandbox", ENGINE_WITHHOLDS;

        /// Composes an INLINE subflow definition carried by the bundle
        /// ([`ironauth_journey::SubflowSource::Inline`]).
        SUBFLOW_INLINE => "subflow.inline", ENGINE_GRANTS;
    }
}

pub use vocabulary::FixedCapability;

/// One capability a bundle exercises, or one an environment grants.
///
/// The wire form is a dotted token. Some tokens come from the closed [`FixedCapability`]
/// vocabulary; the rest carry an identifier the artifact supplies (`step.<kind>`,
/// `node_group.<group>`, `subflow.builtin.<name>`) and are built from the journey crate's own
/// accessors, never from a second list of names.
///
/// Deliberately NOT validated on the way in from a manifest: an unrecognized token deserializes
/// fine and simply cannot appear in the derived set, so it surfaces as an over-declaration. There
/// is no vocabulary list to keep in step and no way for an unknown token to be treated as
/// satisfied.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Capability(String);

impl Capability {
    /// The capability for a fixed vocabulary entry.
    #[must_use]
    pub fn fixed(capability: FixedCapability) -> Self {
        Self(capability.as_wire().to_owned())
    }

    /// The capability a step of this KIND exercises.
    ///
    /// The token is built from [`StepKind::as_wire`], the journey crate's own exhaustive wire-form
    /// match, so a new step kind cannot exist without a capability name and the two cannot drift.
    #[must_use]
    pub fn step(kind: &StepKind) -> Self {
        Self(format!("step.{}", kind.as_wire()))
    }

    /// The capability a step RENDERING under this node group exercises.
    #[must_use]
    pub fn node_group(group: &str) -> Self {
        Self(format!("node_group.{group}"))
    }

    /// The capability a reference to a BUILT-IN subflow exercises.
    #[must_use]
    pub fn builtin_subflow(name: &str) -> Self {
        Self(format!("subflow.builtin.{name}"))
    }

    /// The wire token.
    #[must_use]
    pub fn as_wire(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// The derived capability set
// ---------------------------------------------------------------------------

/// Re-derive the capability set a bundle exercises, from the artifact itself.
///
/// `source` is the bundle's journey with its sub-flows already merged in (the AUTHORED surface),
/// and `compiled` is the same journey after [`ironauth_journey::compile`] composed it (the
/// EFFECTIVE surface, with every subflow inlined). Both are walked and the results unioned,
/// because neither alone is complete:
///
/// - the source alone would miss the interior of a `SubflowSource::Builtin` reference, whose body
///   comes from the IMPORTING environment's registry and is spliced in at composition, so a bundle
///   could reach a step kind or a node group it never names; and
/// - the compiled form alone would miss what composition ERASES, namely the `subflow_call` step
///   kind, the subflow REFERENCES themselves, and the definition-level `subflow` keys
///   `walk_nested_subflow_calls` recovers.
///
/// ## What the walk visits
///
/// Every field of the artifact that selects an EXECUTOR or an engine FEATURE:
///
/// - `steps[].kind`, `steps[].node_group`, and `steps[].decision` (the attachment itself and the
///   decision spec's variant and predicate), on the source, on every inline sub-flow definition,
///   and on every compiled step;
/// - `transitions[].guard`, on the source, on every inline sub-flow definition, and on every
///   compiled edge; and every predicate node beneath a guard or a decision, with its operator, its
///   field source, its member-set kind, and its literal kinds;
/// - `subflows[].source`, both the `builtin` name and the fact of an `inline` reference;
/// - `subflow_definitions[].steps[].subflow`, the DEFINITION-level call key, which resolves against
///   the global definition key set rather than the journey's alias list. See
///   `walk_nested_subflow_calls`: it is the only walk that can name a built-in a nested call
///   reaches, and omitting it was a grant bypass.
///
/// ## What the walk deliberately does NOT visit, and why
///
/// A capability the deriver cannot see is a hole, so this is stated rather than left implicit.
/// The walk does not visit:
///
/// - `schema_version`, `id`, `entry`, and every `comment`: format tag, naming, and prose. No
///   executor is selected by them.
/// - `engine_version`: it is a LAUNCH CONSTRAINT, derived and checked separately by
///   [`derive_min_engine_version`], not a capability.
/// - `steps[].id`, `transitions[].from`/`to`, `subflow_definitions[].entry`/`exits`: pure topology.
///   Which steps exist and how they are wired changes routing, not which engine features run, and
///   [`ironauth_journey::compile`] has already refused every unsound topology before this runs.
/// - `steps[].subflow` AT JOURNEY LEVEL: the document-local ALIAS a call names. The alias resolves
///   to an entry in `subflows`, which IS visited; the alias string itself grants nothing. This is
///   true ONLY of a journey-level call. The same field on a step inside a `subflow_definitions`
///   body is not an alias at all and IS visited, by `walk_nested_subflow_calls`.
/// - The VALUES inside a predicate: a [`ironauth_journey::FieldRef`]'s RFC 6901 pointer, a
///   [`MemberSet`]'s group or scope NAME, and a [`Literal`]'s payload. These select DATA, not an
///   executor, and enumerating them would make the capability set unbounded: an operator would
///   have to grant `predicate.member.group.<every group name>` before any bundle could import. The
///   feature that READS each source is derived instead (`predicate.field.subject_groups`,
///   `predicate.member.group`), which is the thing an operator can meaningfully decide about.
#[must_use]
pub fn derive_capabilities(source: &Journey, compiled: &CompiledJourney) -> BTreeSet<Capability> {
    let mut out = BTreeSet::new();

    walk_steps(&source.steps, &mut out);
    // MEASURED REDUNDANT, and kept. Composition preserves every journey-level edge: `compose`
    // drops a call step's outgoing transitions only to re-graft each one, guard and all, onto every
    // subflow exit (and a subflow declares at least one, so none is lost), and redirects incoming
    // edges rather than dropping them. So every guard this line derives is also on a compiled edge,
    // and deleting the line survives the whole suite. It stays because the redundancy is a fact
    // about today's `compose` rather than about the format, and the failure direction if that ever
    // changes is a capability the operator was never asked about.
    walk_transitions(&source.transitions, &mut out);

    for reference in source.subflows.iter().flatten() {
        walk_subflow_reference(reference, &mut out);
    }
    for definition in source.subflow_definitions.iter().flatten() {
        walk_steps(&definition.steps, &mut out);
        walk_transitions(&definition.transitions, &mut out);
    }
    walk_nested_subflow_calls(source, &mut out);

    for step in compiled.steps.values() {
        out.insert(Capability::step(&step.kind));
        if let Some(group) = &step.node_group {
            out.insert(Capability::node_group(group));
        }
        if let Some(decision) = &step.decision {
            walk_decision(decision, &mut out);
        }
    }
    for edges in compiled.transitions.values() {
        for edge in edges {
            if let Some(guard) = &edge.guard {
                out.insert(Capability::fixed(FixedCapability::TRANSITION_GUARD));
                walk_predicate(guard, &mut out);
            }
        }
    }

    out
}

/// The engine version a bundle actually needs.
///
/// A [`Subflow`] carries no version of its own (only a [`Journey`] declares one), so the derived
/// minimum is the artifact's declared `engine_version` and nothing else. It is derived rather than
/// believed for the same reason the capabilities are: a manifest claiming a lower minimum than the
/// artifact declares would tell an operator the bundle runs on an older engine than it does.
#[must_use]
pub fn derive_min_engine_version(source: &Journey) -> u32 {
    source.engine_version
}

fn walk_steps(steps: &[Step], out: &mut BTreeSet<Capability>) {
    for step in steps {
        out.insert(Capability::step(&step.kind));
        if let Some(group) = &step.node_group {
            out.insert(Capability::node_group(group));
        }
        if let Some(decision) = &step.decision {
            walk_decision(decision, out);
        }
    }
}

fn walk_transitions(transitions: &[Transition], out: &mut BTreeSet<Capability>) {
    for transition in transitions {
        if let Some(guard) = &transition.guard {
            out.insert(Capability::fixed(FixedCapability::TRANSITION_GUARD));
            walk_predicate(guard, out);
        }
    }
}

/// Walk the `subflow` key of every `subflow_call` step inside a SUB-FLOW DEFINITION, which is the
/// journey format's SECOND sub-flow resolution rule.
///
/// A journey-level `subflow_call`'s `subflow` names an ALIAS in `Journey.subflows`
/// (`ironauth-journey/src/validate.rs`, `declared_subflow_ids`), and the alias's `SubflowRef` is
/// what `walk_subflow_reference` derives from. A NESTED `subflow_call`, one inside a
/// `subflow_definitions` body, obeys a DIFFERENT rule: `validate_subflow_fragment`
/// (`ironauth-journey/src/subflow.rs`) resolves its key against the GLOBAL definition key set,
/// every built-in NAME union every inline definition id, and `full_registry` splices from that
/// same set. So a nested call can reach a built-in the journey declares no reference to, and
/// [`ironauth_journey::compose`] then ERASES the call. Neither the reference walk nor the compiled
/// walk can name that built-in, and the whole grant for it would be bypassed.
///
/// The two namespaces cannot be confused: `validate_subflows` refuses an inline definition whose id
/// equals a built-in name ([`JourneyError::DuplicateSubflowDefinition`]), so a key that hits the
/// built-in registry IS the built-in and not something the bundle shadowed. The
/// `a_bundle_defining_a_subflow_named_like_a_builtin_is_refused` test pins that.
///
/// A key naming NEITHER a built-in nor anything else is a dangling reference
/// [`ironauth_journey::compile`] has already refused before this runs; deriving
/// [`FixedCapability::SUBFLOW_INLINE`] for it anyway is fail-closed.
fn walk_nested_subflow_calls(source: &Journey, out: &mut BTreeSet<Capability>) {
    let builtins = builtin_subflows();
    let mut pending: Vec<&Subflow> = source.subflow_definitions.iter().flatten().collect();
    // Every built-in body is spliced at most once, which is what bounds the walk: the only pushes
    // beyond the initial seed are built-in bodies, and each name enters `visited` before its body
    // is pushed, so a built-in that ever called itself (directly or through a ring) would be walked
    // once and then skipped rather than looping.
    let mut visited: BTreeSet<&str> = BTreeSet::new();
    while let Some(definition) = pending.pop() {
        for step in &definition.steps {
            let Some(key) = &step.subflow else { continue };
            match builtins.get(key.as_str()) {
                // The registry's own body is walked too, so a future built-in that nests a call of
                // its own is covered. No built-in does today; this is not waiting to be noticed.
                Some(body) => {
                    out.insert(Capability::builtin_subflow(key));
                    if visited.insert(key.as_str()) {
                        pending.push(body);
                    }
                }
                None => {
                    out.insert(Capability::fixed(FixedCapability::SUBFLOW_INLINE));
                }
            }
        }
    }
}

fn walk_subflow_reference(reference: &SubflowRef, out: &mut BTreeSet<Capability>) {
    match &reference.source {
        SubflowSource::Builtin { name } => {
            out.insert(Capability::builtin_subflow(name));
        }
        SubflowSource::Inline { .. } => {
            out.insert(Capability::fixed(FixedCapability::SUBFLOW_INLINE));
        }
    }
}

/// Walk a decision attachment.
///
/// The attachment's mere PRESENCE derives [`FixedCapability::DECISION_SANDBOX`], the reserved
/// outcome-routing seam, independently of which spec form it carries.
fn walk_decision(decision: &DecisionSpec, out: &mut BTreeSet<Capability>) {
    out.insert(Capability::fixed(FixedCapability::DECISION_SANDBOX));
    match decision {
        DecisionSpec::Predicate { predicate } => {
            out.insert(Capability::fixed(FixedCapability::DECISION_PREDICATE));
            walk_predicate(predicate, out);
        }
    }
}

/// Walk a predicate tree with an EXPLICIT stack rather than recursion.
///
/// The tree is attacker-supplied. `serde_json` already caps nesting at its own recursion limit and
/// [`ironauth_journey::compile`]'s type check enforces
/// [`ironauth_journey::MAX_PREDICATE_DEPTH`] before this ever runs, so a recursive walk would in
/// fact be safe today; an explicit stack makes that independent of both, so no future relaxation
/// of either can turn this into a stack overflow.
fn walk_predicate(root: &Predicate, out: &mut BTreeSet<Capability>) {
    let mut stack: Vec<&Predicate> = vec![root];
    while let Some(node) = stack.pop() {
        match node {
            Predicate::Cmp { field, op, value } => {
                out.insert(Capability::fixed(FixedCapability::PREDICATE_CMP));
                out.insert(Capability::fixed(cmp_op_capability(*op)));
                out.insert(Capability::fixed(field_source_capability(field.source)));
                out.insert(Capability::fixed(literal_capability(value)));
            }
            Predicate::In { field, values } => {
                out.insert(Capability::fixed(FixedCapability::PREDICATE_IN));
                out.insert(Capability::fixed(field_source_capability(field.source)));
                for value in values {
                    out.insert(Capability::fixed(literal_capability(value)));
                }
            }
            Predicate::Member { field, set } => {
                out.insert(Capability::fixed(FixedCapability::PREDICATE_MEMBER));
                out.insert(Capability::fixed(field_source_capability(field.source)));
                out.insert(Capability::fixed(member_set_capability(set)));
            }
            Predicate::And { operands } => {
                out.insert(Capability::fixed(FixedCapability::PREDICATE_AND));
                stack.extend(operands.iter());
            }
            Predicate::Or { operands } => {
                out.insert(Capability::fixed(FixedCapability::PREDICATE_OR));
                stack.extend(operands.iter());
            }
            Predicate::Not { operand } => {
                out.insert(Capability::fixed(FixedCapability::PREDICATE_NOT));
                stack.push(operand);
            }
            Predicate::Always => {
                out.insert(Capability::fixed(FixedCapability::PREDICATE_ALWAYS));
            }
            Predicate::Never => {
                out.insert(Capability::fixed(FixedCapability::PREDICATE_NEVER));
            }
        }
    }
}

/// The capability a comparison operator exercises. Exhaustive with no wildcard arm on purpose: a
/// new operator does not compile until it names one.
fn cmp_op_capability(op: CmpOp) -> FixedCapability {
    match op {
        CmpOp::Eq => FixedCapability::OP_EQ,
        CmpOp::Ne => FixedCapability::OP_NE,
        CmpOp::Lt => FixedCapability::OP_LT,
        CmpOp::Le => FixedCapability::OP_LE,
        CmpOp::Gt => FixedCapability::OP_GT,
        CmpOp::Ge => FixedCapability::OP_GE,
    }
}

/// The capability reading a context source exercises. Exhaustive with no wildcard arm: a new
/// source (which is a new thing a journey can READ about a subject) does not compile until it
/// names a capability an operator can withhold.
fn field_source_capability(source: FieldSource) -> FixedCapability {
    match source {
        FieldSource::Flow => FixedCapability::FIELD_FLOW,
        FieldSource::Signals => FixedCapability::FIELD_SIGNALS,
        FieldSource::SubjectTraits => FixedCapability::FIELD_SUBJECT_TRAITS,
        FieldSource::SubjectGroups => FixedCapability::FIELD_SUBJECT_GROUPS,
        FieldSource::SubjectScopes => FixedCapability::FIELD_SUBJECT_SCOPES,
        FieldSource::Risk => FixedCapability::FIELD_RISK,
    }
}

/// The capability a membership test's SET KIND exercises (never its name, which is data).
fn member_set_capability(set: &MemberSet) -> FixedCapability {
    match set {
        MemberSet::Group { .. } => FixedCapability::MEMBER_GROUP,
        MemberSet::Scope { .. } => FixedCapability::MEMBER_SCOPE,
    }
}

/// The capability a literal's TYPE exercises (never its value, which is data).
fn literal_capability(literal: &Literal) -> FixedCapability {
    match literal {
        Literal::Null => FixedCapability::LITERAL_NULL,
        Literal::Bool(_) => FixedCapability::LITERAL_BOOL,
        Literal::Number(_) => FixedCapability::LITERAL_NUMBER,
        Literal::String(_) => FixedCapability::LITERAL_STRING,
    }
}

// ---------------------------------------------------------------------------
// The importing environment
// ---------------------------------------------------------------------------

/// What the importing environment has GRANTED.
///
/// An imported journey may exercise nothing outside this set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantedCapabilities(BTreeSet<Capability>);

impl GrantedCapabilities {
    /// Everything the engine AS SHIPPED can execute.
    ///
    /// Every element is read from a structural source, so this cannot fall behind the engine.
    /// "Structural" is load-bearing here and each one earned it, because the first draft of this
    /// list said the same sentence about two arrays that were NOT structural:
    ///
    /// - the step kinds are [`StepKind::BUILT_IN`] minus the BUILT-IN-ONLY mint family
    ///   ([`StepKind::is_builtin_only`]), which a custom artifact may not name at all and
    ///   [`ironauth_journey::compile`] refuses independently. `BUILT_IN` was a hand-written array
    ///   beside a hand-written enum, so a new step kind the validator accepted was silently
    ///   ungranted here; it is now generated with the enum by the journey crate's `step_kinds!`
    ///   declaration, so the two are one list;
    /// - the node groups are [`NODE_GROUPS`], the same array the load-time validator accepts, and
    ///   it is a hand-maintained mirror of `ironauth-oidc`'s `NodeGroup` enum LOCKED to it by
    ///   `the_journey_node_group_vocabulary_matches_this_enum`, the only place both are visible;
    /// - the built-in subflows are the keys of [`builtin_subflows`], the registry itself;
    /// - the fixed vocabulary is [`FixedCapability::ALL`] filtered by
    ///   [`FixedCapability::engine_grants`], which every entry must declare.
    ///
    /// A capability the engine gains support for is granted by editing the declaration that says
    /// so, and one it has not gained is simply absent, so an unimplemented feature fails CLOSED.
    #[must_use]
    pub fn engine_default() -> Self {
        let mut granted = BTreeSet::new();
        for wire in StepKind::BUILT_IN {
            let kind = StepKind::from_wire(wire);
            if !kind.is_builtin_only() {
                granted.insert(Capability::step(&kind));
            }
        }
        for group in NODE_GROUPS {
            granted.insert(Capability::node_group(group));
        }
        for name in builtin_subflows().keys() {
            granted.insert(Capability::builtin_subflow(name));
        }
        for fixed in FixedCapability::ALL {
            if fixed.engine_grants() {
                granted.insert(Capability::fixed(fixed));
            }
        }
        Self(granted)
    }

    /// An explicit grant set, for an operator that narrows or widens the default.
    #[must_use]
    pub fn from_capabilities(capabilities: impl IntoIterator<Item = Capability>) -> Self {
        Self(capabilities.into_iter().collect())
    }

    /// Grant one more capability (the shape an M11 that lit up the decision sandbox would take).
    #[must_use]
    pub fn with(mut self, capability: Capability) -> Self {
        self.0.insert(capability);
        self
    }

    /// Withhold one capability.
    #[must_use]
    pub fn without(mut self, capability: &Capability) -> Self {
        self.0.remove(capability);
        self
    }

    /// Whether this environment grants `capability`.
    #[must_use]
    pub fn contains(&self, capability: &Capability) -> bool {
        self.0.contains(capability)
    }

    /// The granted set.
    #[must_use]
    pub fn capabilities(&self) -> &BTreeSet<Capability> {
        &self.0
    }
}

/// The importing environment's side of the import decision: what it grants, and what transports it
/// would serve the journey over.
#[derive(Clone, Debug)]
pub struct ImportEnvironment {
    granted: GrantedCapabilities,
    offered_transports: BTreeSet<String>,
}

impl ImportEnvironment {
    /// Build the importing environment's view.
    ///
    /// `offered_transports` is every transport this deployment would serve a flow over, as the
    /// wire strings the flow engine uses (`ironauth_oidc::Transport::as_str`, today `browser` and
    /// `api`). It is supplied by the caller rather than mirrored here because this crate cannot
    /// depend on the flow engine, and a mirrored list would be exactly the hand-written copy of a
    /// structural source this module exists to avoid. The comparison is a plain set operation, so
    /// nothing here needs to know the vocabulary.
    #[must_use]
    pub fn new(
        granted: GrantedCapabilities,
        offered_transports: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            granted,
            offered_transports: offered_transports.into_iter().collect(),
        }
    }

    /// What this environment grants.
    #[must_use]
    pub fn granted(&self) -> &GrantedCapabilities {
        &self.granted
    }

    /// The transports this environment would serve an imported journey over.
    #[must_use]
    pub fn offered_transports(&self) -> &BTreeSet<String> {
        &self.offered_transports
    }
}

// ---------------------------------------------------------------------------
// Trust
// ---------------------------------------------------------------------------

/// An exporter the importing operator has decided to trust: an issuer, pinned exactly, and the
/// public keys that issuer signs with.
///
/// ## The measured gap
///
/// This value is an ARGUMENT to [`import_archive`], and there is no persistence, no admin API, and
/// no configuration surface behind it. That is deliberate rather than unfinished, and the reason is
/// worth recording precisely.
///
/// The tree DOES hold a per-environment, RLS-scoped registry of operator-registered external
/// issuers with inline JWKS or a `jwks_uri`: the `external_assertion_issuers` table (migration
/// `0020_jwt_bearer_assertion.sql`), reachable through
/// [`crate::repository::ExternalAssertionIssuerRepo`]. It is not reused here, because registering
/// a row in it means one specific thing: that assertions from that issuer may AUTHENTICATE a
/// principal under RFC 7523. Registering a journey exporter there would silently confer that power
/// too. Two different trust decisions sharing one registry is how a registry becomes a
/// vulnerability, so the honest answer is that cross-organization EXPORTER trust has no home yet
/// and needs an operator-facing one of its own. The external-issuer table gained a management API in
/// issue #126, so the second half of that argument is gone; the first half is the whole of it
/// and stands on its own. Exporter trust and assertion-issuer trust are different decisions,
/// and putting them in one registry would be wrong however reachable that registry is.
///
/// ## Why there is no fetch here
///
/// A [`TrustedExporter`] is built from key material the operator supplies, never from a location
/// the ARCHIVE names. An archive that pointed at its own JWKS would be trusting the party it is
/// supposed to be authenticating, and it would additionally hand an attacker a server-side fetch of
/// a URL of their choosing: the exact SSRF shape `ironauth-fetch` exists to contain. When the
/// operator-facing registry does land and an operator configures an exporter by `jwks_uri`, that
/// URL is operator-controlled but still remote and still resolves to whatever DNS says at connect
/// time, so it must go through `ironauth_fetch::Fetcher` (resolve, validate, pin) exactly as
/// `client_keys.rs` and `federation_jwks.rs` already do. Nothing on THIS path fetches anything.
#[derive(Clone, Debug)]
pub struct TrustedExporter {
    issuer: String,
    keys: Vec<TrustedKey>,
}

impl TrustedExporter {
    /// Trust `issuer` for the keys in an operator-supplied JWK Set document.
    ///
    /// The document is parsed by [`ironauth_jose::trusted_keys_from_jwks`], the crate's one
    /// inbound JWK mapping, which skips any key type or curve the verify core cannot represent.
    ///
    /// # Errors
    ///
    /// [`InterchangeError::TrustAnchorUnusable`] when the issuer is empty or the document names no
    /// key this core can verify with, so an unusable anchor is a loud failure rather than a policy
    /// that silently verifies nothing.
    pub fn from_jwks(
        issuer: impl Into<String>,
        jwks_json: &[u8],
    ) -> Result<Self, InterchangeError> {
        Self::from_keys(issuer, trusted_keys_from_jwks(jwks_json))
    }

    /// Trust `issuer` for already-parsed keys.
    ///
    /// # Errors
    ///
    /// [`InterchangeError::TrustAnchorUnusable`] when the issuer is empty or no key is supplied.
    pub fn from_keys(
        issuer: impl Into<String>,
        keys: Vec<TrustedKey>,
    ) -> Result<Self, InterchangeError> {
        let issuer = issuer.into();
        if issuer.is_empty() || keys.is_empty() {
            return Err(InterchangeError::TrustAnchorUnusable);
        }
        Ok(Self { issuer, keys })
    }

    /// The exactly-pinned issuer.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
}

// ---------------------------------------------------------------------------
// The archive and its payload
// ---------------------------------------------------------------------------

/// The `.iaj` container: the RFC 7515 section 7.2.2 FLATTENED JWS JSON serialization.
///
/// Exactly three base64url members and nothing else. There is no unprotected `header` member: an
/// unprotected header is data the signature does not cover, which is a divergence surface, so its
/// presence is refused by `deny_unknown_fields` rather than ignored.
///
/// The issue calls this a "detached" JWS. That is a terminology mismatch worth naming: DETACHED
/// content is RFC 7515 Appendix F, where the payload travels OUTSIDE the JWS and the recipient
/// supplies it, and it is unverifiable here by design because this crate's verifier reads the
/// payload from the second segment. (RFC 7797 is a different thing that is often confused with it:
/// the Unencoded Payload Option, the `b64` header parameter, which this crate's verifier rejects
/// outright along with any `crit`.) The shape the issue actually describes, `{payload, protected,
/// signature}`, is
/// the standard flattened JSON serialization, which is what this is. Keeping the payload inside is
/// also what makes the signed bytes and the parsed bytes the same object.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedArchive {
    /// The base64url protected header (`alg`, `kid`, `typ`).
    pub protected: String,
    /// The base64url payload.
    pub payload: String,
    /// The base64url signature over `protected.payload`.
    pub signature: String,
}

impl SignedArchive {
    /// Join the three RECEIVED segments into the compact serialization the verifier reads.
    ///
    /// A segment carrying a `.` would change how many segments the compact form has, so it is
    /// refused here with a precise reason. The verifier's own three-segment split would refuse it
    /// too, opaquely; this is the belt to that braces.
    fn to_compact(&self) -> Result<String, InterchangeError> {
        for segment in [&self.protected, &self.payload, &self.signature] {
            if segment.is_empty() || segment.contains('.') {
                return Err(InterchangeError::ArchiveSegmentMalformed);
            }
        }
        Ok(format!(
            "{}.{}.{}",
            self.protected, self.payload, self.signature
        ))
    }
}

/// The bundle's safety manifest: the exporter's DECLARATION about what the bundle needs.
///
/// Every field is a claim the importer checks against the artifact, never an input it acts on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyManifest {
    /// Every capability the bundle exercises, as declared. Checked for EXACT equality against
    /// [`derive_capabilities`].
    pub required_capabilities: BTreeSet<Capability>,
    /// Where and on what the bundle may be launched.
    pub launch_constraints: LaunchConstraints,
}

/// The bundle's launch constraints.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchConstraints {
    /// The minimum orchestration ABI the bundle needs. Checked for equality against
    /// [`derive_min_engine_version`], then against [`JOURNEY_ENGINE_VERSION`].
    pub min_engine_version: u32,
    /// The transports the author permits this journey to be launched over. Not derivable (it is
    /// author intent), so it is enforced rather than ignored: every transport the importing
    /// environment offers must appear here.
    pub allowed_transports: BTreeSet<String>,
    /// Whether the bundle needs the M11 decision sandbox. A PROJECTION of the derived capability
    /// set, checked for equality against it, never a separate fact.
    pub requires_sandbox: bool,
}

/// What a successful import produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedBundle {
    /// The verified journey with the bundle's out-of-line sub-flows merged in, ready for
    /// [`crate::flow_version`] to store as a new version.
    pub artifact: Journey,
    /// The canonical JSON of `artifact`.
    ///
    /// This is a RE-SERIALIZATION of the verified value, not the signed bytes. The signature
    /// covers the archive's payload segment; it is not re-checkable against this string, and this
    /// string is never fed back into a verification. A caller that needs to prove provenance later
    /// keeps the archive.
    pub artifact_json: String,
    /// The capability set the importer DERIVED (not the one the manifest declared).
    pub capabilities: BTreeSet<Capability>,
    /// The exporter's issuer, as pinned by the trust anchor and matched exactly by the verifier.
    pub exporter_issuer: String,
    /// The `kid` the archive named. It only ever selected among the exporter's already-trusted
    /// keys.
    pub key_id: Option<String>,
}

/// Why an archive was not produced or not accepted.
///
/// ## What a rendered variant may and may not contain
///
/// No variant carries END-USER DATA. It names capability tokens, sub-flow and step ids, node group
/// names, transports, and version numbers, and none of those is a subject, a credential, or a
/// claim value. That much is structural: the deriver never reads a predicate's literal, a field
/// pointer, or a member-set name (see [`derive_capabilities`]), so no such value can reach an
/// error in the first place.
///
/// What those names are NOT is stable identifiers of the IMPORTER. A cross-organization exporter
/// chooses its own sub-flow ids and its own manifest capability tokens, so the strings a refusal
/// echoes are attacker-chosen text on an operator-facing surface, and
/// [`InterchangeError::SubflowIdConflict`] in particular is raised at the merge stage, BEFORE
/// [`ironauth_journey::compile`] has constrained anything about them. Left raw that is log forging
/// (a newline writes the operator's next log line) and log flooding (a multi-kilobyte id, or a
/// thousand-element failure list, in one line). Every echoed value is therefore rendered through
/// `echo`, which replaces anything outside ASCII graphic-or-space and truncates, and every echoed
/// LIST is bounded by `join_echoed`. The
/// `a_hostile_exporter_cannot_forge_or_flood_an_operator_log_line` acceptance case measures it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InterchangeError {
    /// The archive document is larger than [`MAX_ARCHIVE_BYTES`].
    ArchiveTooLarge {
        /// The ceiling this build admits.
        limit: usize,
    },
    /// The archive document is not the three-member flattened JWS JSON object.
    ArchiveMalformed,
    /// An archive segment is empty or carries a `.`, so it is not a single base64url segment.
    ArchiveSegmentMalformed,
    /// Verification refused the archive. UNIFORM on purpose, mirroring
    /// [`ironauth_jose::VerifyError`]: a caller cannot tell a bad signature from an untrusted key
    /// from a wrong media type. The precise reason is available through
    /// [`InterchangeError::verify_reason`] for server-side diagnostics only.
    SignatureRejected(RejectReason),
    /// The verified payload is not the exact shape an archive carries.
    PayloadShape {
        /// Which structural rule failed. A fixed string, never a caller value.
        detail: &'static str,
    },
    /// The bundle carries two definitions for one sub-flow id, so which body compiles would be
    /// ambiguous.
    SubflowIdConflict {
        /// The duplicated sub-flow definition id.
        id: String,
    },
    /// The artifact is not a load-valid, compilable journey.
    JourneyInvalid(Vec<JourneyError>),
    /// The manifest declares FEWER capabilities than the artifact exercises. This is the
    /// security-relevant direction: the manifest is under-declaring what it will do.
    CapabilityUnderDeclared {
        /// The exercised capabilities the manifest failed to declare, sorted.
        missing: Vec<Capability>,
    },
    /// The manifest declares capabilities the artifact does not exercise. Not a security hole, but
    /// a false safety summary, and refused so the manifest stays a deterministic function of the
    /// payload.
    CapabilityOverDeclared {
        /// The declared capabilities the artifact does not exercise, sorted.
        extra: Vec<Capability>,
    },
    /// The artifact exercises a capability the importing environment has not granted.
    CapabilityNotGranted {
        /// The exercised but ungranted capabilities, sorted.
        missing: Vec<Capability>,
    },
    /// The manifest's `min_engine_version` is not the artifact's.
    EngineVersionMisdeclared {
        /// What the manifest declared.
        declared: u32,
        /// What the artifact needs.
        derived: u32,
    },
    /// The bundle needs an orchestration ABI newer than this build supports.
    EngineVersionUnsupported {
        /// What the bundle needs.
        declared: u32,
        /// What this build supports.
        supported: u32,
    },
    /// The manifest's `requires_sandbox` is not what the artifact implies.
    SandboxMisdeclared {
        /// What the manifest declared.
        declared: bool,
        /// What the artifact implies.
        derived: bool,
    },
    /// The manifest permits no transport at all, so the journey could never be launched.
    NoAllowedTransport,
    /// The importing environment serves no transport at all, so the `allowed_transports` constraint
    /// could not be checked against anything and would be satisfied vacuously.
    EnvironmentServesNoTransport,
    /// The importing environment would serve a transport the manifest does not permit, and nothing
    /// can pin a stored journey to a subset of an environment's transports, so the constraint
    /// cannot be honored.
    TransportNotAllowed {
        /// The offered but disallowed transport.
        transport: String,
    },
    /// The trust anchor names no issuer, or no key this core can verify with.
    TrustAnchorUnusable,
    /// The archive could not be signed.
    SigningFailed,
}

impl InterchangeError {
    /// The precise verification reason, for server-side logs and metrics only. [`None`] for every
    /// failure that is not a verification failure.
    #[must_use]
    pub fn verify_reason(&self) -> Option<RejectReason> {
        match self {
            InterchangeError::SignatureRejected(reason) => Some(*reason),
            _ => None,
        }
    }
}

impl fmt::Display for InterchangeError {
    // One arm per variant: a flat match is the clearest form and the length only reflects the
    // number of variants.
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InterchangeError::ArchiveTooLarge { limit } => {
                write!(f, "interchange archive exceeds the {limit} byte ceiling")
            }
            InterchangeError::ArchiveMalformed => f.write_str(
                "interchange archive is not a flattened JWS JSON object of protected, payload, and signature",
            ),
            InterchangeError::ArchiveSegmentMalformed => {
                f.write_str("an interchange archive segment is empty or is not a single base64url segment")
            }
            // Uniform: the reason is a server-side diagnostic, never rendered to a caller.
            InterchangeError::SignatureRejected(_) => {
                f.write_str("interchange archive signature verification failed")
            }
            InterchangeError::PayloadShape { detail } => {
                write!(f, "interchange payload is malformed: {detail}")
            }
            InterchangeError::SubflowIdConflict { id } => write!(
                f,
                "the bundle carries two definitions for sub-flow id {}",
                echo(id, MAX_ECHOED_IDENTIFIER)
            ),
            InterchangeError::JourneyInvalid(errors) => {
                let echoed: Vec<String> = errors
                    .iter()
                    .map(|error| echo(&error.to_string(), MAX_ECHOED_MESSAGE))
                    .collect();
                write!(
                    f,
                    "the bundled journey is not load-valid: {}",
                    join_echoed(&echoed, "; ")
                )
            }
            InterchangeError::CapabilityUnderDeclared { missing } => write!(
                f,
                "the manifest under-declares: the bundle exercises {} but the manifest does not declare it",
                join_capabilities(missing)
            ),
            InterchangeError::CapabilityOverDeclared { extra } => write!(
                f,
                "the manifest over-declares: it declares {} which the bundle does not exercise",
                join_capabilities(extra)
            ),
            InterchangeError::CapabilityNotGranted { missing } => write!(
                f,
                "this environment has not granted {}, which the bundle requires",
                join_capabilities(missing)
            ),
            InterchangeError::EngineVersionMisdeclared { declared, derived } => write!(
                f,
                "the manifest declares min engine version {declared} but the artifact needs {derived}"
            ),
            InterchangeError::EngineVersionUnsupported {
                declared,
                supported,
            } => write!(
                f,
                "the bundle needs engine version {declared}, above the supported version {supported}"
            ),
            InterchangeError::SandboxMisdeclared { declared, derived } => write!(
                f,
                "the manifest declares requires_sandbox {declared} but the artifact implies {derived}"
            ),
            InterchangeError::NoAllowedTransport => {
                f.write_str("the manifest permits no transport, so the journey could never launch")
            }
            InterchangeError::EnvironmentServesNoTransport => f.write_str(
                "this environment serves no transport, so the manifest's allowed transports could not be honored",
            ),
            // The transport is the IMPORTER'S own configuration rather than exporter text, so it is
            // already a stable local identifier. It goes through `echo` anyway so the guarantee on
            // this type is unconditional and there is no per-variant judgement to get wrong later.
            InterchangeError::TransportNotAllowed { transport } => write!(
                f,
                "this environment serves the {} transport, which the manifest does not permit",
                echo(transport, MAX_ECHOED_IDENTIFIER)
            ),
            InterchangeError::TrustAnchorUnusable => {
                f.write_str("the trusted exporter names no issuer or no usable verification key")
            }
            InterchangeError::SigningFailed => {
                f.write_str("the interchange archive could not be signed")
            }
        }
    }
}

impl std::error::Error for InterchangeError {}

/// The longest ECHOED exporter-supplied identifier a rendered error carries (a sub-flow id, a
/// capability token). Comfortably above any real one; the point is that there IS a ceiling.
const MAX_ECHOED_IDENTIFIER: usize = 64;

/// The longest ECHOED rendered sub-error a [`InterchangeError::JourneyInvalid`] message carries.
/// Longer than an identifier because the journey crate's own prose is part of it.
const MAX_ECHOED_MESSAGE: usize = 200;

/// The most list elements a rendered error names before it summarizes the rest by count. Without
/// this an artifact with a thousand load failures renders a thousand of them into one log line.
const MAX_ECHOED_ELEMENTS: usize = 8;

/// Render exporter-supplied text into an OPERATOR-FACING message safely.
///
/// This is the one place any value that crossed the organization boundary is echoed. A
/// cross-organization exporter chooses its own sub-flow ids, step ids, node group names, and
/// manifest capability tokens, so none of them is a stable identifier of the IMPORTER, and two
/// things follow. A raw newline forges a log line (the exporter writes the next entry of the
/// operator's log); an ANSI CSI sequence repaints the operator's terminal; and several kilobytes of
/// padding floods the log. So every character that is not ASCII graphic or a plain space becomes
/// `?`, which covers control characters, ANSI escapes, and the non-ASCII confusables (a
/// right-to-left override, a homoglyph) too, and the result is truncated to `limit` characters with
/// the true length stated rather than silently dropped.
///
/// Replacing rather than deleting keeps the length of the sanitized region honest, so an operator
/// reading `mfa??step_up` can see that something was removed instead of reading a plausible name.
fn echo(value: &str, limit: usize) -> String {
    let total = value.chars().count();
    let mut out: String = value
        .chars()
        .take(limit)
        .map(|character| {
            if character == ' ' || character.is_ascii_graphic() {
                character
            } else {
                '?'
            }
        })
        .collect();
    if total > limit {
        let _ = write!(out, "[truncated, {total} characters]");
    }
    out
}

/// Join a bounded, sanitized list, summarizing anything past `MAX_ECHOED_ELEMENTS` by count.
fn join_echoed(elements: &[String], separator: &str) -> String {
    let shown = elements.len().min(MAX_ECHOED_ELEMENTS);
    let mut out = elements[..shown].join(separator);
    if elements.len() > shown {
        let _ = write!(out, "{separator}and {} more", elements.len() - shown);
    }
    out
}

/// A capability list for a message.
///
/// The tokens in a NOT-GRANTED or UNDER-DECLARED list are derived, so they came from the journey
/// crate's own accessors. The tokens in an OVER-DECLARED list did not: [`Capability`] is
/// deliberately unvalidated on the way in from a manifest (an unknown token simply cannot be
/// satisfied), so an over-declaring manifest is a direct exporter-to-operator text channel. All
/// three go through `echo` rather than only the one that needs it, so there is no per-variant
/// judgement to get wrong later.
fn join_capabilities(capabilities: &[Capability]) -> String {
    let echoed: Vec<String> = capabilities
        .iter()
        .map(|capability| echo(capability.as_wire(), MAX_ECHOED_IDENTIFIER))
        .collect();
    join_echoed(&echoed, ", ")
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

/// What to put in an archive.
#[derive(Clone, Copy, Debug)]
pub struct ExportRequest<'a> {
    /// The exporting environment's issuer, which lands in `iss` and which the importer pins.
    pub issuer: &'a str,
    /// The journey artifact.
    pub artifact: &'a Journey,
    /// The sub-flow definitions the bundle carries out of line, so the artifact is self-contained.
    pub subflows: &'a [Subflow],
    /// The transports the author permits.
    pub allowed_transports: &'a BTreeSet<String>,
    /// The `iat` to stamp, in seconds since the Unix epoch, from the caller's clock seam.
    pub issued_at_secs: i64,
    /// The `exp` to stamp, in seconds since the Unix epoch.
    ///
    /// There is no default, and the archive expires. `exp` is REQUIRED by
    /// [`ironauth_jose::verify`] and is enforced here rather than relaxed with `allow_expired`,
    /// because an archive that never expires means a signing key stolen from an exporter mints
    /// importable bundles forever. An archive is cheap to re-export, and the alternative reading
    /// (an archive is a permanent artifact) is the one that leaves a compromise unbounded.
    pub expires_at_secs: i64,
}

/// Build and sign an interchange archive.
///
/// The manifest is DERIVED here, never taken from the caller: `required_capabilities`,
/// `min_engine_version`, and `requires_sandbox` all come from the artifact through the same
/// functions the importer re-runs, so an archive this function produces always satisfies the
/// importer's manifest check. `allowed_transports` is the one manifest field that is author intent,
/// and it is the one thing the caller supplies.
///
/// The journey is compiled first, so a bundle that could never import is never exported.
///
/// # Errors
///
/// [`InterchangeError::SubflowIdConflict`] or [`InterchangeError::JourneyInvalid`] when the bundle
/// does not merge and compile, [`InterchangeError::NoAllowedTransport`] for an empty transport
/// set, and [`InterchangeError::SigningFailed`] when the mint or the resulting compact
/// serialization is not well formed.
pub fn export_archive(
    key: &SigningKey,
    request: &ExportRequest<'_>,
) -> Result<String, InterchangeError> {
    if request.allowed_transports.is_empty() {
        return Err(InterchangeError::NoAllowedTransport);
    }
    let merged = merge_subflows(request.artifact, request.subflows)?;
    let compiled = compile(&merged).map_err(InterchangeError::JourneyInvalid)?;
    let capabilities = derive_capabilities(&merged, &compiled);

    let manifest = SafetyManifest {
        launch_constraints: LaunchConstraints {
            min_engine_version: derive_min_engine_version(&merged),
            allowed_transports: request.allowed_transports.clone(),
            requires_sandbox: requires_sandbox(&capabilities),
        },
        required_capabilities: capabilities,
    };

    let mut payload = Map::new();
    payload.insert("iss".to_owned(), Value::String(request.issuer.to_owned()));
    payload.insert(
        "aud".to_owned(),
        Value::String(INTERCHANGE_AUDIENCE.to_owned()),
    );
    payload.insert("iat".to_owned(), Value::from(request.issued_at_secs));
    payload.insert("exp".to_owned(), Value::from(request.expires_at_secs));
    payload.insert(
        "artifact".to_owned(),
        serde_json::to_value(request.artifact).map_err(|_| InterchangeError::SigningFailed)?,
    );
    payload.insert(
        "subflows".to_owned(),
        serde_json::to_value(request.subflows).map_err(|_| InterchangeError::SigningFailed)?,
    );
    payload.insert(
        "manifest".to_owned(),
        serde_json::to_value(&manifest).map_err(|_| InterchangeError::SigningFailed)?,
    );

    // The canonical bytes, through the crate's ONE canonical JSON writer (issue #43), so an
    // archive's bytes depend only on its content. This is an EXPORT-side determinism property: the
    // importer never re-canonicalizes, it verifies and parses the bytes it received.
    let canonical = crate::snapshot::canonical_json_bytes(&Value::Object(payload));

    let compact = sign_jws(
        key,
        &canonical,
        &EmissionOptions::new().with_token_typ(TokenTyp::JourneyInterchange),
    )
    .map_err(|_| InterchangeError::SigningFailed)?;

    // The archive's three members ARE the minted compact segments, split apart, so the flattened
    // form and the compact form are the same bytes rearranged rather than two serializations.
    let mut segments = compact.split('.');
    let (Some(protected), Some(payload), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(InterchangeError::SigningFailed);
    };
    let archive = SignedArchive {
        protected: protected.to_owned(),
        payload: payload.to_owned(),
        signature: signature.to_owned(),
    };
    serde_json::to_string(&archive).map_err(|_| InterchangeError::SigningFailed)
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

/// Verify, compile, and capability-check an interchange archive.
///
/// The stages run in a fixed order whose sequence is the security property, mirroring
/// [`ironauth_jose::verify`]'s own discipline:
///
/// 1. the cheap size cap, before any parse;
/// 2. the container parse (three base64url members, nothing else);
/// 3. the ONE signature verification, through [`ironauth_jose::verify`], pinning `EdDSA`, the
///    exporter's keys, the exporter's issuer, [`INTERCHANGE_AUDIENCE`], and the
///    [`TokenTyp::JourneyInterchange`] media type;
/// 4. the payload shape check on the VERIFIED claims (no unverified content is read before this);
/// 5. the sub-flow merge, refusing an ambiguous id;
/// 6. the #92 load-time [`ironauth_journey::compile`];
/// 7. the capability DERIVATION and the manifest equality check;
/// 8. the launch constraints;
/// 9. the grant check, against the DERIVED set.
///
/// # Errors
///
/// [`InterchangeError`], one variant per stage. A verification failure is uniform.
pub fn import_archive(
    archive: &[u8],
    exporter: &TrustedExporter,
    environment: &ImportEnvironment,
    clock: &dyn Clock,
) -> Result<ImportedBundle, InterchangeError> {
    // Stage 1: the size cap, before any JSON work.
    if archive.len() > MAX_ARCHIVE_BYTES {
        return Err(InterchangeError::ArchiveTooLarge {
            limit: MAX_ARCHIVE_BYTES,
        });
    }

    // Stage 2: the container. `deny_unknown_fields` refuses a fourth member (an unprotected
    // header, a second copy of the artifact) rather than ignoring it.
    let container: SignedArchive =
        serde_json::from_slice(archive).map_err(|_| InterchangeError::ArchiveMalformed)?;
    let compact = container.to_compact()?;

    // Stage 3: the one verification. Trust comes entirely from the policy: `EdDSA` only, the
    // exporter's keys only, the exporter's issuer pinned exactly, and the archive's own media type
    // required. Nothing in the archive selects a key or an algorithm.
    let policy = VerificationPolicy::new(
        vec![JwsAlgorithm::EdDsa],
        exporter.keys.clone(),
        exporter.issuer.clone(),
        INTERCHANGE_AUDIENCE,
        ExpectedTyp::Required(TokenTyp::JourneyInterchange),
    )
    .map_err(|_| InterchangeError::TrustAnchorUnusable)?
    .with_caps(VerificationCaps {
        // A document, not a token: the payload cap is raised and nothing else is.
        max_token_bytes: MAX_ARCHIVE_BYTES,
        max_payload_bytes: MAX_PAYLOAD_BYTES,
        ..VerificationCaps::DEFAULT
    })
    .require_iat(true);
    let verified = verify(&compact, &policy, clock)
        .map_err(|error| InterchangeError::SignatureRejected(error.reason()))?;

    // Stage 4: the shape of the VERIFIED payload. `claims.raw()` is the single parse of the exact
    // bytes the signature covered, produced by the verifier's duplicate-key-rejecting parser.
    // Everything below projects out of that one tree; nothing re-reads the bytes.
    let claims = verified.claims().raw();
    let mut present: Vec<&str> = claims.keys().map(String::as_str).collect();
    present.sort_unstable();
    if present != PAYLOAD_MEMBERS {
        return Err(InterchangeError::PayloadShape {
            detail: "the payload must carry exactly iss, aud, exp, iat, artifact, subflows, and manifest",
        });
    }
    // The verifier accepts `aud` as an array containing the expected value; an archive's audience
    // is the single profile string and nothing else.
    if claims.get("aud") != Some(&Value::String(INTERCHANGE_AUDIENCE.to_owned())) {
        return Err(InterchangeError::PayloadShape {
            detail: "aud must be exactly the interchange audience string",
        });
    }

    let artifact: Journey = project(claims, "artifact")?;
    let subflows: Vec<Subflow> = project(claims, "subflows")?;
    let manifest: SafetyManifest = project(claims, "manifest")?;

    // Stage 5: merge the out-of-line sub-flows into the artifact's own definition list, refusing
    // any id that would resolve to two bodies.
    let merged = merge_subflows(&artifact, &subflows)?;

    // Stage 6: the #92 load-time compile (compose, validate the source and the flattened result,
    // and check a reachable completion). Nothing below runs on an artifact that did not compile.
    let compiled = compile(&merged).map_err(InterchangeError::JourneyInvalid)?;

    // Stage 7: RE-DERIVE, then check the manifest's declaration against the derivation. The
    // manifest is never a source of capabilities, only a claim about them.
    let derived = derive_capabilities(&merged, &compiled);
    let missing: Vec<Capability> = derived
        .difference(&manifest.required_capabilities)
        .cloned()
        .collect();
    if !missing.is_empty() {
        return Err(InterchangeError::CapabilityUnderDeclared { missing });
    }
    let extra: Vec<Capability> = manifest
        .required_capabilities
        .difference(&derived)
        .cloned()
        .collect();
    if !extra.is_empty() {
        return Err(InterchangeError::CapabilityOverDeclared { extra });
    }

    // Stage 8: the launch constraints, each derived-and-compared where it can be and enforced
    // where it cannot.
    check_launch_constraints(&manifest.launch_constraints, &merged, &derived, environment)?;

    // Stage 9: the grant check, over the DERIVED set. This is the gate, and it does not read the
    // manifest, so it holds whatever the manifest said.
    let ungranted: Vec<Capability> = derived
        .iter()
        .filter(|capability| !environment.granted.contains(capability))
        .cloned()
        .collect();
    if !ungranted.is_empty() {
        return Err(InterchangeError::CapabilityNotGranted { missing: ungranted });
    }

    let artifact_json =
        crate::snapshot::canonical_json_string(&serde_json::to_value(&merged).map_err(|_| {
            InterchangeError::PayloadShape {
                detail: "the verified artifact could not be re-serialized",
            }
        })?);
    Ok(ImportedBundle {
        artifact: merged,
        artifact_json,
        capabilities: derived,
        exporter_issuer: exporter.issuer.clone(),
        key_id: verified.key_id().map(str::to_owned),
    })
}

/// Project one member of the verified claim tree into its typed shape.
///
/// This is a typed view of an ALREADY-PARSED value, not a second parse of the archive bytes: the
/// tree came from the verifier's one parse of the signature-covered payload, so there is nothing
/// for a typed view to disagree with.
fn project<T: serde::de::DeserializeOwned>(
    claims: &Map<String, Value>,
    member: &'static str,
) -> Result<T, InterchangeError> {
    let value = claims
        .get(member)
        .ok_or(InterchangeError::PayloadShape { detail: member })?;
    serde_json::from_value(value.clone())
        .map_err(|_| InterchangeError::PayloadShape { detail: member })
}

/// Whether a derived capability set needs the M11 decision sandbox.
///
/// A PROJECTION of the derived set, so `requires_sandbox` and `required_capabilities` cannot
/// disagree: there is one fact and two views of it.
fn requires_sandbox(capabilities: &BTreeSet<Capability>) -> bool {
    capabilities.contains(&Capability::fixed(FixedCapability::DECISION_SANDBOX))
}

/// Merge a bundle's out-of-line sub-flow definitions into the artifact's own list.
///
/// A bundle can carry sub-flow bodies both inside the artifact (`subflow_definitions`, the #92
/// inline form) and beside it (the bundle's `subflows` list, which is what makes the artifact
/// self-contained across an organization boundary). Two lists is two places one id could resolve
/// to, so the merge refuses ANY collision, within the bundle list or against the artifact's own,
/// rather than picking a winner.
fn merge_subflows(artifact: &Journey, subflows: &[Subflow]) -> Result<Journey, InterchangeError> {
    let mut merged = artifact.clone();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for definition in artifact
        .subflow_definitions
        .iter()
        .flatten()
        .chain(subflows.iter())
    {
        if !seen.insert(definition.id.as_str()) {
            return Err(InterchangeError::SubflowIdConflict {
                id: definition.id.clone(),
            });
        }
    }
    if !subflows.is_empty() {
        merged
            .subflow_definitions
            .get_or_insert_with(Vec::new)
            .extend_from_slice(subflows);
    }
    Ok(merged)
}

/// Check the launch constraints: derived-and-compared where the fact is structural, enforced
/// fail-closed where it is author intent.
fn check_launch_constraints(
    constraints: &LaunchConstraints,
    merged: &Journey,
    derived: &BTreeSet<Capability>,
    environment: &ImportEnvironment,
) -> Result<(), InterchangeError> {
    let derived_version = derive_min_engine_version(merged);
    if constraints.min_engine_version != derived_version {
        return Err(InterchangeError::EngineVersionMisdeclared {
            declared: constraints.min_engine_version,
            derived: derived_version,
        });
    }
    // Belt to compile's braces: `compile` already refuses an artifact declaring a version above
    // this build's, and this holds even if that rule ever moves.
    if constraints.min_engine_version > JOURNEY_ENGINE_VERSION {
        return Err(InterchangeError::EngineVersionUnsupported {
            declared: constraints.min_engine_version,
            supported: JOURNEY_ENGINE_VERSION,
        });
    }

    let derived_sandbox = requires_sandbox(derived);
    if constraints.requires_sandbox != derived_sandbox {
        return Err(InterchangeError::SandboxMisdeclared {
            declared: constraints.requires_sandbox,
            derived: derived_sandbox,
        });
    }

    if constraints.allowed_transports.is_empty() {
        return Err(InterchangeError::NoAllowedTransport);
    }
    // An environment offering NOTHING would make the loop below a no-op, so a manifest permitting
    // only some transport this deployment has never heard of would import cleanly. That is the
    // constraint being VACUOUSLY satisfied rather than fail-closed: the loop proves "every offered
    // transport is permitted" and an empty set proves that for free. Requiring at least one offered
    // transport is what turns it into "some permitted transport is actually served".
    if environment.offered_transports.is_empty() {
        return Err(InterchangeError::EnvironmentServesNoTransport);
    }
    // Fail closed in the only direction that is honest. Nothing can pin a stored journey to a
    // subset of an environment's transports, so an environment that would serve this journey over
    // a transport the author excluded cannot honor the constraint and refuses instead of ignoring.
    for transport in &environment.offered_transports {
        if !constraints.allowed_transports.contains(transport) {
            return Err(InterchangeError::TransportNotAllowed {
                transport: transport.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironauth_journey::{FieldRef, JOURNEY_SCHEMA_VERSION};

    fn step(id: &str, kind: StepKind, node_group: Option<&str>) -> Step {
        Step {
            id: id.to_owned(),
            kind,
            node_group: node_group.map(str::to_owned),
            subflow: None,
            decision: None,
            comment: None,
        }
    }

    /// A minimal load-valid journey: one first factor routing unconditionally to a terminal. It
    /// exercises NO guard, so `transition.guard` and every predicate capability are absent.
    fn plain_journey() -> Journey {
        Journey {
            schema_version: JOURNEY_SCHEMA_VERSION.to_owned(),
            id: "login_plain".to_owned(),
            engine_version: JOURNEY_ENGINE_VERSION,
            entry: "primary".to_owned(),
            comment: None,
            steps: vec![
                step("primary", StepKind::IdentifierPassword, Some("password")),
                step("done", StepKind::Terminal, None),
            ],
            transitions: vec![Transition {
                from: "primary".to_owned(),
                to: "done".to_owned(),
                guard: None,
                comment: None,
            }],
            subflows: None,
            subflow_definitions: None,
        }
    }

    fn compiled_capabilities(journey: &Journey) -> BTreeSet<Capability> {
        let compiled = compile(journey).expect("compiles");
        derive_capabilities(journey, &compiled)
    }

    #[test]
    fn the_fixed_vocabulary_has_no_duplicate_token_and_withholds_exactly_these() {
        // No duplicate token. The count that used to follow this loop (`seen.len()` against
        // `ALL.len()`) was unfalsifiable: `seen` is built by iterating `ALL` and every insert is
        // already asserted, so the two could not differ. That property is the macro's anyway.
        let mut seen = BTreeSet::new();
        for fixed in FixedCapability::ALL {
            assert!(
                seen.insert(fixed.as_wire()),
                "{} is declared twice",
                fixed.as_wire()
            );
        }
        // Exactly these are withheld, and each for a reason MEASURED against the shipped engine
        // rather than assumed: the five membership-and-subject-set entries because
        // `source_is_engine_live` marks `subject_groups` and `subject_scopes` NOT-LIVE (so the
        // load-time type check refuses every predicate that could reach them), and the two decision
        // entries because the engine does not consult a decision attachment at all. Pinning the
        // whole list makes a future capability granted by inattention a failing test rather than a
        // silent widening.
        let withheld: Vec<&str> = FixedCapability::ALL
            .iter()
            .filter(|fixed| !fixed.engine_grants())
            .map(|fixed| fixed.as_wire())
            .collect();
        assert_eq!(
            withheld,
            vec![
                "predicate.member",
                "predicate.field.subject_groups",
                "predicate.field.subject_scopes",
                "predicate.member.group",
                "predicate.member.scope",
                "decision.predicate",
                "decision.sandbox",
            ]
        );
    }

    /// No capability whose name carries an artifact-supplied identifier can ever spell a FIXED
    /// capability's token.
    ///
    /// The two namespaces meet in one flat set, so a collision would make two different
    /// capabilities one grant, and an operator granting the harmless one would silently grant the
    /// other. The prefixes make that unrepresentable; this is the check that keeps it so. Note
    /// `subflow.inline` is fixed while `subflow.builtin.<name>` is open, which is exactly the kind
    /// of near-miss the check exists for.
    #[test]
    fn no_artifact_supplied_capability_token_can_collide_with_a_fixed_one() {
        for fixed in FixedCapability::ALL {
            for prefix in ["step.", "node_group.", "subflow.builtin."] {
                assert!(
                    !fixed.as_wire().starts_with(prefix),
                    "{} sits inside the {prefix} namespace",
                    fixed.as_wire()
                );
            }
        }
        // And the three open-ended constructors really do emit those prefixes, so the check above
        // is about the namespaces actually in use rather than three strings nothing produces.
        assert!(
            Capability::step(&StepKind::Terminal)
                .as_wire()
                .starts_with("step.")
        );
        assert!(
            Capability::node_group("password")
                .as_wire()
                .starts_with("node_group.")
        );
        assert!(
            Capability::builtin_subflow("mfa_step_up")
                .as_wire()
                .starts_with("subflow.builtin.")
        );
    }

    /// The engine's NOT-LIVE field sources really are refused by the load-time type check, which
    /// is the measurement the withheld grants above rest on.
    ///
    /// Without this the withheld list would be an assertion about the journey crate that nothing
    /// checks, and if that crate lit the sources up the grant declaration here would quietly
    /// become wrong in the FAIL-CLOSED direction (bundles refused for a capability the engine now
    /// serves). That is the safe direction, but it should still be a failing test rather than a
    /// mystery.
    #[test]
    fn the_withheld_subject_set_sources_are_refused_by_the_journey_type_check() {
        let mut journey = plain_journey();
        journey.transitions[0].guard = Some(Predicate::Member {
            field: FieldRef {
                source: FieldSource::SubjectGroups,
                pointer: String::new(),
            },
            set: MemberSet::Group {
                name: "staff".to_owned(),
            },
        });
        let errors = compile(&journey).expect_err("the engine refuses a not-live source");
        assert!(
            errors
                .iter()
                .any(|error| matches!(error, JourneyError::PredicateType(_))),
            "expected a predicate type error, got {errors:?}"
        );
    }

    /// The deriver names the withheld membership vocabulary even though no compilable artifact can
    /// reach it today, so the day the engine lights those sources up the capability is already
    /// visible rather than silently unmodelled.
    #[test]
    fn the_deriver_names_the_membership_vocabulary_the_engine_does_not_yet_serve() {
        let mut derived = BTreeSet::new();
        walk_predicate(
            &Predicate::Member {
                field: FieldRef {
                    source: FieldSource::SubjectScopes,
                    pointer: String::new(),
                },
                set: MemberSet::Scope {
                    name: "admin".to_owned(),
                },
            },
            &mut derived,
        );
        assert_eq!(
            derived,
            [
                FixedCapability::PREDICATE_MEMBER,
                FixedCapability::FIELD_SUBJECT_SCOPES,
                FixedCapability::MEMBER_SCOPE,
            ]
            .into_iter()
            .map(Capability::fixed)
            .collect::<BTreeSet<_>>()
        );
        // And none of the three is granted, so such a bundle would be refused twice over.
        let granted = GrantedCapabilities::engine_default();
        for capability in &derived {
            assert!(!granted.contains(capability), "{capability} is granted");
        }
    }

    #[test]
    fn the_engine_default_grant_covers_every_granted_fixed_capability_and_no_withheld_one() {
        let granted = GrantedCapabilities::engine_default();
        for fixed in FixedCapability::ALL {
            let capability = Capability::fixed(fixed);
            assert_eq!(
                granted.contains(&capability),
                fixed.engine_grants(),
                "{} grant state",
                fixed.as_wire()
            );
        }
        // Every custom-usable step kind is granted and every built-in-only one is not: a custom
        // artifact may not name the mint family at all.
        for wire in StepKind::BUILT_IN {
            let kind = StepKind::from_wire(wire);
            assert_eq!(
                granted.contains(&Capability::step(&kind)),
                !kind.is_builtin_only(),
                "{wire} grant state"
            );
        }
        for group in NODE_GROUPS {
            assert!(granted.contains(&Capability::node_group(group)), "{group}");
        }
        for name in builtin_subflows().keys() {
            assert!(
                granted.contains(&Capability::builtin_subflow(name)),
                "{name}"
            );
        }
    }

    #[test]
    fn the_deriver_sees_a_step_kind_a_node_group_and_nothing_it_does_not_exercise() {
        let derived = compiled_capabilities(&plain_journey());
        assert!(derived.contains(&Capability::step(&StepKind::IdentifierPassword)));
        assert!(derived.contains(&Capability::step(&StepKind::Terminal)));
        assert!(derived.contains(&Capability::node_group("password")));
        // The journey has no guard, so nothing predicate-shaped is derived. This is the half that
        // makes the derivation a measurement rather than a constant.
        assert!(!derived.contains(&Capability::fixed(FixedCapability::TRANSITION_GUARD)));
        assert!(!derived.contains(&Capability::fixed(FixedCapability::PREDICATE_CMP)));
        assert!(!derived.contains(&Capability::node_group("totp")));
    }

    /// A journey whose guards between them reach every predicate form, operator, engine-LIVE
    /// context source, and literal type the grammar has.
    fn every_corner_journey() -> Journey {
        let mut journey = plain_journey();
        journey
            .steps
            .push(step("mfa", StepKind::MfaChallenge, Some("totp")));
        journey.transitions[0].guard = Some(Predicate::And {
            operands: vec![
                Predicate::Cmp {
                    field: FieldRef {
                        source: FieldSource::Signals,
                        pointer: "/mfa_required".to_owned(),
                    },
                    op: CmpOp::Ne,
                    value: Literal::Bool(true),
                },
                Predicate::Not {
                    operand: Box::new(Predicate::Or {
                        operands: vec![
                            Predicate::In {
                                field: FieldRef {
                                    source: FieldSource::Risk,
                                    pointer: "/level".to_owned(),
                                },
                                values: vec![Literal::String("low".to_owned()), Literal::Null],
                            },
                            Predicate::Cmp {
                                field: FieldRef {
                                    source: FieldSource::Flow,
                                    pointer: "/step_id".to_owned(),
                                },
                                op: CmpOp::Eq,
                                value: Literal::String("primary".to_owned()),
                            },
                            Predicate::Never,
                        ],
                    }),
                },
            ],
        });
        journey.transitions.push(Transition {
            from: "primary".to_owned(),
            to: "mfa".to_owned(),
            guard: Some(Predicate::Cmp {
                field: FieldRef {
                    source: FieldSource::SubjectTraits,
                    pointer: "/tier".to_owned(),
                },
                op: CmpOp::Ge,
                value: Literal::Number(serde_json::Number::from(3)),
            }),
            comment: None,
        });
        journey.transitions.push(Transition {
            from: "mfa".to_owned(),
            to: "done".to_owned(),
            guard: None,
            comment: None,
        });
        journey
    }

    #[test]
    fn the_deriver_reaches_every_corner_of_a_predicate() {
        let derived = compiled_capabilities(&every_corner_journey());
        for expected in [
            FixedCapability::TRANSITION_GUARD,
            FixedCapability::PREDICATE_AND,
            FixedCapability::PREDICATE_OR,
            FixedCapability::PREDICATE_NOT,
            FixedCapability::PREDICATE_CMP,
            FixedCapability::PREDICATE_IN,
            FixedCapability::PREDICATE_NEVER,
            FixedCapability::OP_NE,
            FixedCapability::OP_EQ,
            FixedCapability::OP_GE,
            FixedCapability::FIELD_SIGNALS,
            FixedCapability::FIELD_RISK,
            FixedCapability::FIELD_FLOW,
            FixedCapability::FIELD_SUBJECT_TRAITS,
            FixedCapability::LITERAL_BOOL,
            FixedCapability::LITERAL_NULL,
            FixedCapability::LITERAL_STRING,
            FixedCapability::LITERAL_NUMBER,
        ] {
            assert!(
                derived.contains(&Capability::fixed(expected)),
                "{} was not derived",
                expected.as_wire()
            );
        }
        // Nothing the guard does not use appears.
        for absent in [
            FixedCapability::PREDICATE_ALWAYS,
            FixedCapability::PREDICATE_MEMBER,
            FixedCapability::OP_LT,
            FixedCapability::OP_LE,
            FixedCapability::OP_GT,
            FixedCapability::MEMBER_GROUP,
            FixedCapability::MEMBER_SCOPE,
            FixedCapability::FIELD_SUBJECT_GROUPS,
            FixedCapability::FIELD_SUBJECT_SCOPES,
            FixedCapability::DECISION_SANDBOX,
            FixedCapability::DECISION_PREDICATE,
            FixedCapability::SUBFLOW_INLINE,
        ] {
            assert!(
                !derived.contains(&Capability::fixed(absent)),
                "{} was derived but is not exercised",
                absent.as_wire()
            );
        }
    }

    #[test]
    fn the_deriver_sees_inside_a_builtin_subflow_the_bundle_never_names() {
        // The bundle names `mfa_step_up` and nothing else. Its BODY (an mfa_challenge step under
        // the totp node group) lives in the IMPORTING environment's registry and is spliced in at
        // composition, so a deriver that walked only the source document would miss both.
        let mut journey = plain_journey();
        journey.steps.push(Step {
            subflow: Some("mfa_step_up".to_owned()),
            ..step("call", StepKind::SubflowCall, None)
        });
        journey.transitions[0].to = "call".to_owned();
        journey.transitions.push(Transition {
            from: "call".to_owned(),
            to: "done".to_owned(),
            guard: None,
            comment: None,
        });
        journey.subflows = Some(vec![SubflowRef {
            id: "mfa_step_up".to_owned(),
            source: SubflowSource::Builtin {
                name: "mfa_step_up".to_owned(),
            },
        }]);

        let derived = compiled_capabilities(&journey);
        assert!(
            derived.contains(&Capability::step(&StepKind::MfaChallenge)),
            "the spliced built-in body's step kind is derived"
        );
        assert!(
            derived.contains(&Capability::node_group("totp")),
            "the spliced built-in body's node group is derived"
        );
        // And the source-only facts composition erases are derived too.
        assert!(derived.contains(&Capability::step(&StepKind::SubflowCall)));
        assert!(derived.contains(&Capability::builtin_subflow("mfa_step_up")));
    }

    #[test]
    fn a_decision_attachment_derives_the_withheld_sandbox_capability() {
        let mut journey = plain_journey();
        journey.steps.push(Step {
            decision: Some(DecisionSpec::Predicate {
                predicate: Predicate::Always,
            }),
            ..step("branch", StepKind::Decision, None)
        });
        journey.transitions[0].to = "branch".to_owned();
        journey.transitions.push(Transition {
            from: "branch".to_owned(),
            to: "done".to_owned(),
            guard: None,
            comment: None,
        });

        let derived = compiled_capabilities(&journey);
        assert!(derived.contains(&Capability::fixed(FixedCapability::DECISION_SANDBOX)));
        assert!(derived.contains(&Capability::fixed(FixedCapability::DECISION_PREDICATE)));
        assert!(derived.contains(&Capability::fixed(FixedCapability::PREDICATE_ALWAYS)));
        assert!(requires_sandbox(&derived));
        // The shipped engine withholds BOTH, so this bundle cannot import as things stand. The
        // pair moves together on purpose: `walk_decision` derives the sandbox unconditionally
        // before it matches the spec form, so the predicate entry cannot be reached without it.
        let granted = GrantedCapabilities::engine_default();
        assert!(!granted.contains(&Capability::fixed(FixedCapability::DECISION_SANDBOX)));
        assert!(!granted.contains(&Capability::fixed(FixedCapability::DECISION_PREDICATE)));
    }

    /// The premise `walk_nested_subflow_calls` rests on: a nested `subflow_call` key that
    /// resolves in the BUILT-IN registry really is the built-in, never a bundle-supplied definition
    /// wearing its name.
    ///
    /// If an inline definition could be called `mfa_step_up`, the walk would derive
    /// `subflow.builtin.mfa_step_up` for a body the bundle carried itself, which is an
    /// over-derivation in one direction and, worse, would let a bundle SHADOW a built-in the
    /// operator granted. The journey crate forecloses it at load, and this is the measurement
    /// rather than a reading of that code.
    #[test]
    fn a_bundle_defining_a_subflow_named_like_a_builtin_is_refused() {
        for name in builtin_subflows().keys() {
            let mut journey = plain_journey();
            journey.subflow_definitions = Some(vec![Subflow {
                id: name.clone(),
                entry: "shadow".to_owned(),
                exits: vec!["shadow".to_owned()],
                comment: None,
                steps: vec![step("shadow", StepKind::MfaEnroll, Some("email_otp"))],
                transitions: vec![],
            }]);
            let errors = compile(&journey).expect_err("an inline id shadowing a built-in");
            assert!(
                errors.iter().any(|error| matches!(
                    error,
                    JourneyError::DuplicateSubflowDefinition { id, .. } if id == name
                )),
                "expected a DuplicateSubflowDefinition for {name}, got {errors:?}"
            );
        }
    }

    /// The nested walk terminates on a built-in that calls itself.
    ///
    /// No shipped built-in nests a call at all, so this cannot be built from the real registry.
    /// It is built by handing the walk an INLINE definition that names the built-in and letting
    /// the built-in body be re-entered: the `visited` set is what stops the second visit, and the
    /// assertion is simply that the call returns. A walk that re-pushed an already-visited body
    /// would hang here rather than fail, which is the point of pinning it.
    #[test]
    fn the_nested_subflow_walk_terminates_when_two_definitions_name_the_same_builtin() {
        let call = |id: &str, key: &str| Subflow {
            id: id.to_owned(),
            entry: "inner".to_owned(),
            exits: vec!["inner".to_owned()],
            comment: None,
            steps: vec![Step {
                subflow: Some(key.to_owned()),
                ..step("inner", StepKind::SubflowCall, None)
            }],
            transitions: vec![],
        };
        let mut journey = plain_journey();
        journey.subflow_definitions = Some(vec![
            // Two definitions naming the same built-in, and a pair naming each other: every edge
            // the walk can follow, including a cycle between two inline bodies.
            call("first", "mfa_step_up"),
            call("second", "mfa_step_up"),
            call("ping", "pong"),
            call("pong", "ping"),
        ]);
        let mut out = BTreeSet::new();
        walk_nested_subflow_calls(&journey, &mut out);
        assert!(out.contains(&Capability::builtin_subflow("mfa_step_up")));
        assert!(out.contains(&Capability::fixed(FixedCapability::SUBFLOW_INLINE)));
    }

    #[test]
    fn a_bundle_carrying_a_subflow_id_the_artifact_already_defines_is_refused() {
        let definition = Subflow {
            id: "shared".to_owned(),
            entry: "challenge".to_owned(),
            exits: vec!["challenge".to_owned()],
            comment: None,
            steps: vec![step("challenge", StepKind::MfaChallenge, Some("totp"))],
            transitions: vec![],
        };
        let mut journey = plain_journey();
        journey.subflow_definitions = Some(vec![definition.clone()]);
        assert_eq!(
            merge_subflows(&journey, std::slice::from_ref(&definition)),
            Err(InterchangeError::SubflowIdConflict {
                id: "shared".to_owned()
            })
        );
        // Two copies in the BUNDLE list alone are refused too.
        assert_eq!(
            merge_subflows(&plain_journey(), &[definition.clone(), definition]),
            Err(InterchangeError::SubflowIdConflict {
                id: "shared".to_owned()
            })
        );
    }

    #[test]
    fn an_archive_segment_carrying_a_dot_is_refused_before_verification() {
        let archive = SignedArchive {
            protected: "aGVhZGVy".to_owned(),
            payload: "cGF5.bG9hZA".to_owned(),
            signature: "c2ln".to_owned(),
        };
        assert_eq!(
            archive.to_compact(),
            Err(InterchangeError::ArchiveSegmentMalformed)
        );
        // So is an empty one.
        let archive = SignedArchive {
            protected: String::new(),
            payload: "cGF5".to_owned(),
            signature: "c2ln".to_owned(),
        };
        assert_eq!(
            archive.to_compact(),
            Err(InterchangeError::ArchiveSegmentMalformed)
        );
    }

    #[test]
    fn a_trust_anchor_with_no_issuer_or_no_key_is_refused() {
        assert_eq!(
            TrustedExporter::from_keys("", Vec::new()).map(|_| ()),
            Err(InterchangeError::TrustAnchorUnusable)
        );
        // A JWKS document naming no key this core can verify with is unusable, not empty-but-fine.
        assert_eq!(
            TrustedExporter::from_jwks("https://exporter.test", br#"{"keys":[]}"#).map(|_| ()),
            Err(InterchangeError::TrustAnchorUnusable)
        );
    }
}
