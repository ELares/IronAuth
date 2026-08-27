// SPDX-License-Identifier: MIT OR Apache-2.0

//! Declarative claims mapping (issue #113, acceptance criteria 4 and 5).
//!
//! > Declarative mappings cover renames, group filtering, static claims, and ID-versus-access-
//! > token placement with NO CUSTOM CODE.
//!
//! Four operations, configured as data. The point of the criterion is the "no custom code": an
//! operator who wants `groups` renamed to `team_groups` in the access token should not need a
//! hook, a WASM module, or a CEL expression. Those exist for the cases this cannot express;
//! this exists so they are not needed for the cases it can.
//!
//! The example says `team_groups` rather than `roles`, and the correction is worth keeping.
//! `roles` is RESERVED at the token mint, where `tokens.rs` drops a self-asserted one rather
//! than emitting it -- so the obvious illustration was a rename this layer would have accepted
//! and the mint would have silently discarded. That is exactly the "quietly inert forever"
//! outcome the refusal below exists to prevent, and writing it into the header as the flagship
//! use case would have taught every reader the wrong thing.
//!
//! # Protected claims are refused, not dropped
//!
//! Criterion 5: `iss`, `sub`, `aud`, `exp` and `iat` "cannot be overridden by any mapping or
//! hook; attempts are rejected and audited".
//!
//! REJECTED, which is stronger than ignored and deliberately so. A mapping that silently
//! dropped a rule targeting `sub` would leave an operator believing they had rewritten the
//! subject, and the first they would learn otherwise is a downstream system reading a `sub`
//! they did not expect. A typed refusal names the rule and the claim, so the configuration is
//! wrong at the moment it is written rather than quietly inert forever.
//!
//! The AUDIT half belongs to the caller: this module is pure and writes nothing. It returns
//! which rule was refused and why, so the caller has something specific to record.
//!
//! # What order means here
//!
//! Rules apply in the order given, and that is observable: a rename followed by a static claim
//! of the same name behaves differently from the reverse. Rather than declare one ordering
//! canonical and hide it, the sequence is the operator's and this applies it as written.

use std::collections::BTreeMap;

use crate::scope_claims::is_protected_claim;
use crate::tokens::PROTECTED_ACCESS_TOKEN_CLAIMS;

/// Whether a mapping may write `name`.
///
/// The union of the release floor and the MINT fold, not the floor alone. `PROTECTED_CLAIMS`
/// is five names; `PROTECTED_ACCESS_TOKEN_CLAIMS` is twenty-five, and the extra twenty are the
/// ones something makes a decision on: `scope` authorizes IronAuth's own management API, `cnf`
/// drives `DPoP` proof-of-possession, and `permissions`/`roles`/`org_id` are what `tokens.rs`
/// calls "the only claims in the set a resource server makes an ACCESS decision on, so a
/// self-asserted one is a privilege escalation rather than a cosmetic lie".
///
/// The repo already said the five were a floor. `scope_claims`'s own superset test carries the
/// sentence: "the mint fold is the second fence and must not be narrower than the FIRST". This
/// module gated on the floor, which made it the one operator-facing claim path in the tree that
/// would admit `scope` or `permissions` -- the ID-token extra claims, the client-credentials
/// custom claims, and the enrichment hook's config-load check all refuse them already.
fn is_writable_by_a_mapping(name: &str) -> bool {
    !is_protected_claim(name) && !PROTECTED_ACCESS_TOKEN_CLAIMS.contains(&name)
}

/// The most claims a hook may contribute to one token.
///
/// Deliberately the enrichment hook's bound, not a number chosen here, because the sentence
/// `ironauth-config` wrote beside that one applies verbatim and more strongly: "a claim is
/// cheap to send and expensive to carry, since every one of them rides in every token this
/// subject is issued from now on. The token-size budget (issue #98) is the backstop that
/// refuses an over-large token; this is what stops a misbehaving FGA pushing a thousand claims
/// into that budget in the first place."
///
/// More strongly, because the enrichment hook's filter is an ALLOWLIST an operator populates a
/// name at a time, so its output is bounded by construction. A pre-token hook is a DENYLIST
/// applied to code an integrator deployed, so without this it is unbounded. The more
/// privileged of the two hooks must not have the weaker bound.
///
/// Tied by definition rather than copied, so the two cannot drift apart silently.
pub const MAX_HOOK_CLAIMS: usize = ironauth_config::OIDC_MAX_ENRICHED_CLAIMS;

/// The longest a claim name may be, in bytes.
///
/// A name is a JWT object key that rides in every token and every log line that records the
/// attempt. Nothing legitimate needs more than this; a hook that sends more is either broken or
/// is using the audit trail as a write buffer.
///
/// BYTES, not characters, and the distinction is load-bearing: a cap counted in `char`s would
/// admit four times its stated budget in UTF-8, so the limit would be a different number from
/// the one its name promises.
pub const MAX_CLAIM_NAME_BYTES: usize = 128;

/// What is safe to put in an audit row for a claim named `name`.
///
/// The bound has to apply to BOTH outputs or it is not a bound. Refusing a ten-megabyte claim
/// name and then copying it verbatim into the list a caller is documented to write into an
/// audit row means the limit protects the token and hands the same bytes to the log instead: a
/// hook returning many such names turns the audit sink into its write buffer, which is the
/// exact thing this constant exists to prevent.
///
/// Truncation is on a CHARACTER boundary, because slicing a `String` mid-codepoint panics, and
/// a panic here would be reached by exactly the input this function exists to survive.
fn reportable(name: &str) -> String {
    if name.len() <= MAX_CLAIM_NAME_BYTES {
        return name.to_owned();
    }
    let mut end = MAX_CLAIM_NAME_BYTES;
    while end > 0 && !name.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &name[..end])
}

/// The one judgement both fences make about a claim name.
///
/// Both halves of criterion 5 call this and nothing else, so they are not two fences kept in
/// agreement, they are one fence with two callers. That distinction matters for what the tests
/// have to do: a test comparing the two callers to each other cannot fail, because there is
/// only one list to disagree with. The tests that hold this honest are the ones that assert
/// ABSOLUTELY, naming the claims that must be refused.
///
/// Returns [`None`] if the name may be written.
fn refuse_name(name: &str) -> Option<RefusalReason> {
    if name.trim().is_empty() {
        return Some(RefusalReason::EmptyName);
    }
    // Refused rather than trimmed, and the difference is the whole point. Trimming would make
    // `"sub "` into `sub`, so a padded name would either collide with a claim already present
    // or silently become the reserved one it was padded to evade. Refusing means the string
    // this function judged and the string a caller stores are the same string, so there is no
    // whitespace-padded second form of a name for a TRIMMING normalisation to collapse.
    //
    // Only trimming. Case is a separate axis this does not close: `"SUB"` is accepted, and is
    // correct today because a JWT key is case-sensitive and `SUB` overrides nothing. A later
    // `to_lowercase()` on accepted keys WOULD collapse it onto `sub`, so that normalisation is
    // not safe to add without a case-folded membership test here first.
    if name != name.trim() {
        return Some(RefusalReason::Untrimmed);
    }
    if name.len() > MAX_CLAIM_NAME_BYTES {
        return Some(RefusalReason::NameTooLong);
    }
    if !is_writable_by_a_mapping(name) {
        return Some(RefusalReason::Reserved);
    }
    None
}

/// Which token a claim is written into.
///
/// The wire names are `id_token`, `access_token` and `both`, which is how an operator writes
/// them in a stored rule document and how a config snapshot carries them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Placement {
    /// The ID token only. Identity for the client's own use.
    IdToken,
    /// The access token only. Authorization data for a resource server, which should not need
    /// the whole identity to make a decision.
    AccessToken,
    /// Both. Never the default: a claim no rule places stays in the ID token, where the
    /// extra-claims bag went before this layer had a reader. Reaching an access token is a
    /// thing a mapping must ASK for, because that token is read by every resource server in
    /// the audience.
    Both,
}

/// One declarative operation.
///
/// # The stored wire format
///
/// A rule is an object tagged by `kind`, which is the shape `claims_mappings.rules` holds and
/// the shape a config snapshot carries:
///
/// ```json
/// [
///   {"kind": "rename", "from": "dept", "to": "department"},
///   {"kind": "static", "name": "tier", "value": "gold"},
///   {"kind": "filter_list", "name": "groups", "allow": ["eng", "sre"]},
///   {"kind": "place", "name": "department", "placement": "access_token"}
/// ]
/// ```
///
/// `deny_unknown_fields`, deliberately. A rule with a field this version does not know is a
/// rule this version cannot carry out, and the unknown field is as likely to be the part that
/// RESTRICTS something as the part that adds it -- an `except` on a filter, a condition on a
/// static. Ignoring it would apply a weaker rule than the operator wrote while reporting
/// success. See [`parse`] for what happens to such a document at issuance.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MappingRule {
    /// Rename a claim. The source is removed and its value written under the new name.
    Rename {
        /// The claim to take the value from.
        from: String,
        /// The name to write it under.
        to: String,
    },
    /// Write a constant. Overwrites whatever a previous rule left under the name.
    Static {
        /// The claim to write.
        name: String,
        /// The value, as parsed JSON so an operator can configure an object or a list.
        value: serde_json::Value,
    },
    /// Keep only the listed members of a claim whose value is a list of strings.
    ///
    /// The common case is group filtering: an environment with three thousand groups should not
    /// put all of them in every token, and which ones matter is per-client configuration rather
    /// than code.
    FilterList {
        /// The claim to filter.
        name: String,
        /// The members to keep. A member not present in the value is not an error: the rule
        /// says what may pass, not what must be there.
        allow: Vec<String>,
    },
    /// Place a claim in one token or both.
    Place {
        /// The claim to place.
        name: String,
        /// Where it goes.
        placement: Placement,
    },
}

impl MappingRule {
    /// The claim this rule WRITES, which is the one a protected-claim check must look at.
    ///
    /// A `Rename` writes its destination: reading `sub` and writing `subject` is allowed, and
    /// it is writing INTO `sub` that is refused. Getting this backwards would forbid the safe
    /// direction and permit the unsafe one.
    fn written_claim(&self) -> &str {
        match self {
            Self::Rename { to, .. } => to,
            Self::Static { name, .. }
            | Self::FilterList { name, .. }
            | Self::Place { name, .. } => name,
        }
    }
}

/// Why a mapping was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingRefusal {
    /// Which rule, by position, so an operator can find it in a list of forty.
    pub rule_index: usize,
    /// The claim it tried to write.
    pub claim: String,
    /// Why.
    pub reason: RefusalReason,
}

/// Why a rule was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// The claim is reserved: the protocol's own, or one something makes a decision on.
    Reserved,
    /// The claim name is empty or only whitespace.
    ///
    /// Refused for the reason the enrichment hook's config-load check refuses it: a claim with
    /// no name is not a claim, and a mapping that wrote one would put a key nobody can address
    /// into every token.
    EmptyName,
    /// The claim name has leading or trailing whitespace.
    ///
    /// Its own reason rather than folded into [`Self::Reserved`], because it is a different
    /// mistake with a different fix: `"sub "` is not an attempt to write a reserved claim that
    /// the fence caught, it is a name that would have become one under any normalisation. The
    /// operator-facing message says which, so the fix is "remove the space" rather than
    /// "choose a different claim".
    Untrimmed,
    /// The claim name is longer than [`MAX_CLAIM_NAME_BYTES`].
    NameTooLong,
    /// A hook returned more than [`MAX_HOOK_CLAIMS`] writable claims.
    ///
    /// Produced only by [`filter_hook_claims`]. A mapping's length is bounded when it is
    /// written, by an operator who can see the list; a hook's is not bounded by anything until
    /// here.
    TooManyClaims,
}

impl RefusalReason {
    /// How this reason reads on its own, without a rule index.
    ///
    /// Separate from [`MappingRefusal`]'s `Display` because the two halves of the fence refuse
    /// different shapes: a mapping refusal has a rule number an operator can look up, and a
    /// hook refusal has only a claim name. A single `Display` covering both had to invent a
    /// rule index for [`Self::TooManyClaims`], which no mapping can ever produce, and that arm
    /// was unreachable text nobody could read.
    pub(crate) fn describe(self, claim: &str) -> String {
        match self {
            Self::Reserved => {
                format!("writes the reserved claim `{claim}`, which nothing may set")
            }
            Self::EmptyName => "writes a claim with an empty name".to_owned(),
            Self::Untrimmed => {
                format!("writes the claim `{claim}`, whose name has leading or trailing whitespace")
            }
            Self::NameTooLong => {
                format!("writes a claim whose name is over the {MAX_CLAIM_NAME_BYTES} byte limit")
            }
            Self::TooManyClaims => {
                format!("returns more than the {MAX_HOOK_CLAIMS} claim limit")
            }
        }
    }
}

impl core::fmt::Display for RefusalReason {
    /// Renders WITHOUT a claim name, because this impl does not have one.
    ///
    /// The obvious implementation delegates to [`Self::describe`] with a placeholder, and that
    /// is a trap: `format!("{reason}")` would then print a literal `<claim>` into an audit row
    /// where an operator expects the claim that was refused. A caller holding the name should
    /// call `describe` with it; this is what is honest to say when nobody does.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = match self {
            Self::Reserved => "a reserved claim, which nothing may set",
            Self::EmptyName => "a claim with an empty name",
            Self::Untrimmed => "a claim name with leading or trailing whitespace",
            Self::NameTooLong => "a claim name over the byte limit",
            Self::TooManyClaims => "more claims than the limit allows",
        };
        f.write_str(text)
    }
}

impl core::fmt::Display for MappingRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "rule {} {}",
            self.rule_index,
            self.reason.describe(&self.claim)
        )
    }
}

impl std::error::Error for MappingRefusal {}

/// The claims a mapping produced, split by the token they belong in.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MappedClaims {
    /// Claims for the ID token.
    pub id_token: BTreeMap<String, serde_json::Value>,
    /// Claims for the access token.
    pub access_token: BTreeMap<String, serde_json::Value>,
}

/// Parse a stored rule document into rules that can be applied.
///
/// The store carries `claims_mappings.rules` as a JSON string on purpose: `ironauth-store`
/// cannot depend on this crate, so a second definition of the rule shape there would be two
/// definitions of one wire format. This is the single place that turns the document back into
/// rules, against the one definition that governs it.
///
/// # What a failure here means, and why the caller must fail CLOSED
///
/// The admin write path validates before storing and the table constrains the document's shape,
/// so a stored document that does not parse is a downgrade, a hand-edited row, or corruption.
/// It is tempting to treat that as "no mapping" and issue the token unmapped. That is the wrong
/// direction and it is worth being explicit about why: a mapping is as likely to REMOVE a claim
/// as to add one. `filter_list` on `groups` exists precisely so a token does not carry three
/// thousand group names, and `place` exists so a claim stays out of the access token. Falling
/// back to "unmapped" on a document nobody could read would emit the UNFILTERED claim set --
/// more than the operator configured, from a rule set nobody could evaluate.
///
/// So the caller fails the issuance. Under-claiming is the safe failure for an enrichment; this
/// is not an enrichment.
///
/// # Errors
///
/// [`serde_json::Error`] if the document is not a JSON array of rules this version understands.
pub fn parse(rules_json: &str) -> Result<Vec<MappingRule>, serde_json::Error> {
    serde_json::from_str(rules_json)
}

/// Check a mapping without applying it.
///
/// Separate from [`apply`] because configuration should be refused when it is WRITTEN, not on
/// the first token issued from it. A caller that validates on write turns a protected-claim
/// mistake into an error the operator sees immediately; one that only validates at issuance
/// turns it into a failed login at an unpredictable time.
///
/// # Errors
///
/// [`MappingRefusal`] naming the first rule that writes a protected claim.
pub fn validate(rules: &[MappingRule]) -> Result<(), MappingRefusal> {
    for (index, rule) in rules.iter().enumerate() {
        let written = rule.written_claim();
        if let Some(reason) = refuse_name(written) {
            return Err(MappingRefusal {
                rule_index: index,
                // TRUNCATED, by the same function the hook path uses. `reportable`'s own doc
                // says "the bound has to apply to BOTH outputs or it is not a bound", and this
                // was the output it did not apply to: the name is reflected in a 400 body and
                // logged verbatim at issuance for a hand-edited row, so an unbounded one is an
                // unbounded string in two places a bound was supposed to cover.
                claim: reportable(written),
                reason,
            });
        }
    }
    Ok(())
}

/// How many tokens the caller is going to mint from this mapping's output.
///
/// The mapping model has two destinations because most grants mint two tokens. Three do not:
/// `client_credentials`, `jwt:bearer` and token exchange mint ONE access token and no ID token,
/// through `ClientCredentialsMintRequest`. Handing them a two-token answer forces the caller to
/// invent a projection, and the first one invented was a union -- which quietly INVERTED
/// `place: id_token`, the one rule whose entire meaning is "keep this out of the access token".
///
/// So the projection is made here, where the difference between "the operator placed this" and
/// "nothing placed this, so it defaulted" is still visible. After the partition below it is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    /// An ID token and an access token. Placement means what it says.
    TwoTokens,
    /// One access token, and no ID token to put anything in.
    ///
    /// An UNPLACED claim goes to the one token that exists: the operator expressed no opinion
    /// and dropping it would empty every machine token the day anyone installed a mapping.
    ///
    /// A claim placed `id_token` is NOT EMITTED. That rule exists to keep a claim away from the
    /// resource servers in `aud`, which is exactly who reads this token, so honouring it means
    /// leaving the claim out. `place: access_token` and `place: both` are emitted -- `both`
    /// names two tokens and one of them is this one.
    ///
    /// # A RULE ORDER THAT DISCLOSES, and it is not the one an earlier note here named
    ///
    /// `place` is keyed on a NAME and `rename` carries a placement across with the value, so
    /// placing the claim you then rename is safe and placing it afterwards is not:
    ///
    /// - `place(email -> id_token)` THEN `rename(email -> contact)` moves the placement onto
    ///   `contact`, which is withheld here as asked.
    /// - `rename(email -> contact)` THEN `place(email -> id_token)` places a name that no
    ///   longer exists. `contact` is UNPLACED, and unplaced on this destination means the one
    ///   token there is -- so the claim the operator asked to keep out of an access token is in
    ///   one, under a different name.
    ///
    /// Under `TwoTokens` the same slip is invisible: unplaced defaults to the ID token, which
    /// is where the placement would have put it anyway. The order only becomes a disclosure
    /// when there is one token, which is why it is written down here.
    ///
    /// `a_place_after_a_rename_names_nothing_and_the_claim_is_emitted` pins both orders.
    ///
    /// An earlier version of this section named a different pair -- `place(a)` then
    /// `rename(b -> a)` against its reverse -- and called them opposite. Measured: they are
    /// identical and both withhold, because in one order the placement is written onto the
    /// destination name and in the other it is carried onto it. That note taught the safe order
    /// as the dangerous one, which is worse than no note, and the test above asserts the
    /// correction so it cannot rot back.
    OneAccessToken,
}

/// Apply `rules` to `source`, projecting onto `destination`.
///
/// Validates first, so an unvalidated mapping cannot half-apply: a refusal leaves the caller
/// with no claims rather than with the claims the rules before the bad one produced.
///
/// # Errors
///
/// [`MappingRefusal`], exactly as [`validate`].
pub fn apply_for(
    rules: &[MappingRule],
    source: &BTreeMap<String, serde_json::Value>,
    destination: Destination,
) -> Result<MappedClaims, MappingRefusal> {
    validate(rules)?;

    let mut working = source.clone();
    // Placement is decided per claim, and a claim nothing places goes where it went BEFORE any
    // mapping existed: the ID token.
    //
    // This read `Both` at first, with a comment claiming that WAS the prior behaviour. It was
    // not, and the mistake is worth keeping written down because it made the feature a
    // WIDENING. `MintRequest::access_extra_claims` had no writer before this seam -- that is
    // why `tokens::no_extra_claims()` existed -- so the extra-claims bag reached the ID token
    // only. Measured: installing a mapping of one unrelated `static` rule put `email` and
    // `email_verified` into the access token of every resource server in `aud`, for every
    // client with a mapping. An operator who added a claim would have disclosed several.
    //
    // A mapping may still put a claim in the access token. It has to SAY so, which is what
    // `place` is for and what criterion 4 asks for by name.
    let mut placements: BTreeMap<String, Placement> = BTreeMap::new();

    for rule in rules {
        match rule {
            MappingRule::Rename { from, to } => {
                // A PROTECTED source is COPIED, not moved. Renaming `sub` to `subject` is
                // allowed -- copying the identity into a claim of the operator's choosing is
                // theirs to do -- but the rename also REMOVED it, so `sub` vanished from both
                // tokens. Deleting a protected claim is overriding it: a token with no `sub`
                // is not a token whose `sub` an operator chose to leave out.
                let taken = if is_protected_claim(from) || !is_writable_by_a_mapping(from) {
                    working.get(from).cloned()
                } else {
                    // REMOVED for an ordinary claim. A rename that left the original behind
                    // would be a copy, and an operator renaming an internal name to stop
                    // leaking it would still be leaking it.
                    working.remove(from)
                };
                if let Some(value) = taken {
                    working.insert(to.clone(), value);
                    // The placement follows the value: a claim renamed after being placed keeps
                    // where it was put.
                    if let Some(placement) = placements.remove(from) {
                        placements.insert(to.clone(), placement);
                    }
                }
            }
            MappingRule::Static { name, value } => {
                working.insert(name.clone(), value.clone());
            }
            MappingRule::FilterList { name, allow } => {
                if let Some(serde_json::Value::Array(members)) = working.get(name) {
                    // A list holding anything that is NOT a string is left alone too, for the
                    // same reason a string is: the rule allows NAMES, so a list of objects is a
                    // configuration mistake rather than a list with nothing allowed in it. The
                    // first version filtered it to empty, which is precisely the silent data
                    // loss the comment below claims to avoid -- the comment was right and the
                    // code did not implement it.
                    if members.iter().all(serde_json::Value::is_string) {
                        let kept: Vec<serde_json::Value> = members
                            .iter()
                            .filter(|member| {
                                member
                                    .as_str()
                                    .is_some_and(|text| allow.iter().any(|a| a == text))
                            })
                            .cloned()
                            .collect();
                        working.insert(name.clone(), serde_json::Value::Array(kept));
                    }
                }
                // A claim that is absent, or is not a list of strings, is left ALONE rather
                // than emptied. Emptying it would turn a configuration mistake into silent
                // data loss in every token.
            }
            MappingRule::Place { name, placement } => {
                placements.insert(name.clone(), *placement);
            }
        }
    }

    let mut mapped = MappedClaims::default();
    for (name, value) in working {
        // The EXPLICIT placement, before the default is applied. On a one-token grant the two
        // must be told apart: `None` there means the operator said nothing and the claim goes
        // in the only token, while `Some(IdToken)` means the operator asked for it to stay out
        // of an access token and there is no other token to put it in.
        let placed = placements.get(&name).copied();
        match destination {
            Destination::OneAccessToken => match placed {
                Some(Placement::IdToken) => {}
                Some(Placement::AccessToken | Placement::Both) | None => {
                    mapped.access_token.insert(name, value);
                }
            },
            Destination::TwoTokens => match placed.unwrap_or(Placement::IdToken) {
                Placement::IdToken => {
                    mapped.id_token.insert(name, value);
                }
                Placement::AccessToken => {
                    mapped.access_token.insert(name, value);
                }
                Placement::Both => {
                    mapped.id_token.insert(name.clone(), value.clone());
                    mapped.access_token.insert(name, value);
                }
            },
        }
    }
    Ok(mapped)
}

#[cfg(test)]
mod tests {
    use super::{
        Destination, MappedClaims, MappingRule, Placement, RefusalReason, apply_for, validate,
    };
    use std::collections::BTreeMap;

    fn source() -> BTreeMap<String, serde_json::Value> {
        let mut claims = BTreeMap::new();
        claims.insert("groups".to_owned(), serde_json::json!(["eng", "sre", "hr"]));
        claims.insert("email".to_owned(), serde_json::json!("ada@example.test"));
        claims
    }

    fn only(rule: MappingRule) -> MappedClaims {
        apply_for(&[rule], &source(), Destination::TwoTokens).expect("applies")
    }

    /// A `place` naming a claim a RENAME already moved away is inert, and on a one-token grant
    /// that means the claim is EMITTED.
    ///
    /// `place` is keyed on a name and `rename` carries a placement across with the value, so
    /// the two orders are genuinely different and only one is safe:
    ///
    /// - `place(email -> id_token)` THEN `rename(email -> contact)`: the placement moves with
    ///   the value, `contact` is placed, nothing is emitted.
    /// - `rename(email -> contact)` THEN `place(email -> id_token)`: the place names a claim
    ///   that no longer exists, `contact` is UNPLACED, and on a machine grant unplaced means
    ///   the one token there is, which every resource server in `aud` reads.
    ///
    /// So an operator who writes the rename first has asked for `email` to stay out of an
    /// access token and put it there under another name. Rule ORDER is the whole difference.
    ///
    /// This test exists because the note that used to sit on `Destination` described a
    /// DIFFERENT pair -- `place(a)` then `rename(b -> a)` against its reverse -- and called
    /// them opposite. They are identical, and both withhold. A hazard note naming the wrong
    /// pair is worse than none: it teaches the safe order as the dangerous one.
    #[test]
    fn a_place_after_a_rename_names_nothing_and_the_claim_is_emitted() {
        let mut only_email = BTreeMap::new();
        only_email.insert("email".to_owned(), serde_json::json!("ada@example.test"));

        let safe = apply_for(
            &[
                MappingRule::Place {
                    name: "email".to_owned(),
                    placement: Placement::IdToken,
                },
                MappingRule::Rename {
                    from: "email".to_owned(),
                    to: "contact".to_owned(),
                },
            ],
            &only_email,
            Destination::OneAccessToken,
        )
        .expect("applies");
        assert!(
            safe.access_token.is_empty(),
            "placing BEFORE the rename carries the placement onto the new name: {:?}",
            safe.access_token
        );

        let hazard = apply_for(
            &[
                MappingRule::Rename {
                    from: "email".to_owned(),
                    to: "contact".to_owned(),
                },
                MappingRule::Place {
                    name: "email".to_owned(),
                    placement: Placement::IdToken,
                },
            ],
            &only_email,
            Destination::OneAccessToken,
        )
        .expect("applies");
        assert_eq!(
            hazard.access_token.keys().collect::<Vec<_>>(),
            vec!["contact"],
            "placing AFTER the rename names a claim that is gone, so the renamed claim is \
             unplaced and lands in the one token the resource servers read: {:?}",
            hazard.access_token
        );

        // The pair the old note named, which is NOT order-sensitive. Asserted so the
        // correction cannot rot back into the wrong claim.
        let mut only_b = BTreeMap::new();
        only_b.insert("b".to_owned(), serde_json::json!("value"));
        let place_first = apply_for(
            &[
                MappingRule::Place {
                    name: "a".to_owned(),
                    placement: Placement::IdToken,
                },
                MappingRule::Rename {
                    from: "b".to_owned(),
                    to: "a".to_owned(),
                },
            ],
            &only_b,
            Destination::OneAccessToken,
        )
        .expect("applies");
        let rename_first = apply_for(
            &[
                MappingRule::Rename {
                    from: "b".to_owned(),
                    to: "a".to_owned(),
                },
                MappingRule::Place {
                    name: "a".to_owned(),
                    placement: Placement::IdToken,
                },
            ],
            &only_b,
            Destination::OneAccessToken,
        )
        .expect("applies");
        assert_eq!(
            place_first.access_token, rename_first.access_token,
            "placing the DESTINATION name is order-insensitive; the old note said otherwise"
        );
        assert!(place_first.access_token.is_empty(), "and both withhold");
    }

    /// CRITERION 4, all four operations, with no custom code.
    #[test]
    fn the_four_declarative_operations_each_work() {
        // RENAME, and the original is GONE: a rename that left it behind is a copy, and an
        // operator renaming an internal name to stop leaking it would still be leaking it.
        let renamed = only(MappingRule::Rename {
            from: "groups".to_owned(),
            to: "team_groups".to_owned(),
        });
        assert_eq!(
            renamed.id_token["team_groups"],
            serde_json::json!(["eng", "sre", "hr"])
        );
        assert!(
            !renamed.id_token.contains_key("groups"),
            "a rename must not leave the source behind: {:?}",
            renamed.id_token
        );

        // STATIC.
        let statics = only(MappingRule::Static {
            name: "tier".to_owned(),
            value: serde_json::json!("gold"),
        });
        assert_eq!(statics.id_token["tier"], serde_json::json!("gold"));

        // GROUP FILTERING, which is the case the criterion names.
        let filtered = only(MappingRule::FilterList {
            name: "groups".to_owned(),
            allow: vec!["eng".to_owned(), "hr".to_owned()],
        });
        assert_eq!(
            filtered.id_token["groups"],
            serde_json::json!(["eng", "hr"]),
            "only the allowed members survive, in their original order"
        );
        assert!(
            !filtered.access_token.contains_key("groups"),
            "and an unplaced claim does not reach the access token: `filter_list` filters, it \
             does not also publish"
        );

        // PLACEMENT.
        let placed = only(MappingRule::Place {
            name: "email".to_owned(),
            placement: Placement::IdToken,
        });
        assert!(placed.id_token.contains_key("email"));
        assert!(
            !placed.access_token.contains_key("email"),
            "a resource server should not need the identity to make a decision"
        );
    }

    /// A claim no rule places stays in the ID TOKEN, which is where the extra-claims bag went
    /// before this layer had a reader.
    #[test]
    fn an_unplaced_claim_stays_where_it_went_before_this_layer_existed() {
        let mapped = apply_for(&[], &source(), Destination::TwoTokens).expect("applies");
        for name in ["groups", "email"] {
            assert!(mapped.id_token.contains_key(name), "{name} in the id token");
            // NOT the access token, and this is the assertion the first version had backwards.
            // It asserted BOTH, on the stated grounds that both "was the behaviour before any
            // mapping existed" -- and it was not: `MintRequest::access_extra_claims` had no
            // writer at all, so the extra-claims bag reached the ID token only. Installing one
            // unrelated `static` rule therefore disclosed every enriched claim to every
            // resource server in the audience. A test can assert a widening as confidently as
            // it asserts anything; what makes this one right is the fact it is keyed to.
            assert!(
                !mapped.access_token.contains_key(name),
                "{name} must NOT reach the access token unless a rule places it there"
            );
        }
    }

    /// CRITERION 5. A rule WRITING a protected claim is refused, and the refusal names it.
    ///
    /// Refused rather than ignored, and the difference is the whole point: a mapping that
    /// silently dropped a rule targeting `sub` would leave an operator believing they had
    /// rewritten the subject, and the first they would learn otherwise is a downstream system
    /// reading a `sub` they did not expect.
    #[test]
    fn a_rule_writing_a_protected_claim_is_refused_by_name() {
        for (index, rule) in [
            MappingRule::Static {
                name: "sub".to_owned(),
                value: serde_json::json!("attacker"),
            },
            MappingRule::Rename {
                from: "email".to_owned(),
                to: "iss".to_owned(),
            },
            MappingRule::Place {
                name: "aud".to_owned(),
                placement: Placement::IdToken,
            },
            MappingRule::FilterList {
                name: "exp".to_owned(),
                allow: Vec::new(),
            },
        ]
        .into_iter()
        .enumerate()
        {
            let refusal = validate(std::slice::from_ref(&rule)).expect_err("must be refused");
            assert_eq!(refusal.rule_index, 0);
            assert!(
                crate::scope_claims::is_protected_claim(&refusal.claim),
                "case {index}: the refusal must name the protected claim it stopped, got {:?}",
                refusal.claim
            );
            // And `apply` refuses the same thing, so validating on write and applying at
            // issuance cannot disagree.
            assert!(
                apply_for(&[rule], &source(), Destination::TwoTokens).is_err(),
                "case {index}"
            );
        }
    }

    /// READING a protected claim is allowed; only writing one is refused.
    ///
    /// The direction matters and is easy to get backwards. Renaming `sub` to `subject` copies
    /// the identity into a claim of the operator's choosing, which is theirs to do; renaming
    /// something INTO `sub` rewrites the identity, which is not.
    #[test]
    fn reading_a_protected_claim_is_allowed_and_only_writing_is_refused() {
        let mut claims = source();
        claims.insert("sub".to_owned(), serde_json::json!("usr_ada"));
        let mapped = apply_for(
            &[MappingRule::Rename {
                from: "sub".to_owned(),
                to: "subject".to_owned(),
            }],
            &claims,
            Destination::TwoTokens,
        )
        .expect("renaming FROM a protected claim is allowed");
        assert_eq!(mapped.id_token["subject"], serde_json::json!("usr_ada"));
        // AND `sub` SURVIVES. The original test asserted only that the copy landed, so it
        // passed against a rename that DELETED the subject from both tokens -- and a token
        // with no `sub` is not a token whose `sub` an operator chose to leave out. Deleting a
        // protected claim is overriding it.
        assert_eq!(
            mapped.id_token["sub"],
            serde_json::json!("usr_ada"),
            "renaming FROM a protected claim must COPY, never move"
        );
        // Not asserted of the ACCESS token, because a claim no rule places does not reach one.
        // The mint builds that token's own `sub` regardless; what this test is about is that
        // the rename did not delete the source from the set it was in.
    }

    /// The refusal names the OFFENDING rule's position, not the first rule.
    #[test]
    fn the_refusal_points_at_the_rule_that_caused_it() {
        let refusal = validate(&[
            MappingRule::Static {
                name: "tier".to_owned(),
                value: serde_json::json!("gold"),
            },
            MappingRule::Static {
                name: "region".to_owned(),
                value: serde_json::json!("eu"),
            },
            MappingRule::Static {
                name: "iat".to_owned(),
                value: serde_json::json!(0),
            },
        ])
        .expect_err("must be refused");
        assert_eq!(
            refusal.rule_index, 2,
            "an operator with forty rules needs the index of the wrong one"
        );
        assert_eq!(refusal.claim, "iat");
    }

    /// THE WIDER FENCE. A mapping may not write anything the MINT reserves either.
    ///
    /// The five-name release floor was the only gate here, and the repo already said five is a
    /// floor: `scope_claims`'s own superset test carries "the mint fold is the second fence and
    /// must not be narrower than the FIRST". Gating on the floor made this the one
    /// operator-facing claim path in the tree that would admit `scope` or `permissions` --
    /// claims IronAuth's own management API and `DPoP` verifier make decisions on.
    #[test]
    fn a_mapping_may_not_write_anything_the_mint_reserves() {
        for name in crate::tokens::PROTECTED_ACCESS_TOKEN_CLAIMS {
            let refusal = validate(&[MappingRule::Static {
                name: (*name).to_owned(),
                value: serde_json::json!("forged"),
            }])
            .expect_err("must be refused");
            assert_eq!(refusal.claim, *name);
            assert_eq!(refusal.reason, RefusalReason::Reserved);
        }

        // The ones that matter most, named so a future edit to the list has to think about
        // them rather than merely keep the loop above green.
        for name in [
            "scope",
            "permissions",
            "roles",
            "cnf",
            "azp",
            "org_id",
            "amr",
        ] {
            assert!(
                validate(&[MappingRule::Rename {
                    from: "email".to_owned(),
                    to: name.to_owned(),
                }])
                .is_err(),
                "{name} is a claim something makes a decision on"
            );
        }
    }

    /// A claim name that is empty, or only whitespace, is refused with its own reason.
    #[test]
    fn an_empty_claim_name_is_refused() {
        for name in ["", "   ", "\t"] {
            let refusal = validate(&[MappingRule::Static {
                name: name.to_owned(),
                value: serde_json::json!(1),
            }])
            .expect_err("must be refused");
            assert_eq!(
                refusal.reason,
                RefusalReason::EmptyName,
                "an empty name is its own fault, not a reserved-claim one"
            );
        }
    }

    /// A list holding anything that is not a string is left ALONE, not emptied.
    ///
    /// The comment said so and the code did the opposite: filtering a list of objects produced
    /// an empty list, which is exactly the silent data loss the comment claims to avoid.
    #[test]
    fn filtering_a_list_of_non_strings_leaves_it_alone() {
        for value in [
            serde_json::json!([{"id": 1}, {"id": 2}]),
            serde_json::json!([1, 2, 3]),
            serde_json::json!(["ok", 7]),
        ] {
            let mut claims = BTreeMap::new();
            claims.insert("things".to_owned(), value.clone());
            let mapped = apply_for(
                &[MappingRule::FilterList {
                    name: "things".to_owned(),
                    allow: vec!["ok".to_owned()],
                }],
                &claims,
                Destination::TwoTokens,
            )
            .expect("applies");
            assert_eq!(
                mapped.id_token["things"], value,
                "a list the rule cannot express an opinion about is not a list with nothing \
                 allowed in it"
            );
        }
    }

    /// The refusal's DISPLAY names the rule and the claim, which is the operator-facing artifact.
    #[test]
    fn the_refusal_reads_as_something_an_operator_can_act_on() {
        let reserved = validate(&[MappingRule::Static {
            name: "scope".to_owned(),
            value: serde_json::json!("admin"),
        }])
        .expect_err("refused");
        let rendered = reserved.to_string();
        assert!(
            rendered.contains("scope") && rendered.contains("rule 0"),
            "the message must name the claim and the rule: {rendered}"
        );

        let empty = validate(&[MappingRule::Static {
            name: " ".to_owned(),
            value: serde_json::json!(1),
        }])
        .expect_err("refused");
        assert!(
            empty.to_string().contains("empty name"),
            "and an empty name reads differently from a reserved one: {empty}"
        );
    }

    /// CRITERION 5, HOOK HALF. A hook cannot set a reserved claim, and what it tried is
    /// REPORTED rather than swallowed.
    ///
    /// The criterion's sentence covers "any mapping OR HOOK", and the hook is the side with
    /// the wider reach: its output arrives per token from code somebody else deployed.
    #[test]
    fn a_hook_cannot_set_a_reserved_claim_and_the_attempt_is_reported() {
        let mut returned = BTreeMap::new();
        // Two it may set.
        returned.insert("tier".to_owned(), serde_json::json!("gold"));
        returned.insert("region".to_owned(), serde_json::json!("eu"));
        // And the ones it may not, spanning both halves of the fence.
        for reserved in ["sub", "iss", "scope", "permissions", "cnf", "azp", "roles"] {
            returned.insert(reserved.to_owned(), serde_json::json!("forged"));
        }

        let outcome = super::filter_hook_claims(&returned);
        assert_eq!(
            outcome.accepted.keys().collect::<Vec<_>>(),
            vec!["region", "tier"],
            "only the claims a hook may set survive"
        );
        for reserved in ["sub", "iss", "scope", "permissions", "cnf", "azp", "roles"] {
            assert!(
                outcome
                    .refused
                    .contains(&(reserved.to_owned(), RefusalReason::Reserved)),
                "{reserved} must be reported so an auditor knows it was attempted"
            );
            assert!(
                !outcome.accepted.contains_key(reserved),
                "{reserved} must not survive"
            );
        }
    }

    /// A hook's reserved claim does not fail the whole invocation.
    ///
    /// A mapping is rejected because an operator is there to read the error. A hook's output
    /// arrives per token, and failing the invocation would turn a bug in an integrator's code
    /// into an outage in ours -- so the claim is dropped, reported, and the per-client failure
    /// policy decides what that means.
    #[test]
    fn a_hooks_reserved_claim_does_not_discard_its_good_ones() {
        let mut returned = BTreeMap::new();
        returned.insert("sub".to_owned(), serde_json::json!("attacker"));
        returned.insert("tier".to_owned(), serde_json::json!("gold"));

        let outcome = super::filter_hook_claims(&returned);
        assert_eq!(
            outcome.accepted["tier"],
            serde_json::json!("gold"),
            "one bad claim must not take the good ones with it"
        );
        assert_eq!(
            outcome.refused,
            vec![("sub".to_owned(), RefusalReason::Reserved)]
        );
    }

    /// Every name any of the three protected lists holds is refused to a HOOK.
    ///
    /// Asserted ABSOLUTELY, which is the whole point of the rewrite. The first version of this
    /// test compared the hook fence to the mapping fence, and both of them call one predicate,
    /// so it was `assert_eq!(f(n), f(n))`: deleting the fence outright left it green. A test
    /// that derives its expectation from the code under test cannot fail, and this one exists
    /// precisely to fail when the fence narrows.
    ///
    /// All three lists, because `scope_claims` pins only the five-name floor into the other
    /// two. Nothing pinned `RESERVED_ENRICHMENT_CLAIMS` into the mint fold, so a name added
    /// there and nowhere else would be refused at config load and accepted from a hook.
    #[test]
    fn a_hook_may_not_set_any_protected_claim() {
        let mut checked = 0;
        for name in crate::tokens::PROTECTED_ACCESS_TOKEN_CLAIMS
            .iter()
            .chain(crate::scope_claims::PROTECTED_CLAIMS.iter())
            .chain(ironauth_config::RESERVED_ENRICHMENT_CLAIMS.iter())
        {
            let mut returned = BTreeMap::new();
            returned.insert((*name).to_owned(), serde_json::json!(1));
            let outcome = super::filter_hook_claims(&returned);
            assert!(
                outcome.accepted.is_empty(),
                "{name} was accepted from a hook"
            );
            assert_eq!(
                outcome.refused,
                vec![((*name).to_owned(), RefusalReason::Reserved)],
                "{name} must be refused as reserved"
            );
            checked += 1;
        }
        // The loop covering nothing would satisfy every assertion above it. Pinned to the
        // EXACT count rather than a floor: at `>= 25` a whole chained list could be deleted
        // and the assertion would still hold, which is how the only pin that
        // RESERVED_ENRICHMENT_CLAIMS is covered by the mint fold could be removed with
        // nothing red.
        assert_eq!(
            checked, 50,
            "the three lists are 25 + 5 + 20; a link was dropped from the chain"
        );
    }

    /// The names a hook must never set, written out by hand.
    ///
    /// The test above loops the constants, so narrowing a constant narrows the test with it.
    /// This one names them, so removing a claim from `PROTECTED_ACCESS_TOKEN_CLAIMS` has to be
    /// an edit somebody makes here too.
    #[test]
    fn the_claims_a_hook_may_never_set_are_these() {
        for name in [
            "iss",
            "sub",
            "aud",
            "exp",
            "iat",
            "nbf",
            "jti",
            "client_id",
            "scope",
            "typ",
            "token_type",
            "acr",
            "amr",
            "auth_time",
            "nonce",
            "azp",
            "cnf",
            "at_hash",
            "c_hash",
            "sid",
            "org_id",
            "roles",
            "permissions",
            "permissions_status",
            "act",
        ] {
            let mut returned = BTreeMap::new();
            returned.insert(name.to_owned(), serde_json::json!("attacker"));
            assert!(
                super::filter_hook_claims(&returned).accepted.is_empty(),
                "a hook set {name}"
            );
        }
    }

    /// A claim name with no name is refused, on every shape of "no name" the mapping half tests.
    #[test]
    fn a_hook_cannot_set_a_claim_with_no_name() {
        for name in ["", "   ", "\t"] {
            let mut returned = BTreeMap::new();
            returned.insert(name.to_owned(), serde_json::json!(1));
            let outcome = super::filter_hook_claims(&returned);
            assert!(outcome.accepted.is_empty(), "{name:?} was accepted");
            assert_eq!(
                outcome.refused,
                vec![(name.to_owned(), RefusalReason::EmptyName)],
                "{name:?} must be refused as an empty name, under its own reported name"
            );
        }
    }

    /// A padded reserved name is refused, and refused under the name the hook actually sent.
    ///
    /// `"sub "` is in none of the protected lists, which hold exact strings, so before this it
    /// was accepted and `refused` was empty: the attempt was neither rejected nor audited, and
    /// criterion 5 asks for both. It is refused rather than trimmed so that the string judged
    /// and the string stored are the same string.
    #[test]
    fn a_padded_reserved_name_is_refused_and_reported_as_sent() {
        for name in ["sub ", " scope", "cnf\n", "permissions\t", " tier"] {
            let mut returned = BTreeMap::new();
            returned.insert(name.to_owned(), serde_json::json!("attacker"));
            let outcome = super::filter_hook_claims(&returned);
            assert!(outcome.accepted.is_empty(), "{name:?} was accepted");
            assert_eq!(
                outcome.refused,
                vec![(name.to_owned(), RefusalReason::Untrimmed)],
                "{name:?} must be audited under the name the hook sent"
            );
        }
    }

    /// An accepted claim is stored under the exact bytes the fence judged.
    ///
    /// A round-trip check, and deliberately NOT claimed as the guard against a normalising
    /// refactor, because it cannot be one. Trimming the key in the accept branch is an
    /// EQUIVALENT mutation: that branch is reached only when `refuse_name` returned `None`,
    /// which requires `name == name.trim()`, so `name.trim()` and `name` are the same string
    /// there by construction. I verified it by mutation and it survives, as it must.
    ///
    /// What actually closes that hole is one line upstream: `refuse_name` refusing an
    /// untrimmed name outright, so there is never a second form of a name for a normalisation
    /// to collapse. Deleting THAT is caught, by
    /// `a_padded_reserved_name_is_refused_and_reported_as_sent`.
    #[test]
    fn an_accepted_claim_keeps_the_exact_name_the_fence_judged() {
        let mut returned = BTreeMap::new();
        returned.insert("tier".to_owned(), serde_json::json!("gold"));
        let outcome = super::filter_hook_claims(&returned);
        assert_eq!(
            outcome.accepted.keys().collect::<Vec<_>>(),
            vec!["tier"],
            "the stored key must be the judged key"
        );
    }

    /// `refused` is ordered by claim name, which is what the field doc now says.
    #[test]
    fn refusals_are_reported_in_claim_name_order() {
        let mut returned = BTreeMap::new();
        for name in ["sub", "azp", "iss"] {
            returned.insert(name.to_owned(), serde_json::json!(1));
        }
        let outcome = super::filter_hook_claims(&returned);
        assert_eq!(
            outcome
                .refused
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            vec!["azp", "iss", "sub"]
        );
    }

    /// The refusal ROW COUNT is bounded, and what did not fit is counted.
    ///
    /// Truncating each name bounds one dimension and leaves the other open: a million refused
    /// claims is a million rows, so the audit sink is still usable as a write buffer with
    /// shorter strings in it.
    #[test]
    fn the_number_of_reported_refusals_is_bounded() {
        let mut returned = BTreeMap::new();
        for index in 0..10_000 {
            returned.insert(format!("tier{index:05} "), serde_json::json!(1));
        }
        let outcome = super::filter_hook_claims(&returned);
        assert!(
            outcome.accepted.is_empty(),
            "every name here has a trailing space, so every one is refused"
        );
        assert_eq!(outcome.refused.len(), super::MAX_REFUSALS_REPORTED);
        assert_eq!(
            outcome.refused.len() + outcome.refusals_not_reported,
            10_000,
            "the count of refusals must stay true even when the rows are a sample"
        );
    }

    /// An ordinary response reports every refusal and counts none as dropped.
    #[test]
    fn an_ordinary_response_reports_every_refusal() {
        let mut returned = BTreeMap::new();
        returned.insert("sub".to_owned(), serde_json::json!(1));
        returned.insert("tier".to_owned(), serde_json::json!(1));
        let outcome = super::filter_hook_claims(&returned);
        assert_eq!(outcome.refused.len(), 1);
        assert_eq!(
            outcome.refusals_not_reported, 0,
            "nothing was dropped, so nothing may be counted as dropped"
        );
    }

    /// `refused` is sorted by the name AS REPORTED, including truncated ones.
    #[test]
    fn refusals_are_sorted_by_the_name_they_report() {
        let mut returned = BTreeMap::new();
        returned.insert("a".repeat(200), serde_json::json!(1));
        returned.insert(
            format!("{}\u{4e2d}{}", "a".repeat(126), "a".repeat(100)),
            serde_json::json!(1),
        );
        let outcome = super::filter_hook_claims(&returned);
        let reported: Vec<&str> = outcome
            .refused
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        let mut sorted = reported.clone();
        sorted.sort_unstable();
        assert_eq!(
            reported, sorted,
            "the emitted order must match the names emitted, not the names received"
        );
    }

    /// A hook cannot contribute more than `MAX_HOOK_CLAIMS`, and the overflow is audited.
    #[test]
    fn a_hook_cannot_return_unboundedly_many_claims() {
        let mut returned = BTreeMap::new();
        for index in 0..(super::MAX_HOOK_CLAIMS * 4) {
            returned.insert(format!("c{index:05}"), serde_json::json!(1));
        }
        let outcome = super::filter_hook_claims(&returned);
        assert_eq!(outcome.accepted.len(), super::MAX_HOOK_CLAIMS);
        // 4N returned, N accepted, 3N refused as overflow -- but only MAX_REFUSALS_REPORTED
        // rows are transcribed and the rest are counted, so the two numbers must still sum to
        // the overflow.
        assert_eq!(outcome.refused.len(), super::MAX_REFUSALS_REPORTED);
        assert_eq!(
            outcome.refused.len() + outcome.refusals_not_reported,
            super::MAX_HOOK_CLAIMS * 3,
            "every overflowing claim must be reported or counted, never dropped"
        );
        assert!(
            outcome
                .refused
                .iter()
                .all(|(_, reason)| *reason == RefusalReason::TooManyClaims)
        );
    }

    /// A claim name longer than the limit is refused, and the limit counts BYTES.
    ///
    /// The multi-byte pair is what makes the constant's name true. `name.len()` and
    /// `name.chars().count()` agree on every ASCII fixture, so an ASCII-only test admits a
    /// character cap that lets four times the documented budget through.
    #[test]
    fn a_hook_cannot_set_an_unboundedly_long_claim_name() {
        let over = "c".repeat(super::MAX_CLAIM_NAME_BYTES + 1);
        let mut returned = BTreeMap::new();
        returned.insert(over, serde_json::json!(1));
        let outcome = super::filter_hook_claims(&returned);
        assert!(outcome.accepted.is_empty());
        assert_eq!(outcome.refused.len(), 1);
        assert_eq!(outcome.refused[0].1, RefusalReason::NameTooLong);

        let at_limit = "c".repeat(super::MAX_CLAIM_NAME_BYTES);
        let mut ok = BTreeMap::new();
        ok.insert(at_limit, serde_json::json!(1));
        assert_eq!(
            super::filter_hook_claims(&ok).accepted.len(),
            1,
            "the limit is inclusive, or the bound is off by one"
        );

        // 65 two-byte characters is 130 bytes: over the limit, under it by character count.
        let multibyte_over = "\u{e9}".repeat(65);
        let mut wide = BTreeMap::new();
        wide.insert(multibyte_over, serde_json::json!(1));
        assert!(
            super::filter_hook_claims(&wide).accepted.is_empty(),
            "the cap counts bytes, not characters"
        );

        // 64 of them is exactly 128 bytes, and must still be admitted.
        let multibyte_at_limit = "\u{e9}".repeat(64);
        let mut wide_ok = BTreeMap::new();
        wide_ok.insert(multibyte_at_limit, serde_json::json!(1));
        assert_eq!(
            super::filter_hook_claims(&wide_ok).accepted.len(),
            1,
            "128 bytes of two-byte characters is at the limit, not over it"
        );
    }

    /// An over-long name is TRUNCATED before it reaches the audit list.
    ///
    /// The bound has to apply to both outputs or it is not a bound: refusing a ten-megabyte
    /// claim name and then copying it verbatim into the list a caller writes into an audit row
    /// just redirects the same bytes from the token to the log.
    #[test]
    fn an_over_long_name_does_not_reach_the_audit_row_in_full() {
        let huge = "c".repeat(1_000_000);
        let mut returned = BTreeMap::new();
        returned.insert(huge, serde_json::json!(1));
        let outcome = super::filter_hook_claims(&returned);
        assert!(outcome.accepted.is_empty());
        assert_eq!(outcome.refused.len(), 1);
        assert!(
            outcome.refused[0].0.len() <= super::MAX_CLAIM_NAME_BYTES + 3,
            "the audit row carried {} bytes",
            outcome.refused[0].0.len()
        );
        assert!(
            outcome.refused[0].0.ends_with("..."),
            "a truncated name must say it was truncated"
        );
        // The CONTENT, not just the ceiling. Truncating to zero bytes satisfies every length
        // assertion above and reports every over-long claim as the bare string "...", which
        // tells an auditor nothing about which claim was attempted.
        assert!(
            outcome.refused[0]
                .0
                .starts_with(&"c".repeat(super::MAX_CLAIM_NAME_BYTES)),
            "the reported name must keep the claim's prefix: {}",
            outcome.refused[0].0
        );
    }

    /// Truncation never splits a character.
    ///
    /// Slicing a `String` mid-codepoint panics, and the input that would do it is exactly the
    /// input the truncation exists to survive.
    ///
    /// THREE-byte characters, chosen deliberately. The limit is 128, which is divisible by
    /// both 2 and 4, so a name of two-byte or four-byte characters happens to land on a
    /// character boundary at exactly the cut point and would never exercise the walk at all. A
    /// first version of this test used a four-byte emoji and passed with the boundary walk
    /// deleted. 128 = 3 * 42 + 2, so a three-byte character puts the cut mid-codepoint.
    #[test]
    fn truncating_a_name_does_not_split_a_character() {
        assert_ne!(
            super::MAX_CLAIM_NAME_BYTES % 3,
            0,
            "this fixture only bites while the limit is not a multiple of three"
        );
        let wide = "\u{4e2d}".repeat(200);
        let mut returned = BTreeMap::new();
        returned.insert(wide, serde_json::json!(1));
        let outcome = super::filter_hook_claims(&returned);
        assert_eq!(outcome.refused.len(), 1);
        assert!(outcome.refused[0].0.len() <= super::MAX_CLAIM_NAME_BYTES + 3);
        assert!(
            outcome.refused[0].0.ends_with("..."),
            "a truncated name must say it was truncated"
        );
        // 42 whole three-byte characters is 126 bytes, the most that fits under 128 without
        // splitting the 43rd. Pins that the walk kept a prefix rather than collapsing to
        // nothing.
        assert!(
            outcome.refused[0].0.starts_with(&"\u{4e2d}".repeat(42)),
            "the reported name must keep whole characters from the prefix: {}",
            outcome.refused[0].0
        );
    }

    /// A refused claim does not consume the accept budget.
    ///
    /// Without this, counting positions rather than accepted claims passes every other test in
    /// the file while a conforming hook silently loses most of its output and the audit blames
    /// a limit that was never reached.
    #[test]
    fn a_refused_claim_does_not_spend_the_budget_a_good_one_needs() {
        let mut returned = BTreeMap::new();
        for name in crate::tokens::PROTECTED_ACCESS_TOKEN_CLAIMS {
            returned.insert((*name).to_owned(), serde_json::json!("forged"));
        }
        // Sort after every protected name, so under a positional count they would be the ones
        // pushed out.
        for index in 0..super::MAX_HOOK_CLAIMS {
            returned.insert(format!("z{index:03}"), serde_json::json!(1));
        }
        let outcome = super::filter_hook_claims(&returned);
        assert_eq!(
            outcome.accepted.len(),
            super::MAX_HOOK_CLAIMS,
            "every writable claim must fit; a refused one costs nothing"
        );
        assert!(
            !outcome
                .refused
                .iter()
                .any(|(_, reason)| *reason == RefusalReason::TooManyClaims),
            "the limit was never reached, so nothing may be blamed on it"
        );
    }

    /// Every refusal reason renders something an operator can act on.
    #[test]
    fn every_refusal_reason_reads_as_something_actionable() {
        for reason in [
            RefusalReason::Reserved,
            RefusalReason::EmptyName,
            RefusalReason::Untrimmed,
            RefusalReason::NameTooLong,
            RefusalReason::TooManyClaims,
        ] {
            let rendered = reason.describe("tier");
            assert!(!rendered.is_empty(), "{reason:?} renders nothing");
            assert!(
                rendered.len() > 20,
                "{reason:?} renders too little to act on: {rendered}"
            );
        }
        assert!(
            RefusalReason::NameTooLong
                .describe("x")
                .contains(&super::MAX_CLAIM_NAME_BYTES.to_string()),
            "the length refusal must name the limit"
        );
        assert!(
            RefusalReason::TooManyClaims
                .describe("x")
                .contains(&super::MAX_HOOK_CLAIMS.to_string()),
            "the count refusal must name the limit"
        );
    }

    /// The bound a hook gets is the bound the enrichment hook gets.
    #[test]
    fn the_hook_claim_bound_is_tied_to_the_enrichment_bound() {
        assert_eq!(
            super::MAX_HOOK_CLAIMS,
            ironauth_config::OIDC_MAX_ENRICHED_CLAIMS,
            "the more privileged hook must not get the weaker bound"
        );
    }

    /// A mapping refuses a padded name too, since both halves call one function.
    #[test]
    fn a_mapping_cannot_write_a_padded_reserved_name() {
        let refusal = validate(&[MappingRule::Static {
            name: "sub ".to_owned(),
            value: serde_json::json!(1),
        }])
        .expect_err("a padded reserved name must be refused");
        assert_eq!(refusal.reason, RefusalReason::Untrimmed);
        assert!(
            refusal.to_string().contains("whitespace"),
            "the message must say what to fix: {refusal}"
        );
    }

    /// A refused mapping applies NOTHING, rather than the rules before the bad one.
    #[test]
    fn a_refused_mapping_does_not_half_apply() {
        let outcome = apply_for(
            &[
                MappingRule::Static {
                    name: "tier".to_owned(),
                    value: serde_json::json!("gold"),
                },
                MappingRule::Static {
                    name: "sub".to_owned(),
                    value: serde_json::json!("attacker"),
                },
            ],
            &source(),
            Destination::TwoTokens,
        );
        assert!(
            outcome.is_err(),
            "a mapping with a protected write is refused whole"
        );
    }

    /// Filtering a claim that is absent, or is not a list, leaves it alone.
    ///
    /// Emptying it would turn a configuration mistake into silent data loss in every token.
    #[test]
    fn filtering_a_non_list_leaves_it_alone() {
        let filtered = only(MappingRule::FilterList {
            name: "email".to_owned(),
            allow: vec!["nothing".to_owned()],
        });
        assert_eq!(
            filtered.id_token["email"],
            serde_json::json!("ada@example.test"),
            "a string is not an empty list"
        );

        let absent = only(MappingRule::FilterList {
            name: "nosuchclaim".to_owned(),
            allow: vec!["x".to_owned()],
        });
        assert!(!absent.id_token.contains_key("nosuchclaim"));
    }

    /// Rules apply IN ORDER, and the order is observable.
    #[test]
    fn rules_apply_in_the_order_given() {
        let rename_then_static = apply_for(
            &[
                MappingRule::Rename {
                    from: "groups".to_owned(),
                    to: "team_groups".to_owned(),
                },
                MappingRule::Static {
                    name: "team_groups".to_owned(),
                    value: serde_json::json!(["fixed"]),
                },
            ],
            &source(),
            Destination::TwoTokens,
        )
        .expect("applies");
        assert_eq!(
            rename_then_static.id_token["team_groups"],
            serde_json::json!(["fixed"]),
            "the later static wins"
        );

        let static_then_rename = apply_for(
            &[
                MappingRule::Static {
                    name: "team_groups".to_owned(),
                    value: serde_json::json!(["fixed"]),
                },
                MappingRule::Rename {
                    from: "groups".to_owned(),
                    to: "team_groups".to_owned(),
                },
            ],
            &source(),
            Destination::TwoTokens,
        )
        .expect("applies");
        assert_eq!(
            static_then_rename.id_token["team_groups"],
            serde_json::json!(["eng", "sre", "hr"]),
            "the later rename wins; the sequence is the operator's and is applied as written"
        );
    }

    /// A renamed claim keeps where it was placed.
    #[test]
    fn placement_follows_a_rename() {
        let mapped = apply_for(
            &[
                MappingRule::Place {
                    name: "groups".to_owned(),
                    placement: Placement::AccessToken,
                },
                MappingRule::Rename {
                    from: "groups".to_owned(),
                    to: "team_groups".to_owned(),
                },
            ],
            &source(),
            Destination::TwoTokens,
        )
        .expect("applies");
        assert!(
            mapped.access_token.contains_key("team_groups")
                && !mapped.id_token.contains_key("team_groups"),
            "the placement follows the value: id={:?} access={:?}",
            mapped.id_token.keys().collect::<Vec<_>>(),
            mapped.access_token.keys().collect::<Vec<_>>()
        );
    }
}

/// What a hook returned, and what happened to it (issue #113 criterion 5, hook half).
#[derive(Debug, Clone, PartialEq)]
pub struct HookClaimsOutcome {
    /// The claims that survived, ready to fold into the token being built.
    pub accepted: BTreeMap<String, serde_json::Value>,
    /// What was refused and why, sorted by claim name.
    ///
    /// Sorted, not in the order the hook sent them: the parameter is a [`BTreeMap`], so wire
    /// order was discarded by the caller before this function was entered and no
    /// implementation here could recover it. Claim-name order is the better audit property
    /// anyway, because it makes the row reproducible across two invocations that returned the
    /// same set.
    ///
    /// The reason travels with the name because the two refusals need different fixes, and an
    /// audit row that says only "refused" cannot tell an integrator which one they hit.
    ///
    /// Bounded at [`MAX_REFUSALS_REPORTED`] rows. Truncating each NAME bounded one dimension
    /// and left the other open: a hook returning a million claims produced a million rows, so
    /// the audit sink was still usable as a write buffer with shorter strings.
    /// [`Self::refusals_not_reported`] carries what did not fit, so the row count is bounded
    /// without the count of refusals becoming a lie.
    ///
    /// NOT an error and not silently discarded: a list. Criterion 5 says an attempt is
    /// "rejected and AUDITED", and an auditor needs to know which claims were attempted by
    /// whom. Returning them lets the caller write that row; dropping them would leave the
    /// audit with nothing to say, and failing the whole invocation would let one bad claim
    /// take down every login through a client whose hook is merely sloppy.
    pub refused: Vec<(String, RefusalReason)>,
    /// How many refusals did not fit in [`Self::refused`].
    ///
    /// Zero on every ordinary response. Non-zero says the audit row is a sample rather than the
    /// whole story, which is a thing an auditor must be told rather than left to infer from a
    /// suspiciously round row count.
    pub refusals_not_reported: usize,
}

/// The most refusal rows one response reports.
///
/// Twice [`MAX_HOOK_CLAIMS`], so a hook that misnames every claim it was entitled to send still
/// has every one of them named, and a hook returning orders of magnitude more is summarised
/// rather than transcribed.
pub const MAX_REFUSALS_REPORTED: usize = MAX_HOOK_CLAIMS * 2;

/// Filter what a hook returned, refusing the claims no hook may set.
///
/// # Why a hook is filtered where a mapping is REJECTED
///
/// A mapping is configuration: it is written once, by an operator, and a refusal at write time
/// is a message that person reads and acts on. A hook's output arrives per token, from code
/// somebody else deployed, and there is nobody to show an error to at that instant. Rejecting
/// the whole invocation would mean one reserved claim in a hook's response fails every login it
/// touches, which converts a bug in an integrator's code into an outage in ours.
///
/// So the reserved names are dropped and REPORTED, and the issuance SUCCEEDS. The caller
/// reports what was attempted.
///
/// An earlier version of this said "the failure policy #113 requires per client decides
/// whether a refusal is fatal". That policy now exists -- `token_hooks.failure_policy`, issue
/// #114 criterion 3 -- and it does NOT decide this. It governs a hook that did not COMPLETE:
/// a trap, exhausted fuel, a passed deadline, a decline, a component that will not load. A
/// reserved-name refusal is none of those; this function returns a value rather than an error,
/// `fence` has no channel to raise one on, and `run_deployed_hook` returns `Ok`.
///
/// Left as a sentence rather than quietly deleted, because an operator who read the old one
/// would set `fail_closed` believing a hook attempting to forge `sub` would refuse the
/// issuance and be caught loudly. It will not. Wiring the refusal path to the policy needs an
/// error channel out of the fence that does not exist, and that is its own change.
///
/// The fence is the same one mappings get: the release floor UNION the mint fold, because
/// criterion 5's sentence covers "any mapping OR HOOK" and a hook is the side with the wider
/// reach. `scope` authorizes IronAuth's own management API and `cnf` drives `DPoP`; a hook that
/// could set either would be choosing its own authorization.
/// # Bounded, because a denylist alone is not a bound
///
/// The name fence refuses twenty-five names and would admit everything else without limit. A
/// hook returning a hundred thousand claims would have every one of them accepted and, per the
/// field doc above, folded into a token. [`MAX_HOOK_CLAIMS`] is what stops that, and the
/// overflow is refused into `refused` rather than dropped, so the audit records that claims
/// were lost instead of quietly minting a shorter token than the hook asked for.
///
/// Which claims overflow is decided in claim-name order, so it is the same set on every
/// invocation given the same input rather than whichever ones happened to hash first.
#[must_use]
pub fn filter_hook_claims(returned: &BTreeMap<String, serde_json::Value>) -> HookClaimsOutcome {
    let mut outcome = HookClaimsOutcome {
        accepted: BTreeMap::new(),
        refused: Vec::new(),
        refusals_not_reported: 0,
    };
    let record = |name: String, reason: RefusalReason, outcome: &mut HookClaimsOutcome| {
        if outcome.refused.len() < MAX_REFUSALS_REPORTED {
            outcome.refused.push((name, reason));
        } else {
            outcome.refusals_not_reported += 1;
        }
    };
    for (name, value) in returned {
        if let Some(reason) = refuse_name(name) {
            record(reportable(name), reason, &mut outcome);
        } else if outcome.accepted.len() < MAX_HOOK_CLAIMS {
            outcome.accepted.insert(name.clone(), value.clone());
        } else {
            record(name.clone(), RefusalReason::TooManyClaims, &mut outcome);
        }
    }
    // Sorted by the name AS REPORTED, which is what the field doc promises. Input order is
    // claim-name order because the parameter is a BTreeMap, but truncation breaks it: a
    // truncated name ends in `...`, and `.` sorts below every letter, so two names differing
    // only past the limit come out in the opposite order from the one they went in.
    outcome.refused.sort_by(|left, right| left.0.cmp(&right.0));
    outcome
}

/// The stored wire format, which is a contract with rows this crate did not write.
///
/// `claims_mappings.rules` documents are produced by the admin write path, by config-snapshot
/// imports, and by whatever an operator hand-edits. This crate is the only reader. So the tag
/// names and field names are not an implementation detail of `parse`; they are the format, and
/// a rename that compiled here would make every stored document unreadable at the next
/// issuance.
#[cfg(test)]
mod wire_format_tests {
    use super::{Destination, MappingRule, Placement, apply_for, parse};
    use std::collections::BTreeMap;

    /// The EXACT documents already committed elsewhere in this repository parse.
    ///
    /// These strings are copied verbatim from `crates/ironauth-store/tests/claims_mappings.rs`
    /// and `crates/ironauth-store/src/promotion.rs`, which wrote them before any parser existed.
    /// A test that builds its own fixture proves the parser is self-consistent and nothing else:
    /// the question is whether it can read what the tree already stores.
    #[test]
    fn the_documents_already_in_the_tree_parse() {
        let store_test_fixture = r#"[{"kind":"rename","from":"dept","to":"department"},{"kind":"static","name":"tier","value":"gold"}]"#;
        assert_eq!(
            parse(store_test_fixture).expect("the store suite's fixture must parse"),
            vec![
                MappingRule::Rename {
                    from: "dept".to_owned(),
                    to: "department".to_owned(),
                },
                MappingRule::Static {
                    name: "tier".to_owned(),
                    value: serde_json::json!("gold"),
                },
            ]
        );

        let promotion_fixture = r#"[{"kind": "static", "name": "tier", "value": "gold"}]"#;
        assert_eq!(
            parse(promotion_fixture).expect("the promotion fixture must parse"),
            vec![MappingRule::Static {
                name: "tier".to_owned(),
                value: serde_json::json!("gold"),
            }]
        );
    }

    /// Every variant round-trips, so nothing is writable-but-unreadable.
    ///
    /// The `place` rule is the one worth naming: it is the only rule whose payload is an enum,
    /// and a `Placement` serialized as `IdToken` rather than `id_token` would still round-trip
    /// through itself while being unreadable to anyone reading the column.
    #[test]
    fn every_rule_round_trips_through_the_stored_shape() {
        let rules = vec![
            MappingRule::Rename {
                from: "dept".to_owned(),
                to: "department".to_owned(),
            },
            MappingRule::Static {
                name: "tier".to_owned(),
                value: serde_json::json!({"level": 2}),
            },
            MappingRule::FilterList {
                name: "groups".to_owned(),
                allow: vec!["eng".to_owned(), "sre".to_owned()],
            },
            MappingRule::Place {
                name: "department".to_owned(),
                placement: Placement::AccessToken,
            },
        ];
        let document = serde_json::to_string(&rules).expect("serialize");
        assert!(
            document.contains(r#""kind":"filter_list""#)
                && document.contains(r#""placement":"access_token""#),
            "the wire names are snake_case and an operator reads them in the column: {document}"
        );
        assert_eq!(parse(&document).expect("round trip"), rules);
    }

    /// A field this version does not know is a REFUSAL, not a shrug.
    ///
    /// An unknown field is as likely to be the part that restricts as the part that adds. If
    /// `serde` ignored it, a future `{"kind":"filter_list","name":"groups","allow":[...],
    /// "except":[...]}` written by a newer node would apply here WITHOUT the exception list --
    /// a weaker rule than the operator wrote, reported as success.
    #[test]
    fn an_unknown_field_is_refused_rather_than_ignored() {
        let newer =
            r#"[{"kind":"filter_list","name":"groups","allow":["eng"],"except":["contractors"]}]"#;
        let refused = parse(newer).expect_err("a rule carrying an unknown field must not parse");
        assert!(
            refused.to_string().contains("except"),
            "the refusal must NAME the field, or an operator cannot act on it: {refused}"
        );

        // And the same document without the unknown field parses, so the case above is
        // failing for the field and not for something else in the string.
        let known = r#"[{"kind":"filter_list","name":"groups","allow":["eng"]}]"#;
        parse(known).expect("the same rule without the unknown field must parse");
    }

    /// An unknown KIND is refused too, and separately: a new rule type is not a new field.
    #[test]
    fn an_unknown_kind_is_refused() {
        let refused = parse(r#"[{"kind":"redact","name":"groups"}]"#)
            .expect_err("a rule kind this version cannot carry out must not parse");
        assert!(
            refused.to_string().contains("redact"),
            "the refusal must name the kind: {refused}"
        );
    }

    /// The parsed rules ACT. A parser that produces a `Vec` nothing applies is a decoder test.
    #[test]
    fn a_parsed_document_maps_claims() {
        let rules = parse(
            r#"[{"kind":"filter_list","name":"groups","allow":["eng"]},
                {"kind":"rename","from":"dept","to":"department"},
                {"kind":"place","name":"department","placement":"access_token"},
                {"kind":"static","name":"tier","value":"gold"}]"#,
        )
        .expect("parse");
        let mut source = BTreeMap::new();
        source.insert("groups".to_owned(), serde_json::json!(["eng", "sales"]));
        source.insert("dept".to_owned(), serde_json::json!("platform"));

        let mapped = apply_for(&rules, &source, Destination::TwoTokens).expect("apply");
        assert_eq!(
            mapped.id_token.get("groups"),
            Some(&serde_json::json!(["eng"])),
            "the filter kept only the allowed member: {:?}",
            mapped.id_token
        );
        assert_eq!(
            mapped.access_token.get("department"),
            Some(&serde_json::json!("platform")),
            "the rename landed and the placement moved it: {:?}",
            mapped.access_token
        );
        assert!(
            !mapped.id_token.contains_key("department") && !mapped.id_token.contains_key("dept"),
            "a claim placed in the access token is not ALSO in the ID token, and the rename \
             removed the source: {:?}",
            mapped.id_token
        );
        assert_eq!(
            mapped.id_token.get("tier"),
            Some(&serde_json::json!("gold")),
            "a claim no rule places stays where the extra-claims bag already went"
        );
        assert!(
            !mapped.access_token.contains_key("tier"),
            "and does not reach the access token, which a `place` rule is for"
        );
    }
}
