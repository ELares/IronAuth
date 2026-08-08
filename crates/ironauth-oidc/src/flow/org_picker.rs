// SPDX-License-Identifier: MIT OR Apache-2.0

//! The organization picker step (issue #94, PR-B2): the multi-organization login choice that
//! completes org-context selection (param -> auto-select-single -> PICKER).
//!
//! PR-B1 resolves the DURABLE org context at `/authorize` code-issue in the order frozen-session
//! wins, then the `organization` parameter, then auto-select the sole active membership, then none.
//! A MULTI-organization subject with NO parameter fell through to none. This step fills exactly that
//! gap IN the login flow: a fully-authenticated multi-org subject with no parameter chooses one of
//! their live-and-active memberships, and the pick is FROZEN onto the session at login completion,
//! so PR-B1's frozen-session-wins branch returns it at code-issue with NO change to
//! `resolve_org_context`. The relay below the session (`session.org_id` -> code -> `CodeBindings`
//! -> `MintRequest` -> the `org_id` claim) is 100% reused.
//!
//! ## Render-or-skip
//!
//! The step RENDERS the choice ONLY for a multi-org, no-parameter subject. It SKIPS (rendering no
//! nodes, so the engine auto-advances straight to the mint) when the org context is already
//! determined: the request carried an `organization` parameter (the parameter path resolves it at
//! code-issue, so the picker must not double-prompt), OR the subject has AT MOST ONE active
//! membership (0 -> no org context, 1 -> auto-selected). So a single-org, no-membership, or
//! parameter-carrying login is byte-identical to before this step existed.
//!
//! ## Authoritative re-validation (no client trust)
//!
//! The submitted organization is NEVER trusted: the advance re-reads the store and accepts the pick
//! ONLY when it is a LIVE membership of the subject AND an ACTIVE organization, the SAME
//! authoritative check PR-B1's parameter path runs. Every failure mode (not a member, org absent or
//! soft-deleted, org disabled, a malformed or foreign id) is the SAME uniform invalid-submission
//! refusal, so it is never a membership/existence/state oracle. A disabled or foreign organization
//! cannot be picked.

use std::collections::BTreeSet;

use ironauth_store::{OrganizationId, Scope, StoreError, UserId};

use super::message::{self, Message, MessageContext};
use super::model::{InputType, Node, NodeAttributes, NodeGroup, Transport};
use super::{FlowError, Submission};
use crate::state::OidcState;
use crate::util::query_get;

/// The submission node name the picker reads the chosen organization from. One name with one
/// submit control per organization (each carrying its own `org_` id as the value), so the clicked
/// control's value is the pick the engine reads server-authoritatively on both transports.
const ORGANIZATION_NODE: &str = "organization";

/// The `organization` query parameter name on the resuming `/authorize` target, so the picker knows
/// whether a parameter was supplied and must therefore skip (the parameter path resolves it).
const ORGANIZATION_PARAM: &str = "organization";

/// One active organization the subject may pick (issue #94, PR-B2): its id and human-facing display
/// name, both non-secret. The display name rides the option label's message context; the id string
/// is the submit control's value. The id is carried as its rendered STRING form so the pure node
/// builder ([`picker_nodes`]) and the golden corpus need no scope to construct a fixture.
pub(super) struct ActiveOrg {
    /// The organization id (an `org_` id) as its rendered string, the submit control's value.
    pub id: String,
    /// The organization's human-facing display name, riding the option label's message context.
    pub display_name: String,
}

/// The outcome of one organization-picker advance (issue #94, PR-B2).
pub(super) enum OrgPickerStep {
    /// The subject picked a live-and-active organization they are a member of: freeze it onto the
    /// session at completion. Carries the authoritatively re-validated organization id.
    Complete(OrganizationId),
}

/// Whether the resuming `/authorize` target carried a non-empty `organization` parameter (issue
/// #94, PR-B2). When it did, the parameter path resolves the org context at code-issue, so the
/// picker must SKIP rather than double-prompt (the parameter stays authoritative). A login flow
/// created outside `/authorize` (a headless flow with no resume target) carries no parameter.
fn requested_org_present(return_to: Option<&str>) -> bool {
    return_to
        .and_then(|raw| raw.split_once('?').map(|(_, query)| query))
        .and_then(|query| query_get(query, ORGANIZATION_PARAM))
        .is_some_and(|value| !value.is_empty())
}

/// The subject's LIVE memberships whose organization is ACTIVE (issue #94, PR-B2), in the store's
/// deterministic `(created_at, id)` order. Mirrors PR-B1's authoritative reads: a membership is a
/// live row (`list_for_user` filters `deleted_at IS NULL`) and its organization must be active. A
/// disabled or vanished organization is dropped (never offered as a pick). A read fault is the
/// neutral store error, never an oracle.
pub(super) async fn active_orgs(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
) -> Result<Vec<ActiveOrg>, FlowError> {
    let memberships = state
        .store()
        .scoped(scope)
        .org_memberships()
        .list_for_user(subject)
        .await
        .map_err(|_| FlowError::Store)?;
    let mut orgs = Vec::new();
    for membership in memberships {
        match state
            .store()
            .scoped(scope)
            .organizations()
            .get(&membership.organization_id)
            .await
        {
            Ok(record) if record.state.is_active() => orgs.push(ActiveOrg {
                id: record.id.to_string(),
                display_name: record.display_name,
            }),
            // A disabled or soft-deleted organization is not offered as a pick.
            Ok(_) | Err(StoreError::NotFound) => {}
            Err(_) => return Err(FlowError::Store),
        }
    }
    Ok(orgs)
}

/// The ACTIVE organizations the subject is NOT yet a member of but whose verified-domain policy
/// would join them at session establishment (issue #96, criterion 5).
///
/// # Why this set is not already covered by the memberships above
///
/// Just-in-time provisioning (issue #95) runs inside `establish_session`, which is called at flow
/// COMPLETION, after this step has already rendered and been advanced. So on a first login the
/// eligible organizations are not memberships yet and the picker never saw them: a new employee at
/// a verified corporate domain got no choice at all, was joined silently, and was first offered a
/// picker on their SECOND sign-in. Criterion 5 asks for both sets because at picker time they
/// genuinely are two sets.
///
/// # No new authority
///
/// Every organization here is one the subject would have been joined to anyway, moments later, by
/// the same policy, without being asked. Offering it as a pick grants nothing that was not already
/// going to be granted; it only lets the subject say which one this login is for. The eligibility
/// predicate is the store's own `jit_eligible_orgs`, and the domains come from the seam the
/// provisioner itself uses, so the two cannot drift.
///
/// The cheap `any_jit_provisioning_enabled` gate comes first, exactly as it does in the
/// provisioner, so a deployment not using JIT does no extra read on the login path and this step
/// behaves byte-identically to before.
pub(super) async fn jit_eligible_orgs(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
) -> Result<Vec<ActiveOrg>, FlowError> {
    match state
        .store()
        .scoped(scope)
        .org_auth_policies()
        .any_jit_provisioning_enabled()
        .await
    {
        Ok(true) => {}
        // Not in use, or a read fault. Either way, offer nothing: this is the access-granting
        // direction and a store blip is never a reason to widen the list.
        Ok(false) | Err(_) => return Ok(Vec::new()),
    }
    let domains = crate::interaction::verified_email_domains(state, scope, subject).await;
    let mut orgs = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    // `domains` is a BTreeSet and `jit_eligible_orgs` returns the store's deterministic order, so
    // the result is stable across runs. The rendered node list is byte-pinned by the golden
    // corpus, which a set with a nondeterministic order would break intermittently.
    for domain in &domains {
        let eligible = state
            .store()
            .scoped(scope)
            .org_auth_policies()
            .jit_eligible_orgs(domain)
            .await
            .map_err(|_| FlowError::Store)?;
        for org in eligible {
            if !seen.insert(org.to_string()) {
                continue;
            }
            // Already a member: it is in `active_orgs` and must not be offered twice.
            if state
                .store()
                .scoped(scope)
                .org_memberships()
                .exists(&org, subject)
                .await
                .map_err(|_| FlowError::Store)?
            {
                continue;
            }
            match state.store().scoped(scope).organizations().get(&org).await {
                Ok(record) if record.state.is_active() => orgs.push(ActiveOrg {
                    id: record.id.to_string(),
                    display_name: record.display_name,
                }),
                Ok(_) | Err(StoreError::NotFound) => {}
                Err(_) => return Err(FlowError::Store),
            }
        }
    }
    Ok(orgs)
}

/// Every organization the subject may pick: their live memberships FIRST, then the organizations
/// their verified domain makes them eligible to join (issue #96, criterion 5).
///
/// Memberships lead because they are the ordinary case and the ordering is what the golden corpus
/// pins. Both sets render as the same kind of control, deliberately: picking an eligible
/// organization joins the subject to it through the SAME provisioning path that would have joined
/// them silently, so there is no second class of pick and nothing for a caller to distinguish.
pub(super) async fn pickable_orgs(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
) -> Result<Vec<ActiveOrg>, FlowError> {
    let mut orgs = active_orgs(state, scope, subject).await?;
    orgs.extend(jit_eligible_orgs(state, scope, subject).await?);
    Ok(orgs)
}

/// Whether `org` is one the subject may pick: a live-and-active membership, OR an active
/// organization their verified domain makes them JIT-eligible for (issue #96, criterion 5).
///
/// The acceptance predicate must be the SAME set the offer was built from, or the picker renders
/// controls that refuse themselves.
pub(super) async fn is_pickable(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    org: &OrganizationId,
) -> Result<bool, FlowError> {
    if is_active_membership(state, scope, subject, org).await? {
        return Ok(true);
    }
    Ok(jit_eligible_orgs(state, scope, subject)
        .await?
        .iter()
        .any(|eligible| eligible.id == org.to_string()))
}

/// Whether `org` is a LIVE membership of `subject` AND an ACTIVE organization (issue #94, PR-B2):
/// the EXACT authoritative check PR-B1's parameter path runs (`exists` plus an active-state read),
/// so a pick is validated identically to a parameter. Used by the advance to accept a pick and by
/// the login completion to re-enforce active-state once more (defense in depth).
pub(super) async fn is_active_membership(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    org: &OrganizationId,
) -> Result<bool, FlowError> {
    if !state
        .store()
        .scoped(scope)
        .org_memberships()
        .exists(org, subject)
        .await
        .map_err(|_| FlowError::Store)?
    {
        return Ok(false);
    }
    match state.store().scoped(scope).organizations().get(org).await {
        Ok(record) => Ok(record.state.is_active()),
        // A disabled read returns a record (handled above); a vanished org is simply not valid.
        Err(StoreError::NotFound) => Ok(false),
        Err(_) => Err(FlowError::Store),
    }
}

/// The nodes to render when entering the organization picker (issue #94, PR-B2), or an EMPTY vector
/// when the step SKIPS (the org context is already determined, so the engine auto-advances to the
/// mint). The step renders the choice ONLY for a multi-org, no-parameter subject; a parameter, a
/// single active membership, no membership, or a store fault that yields fewer than two active
/// organizations all render nothing.
pub(super) async fn enter_nodes(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    return_to: Option<&str>,
    transport: Transport,
    flow_id: &str,
) -> Result<Vec<Node>, FlowError> {
    // A supplied parameter resolves the org context at code-issue; the picker must not double-prompt.
    if requested_org_present(return_to) {
        return Ok(Vec::new());
    }
    let orgs = pickable_orgs(state, scope, subject).await?;
    // Zero or one pickable organization is already determined (none, or the single one that
    // auto-selects or JIT-joins), so skip. The threshold is unchanged; only the set it counts is
    // wider, so a subject with exactly one eligible organization is still joined silently and
    // never sees a prompt they have no choice in.
    if orgs.len() < 2 {
        return Ok(Vec::new());
    }
    Ok(picker_nodes(transport, flow_id, &orgs))
}

/// Build the organization-picker nodes (issue #94, PR-B2): a leading prompt, ONE submit control per
/// active organization (its display name on the label's message context, its `org_` id the control
/// value), and (on the browser transport) the hidden `flow` continuation node. The SAME builder the
/// live engine and the golden corpus call, so the rendered bytes are pinned.
#[must_use]
pub(super) fn picker_nodes(transport: Transport, flow_id: &str, orgs: &[ActiveOrg]) -> Vec<Node> {
    let mut nodes = Vec::new();
    // The leading prompt copy (informational): choose which organization this login is for.
    nodes.push(Node {
        group: NodeGroup::Default,
        attributes: NodeAttributes::Text {
            message: Message::of(message::ORG_PICKER_PROMPT),
        },
        label: None,
        messages: Vec::new(),
        sequence: 0,
    });
    // One submit control per active organization, in the store's deterministic order. The display
    // name rides the option label's `name` context (never the copy string), so the numeric message
    // registry stays finite for arbitrary organization names.
    for (index, org) in orgs.iter().enumerate() {
        let sequence = u16::try_from(index).unwrap_or(u16::MAX);
        nodes.push(Node::input(
            NodeGroup::Submit,
            sequence,
            NodeAttributes::Input {
                name: ORGANIZATION_NODE.to_owned(),
                input_type: InputType::Submit,
                value: Some(org.id.clone()),
                required: false,
                autocomplete: None,
                disabled: false,
                constraints: None,
            },
            Some(Message::with_context(
                message::ORG_PICKER_OPTION_LABEL,
                MessageContext::one("name", &org.display_name),
            )),
        ));
    }
    if matches!(transport, Transport::Browser) {
        nodes.push(Node::input(
            NodeGroup::Default,
            5,
            NodeAttributes::Input {
                name: "flow".to_owned(),
                input_type: InputType::Hidden,
                value: Some(flow_id.to_owned()),
                required: true,
                autocomplete: None,
                disabled: false,
                constraints: None,
            },
            None,
        ));
    }
    nodes
}

/// Advance the organization picker one transition (issue #94, PR-B2): read the submitted
/// organization, RE-VALIDATE it authoritatively (a live membership of the subject AND an active
/// organization), and on success return the id to freeze onto the session. A missing, malformed,
/// foreign, non-member, or disabled pick is the SAME uniform [`FlowError::InvalidSubmission`]
/// refusal (no oracle), leaving the flow OPEN so the client can re-pick.
///
/// # Errors
///
/// [`FlowError::InvalidSubmission`] for any pick that is not a live-and-active membership of the
/// subject; [`FlowError::Store`] on a persistence fault (fail closed, never an oracle).
pub(super) async fn advance(
    state: &OidcState,
    scope: Scope,
    subject: &UserId,
    submission: &Submission,
) -> Result<OrgPickerStep, FlowError> {
    // The submitted `org_` id (a node value; the client only ever supplies node values). An absent
    // or non-string value is a uniform invalid submission.
    let raw = submission
        .node_values
        .get(ORGANIZATION_NODE)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(FlowError::InvalidSubmission)?;
    // Parse the id in scope. A malformed or cross-scope id is the SAME uniform refusal as a
    // non-member, so it is never a scope/shape oracle.
    let org =
        OrganizationId::parse_in_scope(raw, &scope).map_err(|_| FlowError::InvalidSubmission)?;
    // Authoritative re-validation, identical to PR-B1's parameter path: a live membership AND an
    // active organization. A disabled or foreign organization cannot be picked.
    if is_pickable(state, scope, subject, &org).await? {
        Ok(OrgPickerStep::Complete(org))
    } else {
        Err(FlowError::InvalidSubmission)
    }
}
