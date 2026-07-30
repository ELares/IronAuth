// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The roles of ONE organization membership (issue #97), in two clearly separated
// halves. The first is the set of DIRECT grants, which is exactly the set of rows
// this surface can withdraw. The second is the resolved effective set WITH
// PROVENANCE, which includes grants no control on this surface can remove.
//
// The provenance half is the load bearing one and must not be "tidied" later. It
// is ONE ROW PER GRANT PATH and is NEVER collapsed by slug: a role held both
// directly and through a group is TWO rows. Collapsing them would show an
// operator one grant to withdraw, they would withdraw it, and the role would
// survive by the other path.
//
// Issue #98 added a THIRD reading beside the resolved set: the permission UNION
// those roles carry, and the advisory budget verdict over it. Both are additions to
// the same read, which is why they render as one more half of the same panel rather
// than a separate fetch.
//
// That verdict is the ELEMENT COUNT half of the budget and nothing more, which is
// worth stating here because the natural way to describe it is the wrong one. It
// does not say whether the next token carries the claim, and no string on this
// surface may either: see `budgetWithholdingReason` for the three separate things
// that each suppress the claim without being visible from this read.
//
// This is a PANEL opened from a member row of the organization detail view
// (src/ui/OrganizationsView.tsx). It reads and writes ONLY through the named
// wrappers in src/api/client.ts (the single funnel) and renders every failure
// through the verbatim ErrorView boundary, including the RFC 9470 sudo path on a
// max_age challenge.

import { useState } from "preact/hooks";
import {
  type AssignOrgMembershipRoleRequest,
  type EffectiveRoleSourceView,
  type EffectiveRolesView,
  type KeysetPage,
  type OrgMembershipRoleView,
  type PermissionBudgetView,
  assignOrgMembershipRole,
  fetchOrgMembershipRoles,
  getOrgMembershipEffectiveRoles,
  unassignOrgMembershipRole,
} from "../api/client";
import {
  AsyncBoundary,
  ConfirmButton,
  MorePageNote,
  MutationFeedback,
} from "./ResourceView";
import { type OrgScope, inputValue, sudoFor } from "./orgPanels";
import { type AsyncState, useAsyncResource, useMutation } from "./useResource";

// The entry point: both halves for one membership, sharing one reload so a grant
// change re-reads the resolved picture as well as the direct list.
export function MembershipRolesPanel({
  tenantId,
  environmentId,
  organizationId,
  membershipId,
  organizationActive,
  membershipState,
}: OrgScope & {
  membershipId: string;
  // Whether the organization is enabled, and the lifecycle state of this
  // membership. Both gate RESOLUTION without touching the stored grants, so both
  // are needed to explain an empty resolved set that has grants behind it.
  organizationActive: boolean;
  membershipState: string;
}) {
  const direct = useAsyncResource<KeysetPage<OrgMembershipRoleView>>(
    () =>
      fetchOrgMembershipRoles(
        tenantId,
        environmentId,
        organizationId,
        membershipId,
      ),
    [tenantId, environmentId, organizationId, membershipId],
  );
  const effective = useAsyncResource<EffectiveRolesView>(
    () =>
      getOrgMembershipEffectiveRoles(
        tenantId,
        environmentId,
        organizationId,
        membershipId,
      ),
    [tenantId, environmentId, organizationId, membershipId],
  );
  const mutation = useMutation();
  const [roleId, setRoleId] = useState("");

  // A grant change moves BOTH halves: the direct list gains or loses a row, and
  // the resolved picture must be re-read rather than inferred, because the
  // resolution is the servers.
  function reloadBoth(): void {
    direct.reload();
    effective.reload();
  }

  function onAssign(event: Event): void {
    event.preventDefault();
    const request: AssignOrgMembershipRoleRequest = { role_id: roleId.trim() };
    void mutation
      .run(async () => {
        await assignOrgMembershipRole(
          tenantId,
          environmentId,
          organizationId,
          membershipId,
          request,
        );
      }, "Role granted to the member.")
      .then((ok) => {
        if (ok) {
          setRoleId("");
          reloadBoth();
        }
      });
  }

  return (
    <div class="resource-member-roles">
      <div class="resource-subsection">
        <h4>Roles granted directly</h4>
        <form
          class="resource-form"
          onSubmit={onAssign}
          aria-label="Grant a role to the member"
        >
          <div class="resource-field">
            <label for="org-membership-role-id">Role id</label>
            <input
              id="org-membership-role-id"
              type="text"
              required
              value={roleId}
              onInput={(event) => setRoleId(inputValue(event))}
            />
          </div>
          <button
            type="submit"
            class="resource-btn resource-btn-primary"
            disabled={mutation.state.pending || roleId.trim() === ""}
          >
            Grant to member
          </button>
          <MutationFeedback
            state={mutation.state}
            sudo={sudoFor(mutation.retry)}
          />
        </form>
        <AsyncBoundary
          state={direct.state}
          loadingLabel="Loading direct roles"
          empty={{
            when: (page) => page.items.length === 0,
            render: () => (
              <p class="resource-empty">
                No roles granted directly to this member.
              </p>
            ),
          }}
        >
          {(page) => (
            <div>
              <ul
                class="resource-list"
                aria-label="Roles granted directly to the member"
              >
                {page.items.map((assignment) => (
                  <MembershipRoleRow
                    key={assignment.id}
                    tenantId={tenantId}
                    environmentId={environmentId}
                    organizationId={organizationId}
                    membershipId={membershipId}
                    assignment={assignment}
                    onUnassigned={reloadBoth}
                  />
                ))}
              </ul>
              <MorePageNote
                nextCursor={page.nextCursor}
                noun="direct role grants"
              />
            </div>
          )}
        </AsyncBoundary>
      </div>
      <EffectiveRolesPanel
        state={effective.state}
        suppression={suppressionReason(organizationActive, membershipState)}
      />
    </div>
  );
}

// Why a member can resolve NOTHING while the grants above are still on file.
//
// Resolution requires a live, enabled organization AND an active membership. A
// disabled organization mints no roles for anyone, and a membership in any other
// state resolves none either, in both cases WITHOUT removing a single stored
// grant. An operator who sees an empty resolved set next to a populated grant
// list and is told nothing would reasonably conclude the grants were lost, so
// this states the cause and that the configuration survives. Returns null when
// resolution is not gated, in which case an empty set really does mean no grants.
function suppressionReason(
  organizationActive: boolean,
  membershipState: string,
): string | null {
  if (!organizationActive) {
    return "This organization is disabled, so none of its members resolve any role until it is enabled again. The grants above are still on file and are not lost.";
  }
  if (membershipState !== "active") {
    return `This membership is ${membershipState} rather than active, so it resolves no roles. The grants above are still on file and are not lost.`;
  }
  return null;
}

// Why the ELEMENT half of the budget alone already withholds the permission claim,
// or null when it does not (issue #98).
//
// Deliberately the SAME SHAPE as suppressionReason above, because it answers the
// same class of question: a state where what the store HOLDS and what a token
// CARRIES come apart, which an operator shown only the shorter of the two would
// read as configuration that went missing. So it states the cause AND that nothing
// was lost. Nothing here was refused: the membership holds every permission listed,
// the management plane reports them all, and every attach that produced them
// answered 201. What changes is only what ONE token can carry.
//
// Read the null case NARROWLY, because it is where this went wrong once. Null means
// only that the set is within the configured element MAXIMUM. It does NOT mean the
// next token carries the claim, and no sentence built on it may say so. Three other
// things each suppress the claim on their own and none of them is visible from a
// management read of a membership:
//
//   The byte bound, which the mint measures on the real compact token. The
//   management view evaluates the element half ONLY (see PermissionBudgetView in
//   crates/ironauth-admin/src/org_effective_roles.rs, which says so and explains
//   that an estimate here would be a lie in the direction that matters), while the
//   mint withholds on EITHER bound. With the shipped defaults the two disagree over
//   most of the warning band: a 200 element set of ordinary slugs is inside the 256
//   element maximum while the claim alone already exceeds the 4096 byte token
//   maximum.
//
//   The per audience opt-in. A permission claim reaches a token only for a resource
//   server that opted in, every audience of a multi audience target must have opted
//   in, and a plain code exchange that names no RFC 8707 resource opts in by
//   construction: it carries no permission claim at all.
//
//   The token format. Only a JWT access token can carry the claim.
//
// So this reports a COUNT verdict, and everything else about emission belongs to
// the mint and to the permissions section.
function budgetWithholdingReason(budget: PermissionBudgetView): string | null {
  const overflow = budget.overflow ?? null;
  if (overflow === null) {
    return null;
  }
  return `The next access token will carry NO permission claim, reporting ${overflow} instead, because this set is past the configured maximum of ${budget.max_permission_count}. Every permission listed above is still held and still on file, and nothing was refused: what changed is only what one token can carry.`;
}

// The human wording of ONE grant path, TOTAL over the generated source union.
//
// A `Record` keyed on `EffectiveRoleSourceView` and not a function taking `string`,
// and the difference is the whole point rather than a style preference. This is the
// second attempt at this label: the first was a two branch ternary whose else arm
// said "granted directly", and when issue #98 PR 6 widened the union with `default`
// that arm quietly claimed the organization default role was a direct grant, which
// sends an operator looking for a withdrawal row that does not exist and cannot be
// removed. It shipped that way for the rest of the issue precisely because nothing
// made the widening visible. Keyed on the union, a fifth variant (issue #103
// entitlements is the next candidate, see the `kind` field on `PermissionView`) is a
// compile error naming the missing property instead of a wrong sentence.
const PROVENANCE_LABELS: Record<EffectiveRoleSourceView, string> = {
  direct: "granted directly",
  group: "through a group",
  default: "the default role of the organization",
};

function MembershipRoleRow({
  tenantId,
  environmentId,
  organizationId,
  membershipId,
  assignment,
  onUnassigned,
}: OrgScope & {
  membershipId: string;
  assignment: OrgMembershipRoleView;
  onUnassigned: () => void;
}) {
  const mutation = useMutation();

  function onUnassign(): void {
    void mutation
      .run(async () => {
        await unassignOrgMembershipRole(
          tenantId,
          environmentId,
          organizationId,
          membershipId,
          assignment.role_id,
        );
      }, "Role withdrawn from the member.")
      .then((ok) => {
        if (ok) {
          onUnassigned();
        }
      });
  }

  return (
    <li class="resource-row">
      <code class="resource-link">{assignment.role_id}</code>
      <code class="resource-id">{assignment.id}</code>
      <ConfirmButton
        label="Withdraw from member"
        prompt="Withdraw this direct grant? The member may still resolve the role through a group, which the effective roles below state."
        confirmLabel="Confirm withdraw from member"
        danger
        disabled={mutation.state.pending}
        onConfirm={onUnassign}
      />
      <MutationFeedback state={mutation.state} sudo={sudoFor(mutation.retry)} />
    </li>
  );
}

// The PROVENANCE view: every grant path by which this member holds a role.
//
// One row per path, in the order the server returned them, NEVER collapsed by
// slug. A role reached both directly and through a group is two rows carrying the
// same slug, and that repetition is the answer to "why does this member have this
// role" and to "what happens if I withdraw one grant". Collapsing it would show
// one row, the operator would withdraw the one grant it names, and the role would
// survive by the path that was hidden.
function EffectiveRolesPanel({
  state,
  suppression,
}: {
  state: AsyncState<EffectiveRolesView>;
  // Why resolution is gated off, or null when it is not. Shown only alongside an
  // empty set, where it is the difference between "no grants" and "grants that
  // resolve to nothing right now".
  suppression: string | null;
}) {
  return (
    <div class="resource-subsection">
      <h4>Effective roles, with provenance</h4>
      <p class="resource-note">
        One row per grant path. A slug listed more than once is held by more than
        one path, so withdrawing a single grant leaves the role in place. A path
        marked as the default role of the organization is carried by the
        designation and no withdrawal here removes it. This is what the next
        access token would carry; tokens already issued are not revoked by a
        change here.
      </p>
      <AsyncBoundary state={state} loadingLabel="Loading effective roles">
        {(view) => (
          <div>
            {view.roles.length === 0 ? (
              <div>
                <p class="resource-empty">
                  This member resolves no roles in this organization.
                </p>
                {suppression === null ? null : (
                  <p class="resource-note" role="status">
                    {suppression}
                  </p>
                )}
              </div>
            ) : (
              <ol class="resource-list" aria-label="Effective role grant paths">
                {view.roles.map((entry, index) => (
                  // Keyed by POSITION, the convention issue #97 shipped. Two
                  // entries may carry the same slug (one direct, one through a
                  // group), and BOTH must render; measured, they do under either
                  // keying, so the position key is a convention rather than what
                  // makes that hold. What makes it hold is that nothing collapses
                  // the array, which the test below pins by counting the rows.
                  <li key={`grant-${index}`} class="resource-row">
                    <code class="resource-link">{entry.slug}</code>
                    <span class="resource-provenance">
                      {PROVENANCE_LABELS[entry.source]}
                    </span>
                    {entry.source === "group" ? (
                      <code class="resource-id">
                        {entry.via_group_id ?? "group not stated"}
                      </code>
                    ) : null}
                  </li>
                ))}
              </ol>
            )}
            <EffectivePermissionsPanel
              permissions={view.permissions}
              budget={view.permission_budget}
              suppression={suppression}
            />
          </div>
        )}
      </AsyncBoundary>
    </div>
  );
}

// The permission UNION the roles above carry, and the budget verdict for it
// (issue #98).
//
// Rendered as its own half rather than folded into the rows above, because it is a
// different kind of answer: the roles list is one row per GRANT PATH, while this is
// a deduplicated SET, which is what a token claim is. A permission is carried by a
// role, and the roles list already names the paths, so nothing is lost by not
// repeating the provenance per permission.
//
// It is rendered ALONGSIDE an empty role list rather than inside the empty branch,
// so a set that is somehow non empty is never hidden by a role list that is.
//
// The whole set is listed however large it is and however the budget reads. That is
// structural: this is the one surface that could show an operator what a token will
// NOT carry, so it is the one surface that must never shorten the answer.
function EffectivePermissionsPanel({
  permissions,
  budget,
  suppression,
}: {
  permissions: string[];
  budget: PermissionBudgetView;
  // Why resolution is gated off, or null when it is not, exactly as for the roles
  // half above. Shown only alongside an empty SET, where the same reading applies
  // one field over: an operator seeing no permissions beside a role that visibly
  // attaches some would conclude the attachments went missing.
  suppression: string | null;
}) {
  const withheld = budgetWithholdingReason(budget);
  return (
    <div class="resource-subsection">
      <h4>Permissions these roles carry</h4>
      <p class="resource-note">
        The resolved permission set, deduplicated, in the order the server
        returned it. A permission is carried by a role, so the way to remove one
        is to detach it from the role or to withdraw the role.
      </p>
      {permissions.length === 0 ? (
        <div>
          <p class="resource-empty">
            These roles carry no permissions in this organization.
          </p>
          {suppression === null ? null : (
            <p class="resource-note" role="status">
              Resolution is gated off, which the roles above state, and a
              permission is carried by a role, so nothing resolves here either.
              Every attachment is still on file and is not lost.
            </p>
          )}
        </div>
      ) : (
        <ul class="resource-list" aria-label="Effective permissions">
          {permissions.map((slug, index) => (
            // Keyed by POSITION, the convention every list here follows. Not a
            // defense against a repeated slug: measured on this Preact version a
            // duplicate key collapses no row under either keying. What the test
            // below it pins is that a slug appearing twice yields two rows.
            <li key={`permission-${index}`} class="resource-row">
              <code class="resource-slug">{slug}</code>
            </li>
          ))}
        </ul>
      )}
      <p class="resource-note">
        {budget.permission_count} of at most {budget.max_permission_count}{" "}
        permissions, counted against the element budget, with a warning past{" "}
        {budget.warn_permission_count}. The verdict here is the ELEMENT count
        only: the configured token size bounds of {budget.warn_token_bytes} and{" "}
        {budget.max_token_bytes} bytes are shown as context, and the byte verdict
        belongs to the token mint, which measures the real token rather than
        estimating it here. Holding a permission and receiving it in a token are
        two different things in one more way as well: an access token carries the
        permission claim only for a resource server that has opted in, which the
        permissions section is where to read and set.
      </p>
      {budget.permission_count === permissions.length ? null : (
        <p class="resource-note" role="status">
          The budget counted {budget.permission_count} permissions while{" "}
          {permissions.length} are listed, so the verdict above does not describe
          the set shown. Read the listed set as what is held and treat the verdict
          as unreliable.
        </p>
      )}
      {withheld === null ? null : (
        <p class="resource-note" role="status">
          {withheld}
        </p>
      )}
      {withheld === null && budget.approaching ? (
        <p class="resource-note" role="status">
          This set is past the warning count of {budget.warn_permission_count}{" "}
          but still within the maximum, so the element count alone withholds
          nothing. That is not a statement that the next token carries the whole
          claim: the mint withholds on the byte bound as well, which it measures
          rather than estimates, and only an audience that has opted in receives
          the claim at all.
        </p>
      ) : null}
    </div>
  );
}
