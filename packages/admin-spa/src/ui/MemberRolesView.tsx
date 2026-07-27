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
// This is a PANEL opened from a member row of the organization detail view
// (src/ui/OrganizationsView.tsx). It reads and writes ONLY through the named
// wrappers in src/api/client.ts (the single funnel) and renders every failure
// through the verbatim ErrorView boundary, including the RFC 9470 sudo path on a
// max_age challenge.

import { useState } from "preact/hooks";
import {
  type AssignOrgMembershipRoleRequest,
  type EffectiveRoleView,
  type KeysetPage,
  type OrgMembershipRoleView,
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
  const effective = useAsyncResource<EffectiveRoleView[]>(
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
  state: AsyncState<EffectiveRoleView[]>;
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
        one path, so withdrawing a single grant leaves the role in place. This is
        what the next access token would carry; tokens already issued are not
        revoked by a change here.
      </p>
      <AsyncBoundary
        state={state}
        loadingLabel="Loading effective roles"
        empty={{
          when: (roles) => roles.length === 0,
          render: () => (
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
          ),
        }}
      >
        {(roles) => (
          <ol class="resource-list" aria-label="Effective role grant paths">
            {roles.map((entry, index) => (
              // Keyed by POSITION on purpose. Two entries may carry the same
              // slug (one direct, one through a group); a slug key would make
              // them collide and one row would disappear, which is the exact
              // failure this view exists to prevent.
              <li key={`grant-${index}`} class="resource-row">
                <code class="resource-link">{entry.slug}</code>
                <span class="resource-provenance">
                  {entry.source === "group"
                    ? "through a group"
                    : "granted directly"}
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
      </AsyncBoundary>
    </div>
  );
}
