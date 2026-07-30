// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The permissions ONE ROLE grants (issue #98), nested in the role detail of the
// organization view (src/ui/OrgRolesView.tsx).
//
// This is a PANEL and not a nav section, by the same argument the roles panel is:
// a role is meaningless without an organization selected, and so is the mapping
// from a role to a permission. What is NOT here is the permission VOCABULARY,
// which is ENVIRONMENT scoped and lives in its own section
// (src/ui/PermissionsView.tsx): every organization in an environment maps its
// roles onto one shared vocabulary, so a vocabulary panel on an organization would
// tell an operator that the entries they define belong to that organization.
//
// A row is addressed by the PERMISSION id, never by the mapping row id. The
// mapping id is carried for audit correlation and no endpoint accepts it, exactly
// as with the group and membership role grants.
//
// Two things this panel deliberately does not do:
//
//   It does not resolve a permission id to its slug. The mapping row carries only
//   the id, the slug belongs to the vocabulary, and joining the two here would
//   mean a second read whose failure would have to be reported as a hole in a list
//   that is otherwise complete. The vocabulary section is where a slug is looked
//   up, and it lists both.
//
//   It does not warn about the permission budget. The budget refuses no write and
//   caps nothing that may be STORED, so an attach that pushes a member past it
//   still answers 201 and this panel would be inventing a refusal. The place the
//   budget is answered is the member effective-roles panel, which reads the actual
//   resolved set (src/ui/MemberRolesView.tsx).
//
// It reads and writes ONLY through the named wrappers in src/api/client.ts (the
// single funnel) and renders every failure through the verbatim ErrorView
// boundary, including the RFC 9470 sudo path on a max_age challenge and the 422
// that refuses a permission which is not a live entry of THIS environment.

import { useState } from "preact/hooks";
import {
  type AssignOrgRolePermissionRequest,
  type KeysetPage,
  type OrgRolePermissionView,
  assignOrgRolePermission,
  fetchOrgRolePermissions,
  unassignOrgRolePermission,
} from "../api/client";
import {
  AsyncBoundary,
  ConfirmButton,
  MorePageNote,
  MutationFeedback,
} from "./ResourceView";
import { type OrgScope, inputValue, sudoFor } from "./orgPanels";
import { useAsyncResource, useMutation } from "./useResource";

export function OrgRolePermissionsPanel({
  tenantId,
  environmentId,
  organizationId,
  roleId,
}: OrgScope & { roleId: string }) {
  const { state, reload } = useAsyncResource<KeysetPage<OrgRolePermissionView>>(
    () =>
      fetchOrgRolePermissions(
        tenantId,
        environmentId,
        organizationId,
        roleId,
      ),
    [tenantId, environmentId, organizationId, roleId],
  );
  const mutation = useMutation();
  const [permissionId, setPermissionId] = useState("");

  function onAttach(event: Event): void {
    event.preventDefault();
    const request: AssignOrgRolePermissionRequest = {
      permission_id: permissionId.trim(),
    };
    void mutation
      .run(async () => {
        await assignOrgRolePermission(
          tenantId,
          environmentId,
          organizationId,
          roleId,
          request,
        );
      }, "Permission attached to the role.")
      .then((ok) => {
        if (ok) {
          setPermissionId("");
          reload();
        }
      });
  }

  return (
    <div class="resource-subsection">
      <h4>Permissions this role grants</h4>
      <p class="resource-note">
        Every member who resolves this role holds these permissions. Holding a
        permission and receiving it in a token are two different things: an access
        token carries the permission claim only for a resource server that has
        opted in, and only when that resource server issues a token format able to
        carry one, which the permissions section is where to read and set. The
        permission itself is defined once for the whole environment there; this list
        is only which of those entries this one role carries.
      </p>
      <form
        class="resource-form"
        onSubmit={onAttach}
        aria-label="Attach a permission to the role"
      >
        <div class="resource-field">
          <label for="org-role-permission-id">Permission id</label>
          <input
            id="org-role-permission-id"
            type="text"
            required
            value={permissionId}
            onInput={(event) => setPermissionId(inputValue(event))}
          />
        </div>
        <button
          type="submit"
          class="resource-btn resource-btn-primary"
          disabled={mutation.state.pending || permissionId.trim() === ""}
        >
          Attach permission
        </button>
        <MutationFeedback
          state={mutation.state}
          sudo={sudoFor(mutation.retry)}
        />
      </form>
      <AsyncBoundary
        state={state}
        loadingLabel="Loading the permissions of the role"
        empty={{
          when: (page) => page.items.length === 0,
          render: () => (
            <p class="resource-empty">
              This role carries no permissions. Attach the first one above.
            </p>
          ),
        }}
      >
        {(page) => (
          <div>
            <ul
              class="resource-list"
              aria-label="Permissions the role grants"
            >
              {page.items.map((mapping, index) => (
                // Keyed by POSITION, which is the convention issue #97 shipped for
                // every list in this console. It is a CONVENTION and not a defense:
                // measured on this Preact version, a repeated server supplied key
                // collapses no row either, on a mount or on any re-diff, so the two
                // strategies render the same number of rows. What the tests pin is
                // the property that matters here, that a repeated permission id
                // still yields one row per mapping on file.
                <OrgRolePermissionRow
                  key={`role-permission-${index}`}
                  tenantId={tenantId}
                  environmentId={environmentId}
                  organizationId={organizationId}
                  roleId={roleId}
                  mapping={mapping}
                  onDetached={reload}
                />
              ))}
            </ul>
            <MorePageNote
              nextCursor={page.nextCursor}
              noun="permissions carried by this role"
            />
          </div>
        )}
      </AsyncBoundary>
    </div>
  );
}

function OrgRolePermissionRow({
  tenantId,
  environmentId,
  organizationId,
  roleId,
  mapping,
  onDetached,
}: OrgScope & {
  roleId: string;
  mapping: OrgRolePermissionView;
  onDetached: () => void;
}) {
  const mutation = useMutation();

  function onDetach(): void {
    void mutation
      .run(async () => {
        await unassignOrgRolePermission(
          tenantId,
          environmentId,
          organizationId,
          roleId,
          mapping.permission_id,
        );
      }, "Permission detached from the role.")
      .then((ok) => {
        if (ok) {
          onDetached();
        }
      });
  }

  return (
    <li class="resource-row">
      <code class="resource-link">{mapping.permission_id}</code>
      <code class="resource-id">{mapping.id}</code>
      <ConfirmButton
        label="Detach from role"
        prompt="Detach this permission? Every member who resolves this role stops holding it at the next token issuance. Access tokens already issued are not revoked, and the permission itself stays defined in the environment."
        confirmLabel="Confirm detach from role"
        danger
        disabled={mutation.state.pending}
        onConfirm={onDetach}
      />
      <MutationFeedback state={mutation.state} sudo={sudoFor(mutation.retry)} />
    </li>
  );
}
