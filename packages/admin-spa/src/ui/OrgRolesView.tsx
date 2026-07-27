// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The organization ROLES panel (issue #97). A role is a stable slug one
// organization grants; the slug is what an access token carries and what an
// authorization decision keys on, so it is IMMUTABLE and a rename touches only
// the label.
//
// This is a PANEL of the organization detail view (src/ui/OrganizationsView.tsx),
// not a top level nav section, because a role is meaningless without an
// organization selected. It reads and writes ONLY through the named wrappers in
// src/api/client.ts (the single funnel), stands on the same reusable resource
// hooks and views as the rest of the console, and renders every failure through
// the verbatim ErrorView boundary, including the RFC 9470 sudo path on a max_age
// challenge.

import { useState } from "preact/hooks";
import {
  type CreateOrgRoleRequest,
  type KeysetPage,
  type OrgRoleView,
  type UpdateOrgRoleRequest,
  createOrgRole,
  deleteOrgRole,
  fetchOrgRoles,
  getOrgRole,
  updateOrgRole,
} from "../api/client";
import {
  AsyncBoundary,
  ConfirmButton,
  MorePageNote,
  MutationFeedback,
} from "./ResourceView";
import { type OrgScope, inputValue, sudoFor } from "./orgPanels";
import { useAsyncResource, useMutation } from "./useResource";

// The roles of one organization: define a role, list the roles, and open one to
// rename or delete it.
export function OrgRolesPanel({
  tenantId,
  environmentId,
  organizationId,
}: OrgScope) {
  const { state, reload } = useAsyncResource<KeysetPage<OrgRoleView>>(
    () => fetchOrgRoles(tenantId, environmentId, organizationId),
    [tenantId, environmentId, organizationId],
  );
  const [openRoleId, setOpenRoleId] = useState<string | null>(null);

  return (
    <div class="resource-subsection">
      <h3>Roles</h3>
      <p class="resource-note">
        A role is a stable slug this organization grants. The slug is what an
        access token carries and what an authorization decision keys on, so it is
        immutable: a rename changes only the label.
      </p>
      <OrgRoleCreateForm
        tenantId={tenantId}
        environmentId={environmentId}
        organizationId={organizationId}
        onCreated={reload}
      />
      <AsyncBoundary
        state={state}
        loadingLabel="Loading roles"
        empty={{
          when: (page) => page.items.length === 0,
          render: () => (
            <p class="resource-empty">
              No roles yet. Define the first one above.
            </p>
          ),
        }}
      >
        {(page) => (
          <div>
            <ul class="resource-list" aria-label="Roles of the organization">
              {page.items.map((role) => (
                <li key={role.id} class="resource-row">
                  <button
                    type="button"
                    class="resource-linkbtn"
                    aria-expanded={openRoleId === role.id}
                    onClick={() =>
                      setOpenRoleId(openRoleId === role.id ? null : role.id)
                    }
                  >
                    {role.display_name}
                  </button>
                  <code class="resource-slug">{role.slug}</code>
                  <code class="resource-id">{role.id}</code>
                </li>
              ))}
            </ul>
            <MorePageNote nextCursor={page.nextCursor} noun="roles" />
          </div>
        )}
      </AsyncBoundary>
      {openRoleId === null ? null : (
        <OrgRoleDetail
          key={openRoleId}
          tenantId={tenantId}
          environmentId={environmentId}
          organizationId={organizationId}
          roleId={openRoleId}
          onChanged={reload}
          onDeleted={() => {
            setOpenRoleId(null);
            reload();
          }}
        />
      )}
    </div>
  );
}

function OrgRoleCreateForm({
  tenantId,
  environmentId,
  organizationId,
  onCreated,
}: OrgScope & { onCreated: () => void }) {
  const mutation = useMutation();
  const [slug, setSlug] = useState("");
  const [displayName, setDisplayName] = useState("");

  function onSubmit(event: Event): void {
    event.preventDefault();
    const request: CreateOrgRoleRequest = {
      slug: slug.trim(),
      display_name: displayName.trim(),
    };
    void mutation
      .run(async () => {
        await createOrgRole(
          tenantId,
          environmentId,
          organizationId,
          request,
        );
      }, "Role defined.")
      .then((ok) => {
        if (ok) {
          setSlug("");
          setDisplayName("");
          onCreated();
        }
      });
  }

  return (
    <form class="resource-form" onSubmit={onSubmit} aria-label="Define a role">
      <div class="resource-field">
        <label for="org-role-slug">Slug</label>
        <input
          id="org-role-slug"
          type="text"
          required
          value={slug}
          onInput={(event) => setSlug(inputValue(event))}
        />
      </div>
      <div class="resource-field">
        <label for="org-role-display-name">Display name</label>
        <input
          id="org-role-display-name"
          type="text"
          required
          value={displayName}
          onInput={(event) => setDisplayName(inputValue(event))}
        />
      </div>
      <button
        type="submit"
        class="resource-btn resource-btn-primary"
        disabled={
          mutation.state.pending ||
          slug.trim() === "" ||
          displayName.trim() === ""
        }
      >
        Define role
      </button>
      <MutationFeedback state={mutation.state} sudo={sudoFor(mutation.retry)} />
    </form>
  );
}

// One role, read FRESH rather than reused from the list row, so a rename made in
// another console session is visible. Renames the label; deletes the role.
function OrgRoleDetail({
  tenantId,
  environmentId,
  organizationId,
  roleId,
  onChanged,
  onDeleted,
}: OrgScope & {
  roleId: string;
  onChanged: () => void;
  onDeleted: () => void;
}) {
  const { state, reload } = useAsyncResource<OrgRoleView>(
    () => getOrgRole(tenantId, environmentId, organizationId, roleId),
    [tenantId, environmentId, organizationId, roleId],
  );
  const mutation = useMutation();
  const [displayName, setDisplayName] = useState<string | null>(null);

  function onRename(event: Event): void {
    event.preventDefault();
    // An UNTOUCHED field is OMITTED, never sent as an empty string. The body is
    // an RFC 7396 style partial edit where an absent field is left unchanged, so
    // omitting it says "no change"; sending "" asks for an empty label, which the
    // server refuses with a message that contradicts the populated field the
    // operator is looking at.
    const request: UpdateOrgRoleRequest =
      displayName === null ? {} : { display_name: displayName.trim() };
    void mutation
      .run(async () => {
        await updateOrgRole(
          tenantId,
          environmentId,
          organizationId,
          roleId,
          request,
        );
      }, "Role renamed.")
      .then((ok) => {
        if (ok) {
          reload();
          onChanged();
        }
      });
  }

  function onDelete(): void {
    void mutation
      .run(async () => {
        await deleteOrgRole(tenantId, environmentId, organizationId, roleId);
      }, "Role deleted.")
      .then((ok) => {
        if (ok) {
          onDeleted();
        }
      });
  }

  return (
    <div class="resource-detail-panel">
      <AsyncBoundary state={state} loadingLabel="Loading role">
        {(role) => (
          <div>
            <h4>Role {role.slug}</h4>
            <dl class="resource-detail">
              <dt>Identifier</dt>
              <dd>
                <code>{role.id}</code>
              </dd>
              <dt>Slug</dt>
              <dd>
                <code>{role.slug}</code>
              </dd>
              <dt>Created</dt>
              <dd>{new Date(role.created_at_unix_ms).toISOString()}</dd>
            </dl>
            <form
              class="resource-form"
              onSubmit={onRename}
              aria-label="Rename the role"
            >
              <div class="resource-field">
                <label for="org-role-rename">Display name</label>
                <input
                  id="org-role-rename"
                  type="text"
                  required
                  value={displayName ?? role.display_name}
                  onInput={(event) => setDisplayName(inputValue(event))}
                />
              </div>
              <button
                type="submit"
                class="resource-btn resource-btn-primary"
                disabled={mutation.state.pending}
              >
                Rename role
              </button>
            </form>
            <div class="resource-actions" role="group" aria-label="Role actions">
              <ConfirmButton
                label="Delete role"
                prompt="Delete this role? Every grant of it is withdrawn, and members stop resolving it at the next token issuance. Access tokens already issued are not revoked."
                confirmLabel="Confirm delete role"
                danger
                disabled={mutation.state.pending}
                onConfirm={onDelete}
              />
            </div>
            <MutationFeedback
              state={mutation.state}
              sudo={sudoFor(mutation.retry)}
            />
          </div>
        )}
      </AsyncBoundary>
    </div>
  );
}
