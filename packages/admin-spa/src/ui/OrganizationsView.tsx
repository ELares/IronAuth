// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The organizations CRUD surface (issue #94), SCOPED to the active
// {tenant, environment} from the switcher: the list, the create form, the detail,
// the disable and enable lifecycle, the soft delete, and a nested memberships
// panel (add a member by user id, list the members, remove a member).
// Organizations and their memberships live UNDER an environment, so this surface
// reads BOTH the active tenant and the active environment from the scope store and
// injects them into every call, exactly as the users surface does. When no
// {tenant, environment} is in scope it shows a prompt and makes ZERO calls. It
// reads and writes ONLY through the named wrappers in src/api/client.ts (the
// single funnel), stands on the same reusable resource hooks and views, and
// renders every failure through the verbatim ErrorView boundary, including the RFC
// 9470 sudo path on a max_age challenge.
//
// The list reads are keyset paginated: when the wrapper reports a next cursor this
// surface tells the operator more rows exist beyond the first page (the
// no-silent-truncation rule) rather than dropping the tail.
//
// The detail also mounts the issue #97 panels: the roles of the organization
// (src/ui/OrgRolesView.tsx) and its group hierarchy (src/ui/OrgGroupsView.tsx),
// and each member row opens that member's direct role grants and resolved
// effective roles (src/ui/MemberRolesView.tsx). Those surfaces are org scoped and
// meaningless without an organization, so they live here rather than in the nav.
//
// Issue #98 adds one more of that kind: the DEFAULT ROLE designation
// (src/ui/OrgDefaultRoleView.tsx), a single valued property of one organization.
// Its counterparts that are ENVIRONMENT scoped, the permission vocabulary and the
// resource-server claim opt-in, are deliberately NOT here: they live in their own
// nav section (src/ui/PermissionsView.tsx), because one vocabulary is shared by
// every organization in the environment and a panel here would say otherwise.

import { useLocation } from "preact-iso";
import { consoleHref } from "./routing";
import { useState } from "preact/hooks";
import {
  type CreateMembershipRequest,
  type CreateOrganizationRequest,
  type KeysetPage,
  type MembershipView,
  type OrganizationView,
  addMembership,
  createOrganization,
  deleteOrganization,
  disableOrganization,
  enableOrganization,
  fetchMemberships,
  fetchOrganizations,
  getOrganization,
  removeMembership,
} from "../api/client";
import { activeScope } from "../scope/store";
import type { SudoRecovery } from "./ErrorView";
import {
  AsyncBoundary,
  ConfirmButton,
  MorePageNote,
  MutationFeedback,
  ResourceHeading,
  ResourceCreateAction,
  ResourceFormIntro,
  ResourceCollection,
  ResourceDetailNav,
} from "./ResourceView";
import { MembershipRolesPanel } from "./MemberRolesView";
import { OrgApiKeysPanel } from "./OrgApiKeysView";
import { OrgDefaultRolePanel } from "./OrgDefaultRoleView";
import { OrgGroupsPanel } from "./OrgGroupsView";
import { OrgRolesPanel } from "./OrgRolesView";
import { useAsyncResource, useMutation } from "./useResource";

function inputValue(event: Event): string {
  return (event.target as HTMLInputElement).value;
}

// The organizations list root, scoped to the active {tenant, environment}. When no
// scope is selected there is nothing to list, so it prompts and makes ZERO calls.
export function OrganizationsList() {
  const scope = activeScope.value;
  if (scope === null) {
    return (
      <section class="resource" aria-labelledby="organizations-heading">
        <ResourceHeading
          id="organizations-heading"
          title="Organizations"
          description="Manage organizations, their members and shared access policies."
        />
        <p class="resource-empty">
          Select a tenant and environment to view its organizations.
        </p>
      </section>
    );
  }
  return (
    <OrganizationsForScope
      key={`${scope.tenantId}/${scope.environmentId}`}
      tenantId={scope.tenantId}
      environmentId={scope.environmentId}
    />
  );
}

function OrganizationsForScope({
  tenantId,
  environmentId,
}: {
  tenantId: string;
  environmentId: string;
}) {
  const [notice, setNotice] = useState<string | null>(null);
  const { state, reload } = useAsyncResource<KeysetPage<OrganizationView>>(
    () => fetchOrganizations(tenantId, environmentId),
    [tenantId, environmentId],
  );
  return (
    <section class="resource" aria-labelledby="organizations-heading">
      <ResourceHeading
        id="organizations-heading"
        title="Organizations"
        description="Manage organizations, their members and shared access policies."
        actions={
          <ResourceCreateAction label="Create organization">
            {(close) => (
              <OrganizationCreateForm
                tenantId={tenantId}
                environmentId={environmentId}
                onCreated={() => {
                  setNotice("Organization created.");
                  reload();
                  close();
                }}
              />
            )}
          </ResourceCreateAction>
        }
      />
      {notice === null ? null : (
        <p class="resource-success" role="status" aria-live="polite">
          {notice}
        </p>
      )}
      <AsyncBoundary
        state={state}
        loadingLabel="Loading organizations"
        empty={{
          when: (page) => page.items.length === 0,
          render: () => <p class="resource-empty">No organizations yet.</p>,
        }}
      >
        {(page) => (
          <div>
            <ResourceCollection
              items={page.items}
              noun="organizations"
              searchText={(org) =>
                [
                  org.display_name,
                  org.id,
                  org.active ? "active" : "disabled",
                ].join(" ")
              }
              paginated
            >
              {(visible) => (
                <ul class="resource-list">
                  {visible.map((org) => (
                    <li key={org.id} class="resource-row">
                      <a
                        class="resource-link"
                        href={consoleHref(`/organizations/${org.id}`)}
                      >
                        {org.display_name}
                      </a>
                      <code class="resource-id">{org.id}</code>
                      <span
                        class={`resource-status resource-status-${
                          org.active ? "active" : "disabled"
                        }`}
                      >
                        {org.active ? "active" : "disabled"}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </ResourceCollection>
            <MorePageNote nextCursor={page.nextCursor} noun="organizations" />
          </div>
        )}
      </AsyncBoundary>
    </section>
  );
}

function OrganizationCreateForm({
  tenantId,
  environmentId,
  onCreated,
}: {
  tenantId: string;
  environmentId: string;
  onCreated: () => void;
}) {
  const mutation = useMutation();
  const [displayName, setDisplayName] = useState("");

  function onSubmit(event: Event): void {
    event.preventDefault();
    const request: CreateOrganizationRequest = {
      display_name: displayName.trim(),
    };
    void mutation
      .run(async () => {
        await createOrganization(tenantId, environmentId, request);
      }, "Organization created.")
      .then((ok) => {
        if (ok) {
          setDisplayName("");
          onCreated();
        }
      });
  }

  return (
    <form
      class="resource-form"
      onSubmit={onSubmit}
      aria-label="Create an organization"
    >
      <ResourceFormIntro
        title="Create organization"
        description="Give the organization a recognizable name. Members and roles can be added after creation."
      />
      <div class="resource-field">
        <label for="organization-display-name">Display name</label>
        <input
          id="organization-display-name"
          placeholder={"Acme Engineering"}
          type="text"
          required
          value={displayName}
          onInput={(event) => setDisplayName(inputValue(event))}
        />
      </div>
      <button
        type="submit"
        class="resource-btn resource-btn-primary"
        disabled={mutation.state.pending || displayName.trim() === ""}
      >
        Create organization
      </button>
      <MutationFeedback state={mutation.state} />
    </form>
  );
}

// One organization: its fields, the disable or enable lifecycle (by current
// active flag), the soft delete, and the nested memberships panel. The tenant and
// environment come from the active scope; a delete returns to the list. A max_age
// failure on any write drives the RFC 9470 sudo recovery, elevating within the
// active scope and replaying the write.
export function OrganizationDetail({
  organizationId,
}: {
  organizationId?: string;
}) {
  const scope = activeScope.value;
  if (scope === null) {
    return (
      <section class="resource" aria-labelledby="organization-detail-heading">
        <ResourceHeading
          id="organization-detail-heading"
          title="Organization"
          description="Manage members, roles, groups and credentials for this organization."
        />
        <p class="resource-empty">
          Select a tenant and environment to view this organization.
        </p>
      </section>
    );
  }
  return (
    <OrganizationDetailFor
      key={`${scope.tenantId}/${scope.environmentId}/${organizationId ?? ""}`}
      tenantId={scope.tenantId}
      environmentId={scope.environmentId}
      organizationId={organizationId ?? ""}
    />
  );
}

function OrganizationDetailFor({
  tenantId,
  environmentId,
  organizationId,
}: {
  tenantId: string;
  environmentId: string;
  organizationId: string;
}) {
  const location = useLocation();
  const { state, reload } = useAsyncResource<OrganizationView>(
    () => getOrganization(tenantId, environmentId, organizationId),
    [tenantId, environmentId, organizationId],
  );
  const mutation = useMutation();
  const scope = activeScope.value;
  const sudo: SudoRecovery | undefined =
    scope === null ? undefined : { scope, retry: mutation.retry };

  function onDelete(): void {
    void mutation.run(async () => {
      await deleteOrganization(tenantId, environmentId, organizationId);
      if (typeof location.route === "function") {
        location.route(consoleHref("/organizations"));
      }
    }, "Organization deleted.");
  }

  return (
    <section class="resource" aria-labelledby="organization-detail-heading">
      <p>
        <a class="resource-back" href={consoleHref("/organizations")}>
          Back to organizations
        </a>
      </p>
      <AsyncBoundary state={state} loadingLabel="Loading organization">
        {(org) => (
          <div>
            <ResourceHeading
              id="organization-detail-heading"
              title={org.display_name}
              description="Manage members, roles, groups and credentials for this organization."
            />
            <ResourceDetailNav
              items={[
                { id: "organization-members", label: "Members" },
                { id: "organization-default-role", label: "Default role" },
                { id: "organization-keys", label: "API keys" },
                { id: "organization-roles", label: "Roles" },
                { id: "organization-groups", label: "Groups" },
              ]}
            />
            <dl class="resource-detail">
              <dt>Identifier</dt>
              <dd>
                <code>{org.id}</code>
              </dd>
              <dt>Status</dt>
              <dd>{org.active ? "active" : "disabled"}</dd>
              <dt>Tenant</dt>
              <dd>
                <code>{org.tenant_id}</code>
              </dd>
              <dt>Environment</dt>
              <dd>
                <code>{org.environment_id}</code>
              </dd>
              <dt>Created</dt>
              <dd>{new Date(org.created_at_unix_ms).toISOString()}</dd>
            </dl>
            <div
              class="resource-actions"
              role="group"
              aria-label="Organization lifecycle"
            >
              {org.active ? (
                <ConfirmButton
                  label="Disable"
                  prompt="Disable this organization? It stays readable but is marked disabled."
                  confirmLabel="Confirm disable"
                  danger
                  disabled={mutation.state.pending}
                  onConfirm={() => {
                    void mutation
                      .run(async () => {
                        await disableOrganization(
                          tenantId,
                          environmentId,
                          organizationId,
                        );
                      }, "Organization disabled.")
                      .then((ok) => {
                        if (ok) {
                          reload();
                        }
                      });
                  }}
                />
              ) : (
                <ConfirmButton
                  label="Enable"
                  prompt="Re-enable this organization?"
                  confirmLabel="Confirm enable"
                  disabled={mutation.state.pending}
                  onConfirm={() => {
                    void mutation
                      .run(async () => {
                        await enableOrganization(
                          tenantId,
                          environmentId,
                          organizationId,
                        );
                      }, "Organization enabled.")
                      .then((ok) => {
                        if (ok) {
                          reload();
                        }
                      });
                  }}
                />
              )}
              <ConfirmButton
                label="Delete"
                prompt="Delete this organization? This cannot be undone."
                confirmLabel="Confirm delete"
                danger
                disabled={mutation.state.pending}
                onConfirm={onDelete}
              />
            </div>
            <MutationFeedback state={mutation.state} sudo={sudo} />

            <MembershipsPanel
              tenantId={tenantId}
              environmentId={environmentId}
              organizationId={organizationId}
              organizationActive={org.active}
            />

            <OrgDefaultRolePanel
              tenantId={tenantId}
              environmentId={environmentId}
              organizationId={organizationId}
            />

            <OrgApiKeysPanel
              tenantId={tenantId}
              environmentId={environmentId}
              organizationId={organizationId}
            />

            <OrgRolesPanel
              tenantId={tenantId}
              environmentId={environmentId}
              organizationId={organizationId}
            />

            <OrgGroupsPanel
              tenantId={tenantId}
              environmentId={environmentId}
              organizationId={organizationId}
            />
          </div>
        )}
      </AsyncBoundary>
    </section>
  );
}

// The members of one organization (operationIds listMemberships /
// createMembership / deleteMembership): add a member by user id, list the current
// members, and remove a member. A membership lives UNDER the organization, so
// every call injects the organization id alongside the active scope.
//
// Each row also opens the roles of that member (issue #97): the direct grants and
// the resolved effective roles with provenance. At most ONE row is open at a
// time, so the ids the nested forms carry stay unique in the document and the
// panel never fires reads for members the operator is not looking at.
function MembershipsPanel({
  tenantId,
  environmentId,
  organizationId,
  organizationActive,
}: {
  tenantId: string;
  environmentId: string;
  organizationId: string;
  // A DISABLED organization resolves NO roles for any member while its grants
  // stay on file, so the roles panel needs this to explain an empty resolved set.
  organizationActive: boolean;
}) {
  const { state, reload } = useAsyncResource<KeysetPage<MembershipView>>(
    () => fetchMemberships(tenantId, environmentId, organizationId),
    [tenantId, environmentId, organizationId],
  );
  const [notice, setNotice] = useState<string | null>(null);
  const [openMembershipId, setOpenMembershipId] = useState<string | null>(null);
  return (
    <div class="resource-subsection">
      <div class="resource-toolbar resource-section-heading">
        <div>
          <h2 id="organization-members">Members</h2>
          <p class="resource-hint">
            Manage membership and each member&#39;s roles.
          </p>
        </div>
        <ResourceCreateAction label="Add member">
          {(close) => (
            <MembershipAddForm
              tenantId={tenantId}
              environmentId={environmentId}
              organizationId={organizationId}
              onAdded={() => {
                setNotice("Member added.");
                reload();
                close();
              }}
            />
          )}
        </ResourceCreateAction>
      </div>
      {notice === null ? null : (
        <p class="resource-success" role="status" aria-live="polite">
          {notice}
        </p>
      )}
      <AsyncBoundary
        state={state}
        loadingLabel="Loading members"
        empty={{
          when: (page) => page.items.length === 0,
          render: () => <p class="resource-empty">No members yet.</p>,
        }}
      >
        {(page) => (
          <div>
            <ResourceCollection
              items={page.items}
              noun="members"
              headingLevel={3}
              searchText={(member) =>
                [member.user_id, member.id, member.state].join(" ")
              }
              paginated
            >
              {(visible) => (
                <ul class="resource-list">
                  {visible.map((member) => (
                    <MembershipRow
                      key={member.id}
                      tenantId={tenantId}
                      environmentId={environmentId}
                      organizationId={organizationId}
                      member={member}
                      organizationActive={organizationActive}
                      rolesOpen={openMembershipId === member.id}
                      onToggleRoles={() =>
                        setOpenMembershipId(
                          openMembershipId === member.id ? null : member.id,
                        )
                      }
                      onRemoved={reload}
                    />
                  ))}
                </ul>
              )}
            </ResourceCollection>
            <MorePageNote nextCursor={page.nextCursor} noun="members" />
          </div>
        )}
      </AsyncBoundary>
    </div>
  );
}

function MembershipAddForm({
  tenantId,
  environmentId,
  organizationId,
  onAdded,
}: {
  tenantId: string;
  environmentId: string;
  organizationId: string;
  onAdded: () => void;
}) {
  const mutation = useMutation();
  const [userId, setUserId] = useState("");

  function onSubmit(event: Event): void {
    event.preventDefault();
    const request: CreateMembershipRequest = { user_id: userId.trim() };
    void mutation
      .run(async () => {
        await addMembership(tenantId, environmentId, organizationId, request);
      }, "Member added.")
      .then((ok) => {
        if (ok) {
          setUserId("");
          onAdded();
        }
      });
  }

  return (
    <form
      class="resource-form"
      onSubmit={onSubmit}
      aria-label="Add a member to the organization"
    >
      <ResourceFormIntro
        title="Add member"
        headingLevel={3}
        description="Enter the ID of an existing user in this environment."
      />
      <div class="resource-field">
        <label for="membership-user-id">User id</label>
        <input
          id="membership-user-id"
          placeholder={"User ID from the Users screen"}
          type="text"
          required
          value={userId}
          onInput={(event) => setUserId(inputValue(event))}
        />
      </div>
      <button
        type="submit"
        class="resource-btn resource-btn-primary"
        disabled={mutation.state.pending || userId.trim() === ""}
      >
        Add member
      </button>
      <MutationFeedback state={mutation.state} />
    </form>
  );
}

function MembershipRow({
  tenantId,
  environmentId,
  organizationId,
  member,
  organizationActive,
  rolesOpen,
  onToggleRoles,
  onRemoved,
}: {
  tenantId: string;
  environmentId: string;
  organizationId: string;
  member: MembershipView;
  organizationActive: boolean;
  rolesOpen: boolean;
  onToggleRoles: () => void;
  onRemoved: () => void;
}) {
  const mutation = useMutation();

  function onRemove(): void {
    void mutation
      .run(async () => {
        await removeMembership(
          tenantId,
          environmentId,
          organizationId,
          member.id,
        );
      }, "Member removed.")
      .then((ok) => {
        if (ok) {
          onRemoved();
        }
      });
  }

  return (
    <li class="resource-row-block">
      <div class="resource-row">
        <code class="resource-link">{member.user_id}</code>
        <code class="resource-id">{member.id}</code>
        <span class="resource-status">{member.state}</span>
        <button
          type="button"
          class="resource-btn"
          aria-expanded={rolesOpen}
          aria-controls={
            rolesOpen ? `membership-roles-${member.id}` : undefined
          }
          onClick={onToggleRoles}
        >
          {rolesOpen ? "Hide roles" : "Show roles"}
        </button>
        <ConfirmButton
          label="Remove"
          prompt="Remove this member from the organization?"
          confirmLabel="Confirm remove"
          danger
          disabled={mutation.state.pending}
          onConfirm={onRemove}
        />
        <MutationFeedback state={mutation.state} />
      </div>
      {rolesOpen ? (
        <MembershipRolesPanel
          tenantId={tenantId}
          environmentId={environmentId}
          organizationId={organizationId}
          membershipId={member.id}
          organizationActive={organizationActive}
          membershipState={member.state}
        />
      ) : null}
    </li>
  );
}
