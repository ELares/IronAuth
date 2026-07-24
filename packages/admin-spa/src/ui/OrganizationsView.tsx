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

import { useLocation } from "preact-iso";
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
import { AsyncBoundary, ConfirmButton, MutationFeedback } from "./ResourceView";
import { useAsyncResource, useMutation } from "./useResource";

function inputValue(event: Event): string {
  return (event.target as HTMLInputElement).value;
}

// A "more exist beyond this page" note, rendered when a keyset read reports a next
// cursor. The list shows the first page; this makes the remainder explicit rather
// than silently dropping the tail. `noun` names the resource in the sentence.
function MorePageNote({
  nextCursor,
  noun,
}: {
  nextCursor: string | null;
  noun: string;
}) {
  if (nextCursor === null) {
    return null;
  }
  return (
    <p class="resource-more" role="status">
      More {noun} exist beyond this page. Only the first page is shown.
    </p>
  );
}

// The organizations list root, scoped to the active {tenant, environment}. When no
// scope is selected there is nothing to list, so it prompts and makes ZERO calls.
export function OrganizationsList() {
  const scope = activeScope.value;
  if (scope === null) {
    return (
      <section class="resource" aria-labelledby="organizations-heading">
        <h2 id="organizations-heading">Organizations</h2>
        <p class="resource-empty">
          Select a tenant and environment to view its organizations.
        </p>
      </section>
    );
  }
  return (
    <OrganizationsForScope
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
  const { state, reload } = useAsyncResource<KeysetPage<OrganizationView>>(
    () => fetchOrganizations(tenantId, environmentId),
    [tenantId, environmentId],
  );
  return (
    <section class="resource" aria-labelledby="organizations-heading">
      <h2 id="organizations-heading">Organizations</h2>
      <OrganizationCreateForm
        tenantId={tenantId}
        environmentId={environmentId}
        onCreated={reload}
      />
      <AsyncBoundary
        state={state}
        loadingLabel="Loading organizations"
        empty={{
          when: (page) => page.items.length === 0,
          render: () => (
            <p class="resource-empty">
              No organizations yet. Create the first one above.
            </p>
          ),
        }}
      >
        {(page) => (
          <div>
            <ul class="resource-list">
              {page.items.map((org) => (
                <li key={org.id} class="resource-row">
                  <a
                    class="resource-link"
                    href={`/organizations/${org.id}`}
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
      <div class="resource-field">
        <label for="organization-display-name">Display name</label>
        <input
          id="organization-display-name"
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
        <h2 id="organization-detail-heading">Organization</h2>
        <p class="resource-empty">
          Select a tenant and environment to view this organization.
        </p>
      </section>
    );
  }
  return (
    <OrganizationDetailFor
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
        location.route("/organizations");
      }
    }, "Organization deleted.");
  }

  return (
    <section class="resource" aria-labelledby="organization-detail-heading">
      <p>
        <a class="resource-back" href="/organizations">
          Back to organizations
        </a>
      </p>
      <AsyncBoundary state={state} loadingLabel="Loading organization">
        {(org) => (
          <div>
            <h2 id="organization-detail-heading">{org.display_name}</h2>
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
function MembershipsPanel({
  tenantId,
  environmentId,
  organizationId,
}: {
  tenantId: string;
  environmentId: string;
  organizationId: string;
}) {
  const { state, reload } = useAsyncResource<KeysetPage<MembershipView>>(
    () => fetchMemberships(tenantId, environmentId, organizationId),
    [tenantId, environmentId, organizationId],
  );
  return (
    <div class="resource-subsection">
      <h3>Members</h3>
      <MembershipAddForm
        tenantId={tenantId}
        environmentId={environmentId}
        organizationId={organizationId}
        onAdded={reload}
      />
      <AsyncBoundary
        state={state}
        loadingLabel="Loading members"
        empty={{
          when: (page) => page.items.length === 0,
          render: () => (
            <p class="resource-empty">
              No members yet. Add the first one above.
            </p>
          ),
        }}
      >
        {(page) => (
          <div>
            <ul class="resource-list">
              {page.items.map((member) => (
                <MembershipRow
                  key={member.id}
                  tenantId={tenantId}
                  environmentId={environmentId}
                  organizationId={organizationId}
                  member={member}
                  onRemoved={reload}
                />
              ))}
            </ul>
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
      <div class="resource-field">
        <label for="membership-user-id">User id</label>
        <input
          id="membership-user-id"
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
  onRemoved,
}: {
  tenantId: string;
  environmentId: string;
  organizationId: string;
  member: MembershipView;
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
    <li class="resource-row">
      <code class="resource-link">{member.user_id}</code>
      <code class="resource-id">{member.id}</code>
      <span class="resource-status">{member.state}</span>
      <ConfirmButton
        label="Remove"
        prompt="Remove this member from the organization?"
        confirmLabel="Confirm remove"
        danger
        disabled={mutation.state.pending}
        onConfirm={onRemove}
      />
      <MutationFeedback state={mutation.state} />
    </li>
  );
}
