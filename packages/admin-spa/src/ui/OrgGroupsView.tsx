// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The organization GROUPS panel (issue #97): the hierarchy, the group detail, the
// memberships bound into a group, and the roles a group grants. A group nests
// inside another group, and every role a group grants is resolved by its members
// and by the members of every group beneath it.
//
// Two things here are load bearing and must not be "tidied" later.
//
//   The tree renders EVERY loaded group exactly once (see src/ui/groupTree.ts). A
//   group whose parent is deleted, or is on a page not read yet, appears at the
//   top level MARKED rather than vanishing with its subtree. That is also how the
//   server treats it, because a delete DETACHES rather than cascading.
//
//   MOVING a group is its own operation, never folded into the rename. It is the
//   one mutation the server can refuse on structural grounds (a cycle, or nesting
//   past the configured maximum depth), and those 422 bodies are rendered
//   VERBATIM, because rewording them would cost the operator the reason.
//
//   The move control SUBMITS EXACTLY WHAT IT DISPLAYS. The options are built from
//   the loaded page, so a group whose current parent is deleted or beyond that
//   page has no option matching it; the select would then render blank while a
//   fallback to the stored parent quietly submitted a value the operator never
//   saw. One expression feeds both the rendered value and the submitted body, and
//   the unresolvable case is stated in words rather than defaulted in silence.
//
// This is a PANEL of the organization detail view (src/ui/OrganizationsView.tsx).
// It reads and writes ONLY through the named wrappers in src/api/client.ts (the
// single funnel) and renders every failure through the verbatim ErrorView
// boundary, including the RFC 9470 sudo path on a max_age challenge.

import { useEffect, useRef, useState } from "preact/hooks";
import {
  type AddOrgGroupMemberRequest,
  type AssignOrgGroupRoleRequest,
  type CreateOrgGroupRequest,
  type KeysetPage,
  type OrgGroupMemberView,
  type OrgGroupRoleView,
  type OrgGroupView,
  type UpdateOrgGroupRequest,
  addOrgGroupMember,
  assignOrgGroupRole,
  createOrgGroup,
  deleteOrgGroup,
  fetchOrgGroupMembers,
  fetchOrgGroupRoles,
  fetchOrgGroups,
  getOrgGroup,
  removeOrgGroupMember,
  setOrgGroupParent,
  unassignOrgGroupRole,
  updateOrgGroup,
} from "../api/client";
import {
  AsyncBoundary,
  ConfirmButton,
  MorePageNote,
  MutationFeedback,
  ResourceFormIntro,
  ResourceCreateAction,
} from "./ResourceView";
import {
  type GroupNode,
  buildGroupForest,
  groupAndDescendantIds,
} from "./groupTree";
import { type OrgScope, inputValue, selectValue, sudoFor } from "./orgPanels";
import { useAsyncResource, useMutation } from "./useResource";

// The sentinel option value meaning "no parent": a select carries strings, and
// the empty string is not a valid group id, so it cannot collide with one.
const NO_PARENT = "";

// The group hierarchy of one organization, rendered as a TREE built from the flat
// page, plus the detail of the group the operator opened.
export function OrgGroupsPanel({
  tenantId,
  environmentId,
  organizationId,
}: OrgScope) {
  const { state, reload } = useAsyncResource<KeysetPage<OrgGroupView>>(
    () => fetchOrgGroups(tenantId, environmentId, organizationId),
    [tenantId, environmentId, organizationId],
  );
  const [openGroupId, setOpenGroupId] = useState<string | null>(null);
  useEffect(
    () => setOpenGroupId(null),
    [tenantId, environmentId, organizationId],
  );
  const loaded = state.data?.items ?? [];

  return (
    <div class="resource-subsection">
      <div class="resource-subsection-heading">
        <h2 id="organization-groups">Groups</h2>
        <ResourceCreateAction
          key={`${tenantId}:${environmentId}:${organizationId}`}
          label="Create group"
        >
          {(close) => (
            <OrgGroupCreateForm
              tenantId={tenantId}
              environmentId={environmentId}
              organizationId={organizationId}
              groups={loaded}
              onCreated={() => {
                close();
                reload();
              }}
            />
          )}
        </ResourceCreateAction>
      </div>
      <p class="resource-hint">
        Organize members into a hierarchy. Members inherit the roles granted to
        their group and its parents.
      </p>
      <details class="resource-help">
        <summary>How group inheritance works</summary>
        <p class="resource-note">
          A group nests inside another group, and every role a group grants is
          resolved by its members and by the members of every group beneath it.
        </p>
      </details>

      <AsyncBoundary
        state={state}
        loadingLabel="Loading groups"
        empty={{
          when: (page) => page.items.length === 0,
          render: () => <p class="resource-empty">No groups yet.</p>,
        }}
      >
        {(page) => (
          <div>
            <GroupTree
              nodes={buildGroupForest(page.items)}
              openGroupId={openGroupId}
              onToggle={(id) => setOpenGroupId(openGroupId === id ? null : id)}
            />
            <MorePageNote nextCursor={page.nextCursor} noun="groups" />
          </div>
        )}
      </AsyncBoundary>
      {openGroupId === null ? null : (
        <OrgGroupDetail
          key={openGroupId}
          tenantId={tenantId}
          environmentId={environmentId}
          organizationId={organizationId}
          groupId={openGroupId}
          groups={loaded}
          onChanged={reload}
          onDeleted={() => {
            setOpenGroupId(null);
            reload();
          }}
        />
      )}
    </div>
  );
}

// The hierarchy itself: a flattened ARIA tree. Every loaded group is one row,
// its nesting carried by aria-level (and mirrored visually by the indent), so a
// row can never be lost to a parent that is missing from the page. A row whose
// parent could not be resolved is marked, and the marking is explained once
// below the tree rather than per row.
function GroupTree({
  nodes,
  openGroupId,
  onToggle,
}: {
  nodes: ReadonlyArray<GroupNode>;
  openGroupId: string | null;
  onToggle: (groupId: string) => void;
}) {
  const buttons = useRef<Array<HTMLButtonElement | null>>([]);
  const [focusedGroupId, setFocusedGroupId] = useState<string | null>(null);
  const focusId =
    nodes.find((node) => node.group.id === focusedGroupId)?.group.id ??
    nodes[0]?.group.id;
  const anyDetached = nodes.some((node) => node.detached);
  return (
    <div>
      <p id="organization-group-navigation-help" class="resource-hint">
        Use the arrow keys to move between groups. Press Enter to view a group.
      </p>
      <ul
        class="resource-tree"
        role="tree"
        aria-label="Group hierarchy of the organization"
        aria-describedby="organization-group-navigation-help"
      >
        {nodes.map((node, index) => (
          <li
            key={node.group.id}
            class="resource-row resource-tree-item"
            role="treeitem"
            aria-level={node.depth + 1}
            aria-selected={openGroupId === node.group.id}
            aria-expanded={
              (nodes[index + 1]?.depth ?? -1) > node.depth ? true : undefined
            }
          >
            {node.depth === 0 ? null : (
              <span class="resource-tree-indent" aria-hidden="true">
                {Array.from({ length: node.depth }, (_, level) => (
                  <span key={level} class="resource-tree-indent-step" />
                ))}
              </span>
            )}
            <button
              ref={(button) => {
                buttons.current[index] = button;
              }}
              type="button"
              class="resource-linkbtn"
              tabIndex={focusId === node.group.id ? 0 : -1}
              onFocus={() => setFocusedGroupId(node.group.id)}
              onKeyDown={(event) => {
                let target = index;
                if (event.key === "ArrowDown")
                  target = Math.min(index + 1, nodes.length - 1);
                else if (event.key === "ArrowUp")
                  target = Math.max(index - 1, 0);
                else if (event.key === "Home") target = 0;
                else if (event.key === "End") target = nodes.length - 1;
                else if (event.key === "ArrowRight") {
                  if ((nodes[index + 1]?.depth ?? -1) > node.depth)
                    target = index + 1;
                } else if (event.key === "ArrowLeft") {
                  for (let parent = index - 1; parent >= 0; parent -= 1) {
                    if (nodes[parent].depth < node.depth) {
                      target = parent;
                      break;
                    }
                  }
                } else return;
                event.preventDefault();
                buttons.current[target]?.focus();
              }}
              aria-expanded={openGroupId === node.group.id}
              aria-controls={
                openGroupId === node.group.id
                  ? `org-group-detail-${node.group.id}`
                  : undefined
              }
              onClick={() => onToggle(node.group.id)}
            >
              {node.group.display_name}
            </button>
            <code class="resource-slug">{node.group.slug}</code>
            <code class="resource-id">{node.group.id}</code>
            {node.detached ? (
              <span class="resource-status resource-status-disabled">
                detached parent
              </span>
            ) : null}
          </li>
        ))}
      </ul>
      {anyDetached ? (
        <p class="resource-note" role="status">
          A group marked detached names a parent that is not readable here,
          because the parent was deleted or is beyond this page. It is shown at
          the top level, which is also how the server treats it.
        </p>
      ) : null}
    </div>
  );
}

function OrgGroupCreateForm({
  tenantId,
  environmentId,
  organizationId,
  groups,
  onCreated,
}: OrgScope & {
  groups: ReadonlyArray<OrgGroupView>;
  onCreated: () => void;
}) {
  const mutation = useMutation();
  const [slug, setSlug] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [parentId, setParentId] = useState(NO_PARENT);

  function onSubmit(event: Event): void {
    event.preventDefault();
    const request: CreateOrgGroupRequest = {
      slug: slug.trim(),
      display_name: displayName.trim(),
      parent_id: parentId === NO_PARENT ? null : parentId,
    };
    void mutation.run(async () => {
      await createOrgGroup(tenantId, environmentId, organizationId, request);
      setSlug("");
      setDisplayName("");
      setParentId(NO_PARENT);
      onCreated();
    }, "Group defined.");
  }

  return (
    <form class="resource-form" onSubmit={onSubmit} aria-label="Define a group">
      <ResourceFormIntro
        title="Define group"
        headingLevel={3}
        description="Create a group at the top level or under an existing group."
      />
      <div class="resource-field">
        <label for="org-group-slug">Slug</label>
        <input
          id="org-group-slug"
          placeholder={"engineering"}
          type="text"
          required
          value={slug}
          onInput={(event) => setSlug(inputValue(event))}
        />
      </div>
      <div class="resource-field">
        <label for="org-group-display-name">Display name</label>
        <input
          id="org-group-display-name"
          placeholder={"Engineering"}
          type="text"
          required
          value={displayName}
          onInput={(event) => setDisplayName(inputValue(event))}
        />
      </div>
      <div class="resource-field">
        <label for="org-group-parent">Parent group</label>
        <select
          id="org-group-parent"
          value={parentId}
          onChange={(event) => setParentId(selectValue(event))}
        >
          <option value={NO_PARENT}>No parent, a top level group</option>
          {groups.map((group) => (
            <option key={group.id} value={group.id}>
              {group.display_name}
            </option>
          ))}
        </select>
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
        Define group
      </button>
      <MutationFeedback state={mutation.state} sudo={sudoFor(mutation.retry)} />
    </form>
  );
}

// One group, read FRESH: rename, MOVE, delete, plus the members bound into it and
// the roles it grants.
function OrgGroupDetail({
  tenantId,
  environmentId,
  organizationId,
  groupId,
  groups,
  onChanged,
  onDeleted,
}: OrgScope & {
  groupId: string;
  groups: ReadonlyArray<OrgGroupView>;
  onChanged: () => void;
  onDeleted: () => void;
}) {
  const { state, reload } = useAsyncResource<OrgGroupView>(
    () => getOrgGroup(tenantId, environmentId, organizationId, groupId),
    [tenantId, environmentId, organizationId, groupId],
  );
  const mutation = useMutation();
  const [displayName, setDisplayName] = useState<string | null>(null);
  const [parentId, setParentId] = useState<string | null>(null);

  // The groups this one may move under. Its own subtree is excluded because
  // moving a group beneath its own descendant is a cycle. This only prunes
  // options the console can already tell are impossible; the server decides, and
  // its refusal is rendered verbatim below.
  const blocked = groupAndDescendantIds(groups, groupId);
  const candidates = groups.filter((group) => !blocked.has(group.id));

  function onRename(event: Event): void {
    event.preventDefault();
    // An UNTOUCHED field is OMITTED, never sent as an empty string. The body is
    // an RFC 7396 style partial edit where an absent field is left unchanged, so
    // omitting it says "no change"; sending "" asks for an empty label, which the
    // server refuses with a message that contradicts the populated field the
    // operator is looking at.
    const request: UpdateOrgGroupRequest =
      displayName === null ? {} : { display_name: displayName.trim() };
    void mutation
      .run(async () => {
        await updateOrgGroup(
          tenantId,
          environmentId,
          organizationId,
          groupId,
          request,
        );
      }, "Group renamed.")
      .then((ok) => {
        if (ok) {
          reload();
          onChanged();
        }
      });
  }

  // `chosen` is the value the select is RENDERING, computed once below and passed
  // in, so what the operator sees and what reaches the wire cannot diverge.
  function onMove(event: Event, chosen: string): void {
    event.preventDefault();
    void mutation
      .run(async () => {
        await setOrgGroupParent(
          tenantId,
          environmentId,
          organizationId,
          groupId,
          { parent_id: chosen === NO_PARENT ? null : chosen },
        );
      }, "Group moved.")
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
        await deleteOrgGroup(tenantId, environmentId, organizationId, groupId);
      }, "Group deleted.")
      .then((ok) => {
        if (ok) {
          onDeleted();
        }
      });
  }

  return (
    <div class="resource-detail-panel" id={`org-group-detail-${groupId}`}>
      <AsyncBoundary state={state} loadingLabel="Loading group">
        {(group) => (
          <div>
            <h3>Group {group.slug}</h3>
            <dl class="resource-detail">
              <dt>Identifier</dt>
              <dd>
                <code>{group.id}</code>
              </dd>
              <dt>Slug</dt>
              <dd>
                <code>{group.slug}</code>
              </dd>
              <dt>Parent</dt>
              <dd>
                <code>{group.parent_id ?? "none, a top level group"}</code>
              </dd>
              <dt>Created</dt>
              <dd>{new Date(group.created_at_unix_ms).toISOString()}</dd>
            </dl>
            <form
              class="resource-form"
              onSubmit={onRename}
              aria-label="Rename the group"
            >
              <div class="resource-field">
                <label for="org-group-rename">Display name</label>
                <input
                  id="org-group-rename"
                  type="text"
                  required
                  value={displayName ?? group.display_name}
                  onInput={(event) => setDisplayName(inputValue(event))}
                />
              </div>
              <button
                type="submit"
                class="resource-btn resource-btn-primary"
                disabled={mutation.state.pending}
              >
                Rename group
              </button>
            </form>
            <OrgGroupMoveForm
              group={group}
              candidates={candidates}
              parentId={parentId}
              onChoose={setParentId}
              onSubmit={onMove}
              pending={mutation.state.pending}
            />
            <div
              class="resource-actions"
              role="group"
              aria-label="Group actions"
            >
              <ConfirmButton
                label="Delete group"
                prompt="Delete this group? Its children are detached rather than deleted, and they become top level groups."
                confirmLabel="Confirm delete group"
                danger
                disabled={mutation.state.pending}
                onConfirm={onDelete}
              />
            </div>
            <MutationFeedback
              state={mutation.state}
              sudo={sudoFor(mutation.retry)}
            />
            <OrgGroupMembersPanel
              tenantId={tenantId}
              environmentId={environmentId}
              organizationId={organizationId}
              groupId={groupId}
            />
            <OrgGroupRolesPanel
              tenantId={tenantId}
              environmentId={environmentId}
              organizationId={organizationId}
              groupId={groupId}
            />
          </div>
        )}
      </AsyncBoundary>
    </div>
  );
}

// The MOVE control, kept whole so the value it RENDERS and the value it SUBMITS
// are ONE expression.
//
// `candidates` is built from the loaded page, so the current parent of this group
// matches no option whenever that parent was deleted or sits beyond the page. A
// select handed a value no option carries renders BLANK, and the group the
// operator is most likely to open here is exactly that one, because the tree
// marks it "detached parent". Falling back to the stored parent on submit would
// then PUT a value the control never showed: the server accepts the reparent to
// the parent it already had, the panel reports "Group moved.", and nothing moved.
//
// So the fallback is the sentinel the control is actually displaying, and the
// case is STATED rather than defaulted in silence. An extra disabled option
// naming the unresolvable parent was considered and rejected: an option is only
// visible once the dropdown is opened, which is the step the mistaken operator
// never takes, and selecting it would restore the same no-op submit.
function OrgGroupMoveForm({
  group,
  candidates,
  parentId,
  onChoose,
  onSubmit,
  pending,
}: {
  group: OrgGroupView;
  candidates: ReadonlyArray<OrgGroupView>;
  // The parent the operator picked, or null while the control is untouched.
  parentId: string | null;
  onChoose: (value: string) => void;
  onSubmit: (event: Event, chosen: string) => void;
  pending: boolean;
}) {
  const currentParent = group.parent_id ?? NO_PARENT;
  const selectable =
    currentParent === NO_PARENT ||
    candidates.some((candidate) => candidate.id === currentParent);
  // The single source of both the rendered value and the submitted body.
  const selected = parentId ?? (selectable ? currentParent : NO_PARENT);

  return (
    <form
      class="resource-form"
      onSubmit={(event) => onSubmit(event, selected)}
      aria-label="Move the group"
    >
      <div class="resource-field">
        <label for="org-group-move-parent">New parent group</label>
        <select
          id="org-group-move-parent"
          value={selected}
          onChange={(event) => onChoose(selectValue(event))}
        >
          <option value={NO_PARENT}>No parent, a top level group</option>
          {candidates.map((candidate) => (
            <option key={candidate.id} value={candidate.id}>
              {candidate.display_name}
            </option>
          ))}
        </select>
      </div>
      {selectable ? null : (
        <p class="resource-note" role="status">
          The current parent of this group is not among the groups readable
          here, because it was deleted or lies beyond this page. This control
          therefore starts at no parent, so moving now makes this a top level
          group.
        </p>
      )}
      <p class="resource-note">
        A move that would loop the hierarchy, or nest it deeper than the
        configured maximum, is refused by the server and the reason is shown
        here unchanged.
      </p>
      <button
        type="submit"
        class="resource-btn resource-btn-primary"
        disabled={pending}
      >
        Move group
      </button>
    </form>
  );
}

// The memberships bound into one group. The binding is keyed by MEMBERSHIP id
// (an omb_ id from the members panel above), never by a bare user id.
function OrgGroupMembersPanel({
  tenantId,
  environmentId,
  organizationId,
  groupId,
}: OrgScope & { groupId: string }) {
  const { state, reload } = useAsyncResource<KeysetPage<OrgGroupMemberView>>(
    () =>
      fetchOrgGroupMembers(tenantId, environmentId, organizationId, groupId),
    [tenantId, environmentId, organizationId, groupId],
  );
  const mutation = useMutation();
  const [membershipId, setMembershipId] = useState("");
  useEffect(
    () => setMembershipId(""),
    [tenantId, environmentId, organizationId, groupId],
  );

  function onAdd(event: Event, close: () => void): void {
    event.preventDefault();
    const request: AddOrgGroupMemberRequest = {
      membership_id: membershipId.trim(),
    };
    void mutation.run(async () => {
      await addOrgGroupMember(
        tenantId,
        environmentId,
        organizationId,
        groupId,
        request,
      );
      setMembershipId("");
      close();
      reload();
    }, "Member added to the group.");
  }

  return (
    <div class="resource-subsection">
      <div class="resource-subsection-heading">
        <h4>Members of this group</h4>
        <ResourceCreateAction
          key={`${tenantId}:${environmentId}:${organizationId}:${groupId}`}
          label="Add group member"
          pending={mutation.state.pending}
          onOpen={() => {
            setMembershipId("");
            mutation.reset();
          }}
        >
          {(close) => (
            <form
              class="resource-form"
              onSubmit={(event) => onAdd(event, close)}
              aria-label="Add a member to the group"
            >
              <ResourceFormIntro
                title="Add group member"
                headingLevel={3}
                description="Enter the organization membership ID to add a member to this group."
              />
              <div class="resource-field">
                <label for="org-group-member-id">Membership id</label>
                <input
                  id="org-group-member-id"
                  type="text"
                  required
                  value={membershipId}
                  onInput={(event) => setMembershipId(inputValue(event))}
                />
              </div>
              <button
                type="submit"
                class="resource-btn resource-btn-primary"
                disabled={mutation.state.pending || membershipId.trim() === ""}
              >
                Add to group
              </button>
              <MutationFeedback
                state={mutation.state}
                sudo={sudoFor(mutation.retry)}
              />
            </form>
          )}
        </ResourceCreateAction>
      </div>
      <MutationFeedback state={mutation.state} sudo={sudoFor(mutation.retry)} />

      <AsyncBoundary
        state={state}
        loadingLabel="Loading group members"
        empty={{
          when: (page) => page.items.length === 0,
          render: () => (
            <p class="resource-empty">No members in this group yet.</p>
          ),
        }}
      >
        {(page) => (
          <div>
            <ul class="resource-list" aria-label="Members of the group">
              {page.items.map((member) => (
                <OrgGroupMemberRow
                  key={member.id}
                  tenantId={tenantId}
                  environmentId={environmentId}
                  organizationId={organizationId}
                  groupId={groupId}
                  member={member}
                  onRemoved={reload}
                />
              ))}
            </ul>
            <MorePageNote nextCursor={page.nextCursor} noun="group members" />
          </div>
        )}
      </AsyncBoundary>
    </div>
  );
}

function OrgGroupMemberRow({
  tenantId,
  environmentId,
  organizationId,
  groupId,
  member,
  onRemoved,
}: OrgScope & {
  groupId: string;
  member: OrgGroupMemberView;
  onRemoved: () => void;
}) {
  const mutation = useMutation();

  function onRemove(): void {
    void mutation
      .run(async () => {
        await removeOrgGroupMember(
          tenantId,
          environmentId,
          organizationId,
          groupId,
          member.membership_id,
        );
      }, "Member removed from the group.")
      .then((ok) => {
        if (ok) {
          onRemoved();
        }
      });
  }

  return (
    <li class="resource-row">
      <code class="resource-link">{member.membership_id}</code>
      <code class="resource-id">{member.id}</code>
      <ConfirmButton
        label="Remove from group"
        prompt="Remove this member from the group? Roles the group grants stop resolving for them at the next token issuance."
        confirmLabel="Confirm remove from group"
        danger
        disabled={mutation.state.pending}
        onConfirm={onRemove}
      />
      <MutationFeedback state={mutation.state} sudo={sudoFor(mutation.retry)} />
    </li>
  );
}

// The roles one group grants. Every live member of the group, and of every group
// beneath it, resolves these.
function OrgGroupRolesPanel({
  tenantId,
  environmentId,
  organizationId,
  groupId,
}: OrgScope & { groupId: string }) {
  const { state, reload } = useAsyncResource<KeysetPage<OrgGroupRoleView>>(
    () => fetchOrgGroupRoles(tenantId, environmentId, organizationId, groupId),
    [tenantId, environmentId, organizationId, groupId],
  );
  const mutation = useMutation();
  const [roleId, setRoleId] = useState("");
  useEffect(
    () => setRoleId(""),
    [tenantId, environmentId, organizationId, groupId],
  );

  function onAssign(event: Event, close: () => void): void {
    event.preventDefault();
    const request: AssignOrgGroupRoleRequest = { role_id: roleId.trim() };
    void mutation.run(async () => {
      await assignOrgGroupRole(
        tenantId,
        environmentId,
        organizationId,
        groupId,
        request,
      );
      setRoleId("");
      close();
      reload();
    }, "Role granted to the group.");
  }

  return (
    <div class="resource-subsection">
      <div class="resource-subsection-heading">
        <h4>Roles granted by this group</h4>
        <ResourceCreateAction
          key={`${tenantId}:${environmentId}:${organizationId}:${groupId}`}
          label="Grant group role"
          pending={mutation.state.pending}
          onOpen={() => {
            setRoleId("");
            mutation.reset();
          }}
        >
          {(close) => (
            <form
              class="resource-form"
              onSubmit={(event) => onAssign(event, close)}
              aria-label="Grant a role to the group"
            >
              <ResourceFormIntro
                title="Grant group role"
                headingLevel={3}
                description="Grant a role defined for this organization to the members of this group."
              />
              <div class="resource-field">
                <label for="org-group-role-id">Role id</label>
                <input
                  id="org-group-role-id"
                  placeholder={"Role ID from this organization"}
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
                Grant to group
              </button>
              <MutationFeedback
                state={mutation.state}
                sudo={sudoFor(mutation.retry)}
              />
            </form>
          )}
        </ResourceCreateAction>
      </div>
      <MutationFeedback state={mutation.state} sudo={sudoFor(mutation.retry)} />

      <AsyncBoundary
        state={state}
        loadingLabel="Loading group roles"
        empty={{
          when: (page) => page.items.length === 0,
          render: () => (
            <p class="resource-empty">This group grants no roles yet.</p>
          ),
        }}
      >
        {(page) => (
          <div>
            <ul class="resource-list" aria-label="Roles the group grants">
              {page.items.map((assignment) => (
                <OrgGroupRoleRow
                  key={assignment.id}
                  tenantId={tenantId}
                  environmentId={environmentId}
                  organizationId={organizationId}
                  groupId={groupId}
                  assignment={assignment}
                  onUnassigned={reload}
                />
              ))}
            </ul>
            <MorePageNote
              nextCursor={page.nextCursor}
              noun="roles granted by this group"
            />
          </div>
        )}
      </AsyncBoundary>
    </div>
  );
}

function OrgGroupRoleRow({
  tenantId,
  environmentId,
  organizationId,
  groupId,
  assignment,
  onUnassigned,
}: OrgScope & {
  groupId: string;
  assignment: OrgGroupRoleView;
  onUnassigned: () => void;
}) {
  const mutation = useMutation();

  function onUnassign(): void {
    void mutation
      .run(async () => {
        await unassignOrgGroupRole(
          tenantId,
          environmentId,
          organizationId,
          groupId,
          assignment.role_id,
        );
      }, "Role withdrawn from the group.")
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
        label="Withdraw from group"
        prompt="Withdraw this role from the group? Members stop resolving it through this group at the next token issuance, and may still hold it another way."
        confirmLabel="Confirm withdraw from group"
        danger
        disabled={mutation.state.pending}
        onConfirm={onUnassign}
      />
      <MutationFeedback state={mutation.state} sudo={sudoFor(mutation.retry)} />
    </li>
  );
}
