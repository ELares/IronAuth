// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The DEFAULT ROLE of one organization (issue #98): the single role every active
// member resolves without a grant row of their own.
//
// A PANEL of the organization detail view (src/ui/OrganizationsView.tsx), because a
// default role is a single valued property of one organization and is meaningless
// without one selected.
//
// Two facts drive the whole shape of this panel:
//
//   Designating is a MOVE, not an addition. The store clears whatever role held the
//   designation and sets it on the chosen one in one transaction, so a second
//   designation moves it rather than being refused. The control is therefore a
//   selector over the roles of the organization, never a per row toggle that could
//   suggest two roles can hold it at once.
//
//   Clearing DELETES NOTHING. The role stays a live role and every direct and group
//   grant of it stands; what stops is the resolution that gave it to every member
//   without a row. The confirm prompt says that, because "clear" beside a role name
//   otherwise reads as deleting the role.
//
// The designation currently on file is read from `is_default` on the roles of the
// organization rather than from a dedicated read, because the contract has no GET
// for it. That has one consequence this panel refuses to paper over: the roles read
// is KEYSET paginated, so when no role on the first page holds the designation AND a
// next page exists, whether a role further on holds it is genuinely UNKNOWN here. It
// says so rather than reporting no default, which would be a plain misstatement of
// what every member resolves.
//
// It reads and writes ONLY through the named wrappers in src/api/client.ts (the
// single funnel) and renders every failure through the verbatim ErrorView boundary,
// including the RFC 9470 sudo path on a max_age challenge.

import { useState } from "preact/hooks";
import {
  type KeysetPage,
  type OrgRoleView,
  clearOrgDefaultRole,
  fetchOrgRoles,
  setOrgDefaultRole,
} from "../api/client";
import {
  AsyncBoundary,
  ConfirmButton,
  MorePageNote,
  MutationFeedback,
} from "./ResourceView";
import { type OrgScope, selectValue, sudoFor } from "./orgPanels";
import { type Mutation, useAsyncResource, useMutation } from "./useResource";

export function OrgDefaultRolePanel({
  tenantId,
  environmentId,
  organizationId,
}: OrgScope) {
  const { state, reload } = useAsyncResource<KeysetPage<OrgRoleView>>(
    () => fetchOrgRoles(tenantId, environmentId, organizationId),
    [tenantId, environmentId, organizationId],
  );
  // The write state is held HERE, above the AsyncBoundary, and not inside the form
  // below it. A successful designation reloads the roles, the reload flips the
  // boundary back to loading, and anything holding state under it is unmounted, so a
  // mutation owned by the form would have its outcome destroyed by its own success.
  // This is the same placement OrgRoleDetail uses for the same reason.
  const mutation = useMutation();

  return (
    <div class="resource-subsection">
      <h3>Default role</h3>
      <p class="resource-note">
        The one role every active member of this organization resolves without a
        grant of their own. Designating a role MOVES the designation off whatever
        role held it, and clearing it deletes nothing: the role and every grant of
        it stay exactly as they are.
      </p>
      <AsyncBoundary
        state={state}
        loadingLabel="Loading the roles of the organization"
        empty={{
          when: (page) => page.items.length === 0,
          render: () => (
            <p class="resource-empty">
              This organization defines no roles yet, so there is nothing to
              designate. Define one in the roles panel below.
            </p>
          ),
        }}
      >
        {(page) => (
          <DefaultRoleForm
            tenantId={tenantId}
            environmentId={environmentId}
            organizationId={organizationId}
            page={page}
            mutation={mutation}
            onChanged={reload}
          />
        )}
      </AsyncBoundary>
      <MutationFeedback state={mutation.state} sudo={sudoFor(mutation.retry)} />
    </div>
  );
}

// What the panel can say about the designation currently on file, given ONE page of
// roles. Three answers and not two, because "no role on this page holds it" is not
// the same statement as "no role holds it" while a next page exists.
export type DefaultRoleReading =
  | { kind: "held"; role: OrgRoleView }
  | { kind: "none" }
  | { kind: "unknown" };

// Pure, so the tri-state is testable without a DOM. Exported for that reason.
export function readDefaultRole(
  page: KeysetPage<OrgRoleView>,
): DefaultRoleReading {
  const held = page.items.find((role) => role.is_default);
  if (held !== undefined) {
    return { kind: "held", role: held };
  }
  return page.nextCursor === null ? { kind: "none" } : { kind: "unknown" };
}

function DefaultRoleForm({
  tenantId,
  environmentId,
  organizationId,
  page,
  mutation,
  onChanged,
}: OrgScope & {
  page: KeysetPage<OrgRoleView>;
  // Owned by the panel above, so a reload triggered by a successful write cannot
  // unmount the state that holds that write's outcome.
  mutation: Mutation;
  onChanged: () => void;
}) {
  const reading = readDefaultRole(page);
  // The role the selector starts on: the one holding the designation when it is on
  // this page, else the first option. Held as an OPTIONAL override so an operator
  // choice is what is submitted, and so a reload that changes the designation is
  // reflected rather than being pinned by a stale initial value.
  //
  // What actually clears it after a write is the REMOUNT, not the reset below.
  // `useAsyncResource.reload` sets the state back to `loading` before it refetches,
  // the AsyncBoundary above unmounts everything under it while that holds, and this
  // state dies with it. Measured: removing either `setChoice(null)` leaves the whole
  // suite green, and no test can distinguish them, which is why neither is claimed to
  // be pinned. They are kept as the local statement of intent for a future boundary
  // that keeps its children mounted across a refetch, where they would become the
  // only thing standing between an operator and a control pinned at a value the
  // store has moved past.
  const [choice, setChoice] = useState<string | null>(null);
  const initial =
    reading.kind === "held" ? reading.role.id : page.items[0].id;
  const selected = choice ?? initial;

  function onDesignate(event: Event): void {
    event.preventDefault();
    void mutation
      .run(async () => {
        await setOrgDefaultRole(tenantId, environmentId, organizationId, {
          role_id: selected,
        });
      }, "Default role designated.")
      .then((ok) => {
        if (ok) {
          setChoice(null);
          onChanged();
        }
      });
  }

  function onClear(): void {
    void mutation
      .run(async () => {
        await clearOrgDefaultRole(tenantId, environmentId, organizationId);
      }, "Default role designation cleared.")
      .then((ok) => {
        if (ok) {
          setChoice(null);
          onChanged();
        }
      });
  }

  return (
    <div>
      <p class="resource-note" role="status">
        {reading.kind === "held"
          ? `The default role is ${reading.role.slug}, so every active member resolves it.`
          : reading.kind === "none"
            ? "No role is designated, so a member resolves only the roles granted to them or to a group they belong to."
            : "No role on this page of roles holds the designation, and more roles exist beyond this page, so whether one of those holds it cannot be read here."}
      </p>
      <form
        class="resource-form"
        onSubmit={onDesignate}
        aria-label="Designate the default role"
      >
        <div class="resource-field">
          <label for="org-default-role">Role</label>
          <select
            id="org-default-role"
            value={selected}
            onChange={(event) => setChoice(selectValue(event))}
          >
            {page.items.map((role, index) => (
              // Keyed by POSITION, the convention every list in this console
              // follows. Not a defense against a repeated slug: measured, a
              // duplicate key drops no option under either keying. Two live roles
              // cannot share a slug anyway; the test pins the option COUNT.
              <option key={`default-role-${index}`} value={role.id}>
                {role.slug}
              </option>
            ))}
          </select>
        </div>
        <button
          type="submit"
          class="resource-btn resource-btn-primary"
          disabled={mutation.state.pending}
        >
          Designate default role
        </button>
      </form>
      <div
        class="resource-actions"
        role="group"
        aria-label="Default role designation"
      >
        {/* Offered for the two readings where a designation may exist and NOT for
            the `none` reading, where this panel has just said no role holds one and
            the endpoint answers 404 for exactly that state. Offering a control whose
            only outcome is a not-found beside a sentence saying there is nothing to
            clear would read as the console disagreeing with itself. The `unknown`
            reading DOES keep it: a role beyond this page may hold the designation,
            so clearing is a real action there. */}
        {reading.kind === "none" ? null : (
          <ConfirmButton
            label="Clear the designation"
            prompt="Clear the default role? The role and every grant of it stay exactly as they are. What stops is that members without a grant of their own resolve it, from the next token issuance. Access tokens already issued are not revoked."
            confirmLabel="Confirm clear the designation"
            danger
            disabled={mutation.state.pending}
            onConfirm={onClear}
          />
        )}
      </div>
      <MorePageNote
        nextCursor={page.nextCursor}
        noun="roles that could be designated"
      />
    </div>
  );
}
