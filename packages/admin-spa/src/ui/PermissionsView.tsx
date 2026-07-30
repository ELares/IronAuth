// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The permission surface (issue #98), SCOPED to the active {tenant, environment}
// from the switcher, holding the two halves of issue #98 that belong to an
// ENVIRONMENT rather than to an organization:
//
//   1. The VOCABULARY. A permission is defined once per environment, and every
//      organization in that environment maps its roles onto the same set of
//      entries. That is precisely why this is a nav section and not a panel of the
//      organization detail: a vocabulary panel sitting under one organization would
//      tell an operator the entries they define belong to that organization, and
//      they do not. What IS org scoped is the mapping from a role to an entry, and
//      that lives in the role detail (src/ui/OrgRolePermissionsView.tsx).
//
//   2. The claim OPT-IN per registered resource server. Resolving a permission is
//      not the same as EMITTING it: a permission claim reaches an access token only
//      for an audience that has opted in. So the two halves belong on one page,
//      because a vocabulary that is fully attached and never emitted is the
//      confusion this page exists to prevent.
//
// The resource servers are addressed by their `rsv_` id and not by audience, because
// an audience is an absolute URI containing a colon and a slash and cannot be a path
// segment. Nothing else about a resource server is editable here; only the opt-in.
//
// When no {tenant, environment} is in scope this surface prompts and makes ZERO
// calls. It reads and writes ONLY through the named wrappers in src/api/client.ts
// (the single funnel), stands on the same reusable resource hooks and views, and
// renders every failure through the verbatim ErrorView boundary, including the RFC
// 9470 sudo path on a max_age challenge and the two typed refusals this surface can
// provoke: the 400 that names an immutable field, and the 422 that refuses the
// opt-in for a resource server whose token format cannot carry a claim.

import { useState } from "preact/hooks";
import {
  type CreatePermissionRequest,
  type KeysetPage,
  type PermissionView,
  type ResourceServerView,
  type UpdatePermissionRequest,
  createPermission,
  deletePermission,
  fetchPermissions,
  fetchResourceServers,
  getPermission,
  setResourceServerPermissionClaims,
  updatePermission,
} from "../api/client";
import { activeScope } from "../scope/store";
import type { SudoRecovery } from "./ErrorView";
import {
  AsyncBoundary,
  ConfirmButton,
  MorePageNote,
  MutationFeedback,
} from "./ResourceView";
import { useAsyncResource, useMutation } from "./useResource";

function inputValue(event: Event): string {
  return (event.target as HTMLInputElement).value;
}

// The scope every wrapper on this surface is injected with. Both halves are
// environment scoped, so both take exactly this.
interface EnvScope {
  tenantId: string;
  environmentId: string;
}

// The sudo recovery for a write here: the RFC 9470 challenge re-authenticates,
// elevates within the ACTIVE scope, and replays the write. Absent when no scope is
// active, which cannot happen while this surface is mounted, but is handled rather
// than asserted.
function sudoFor(retry: () => Promise<void>): SudoRecovery | undefined {
  const scope = activeScope.value;
  return scope === null ? undefined : { scope, retry };
}

export function PermissionsList() {
  const scope = activeScope.value;
  if (scope === null) {
    return (
      <section class="resource" aria-labelledby="permissions-heading">
        <h2 id="permissions-heading">Permissions</h2>
        <p class="resource-empty">
          Select a tenant and environment to manage its permissions.
        </p>
      </section>
    );
  }
  return (
    <PermissionsForScope
      tenantId={scope.tenantId}
      environmentId={scope.environmentId}
    />
  );
}

function PermissionsForScope({ tenantId, environmentId }: EnvScope) {
  return (
    <section class="resource" aria-labelledby="permissions-heading">
      <h2 id="permissions-heading">Permissions</h2>
      <p class="resource-note">
        The permission vocabulary of this environment, and which audiences receive
        it. A permission is defined once here and every organization in this
        environment attaches the same entries to its own roles, which is done in the
        role detail of an organization rather than here.
      </p>
      <PermissionVocabularyPanel
        tenantId={tenantId}
        environmentId={environmentId}
      />
      <ResourceServerClaimsPanel
        tenantId={tenantId}
        environmentId={environmentId}
      />
    </section>
  );
}

// ---- The vocabulary --------------------------------------------------------

function PermissionVocabularyPanel({ tenantId, environmentId }: EnvScope) {
  const { state, reload } = useAsyncResource<KeysetPage<PermissionView>>(
    () => fetchPermissions(tenantId, environmentId),
    [tenantId, environmentId],
  );
  const [openPermissionId, setOpenPermissionId] = useState<string | null>(null);

  return (
    <div class="resource-subsection">
      <h3>Vocabulary</h3>
      <p class="resource-note">
        A permission is a namespaced stable slug with two or more dot separated
        segments. The slug is what an access token claim carries and what an
        authorization decision keys on, so it is immutable: a relabel changes only
        the label. Case and inner punctuation are never touched here, so a non
        canonical value is refused by the server rather than quietly rewritten.
        Surrounding whitespace is the one exception and is trimmed, because no
        canonical slug can contain any, so trimming it cannot turn a refusal into a
        different stored value.
      </p>
      <PermissionCreateForm
        tenantId={tenantId}
        environmentId={environmentId}
        onCreated={reload}
      />
      <AsyncBoundary
        state={state}
        loadingLabel="Loading the permission vocabulary"
        empty={{
          when: (page) => page.items.length === 0,
          render: () => (
            <p class="resource-empty">
              No permissions yet. Define the first one above.
            </p>
          ),
        }}
      >
        {(page) => (
          <div>
            <ul
              class="resource-list"
              aria-label="Permissions of the environment"
            >
              {page.items.map((permission, index) => (
                // Keyed by POSITION, the convention issue #97 shipped for every
                // list here. A convention and not a defense: a repeated server
                // supplied key collapses no row on this Preact version either.
                <li key={`permission-${index}`} class="resource-row">
                  <button
                    type="button"
                    class="resource-linkbtn"
                    aria-expanded={openPermissionId === permission.id}
                    onClick={() =>
                      setOpenPermissionId(
                        openPermissionId === permission.id
                          ? null
                          : permission.id,
                      )
                    }
                  >
                    {permission.display_name}
                  </button>
                  <code class="resource-slug">{permission.slug}</code>
                  <span class="resource-kind">{permission.kind}</span>
                  <code class="resource-id">{permission.id}</code>
                </li>
              ))}
            </ul>
            <MorePageNote nextCursor={page.nextCursor} noun="permissions" />
          </div>
        )}
      </AsyncBoundary>
      {openPermissionId === null ? null : (
        <PermissionDetail
          key={openPermissionId}
          tenantId={tenantId}
          environmentId={environmentId}
          permissionId={openPermissionId}
          onChanged={reload}
          onDeleted={() => {
            setOpenPermissionId(null);
            reload();
          }}
        />
      )}
    </div>
  );
}

function PermissionCreateForm({
  tenantId,
  environmentId,
  onCreated,
}: EnvScope & { onCreated: () => void }) {
  const mutation = useMutation();
  const [slug, setSlug] = useState("");
  const [displayName, setDisplayName] = useState("");

  function onSubmit(event: Event): void {
    event.preventDefault();
    // The slug is sent as typed except for surrounding whitespace, which no
    // canonical slug can contain, so trimming it cannot turn a refusal into a
    // different stored value. Case and inner punctuation are NOT touched: the
    // server states the rule and refuses, and repairing a slug in the browser would
    // store a name the operator did not write while a token claim carries it.
    const request: CreatePermissionRequest = {
      slug: slug.trim(),
      display_name: displayName.trim(),
    };
    void mutation
      .run(async () => {
        await createPermission(tenantId, environmentId, request);
      }, "Permission defined.")
      .then((ok) => {
        if (ok) {
          setSlug("");
          setDisplayName("");
          onCreated();
        }
      });
  }

  return (
    <form
      class="resource-form"
      onSubmit={onSubmit}
      aria-label="Define a permission"
    >
      <div class="resource-field">
        <label for="permission-slug">Slug</label>
        <input
          id="permission-slug"
          type="text"
          required
          value={slug}
          onInput={(event) => setSlug(inputValue(event))}
        />
      </div>
      <div class="resource-field">
        <label for="permission-display-name">Display name</label>
        <input
          id="permission-display-name"
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
        Define permission
      </button>
      <MutationFeedback state={mutation.state} sudo={sudoFor(mutation.retry)} />
    </form>
  );
}

// One vocabulary entry, read FRESH rather than reused from the list row, so a
// relabel made in another console session is visible. Relabels; deletes.
function PermissionDetail({
  tenantId,
  environmentId,
  permissionId,
  onChanged,
  onDeleted,
}: EnvScope & {
  permissionId: string;
  onChanged: () => void;
  onDeleted: () => void;
}) {
  const { state, reload } = useAsyncResource<PermissionView>(
    () => getPermission(tenantId, environmentId, permissionId),
    [tenantId, environmentId, permissionId],
  );
  const mutation = useMutation();
  const [displayName, setDisplayName] = useState<string | null>(null);

  function onRelabel(event: Event): void {
    event.preventDefault();
    // An UNTOUCHED field is OMITTED, never sent as an empty string, and the slug
    // and the kind are NEVER on this body at all. The server refuses either KEY
    // being present, null included, because both are immutable, so putting one here
    // would turn every relabel into a 400.
    const request: UpdatePermissionRequest =
      displayName === null ? {} : { display_name: displayName.trim() };
    void mutation
      .run(async () => {
        await updatePermission(
          tenantId,
          environmentId,
          permissionId,
          request,
        );
      }, "Permission relabelled.")
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
        await deletePermission(tenantId, environmentId, permissionId);
      }, "Permission deleted.")
      .then((ok) => {
        if (ok) {
          onDeleted();
        }
      });
  }

  return (
    <div class="resource-detail-panel">
      <AsyncBoundary state={state} loadingLabel="Loading permission">
        {(permission) => (
          <div>
            <h4>Permission {permission.slug}</h4>
            <dl class="resource-detail">
              <dt>Identifier</dt>
              <dd>
                <code>{permission.id}</code>
              </dd>
              <dt>Slug</dt>
              <dd>
                <code>{permission.slug}</code>
              </dd>
              <dt>Kind</dt>
              <dd>{permission.kind}</dd>
              <dt>Created</dt>
              <dd>
                {new Date(permission.created_at_unix_ms).toISOString()}
              </dd>
            </dl>
            <form
              class="resource-form"
              onSubmit={onRelabel}
              aria-label="Relabel the permission"
            >
              <div class="resource-field">
                <label for="permission-relabel">Display name</label>
                <input
                  id="permission-relabel"
                  type="text"
                  required
                  value={displayName ?? permission.display_name}
                  onInput={(event) => setDisplayName(inputValue(event))}
                />
              </div>
              <button
                type="submit"
                class="resource-btn resource-btn-primary"
                disabled={mutation.state.pending}
              >
                Relabel permission
              </button>
            </form>
            <div
              class="resource-actions"
              role="group"
              aria-label="Permission actions"
            >
              <ConfirmButton
                label="Delete permission"
                prompt="Delete this permission? Every role in every organization of this environment stops carrying it, and members stop holding it at the next token issuance. Access tokens already issued are not revoked."
                confirmLabel="Confirm delete permission"
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

// ---- The claim opt-in per resource server ----------------------------------

function ResourceServerClaimsPanel({ tenantId, environmentId }: EnvScope) {
  const { state, reload } = useAsyncResource<KeysetPage<ResourceServerView>>(
    () => fetchResourceServers(tenantId, environmentId),
    [tenantId, environmentId],
  );

  return (
    <div class="resource-subsection">
      <h3>Permission claim per audience</h3>
      <p class="resource-note">
        Holding a permission and receiving it in a token are two different things.
        An access token carries the permission claim only for a resource server
        that has opted in, and only when that resource server issues a token format
        able to carry one, so an opaque token cannot be opted in and the refusal
        says so. Nothing else about a resource server is editable here.
      </p>
      <AsyncBoundary
        state={state}
        loadingLabel="Loading the resource servers"
        empty={{
          when: (page) => page.items.length === 0,
          render: () => (
            <p class="resource-empty">
              No resource servers are registered in this environment, so no
              audience can receive a permission claim yet.
            </p>
          ),
        }}
      >
        {(page) => (
          <div>
            <ul
              class="resource-list"
              aria-label="Resource servers of the environment"
            >
              {page.items.map((server, index) => (
                // Keyed by POSITION, the same convention as every other list here,
                // not a defense against a repeated audience: measured, a duplicate
                // key collapses no row under either keying strategy. What the tests
                // pin is that every registered audience gets a row of its own, so
                // none that is emitting can be missing from this list.
                <ResourceServerRow
                  key={`resource-server-${index}`}
                  tenantId={tenantId}
                  environmentId={environmentId}
                  server={server}
                  onChanged={reload}
                />
              ))}
            </ul>
            <MorePageNote nextCursor={page.nextCursor} noun="resource servers" />
          </div>
        )}
      </AsyncBoundary>
    </div>
  );
}

function ResourceServerRow({
  tenantId,
  environmentId,
  server,
  onChanged,
}: EnvScope & {
  server: ResourceServerView;
  onChanged: () => void;
}) {
  const mutation = useMutation();

  // Two explicit buttons by CURRENT state rather than one toggle, so the control
  // always names the outcome it produces. The write sends only
  // permission_claims_enabled: the token format is read only on this endpoint and
  // naming it would be a 400, which is deliberate, because a caller who believed
  // they had also changed the format to make the opt-in legal must not be told 200.
  function setEnabled(enabled: boolean): void {
    const confirmation = enabled
      ? "Permission claim enabled for this audience."
      : "Permission claim disabled for this audience.";
    void mutation
      .run(async () => {
        await setResourceServerPermissionClaims(
          tenantId,
          environmentId,
          server.id,
          enabled,
        );
      }, confirmation)
      .then((ok) => {
        if (ok) {
          onChanged();
        }
      });
  }

  return (
    <li class="resource-row-block">
      <div class="resource-row">
        <code class="resource-link">{server.audience}</code>
        <code class="resource-id">{server.id}</code>
        <span class="resource-kind">{server.token_format}</span>
        <span class="resource-status">
          {server.permission_claims_enabled
            ? "permission claim enabled"
            : "permission claim disabled"}
        </span>
        {server.permission_claims_enabled ? (
          <ConfirmButton
            label="Disable the claim"
            prompt="Stop sending the permission claim to this audience? Nothing about who holds which permission changes; from the next token issuance this audience simply stops being told. Access tokens already issued are not revoked."
            confirmLabel="Confirm disable the claim"
            danger
            disabled={mutation.state.pending}
            onConfirm={() => setEnabled(false)}
          />
        ) : (
          <button
            type="button"
            class="resource-btn resource-btn-primary"
            disabled={mutation.state.pending}
            onClick={() => setEnabled(true)}
          >
            Enable the claim
          </button>
        )}
      </div>
      <MutationFeedback state={mutation.state} sudo={sudoFor(mutation.retry)} />
    </li>
  );
}
