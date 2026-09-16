// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The users CRUD surface (issue #90, PR 5), SCOPED to the active
// {tenant, environment} from the switcher: the list, the create form, the
// detail, the PATCH update (an RFC 7396 merge patch of the standard claims), the
// documented lifecycle state transitions, the session revoke, the external id
// mapping, and the delete. Users live UNDER an environment, so this surface reads
// BOTH the active tenant and the active environment from the scope store and
// injects them into every call, exactly as the environments surface injects the
// tenant. When no {tenant, environment} is in scope it shows a prompt and makes
// ZERO calls. It reads and writes ONLY through the named wrappers in
// src/api/client.ts (the single funnel), stands on the same reusable resource
// hooks and views the tenants and environments surfaces use, and renders every
// failure through the verbatim ErrorView boundary, including the RFC 9470 sudo
// path on a max_age challenge.

import { useLocation } from "preact-iso";
import { consoleHref } from "./routing";
import { useState } from "preact/hooks";
import {
  type CreateUserRequest,
  type SetUserStateRequest,
  type UpdateUserRequest,
  type UserStateView,
  type UserView,
  createUser,
  deleteUser,
  fetchUsers,
  getUser,
  linkUserExternalId,
  revokeUserSessions,
  setUserState,
  unlinkUserExternalId,
  updateUser,
} from "../api/client";
import { activeScope } from "../scope/store";
import type { SudoRecovery } from "./ErrorView";
import {
  AsyncBoundary,
  ConfirmButton,
  MutationFeedback,
  ResourceHeading,
  ResourceFormIntro,
  ResourceCollection,
  resourceLabel,
  ResourceDetailNav,
} from "./ResourceView";
import { UserPersonalAccessTokensPanel } from "./UserPersonalAccessTokensView";
import { useAsyncResource, useMutation } from "./useResource";

// The lifecycle states the management contract exposes (issue #52). Every state
// is a valid transition target; scheduled_offboarding additionally needs an
// instant, so the create form offers only the creatable states (all but that).
const USER_STATES: ReadonlyArray<UserStateView> = [
  "active",
  "blocked",
  "disabled",
  "pending_verification",
  "scheduled_offboarding",
  "waitlisted",
];
const CREATABLE_STATES: ReadonlyArray<UserStateView> = USER_STATES.filter(
  (state) => state !== "scheduled_offboarding",
);

function inputValue(event: Event): string {
  return (event.target as HTMLInputElement).value;
}

function checkboxChecked(event: Event): boolean {
  return (event.target as HTMLInputElement).checked;
}

// The users list, scoped to the active {tenant, environment}. When no scope is
// selected (no tenant, or a tenant with no environment) there is nothing to list,
// so the surface prompts rather than fetching an empty path: ZERO calls.
export function UsersList() {
  const scope = activeScope.value;
  if (scope === null) {
    return (
      <section class="resource" aria-labelledby="users-heading">
        <ResourceHeading
          id="users-heading"
          title="Users"
          description="Manage identities, account access and user credentials in this environment."
        />
        <p class="resource-empty">
          Select a tenant and environment to view its users.
        </p>
      </section>
    );
  }
  return (
    <UsersForScope
      tenantId={scope.tenantId}
      environmentId={scope.environmentId}
    />
  );
}

function UsersForScope({
  tenantId,
  environmentId,
}: {
  tenantId: string;
  environmentId: string;
}) {
  const { state, reload } = useAsyncResource<UserView[]>(
    () => fetchUsers(tenantId, environmentId),
    [tenantId, environmentId],
  );
  return (
    <section class="resource" aria-labelledby="users-heading">
      <ResourceHeading
        id="users-heading"
        title="Users"
        description="Manage identities, account access and user credentials in this environment."
      />
      <UserCreateForm
        tenantId={tenantId}
        environmentId={environmentId}
        onCreated={reload}
      />
      <AsyncBoundary
        state={state}
        loadingLabel="Loading users"
        empty={{
          when: (items) => items.length === 0,
          render: () => (
            <p class="resource-empty">
              No users yet. Create the first one above.
            </p>
          ),
        }}
      >
        {(items) => (
          <ResourceCollection
            items={items}
            noun="users"
            searchText={(user) =>
              [
                user.identifier,
                user.id,
                user.state,
                resourceLabel(user.state),
                user.external_id ?? "",
              ].join(" ")
            }
          >
            {(visible) => (
              <ul class="resource-list">
                {visible.map((user) => (
                  <li key={user.id} class="resource-row">
                    <a
                      class="resource-link"
                      href={consoleHref(`/users/${user.id}`)}
                    >
                      {user.identifier}
                    </a>
                    <code class="resource-id">{user.id}</code>
                    <span
                      class={`resource-status resource-status-${user.state}`}
                    >
                      {resourceLabel(user.state)}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </ResourceCollection>
        )}
      </AsyncBoundary>
    </section>
  );
}

function UserCreateForm({
  tenantId,
  environmentId,
  onCreated,
}: {
  tenantId: string;
  environmentId: string;
  onCreated: () => void;
}) {
  const mutation = useMutation();
  const [identifier, setIdentifier] = useState("");
  const [externalId, setExternalId] = useState("");
  const [initialState, setInitialState] = useState<UserStateView>("active");

  function onSubmit(event: Event): void {
    event.preventDefault();
    const request: CreateUserRequest = {
      identifier: identifier.trim(),
      state: initialState,
    };
    if (externalId.trim() !== "") {
      request.external_id = externalId.trim();
    }
    void mutation
      .run(async () => {
        await createUser(tenantId, environmentId, request);
      }, "User created.")
      .then((ok) => {
        if (ok) {
          setIdentifier("");
          setExternalId("");
          setInitialState("active");
          onCreated();
        }
      });
  }

  return (
    <form class="resource-form" onSubmit={onSubmit} aria-label="Create a user">
      <ResourceFormIntro
        title="Create user"
        description="Add an identity using its login identifier. External IDs help match identities across systems."
      />
      <div class="resource-field">
        <label for="user-identifier">Identifier</label>
        <input
          id="user-identifier"
          placeholder={"alex@example.com"}
          type="text"
          required
          value={identifier}
          onInput={(event) => setIdentifier(inputValue(event))}
        />
      </div>
      <div class="resource-field">
        <label for="user-external-id">External id (optional)</label>
        <input
          id="user-external-id"
          placeholder={"ID in your user directory"}
          type="text"
          value={externalId}
          onInput={(event) => setExternalId(inputValue(event))}
        />
      </div>
      <div class="resource-field">
        <label for="user-initial-state">Initial state</label>
        <select
          id="user-initial-state"
          value={initialState}
          onChange={(event) =>
            setInitialState(
              (event.target as HTMLSelectElement).value as UserStateView,
            )
          }
        >
          {CREATABLE_STATES.map((value) => (
            <option key={value} value={value}>
              {resourceLabel(value)}
            </option>
          ))}
        </select>
      </div>
      <button
        type="submit"
        class="resource-btn resource-btn-primary"
        disabled={mutation.state.pending || identifier.trim() === ""}
      >
        Create user
      </button>
      <MutationFeedback state={mutation.state} />
    </form>
  );
}

// One user: its fields, the PATCH profile update, the lifecycle state transition,
// the external id mapping, the session revoke, and the delete. The tenant and
// environment come from the active scope; a delete returns to the list. A max_age
// failure on any write drives the RFC 9470 sudo recovery, elevating within the
// active scope and replaying the write.
export function UserDetail({ userId }: { userId?: string }) {
  const scope = activeScope.value;
  if (scope === null) {
    return (
      <section class="resource" aria-labelledby="user-detail-heading">
        <ResourceHeading
          id="user-detail-heading"
          title="User"
          description="Review this identity and manage its profile, access and credentials."
        />
        <p class="resource-empty">
          Select a tenant and environment to view this user.
        </p>
      </section>
    );
  }
  return (
    <UserDetailFor
      tenantId={scope.tenantId}
      environmentId={scope.environmentId}
      userId={userId ?? ""}
    />
  );
}

function UserDetailFor({
  tenantId,
  environmentId,
  userId,
}: {
  tenantId: string;
  environmentId: string;
  userId: string;
}) {
  const location = useLocation();
  const { state, reload } = useAsyncResource<UserView>(
    () => getUser(tenantId, environmentId, userId),
    [tenantId, environmentId, userId],
  );
  const mutation = useMutation();
  const scope = activeScope.value;
  const sudo: SudoRecovery | undefined =
    scope === null ? undefined : { scope, retry: mutation.retry };

  function onDelete(): void {
    void mutation.run(async () => {
      await deleteUser(tenantId, environmentId, userId);
      if (typeof location.route === "function") {
        location.route(consoleHref("/users"));
      }
    }, "User deleted.");
  }

  return (
    <section class="resource" aria-labelledby="user-detail-heading">
      <p>
        <a class="resource-back" href={consoleHref("/users")}>
          Back to users
        </a>
      </p>
      <AsyncBoundary state={state} loadingLabel="Loading user">
        {(user) => (
          <div>
            <ResourceHeading
              id="user-detail-heading"
              title={user.identifier}
              description="Review this identity and manage its profile, access and credentials."
            />
            <ResourceDetailNav
              items={[
                { id: "user-profile", label: "Profile" },
                { id: "user-lifecycle", label: "Access" },
                { id: "user-external", label: "External ID" },
                { id: "user-sessions", label: "Sessions" },
                { id: "user-tokens", label: "Tokens" },
              ]}
            />
            <dl class="resource-detail">
              <dt>Identifier</dt>
              <dd>
                <code>{user.id}</code>
              </dd>
              <dt>Login handle</dt>
              <dd>{user.identifier}</dd>
              <dt>Tenant</dt>
              <dd>
                <code>{user.tenant_id}</code>
              </dd>
              <dt>Environment</dt>
              <dd>
                <code>{user.environment_id}</code>
              </dd>
              <dt>State</dt>
              <dd>{resourceLabel(user.state)}</dd>
              <dt>External id</dt>
              <dd>{user.external_id ?? "none"}</dd>
              <dt>Scheduled offboarding</dt>
              <dd>
                {user.scheduled_offboarding_at_unix_ms === null ||
                user.scheduled_offboarding_at_unix_ms === undefined
                  ? "none"
                  : new Date(
                      user.scheduled_offboarding_at_unix_ms,
                    ).toISOString()}
              </dd>
              <dt>Created</dt>
              <dd>{new Date(user.created_at_unix_ms).toISOString()}</dd>
              <dt>Updated</dt>
              <dd>{new Date(user.updated_at_unix_ms).toISOString()}</dd>
            </dl>

            <UserClaimsForm
              tenantId={tenantId}
              environmentId={environmentId}
              userId={userId}
              mutation={mutation}
              onUpdated={reload}
            />

            <UserStateForm
              tenantId={tenantId}
              environmentId={environmentId}
              userId={userId}
              current={user.state}
              mutation={mutation}
              onChanged={reload}
            />

            <UserExternalIdForm
              tenantId={tenantId}
              environmentId={environmentId}
              userId={userId}
              linked={user.external_id ?? null}
              mutation={mutation}
              onChanged={reload}
            />

            <UserSessionsForm
              tenantId={tenantId}
              environmentId={environmentId}
              userId={userId}
              mutation={mutation}
            />

            <UserPersonalAccessTokensPanel
              tenantId={tenantId}
              environmentId={environmentId}
              userId={userId}
              mutation={mutation}
            />

            <div
              class="resource-actions"
              role="group"
              aria-label="User actions"
            >
              <ConfirmButton
                label="Delete"
                prompt="Delete this user? This offboards the user and cascades their sessions."
                confirmLabel="Confirm delete"
                danger
                disabled={mutation.state.pending}
                onConfirm={onDelete}
              />
            </div>
            <MutationFeedback state={mutation.state} sudo={sudo} />
          </div>
        )}
      </AsyncBoundary>
    </section>
  );
}

// The PATCH profile update (operationId updateUser): an RFC 7396 merge patch of
// the standard claims. The contract's request accepts ONLY `claims`, so this
// sends only that field. The textarea is validated as JSON before the call (a
// client side input check, not a network error channel); the server outcome is
// rendered through the one shared mutation feedback below the actions.
function UserClaimsForm({
  tenantId,
  environmentId,
  userId,
  mutation,
  onUpdated,
}: {
  tenantId: string;
  environmentId: string;
  userId: string;
  mutation: ReturnType<typeof useMutation>;
  onUpdated: () => void;
}) {
  const [claims, setClaims] = useState("");
  const [invalid, setInvalid] = useState(false);

  function onSubmit(event: Event): void {
    event.preventDefault();
    let parsed: Record<string, unknown>;
    try {
      const value: unknown = JSON.parse(claims);
      if (value === null || typeof value !== "object" || Array.isArray(value)) {
        setInvalid(true);
        return;
      }
      parsed = value as Record<string, unknown>;
    } catch {
      setInvalid(true);
      return;
    }
    setInvalid(false);
    // The contract types `claims` as a freeform JSON object (openapi-typescript
    // renders that as Record<string, never>); the parsed document is that object,
    // cast to the generated field type so the call stays typed against the
    // contract rather than reaching for `any`.
    const request: UpdateUserRequest = {
      claims: parsed as UpdateUserRequest["claims"],
    };
    void mutation
      .run(async () => {
        await updateUser(tenantId, environmentId, userId, request);
      }, "User claims updated.")
      .then((ok) => {
        if (ok) {
          setClaims("");
          onUpdated();
        }
      });
  }

  return (
    <form
      class="resource-form"
      onSubmit={onSubmit}
      id="user-profile"
      aria-label="Update user claims"
    >
      <ResourceFormIntro
        title="Profile claims"
        description="Update profile fields with a JSON object. Only the fields you include are changed."
      />
      <div class="resource-field">
        <label for="user-claims">Claims (JSON object)</label>
        <textarea
          id="user-claims"
          spellcheck={false}
          aria-describedby="user-claims-help"
          aria-invalid={invalid}
          placeholder={'{"name": "Alex Morgan"}'}
          rows={4}
          value={claims}
          onInput={(event) =>
            setClaims((event.target as HTMLTextAreaElement).value)
          }
        />
        <p id="user-claims-help" class="resource-hint">
          Use a JSON object, such as &#123;"name": "Alex Morgan"&#125;. Set a
          field to null to remove it.
        </p>
        {invalid ? (
          <p class="resource-field-error" role="alert">
            Enter a valid JSON object.
          </p>
        ) : null}
      </div>
      <button
        type="submit"
        class="resource-btn"
        disabled={mutation.state.pending || claims.trim() === ""}
      >
        Update claims
      </button>
    </form>
  );
}

// The lifecycle state transition (operationId setUserState). The target state
// (and, only for scheduled_offboarding, its instant) plus an optional hard_kill
// ride in the body. Gated behind an explicit confirm since a transition can end
// the user's sessions.
function UserStateForm({
  tenantId,
  environmentId,
  userId,
  current,
  mutation,
  onChanged,
}: {
  tenantId: string;
  environmentId: string;
  userId: string;
  current: UserStateView;
  mutation: ReturnType<typeof useMutation>;
  onChanged: () => void;
}) {
  const [target, setTarget] = useState<UserStateView>(current);
  const [offboardAt, setOffboardAt] = useState("");
  const [hardKill, setHardKill] = useState(false);
  const needsInstant = target === "scheduled_offboarding";
  const offboardingInstant = new Date(offboardAt).getTime();
  const instantMissing =
    needsInstant &&
    (offboardAt.trim() === "" || Number.isNaN(offboardingInstant));

  function onConfirm(): void {
    const request: SetUserStateRequest = { state: target };
    if (hardKill) {
      request.hard_kill = true;
    }
    if (needsInstant) {
      request.scheduled_offboarding_at_unix_ms = offboardingInstant;
    }
    void mutation
      .run(async () => {
        await setUserState(tenantId, environmentId, userId, request);
      }, "User state changed.")
      .then((ok) => {
        if (ok) {
          onChanged();
        }
      });
  }

  return (
    <div
      class="resource-subsection"
      role="group"
      aria-label="Change user state"
    >
      <h2 id="user-lifecycle">Lifecycle state</h2>
      <p class="resource-hint">
        Choose the account state. A state change may end the user&#39;s active
        sessions.
      </p>
      <div class="resource-field">
        <label for="user-target-state">Target state</label>
        <select
          id="user-target-state"
          value={target}
          onChange={(event) =>
            setTarget(
              (event.target as HTMLSelectElement).value as UserStateView,
            )
          }
        >
          {USER_STATES.map((value) => (
            <option key={value} value={value}>
              {resourceLabel(value)}
            </option>
          ))}
        </select>
      </div>
      {needsInstant ? (
        <div class="resource-field">
          <label for="user-offboard-at">
            Scheduled offboarding date and time
          </label>
          <input
            id="user-offboard-at"
            type="datetime-local"
            aria-describedby="user-offboard-at-help"
            required
            value={offboardAt}
            onInput={(event) => setOffboardAt(inputValue(event))}
          />
          <p id="user-offboard-at-help" class="resource-hint">
            Uses your device&#39;s local time zone.
          </p>
        </div>
      ) : null}
      <div class="resource-field resource-field-inline">
        <input
          id="user-state-hard-kill"
          type="checkbox"
          checked={hardKill}
          onChange={(event) => setHardKill(checkboxChecked(event))}
        />
        <label for="user-state-hard-kill">
          Hard kill: also revoke offline_access refresh families
        </label>
      </div>
      <ConfirmButton
        label="Change state"
        prompt="Change this user's lifecycle state?"
        confirmLabel="Confirm state change"
        danger
        disabled={mutation.state.pending || instantMissing}
        onConfirm={onConfirm}
      />
    </div>
  );
}

// The external id mapping (operationIds linkUserExternalId / unlinkUserExternalId).
// Linking sets the correlation id; unlinking clears it and is gated behind a
// confirm.
function UserExternalIdForm({
  tenantId,
  environmentId,
  userId,
  linked,
  mutation,
  onChanged,
}: {
  tenantId: string;
  environmentId: string;
  userId: string;
  linked: string | null;
  mutation: ReturnType<typeof useMutation>;
  onChanged: () => void;
}) {
  const [externalId, setExternalId] = useState("");

  function onLink(event: Event): void {
    event.preventDefault();
    void mutation
      .run(async () => {
        await linkUserExternalId(tenantId, environmentId, userId, {
          external_id: externalId.trim(),
        });
      }, "External id linked.")
      .then((ok) => {
        if (ok) {
          setExternalId("");
          onChanged();
        }
      });
  }

  function onUnlink(): void {
    void mutation.run(async () => {
      await unlinkUserExternalId(tenantId, environmentId, userId);
      onChanged();
    }, "External id unlinked.");
  }

  return (
    <div class="resource-subsection">
      <h2 id="user-external">External ID</h2>
      <p class="resource-hint">
        Link this user to the matching identity in an external system.
      </p>
      <form
        class="resource-form"
        onSubmit={onLink}
        aria-label="Link external id"
      >
        <div class="resource-field">
          <label for="user-link-external-id">External id</label>
          <input
            id="user-link-external-id"
            type="text"
            required
            value={externalId}
            onInput={(event) => setExternalId(inputValue(event))}
          />
        </div>
        <button
          type="submit"
          class="resource-btn"
          disabled={mutation.state.pending || externalId.trim() === ""}
        >
          Link external id
        </button>
      </form>
      {linked === null ? null : (
        <div
          class="resource-actions"
          role="group"
          aria-label="Unlink external id"
        >
          <ConfirmButton
            label="Unlink"
            prompt="Unlink this user's external id?"
            confirmLabel="Confirm unlink"
            danger
            disabled={mutation.state.pending}
            onConfirm={onUnlink}
          />
        </div>
      )}
    </div>
  );
}

// The session revoke (operationId revokeUserSessions): end every session of the
// user. The default preserves the offline_access families (the documented
// offline-survives-logout semantic); hard_kill cuts the principal off entirely.
// Gated behind a confirm.
function UserSessionsForm({
  tenantId,
  environmentId,
  userId,
  mutation,
}: {
  tenantId: string;
  environmentId: string;
  userId: string;
  mutation: ReturnType<typeof useMutation>;
}) {
  const [hardKill, setHardKill] = useState(false);

  function onRevoke(): void {
    void mutation.run(async () => {
      await revokeUserSessions(tenantId, environmentId, userId, {
        hard_kill: hardKill,
      });
    }, "User sessions revoked.");
  }

  return (
    <div class="resource-subsection">
      <h2 id="user-sessions">Sessions</h2>
      <p class="resource-hint">Sign this user out of every active session.</p>
      <div class="resource-field resource-field-inline">
        <input
          id="user-revoke-hard-kill"
          type="checkbox"
          checked={hardKill}
          onChange={(event) => setHardKill(checkboxChecked(event))}
        />
        <label for="user-revoke-hard-kill">
          Hard kill: also revoke offline_access refresh families
        </label>
      </div>
      <div
        class="resource-actions"
        role="group"
        aria-label="Revoke user sessions"
      >
        <ConfirmButton
          label="Revoke sessions"
          prompt="Revoke every session for this user?"
          confirmLabel="Confirm revoke"
          danger
          disabled={mutation.state.pending}
          onConfirm={onRevoke}
        />
      </div>
    </div>
  );
}
