// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The invitations CRUD surface (issue #94, issue #60), SCOPED to the active
// {tenant, environment} from the switcher: the list with a lifecycle state
// filter, the create form, and per-row resend and revoke. Invitations live UNDER
// an environment, so this surface reads BOTH the active tenant and the active
// environment from the scope store and injects them into every call. When no
// {tenant, environment} is in scope it prompts and makes ZERO calls.
//
// The invitation token is a CREDENTIAL: the server returns the raw single-use
// token exactly ONCE (on a genuine create, and again on a resend, which mints a
// fresh one). This surface holds it in component state (memory only) and renders
// it a single time as copy-once. It is NEVER written to localStorage or
// sessionStorage, NEVER logged, and NEVER placed in a URL, matching the DCR
// initial-access-token posture. Leaving the surface drops it entirely.
//
// It reads and writes ONLY through the named wrappers in src/api/client.ts (the
// single funnel), stands on the same reusable resource hooks and views, and
// renders every failure through the verbatim ErrorView boundary, including the RFC
// 9470 sudo path on a max_age challenge. The list read is keyset paginated: a next
// cursor surfaces a "more exist" note rather than dropping the tail.

import { useState } from "preact/hooks";
import {
  type CreateInvitationRequest,
  type InvitationCreatedView,
  type InvitationCredentialTypeView,
  type InvitationStateView,
  type InvitationView,
  type KeysetPage,
  createInvitation,
  fetchInvitations,
  resendInvitation,
  revokeInvitation,
} from "../api/client";
import { activeScope } from "../scope/store";
import type { SudoRecovery } from "./ErrorView";
import { AsyncBoundary, ConfirmButton, MutationFeedback } from "./ResourceView";
import { useAsyncResource, useMutation } from "./useResource";

// The lifecycle states the filter offers, plus the "all" pseudo value that clears
// the filter. Matches the closed InvitationStateView wire enum.
const INVITATION_STATES: ReadonlyArray<InvitationStateView> = [
  "pending",
  "accepted",
  "revoked",
];

// The primary-login credential kinds a create can request. An empty selection
// omits the field so the server applies its default.
const CREDENTIAL_TYPES: ReadonlyArray<InvitationCredentialTypeView> = [
  "password",
  "passkey",
];

function inputValue(event: Event): string {
  return (event.target as HTMLInputElement).value;
}

// The invitations surface root, scoped to the active {tenant, environment}. When
// no scope is selected there is nothing to list, so it prompts and makes ZERO
// calls.
export function InvitationsList() {
  const scope = activeScope.value;
  if (scope === null) {
    return (
      <section class="resource" aria-labelledby="invitations-heading">
        <h2 id="invitations-heading">Invitations</h2>
        <p class="resource-empty">
          Select a tenant and environment to view its invitations.
        </p>
      </section>
    );
  }
  // Key by scope so a header scope switch (a signal update, NOT a route change)
  // remounts the subtree and drops its memory-only copy-once token, rather than
  // preserving the instance and showing the prior scope token under the new scope.
  return (
    <InvitationsForScope
      key={`${scope.tenantId}/${scope.environmentId}`}
      tenantId={scope.tenantId}
      environmentId={scope.environmentId}
    />
  );
}

function InvitationsForScope({
  tenantId,
  environmentId,
}: {
  tenantId: string;
  environmentId: string;
}) {
  // The state filter: "all" clears it, otherwise one lifecycle state narrows the
  // read. It is a dependency of the list read, so changing it refetches.
  const [filter, setFilter] = useState<InvitationStateView | "all">("all");
  // The most recently issued invitation, held in memory ONLY so its copy-once
  // token can be surfaced a single time. Both create and resend feed this; it is
  // never persisted or logged.
  const [issued, setIssued] = useState<InvitationCreatedView | null>(null);

  const stateFilter = filter === "all" ? undefined : filter;
  const { state, reload } = useAsyncResource<KeysetPage<InvitationView>>(
    () => fetchInvitations(tenantId, environmentId, stateFilter),
    [tenantId, environmentId, filter],
  );

  return (
    <section class="resource" aria-labelledby="invitations-heading">
      <h2 id="invitations-heading">Invitations</h2>
      <InvitationCreateForm
        tenantId={tenantId}
        environmentId={environmentId}
        onCreated={(result) => {
          setIssued(result);
          reload();
        }}
      />
      {issued === null ? null : <IssuedInvitation created={issued} />}
      <div class="resource-field">
        <label for="invitation-state-filter">Filter by state</label>
        <select
          id="invitation-state-filter"
          value={filter}
          onChange={(event) =>
            setFilter(
              (event.target as HTMLSelectElement).value as
                | InvitationStateView
                | "all",
            )
          }
        >
          <option value="all">all</option>
          {INVITATION_STATES.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
      </div>
      <AsyncBoundary
        state={state}
        loadingLabel="Loading invitations"
        empty={{
          when: (page) => page.items.length === 0,
          render: () => (
            <p class="resource-empty">
              No invitations match. Create one above.
            </p>
          ),
        }}
      >
        {(page) => (
          <div>
            <ul class="resource-list">
              {page.items.map((invitation) => (
                <InvitationRow
                  key={invitation.id}
                  tenantId={tenantId}
                  environmentId={environmentId}
                  invitation={invitation}
                  onIssued={setIssued}
                  onChanged={reload}
                />
              ))}
            </ul>
            {page.nextCursor === null ? null : (
              <p class="resource-more" role="status">
                More invitations exist beyond this page. Only the first page is
                shown.
              </p>
            )}
          </div>
        )}
      </AsyncBoundary>
    </section>
  );
}

function InvitationCreateForm({
  tenantId,
  environmentId,
  onCreated,
}: {
  tenantId: string;
  environmentId: string;
  onCreated: (result: InvitationCreatedView) => void;
}) {
  const mutation = useMutation();
  const [identifier, setIdentifier] = useState("");
  const [credentialType, setCredentialType] = useState<string>("");
  const [expiresIn, setExpiresIn] = useState("");

  function onSubmit(event: Event): void {
    event.preventDefault();
    const request: CreateInvitationRequest = {
      identifier: identifier.trim(),
    };
    if (credentialType !== "") {
      request.credential_type =
        credentialType as InvitationCredentialTypeView;
    }
    if (expiresIn.trim() !== "") {
      request.expires_in_secs = Number(expiresIn.trim());
    }
    void mutation
      .run(async () => {
        const result = await createInvitation(
          tenantId,
          environmentId,
          request,
        );
        // Hand the result to the parent, which holds it in memory only and
        // surfaces the copy-once token a single time. Never persisted or logged.
        onCreated(result);
      }, "Invitation created.")
      .then((ok) => {
        if (ok) {
          setIdentifier("");
          setCredentialType("");
          setExpiresIn("");
        }
      });
  }

  return (
    <form
      class="resource-form"
      onSubmit={onSubmit}
      aria-label="Create an invitation"
    >
      <div class="resource-field">
        <label for="invitation-identifier">Invited identifier</label>
        <input
          id="invitation-identifier"
          type="text"
          required
          value={identifier}
          onInput={(event) => setIdentifier(inputValue(event))}
        />
      </div>
      <div class="resource-field">
        <label for="invitation-credential-type">
          Credential type (optional)
        </label>
        <select
          id="invitation-credential-type"
          value={credentialType}
          onChange={(event) =>
            setCredentialType((event.target as HTMLSelectElement).value)
          }
        >
          <option value="">default</option>
          {CREDENTIAL_TYPES.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
      </div>
      <div class="resource-field">
        <label for="invitation-expires-in">
          Lifetime in seconds (optional, blank for the configured default)
        </label>
        <input
          id="invitation-expires-in"
          type="number"
          min={0}
          value={expiresIn}
          onInput={(event) => setExpiresIn(inputValue(event))}
        />
      </div>
      <button
        type="submit"
        class="resource-btn resource-btn-primary"
        disabled={mutation.state.pending || identifier.trim() === ""}
      >
        Create invitation
      </button>
      <MutationFeedback state={mutation.state} />
    </form>
  );
}

function InvitationRow({
  tenantId,
  environmentId,
  invitation,
  onIssued,
  onChanged,
}: {
  tenantId: string;
  environmentId: string;
  invitation: InvitationView;
  onIssued: (result: InvitationCreatedView) => void;
  onChanged: () => void;
}) {
  const mutation = useMutation();
  const scope = activeScope.value;
  const sudo: SudoRecovery | undefined =
    scope === null ? undefined : { scope, retry: mutation.retry };
  const isPending = invitation.state === "pending";

  function onResend(): void {
    // A resend mints a FRESH copy-once token and a new expiry; both are surfaced
    // in the IssuedInvitation panel via onIssued (the authoritative fresh state),
    // so the list is deliberately NOT reloaded here. Reloading would remount this
    // row and drop the inline confirmation before an operator could read it; the
    // invitation stays pending either way, so the row itself does not change.
    void mutation.run(async () => {
      const result = await resendInvitation(
        tenantId,
        environmentId,
        invitation.id,
      );
      onIssued(result);
    }, "Invitation resent.");
  }

  function onRevoke(): void {
    void mutation
      .run(async () => {
        await revokeInvitation(tenantId, environmentId, invitation.id);
      }, "Invitation revoked.")
      .then((ok) => {
        if (ok) {
          onChanged();
        }
      });
  }

  return (
    <li class="resource-row">
      <span class="resource-link">{invitation.target_identifier}</span>
      <code class="resource-id">{invitation.id}</code>
      <span class={`resource-status resource-status-${invitation.state}`}>
        {invitation.state}
      </span>
      <span class="resource-meta">
        expires {new Date(invitation.expires_at_unix_ms).toISOString()}
      </span>
      {isPending ? (
        <span class="resource-actions" role="group" aria-label="Invitation actions">
          <button
            type="button"
            class="resource-btn"
            disabled={mutation.state.pending}
            onClick={onResend}
          >
            Resend
          </button>
          <ConfirmButton
            label="Revoke"
            prompt="Revoke this invitation? Its token becomes unredeemable."
            confirmLabel="Confirm revoke"
            danger
            disabled={mutation.state.pending}
            onConfirm={onRevoke}
          />
        </span>
      ) : null}
      <MutationFeedback state={mutation.state} sudo={sudo} />
    </li>
  );
}

// Render a freshly issued invitation. When the server returned the raw token (a
// genuine create or a resend), it is shown ONCE as copy-once: an operator delivers
// it out of band now because it is never retrievable again. An idempotent replay
// omits the token. The token value is rendered as TEXT (Preact escapes text
// children) and is held only in the parent's memory state, never persisted, never
// logged, never placed in a URL.
function IssuedInvitation({ created }: { created: InvitationCreatedView }) {
  const hasToken = typeof created.token === "string" && created.token !== "";
  return (
    <div class="resource-token" role="status" aria-live="polite">
      <dl class="resource-detail">
        <dt>Invitation id</dt>
        <dd>
          <code>{created.invitation.id}</code>
        </dd>
        <dt>Invited identifier</dt>
        <dd>{created.invitation.target_identifier}</dd>
        <dt>Expires at</dt>
        <dd>
          {new Date(created.invitation.expires_at_unix_ms).toISOString()}
        </dd>
      </dl>
      {hasToken ? (
        <div class="resource-token-secret">
          <p class="resource-token-warning">
            Copy this invitation token now. It is shown only once and cannot be
            retrieved again. Deliver it to the invitee out of band to compose
            their accept link.
          </p>
          <code class="resource-token-value">{created.token}</code>
        </div>
      ) : (
        <p class="resource-token-warning">
          No token value was returned; it is shown only at the original creation.
        </p>
      )}
    </div>
  );
}
