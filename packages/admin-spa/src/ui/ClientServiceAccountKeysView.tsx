// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The API keys belonging to the service account of one client (issue #99, criterion 6).
//
// Reached through the CLIENT rather than through the principal, because that is the only
// handle an operator has. A service account is minted per client and lazily, at the first
// client-credentials issuance that client makes, and there is no route that lists principals,
// so the panel takes a client id the way the scope-allowlist panel beside it does.
//
// The lookup answers three different things and the panel says which:
//
//   - a 404, meaning no such client in this scope,
//   - a live client with NO principal, meaning nothing has used the machine grant yet,
//   - a principal, whose keys are then listed.
//
// Collapsing the middle case into an empty key list would tell an operator "this client has no
// keys" about a client that cannot have any yet, which reads as a working integration missing
// its credential rather than as an integration that has never run.
//
// Everything below the lookup is the same shape as OrgApiKeysPanel and
// UserPersonalAccessTokensPanel, rendering the same object through the same shared view type.

import { useState } from "preact/hooks";
import {
  type ApiKeyView,
  createServiceAccountKey,
  fetchClientServiceAccount,
  fetchServiceAccountKeys,
  revokeServiceAccountKey,
  rotateServiceAccountKey,
} from "../api/client";
import { describe } from "./OrgApiKeysView";
import {
  AsyncBoundary,
  ConfirmButton,
  MutationFeedback,
  SecretCopyButton,
} from "./ResourceView";
import { inputValue, sudoFor } from "./orgPanels";
import { useAsyncResource, useMutation } from "./useResource";

export function ClientServiceAccountKeysPanel({
  tenantId,
  environmentId,
}: {
  tenantId: string;
  environmentId: string;
}) {
  const [clientId, setClientId] = useState("");
  const [lookupId, setLookupId] = useState<string | null>(null);

  return (
    <div class="resource-subsection">
      <h2 id="client-keys">Machine identity keys</h2>
      <p class="resource-note">
        Keys authenticate as a client&#39;s service account. The account is created
        the first time the client uses machine credentials. Save each key when
        it is created; it cannot be retrieved later.
      </p>
      <form
        class="resource-form"
        aria-label="Look up a client service account"
        onSubmit={(event) => {
          event.preventDefault();
          const trimmed = clientId.trim();
          setLookupId(trimmed === "" ? null : trimmed);
        }}
      >
        <label class="resource-field">
          Client id
          <input
            type="text"
            value={clientId}
            onInput={(event) => setClientId(inputValue(event))}
          />
        </label>
        <button
          class="resource-btn resource-btn-primary"
          type="submit"
          disabled={clientId.trim() === ""}
        >
          Look up
        </button>
      </form>
      {lookupId === null ? null : (
        <ServiceAccountFor
          tenantId={tenantId}
          environmentId={environmentId}
          clientId={lookupId}
        />
      )}
    </div>
  );
}

// Resolve the principal, then hand off. Split from the panel above so that the loading and
// error states of the lookup belong to the lookup rather than to the key list under it.
function ServiceAccountFor({
  tenantId,
  environmentId,
  clientId,
}: {
  tenantId: string;
  environmentId: string;
  clientId: string;
}) {
  const { state } = useAsyncResource<{ id: string | null }>(
    async () => ({
      id: await fetchClientServiceAccount(tenantId, environmentId, clientId),
    }),
    [tenantId, environmentId, clientId],
  );
  return (
    <AsyncBoundary
      state={state}
      loadingLabel="Looking up the service account of the client"
    >
      {({ id: serviceAccountId }) =>
        serviceAccountId === null ? (
          <p class="resource-empty">
            This client has no service account yet. One is minted the first time
            the client uses the machine grant.
          </p>
        ) : (
          <ServiceAccountKeys
            tenantId={tenantId}
            environmentId={environmentId}
            serviceAccountId={serviceAccountId}
          />
        )
      }
    </AsyncBoundary>
  );
}

function ServiceAccountKeys({
  tenantId,
  environmentId,
  serviceAccountId,
}: {
  tenantId: string;
  environmentId: string;
  serviceAccountId: string;
}) {
  const { state, reload } = useAsyncResource<ApiKeyView[]>(
    () => fetchServiceAccountKeys(tenantId, environmentId, serviceAccountId),
    [tenantId, environmentId, serviceAccountId],
  );
  // Held ABOVE the AsyncBoundary below, so a reload does not unmount the thing reporting
  // the outcome of the mutation that caused it.
  const mutation = useMutation();
  // DISPLAY ONCE. Its OWN creation reloads the list WITHOUT clearing it, so the operator
  // can still see the key beside the row that now exists; every OTHER reload clears it.
  const [issued, setIssued] = useState<{ id: string; key: string } | null>(
    null,
  );
  const [name, setName] = useState("");
  const reloadClearingKey = () => {
    setIssued(null);
    reload();
  };

  return (
    <>
      <p class="resource-note">
        Principal <code class="resource-row-id">{serviceAccountId}</code>
      </p>
      <form
        class="resource-form"
        onSubmit={(event) => {
          event.preventDefault();
          const trimmed = name.trim();
          if (trimmed === "") {
            return;
          }
          void mutation
            .run(async () => {
              const created = await createServiceAccountKey(
                tenantId,
                environmentId,
                serviceAccountId,
                trimmed,
              );
              // Absent on an idempotent replay. Showing nothing is correct there: the key
              // was issued once and this is not that once.
              setIssued(
                created.key === undefined || created.key === null
                  ? null
                  : { id: created.id, key: created.key },
              );
            }, "Key created.")
            .then((ok: boolean) => {
              if (ok) {
                setName("");
                reload();
              }
            });
        }}
      >
        <label class="resource-field">
          New key name
          <input
            type="text"
            required
            placeholder="Production integration"
            value={name}
            disabled={mutation.state.pending}
            onInput={(event) => setName(inputValue(event))}
          />
        </label>
        <button
          class="resource-btn resource-btn-primary"
          type="submit"
          disabled={mutation.state.pending || name.trim() === ""}
        >
          Create key
        </button>
      </form>
      {issued === null ? null : (
        <div class="resource-callout">
          <h3>Save your new API key</h3>
          <p>
            Copy this key now. It is shown once and cannot be recovered,
            including by reloading this page.
          </p>
          <code class="resource-secret">{issued.key}</code>
          <SecretCopyButton value={issued.key} label="Copy key" />
        </div>
      )}
      <AsyncBoundary
        state={state}
        loadingLabel="Loading the keys of the service account"
        empty={{
          when: (keys) => keys.length === 0,
          render: () => (
            <p class="resource-empty">This service account has no keys.</p>
          ),
        }}
      >
        {(keys) => (
          <ul class="resource-list">
            {keys.map((key) => (
              <li key={key.id} class="resource-row">
                <span class="resource-row-name">{key.display_name}</span>
                <code class="resource-row-id">{key.id}</code>
                <span class="resource-row-note">{describe(key)}</span>
                {key.revoked_at_unix_ms === undefined ||
                key.revoked_at_unix_ms === null ? (
                  <>
                    <ConfirmButton
                      label="Rotate"
                      prompt="Rotate this key? The current key stops working immediately. Save the replacement now; it keeps the same name and expiry and is shown only once."
                      confirmLabel="Confirm rotate"
                      disabled={mutation.state.pending}
                      onConfirm={() =>
                        void mutation
                          .run(async () => {
                            const created = await rotateServiceAccountKey(
                              tenantId,
                              environmentId,
                              serviceAccountId,
                              key.id,
                            );
                            setIssued(
                              created.key === undefined || created.key === null
                                ? null
                                : { id: created.id, key: created.key },
                            );
                          }, "Key rotated.")
                          .then((ok: boolean) => {
                            if (ok) {
                              // Plain `reload`: the replacement must survive the reload
                              // its own rotation triggers, exactly as on create.
                              reload();
                            }
                          })
                      }
                    />
                    <ConfirmButton
                      label="Revoke"
                      prompt="Revoke this key? It stops authenticating on the next request. This cannot be undone."
                      confirmLabel="Confirm revoke"
                      danger
                      disabled={mutation.state.pending}
                      onConfirm={() =>
                        void mutation
                          .run(async () => {
                            await revokeServiceAccountKey(
                              tenantId,
                              environmentId,
                              serviceAccountId,
                              key.id,
                            );
                          }, "Key revoked.")
                          // Reload only on SUCCESS: reloading after a failure replaces the
                          // error with a fresh render of the unchanged list, which reads as
                          // though the revoke worked.
                          .then((ok: boolean) => {
                            if (ok) {
                              reloadClearingKey();
                            }
                          })
                      }
                    />
                  </>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </AsyncBoundary>
      <MutationFeedback state={mutation.state} sudo={sudoFor(mutation.retry)} />
    </>
  );
}
