// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The personal access tokens of one user (issue #99, criterion 6).
//
// A PANEL of the user detail view, because a token belongs to a user and the list is
// meaningless without one selected. The sibling of OrgApiKeysPanel, rendering the same
// object through the same shared `ApiKeyView` type, so the two surfaces cannot drift
// into showing different fields for the same thing.
//
// It carries NO token material by construction: the listing endpoint has no digest to
// return and `ApiKeyView` has no field for one. A management surface that showed
// verifiers would hand a credential-equivalent to everyone allowed to LOOK, which is a
// strictly larger set than those allowed to USE.
//
// Revoked tokens are shown rather than filtered, so an operator investigating a leak
// can tell "revoked at 14:02" from "no such token", and so a rotation does not read as
// a replacement appearing from nowhere.
//
// # Two differences from the organization panel, both forced by where this is mounted
//
// It takes the detail view's SHARED `mutation` rather than owning one, because that
// view renders a single MutationFeedback for every panel under it and a second one
// would report the same outcome twice.
//
// It owns its OWN list resource and never calls the parent's reload. The parent's
// AsyncBoundary unmounts everything under it while reloading, which would destroy the
// display-once token this panel is holding. Reloading only its own list is what lets
// the newly minted token stay on screen beside the row that now exists.

import { useState } from "preact/hooks";
import {
  type ApiKeyView,
  createUserPersonalAccessToken,
  fetchUserPersonalAccessTokens,
  revokeUserPersonalAccessToken,
  rotateUserPersonalAccessToken,
} from "../api/client";
import { describe } from "./OrgApiKeysView";
import { AsyncBoundary, ConfirmButton } from "./ResourceView";
import { inputValue } from "./orgPanels";
import { type Mutation, useAsyncResource } from "./useResource";

export function UserPersonalAccessTokensPanel({
  tenantId,
  environmentId,
  userId,
  mutation,
}: {
  tenantId: string;
  environmentId: string;
  userId: string;
  mutation: Mutation;
}) {
  const { state, reload } = useAsyncResource<ApiKeyView[]>(
    () => fetchUserPersonalAccessTokens(tenantId, environmentId, userId),
    [tenantId, environmentId, userId],
  );
  // DISPLAY ONCE. The minted token lives here and nowhere else. Its OWN creation
  // reloads the list WITHOUT clearing it, because the point is that the operator can
  // still see it beside the row that now exists; every OTHER reload clears it.
  //
  // Deliberately not part of the list rows. A row is re-rendered from the server on
  // every reload, so a token held there would either vanish inconsistently or, worse,
  // survive in the DOM long after the operator stopped looking. The server cannot
  // return it again, so the panel must not behave as though it could.
  const [issued, setIssued] = useState<{ id: string; key: string } | null>(null);
  const [name, setName] = useState("");
  const reloadClearingToken = () => {
    setIssued(null);
    reload();
  };

  return (
    <div class="resource-subsection">
      <h3>Personal access tokens</h3>
      <p class="resource-note">
        The tokens that authenticate as this user. The token itself is shown once, when
        it is created, and is never recoverable afterwards: this list carries only the
        handle. Revoked tokens stay listed so a rotation is legible.
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
              const created = await createUserPersonalAccessToken(
                tenantId,
                environmentId,
                userId,
                trimmed,
              );
              // `key` is absent on an idempotent replay. Showing nothing is correct
              // there: the token was issued once and this is not that once.
              setIssued(
                created.key === undefined || created.key === null
                  ? null
                  : { id: created.id, key: created.key },
              );
            }, "Token created.")
            .then((ok: boolean) => {
              if (ok) {
                setName("");
                reload();
              }
            });
        }}
      >
        <label>
          New token name
          <input
            type="text"
            value={name}
            disabled={mutation.state.pending}
            onInput={(event) => setName(inputValue(event))}
          />
        </label>
        <button type="submit" disabled={mutation.state.pending}>
          Create token
        </button>
      </form>
      {issued === null ? null : (
        <div class="resource-callout">
          <p>
            Copy this token now. It is shown once and cannot be recovered, including by
            reloading this page.
          </p>
          <code class="resource-secret">{issued.key}</code>
        </div>
      )}
      <AsyncBoundary
        state={state}
        loadingLabel="Loading the personal access tokens of the user"
        empty={{
          when: (tokens) => tokens.length === 0,
          render: () => (
            <p class="resource-empty">This user has no personal access tokens.</p>
          ),
        }}
      >
        {(tokens) => (
          <ul class="resource-list">
            {tokens.map((token) => (
              <li key={token.id} class="resource-row">
                <span class="resource-row-name">{token.display_name}</span>
                <code class="resource-row-id">{token.id}</code>
                <span class="resource-row-note">{describe(token)}</span>
                {/* No control on an already revoked token. Revoking twice is a no-op
                    at the store, but offering the button suggests there is something
                    left to stop, which is the opposite of what the row says. */}
                {token.revoked_at_unix_ms === undefined ||
                token.revoked_at_unix_ms === null ? (
                  <>
                    <ConfirmButton
                      label="Rotate"
                      prompt="Rotate this token? The current token stops authenticating immediately and a replacement is issued in the same transaction, inheriting this token's name and expiry. The new token is shown ONCE and cannot be recovered."
                      confirmLabel="Confirm rotate"
                      disabled={mutation.state.pending}
                      onConfirm={() =>
                        void mutation
                          .run(async () => {
                            const created = await rotateUserPersonalAccessToken(
                              tenantId,
                              environmentId,
                              userId,
                              token.id,
                            );
                            setIssued(
                              created.key === undefined || created.key === null
                                ? null
                                : { id: created.id, key: created.key },
                            );
                          }, "Token rotated.")
                          .then((ok: boolean) => {
                            if (ok) {
                              // Plain `reload`, NOT `reloadClearingToken`: the
                              // replacement must survive the reload its own rotation
                              // triggers, exactly as on create.
                              reload();
                            }
                          })
                      }
                    />
                    <ConfirmButton
                      label="Revoke"
                      prompt="Revoke this token? Anything using it stops authenticating on its very next request, and the token cannot be recovered or un-revoked. The row stays listed so the revocation is legible."
                      confirmLabel="Confirm revoke"
                      danger
                      disabled={mutation.state.pending}
                      onConfirm={() =>
                        void mutation
                          .run(async () => {
                            await revokeUserPersonalAccessToken(
                              tenantId,
                              environmentId,
                              userId,
                              token.id,
                            );
                          }, "Token revoked.")
                          // Reload only on SUCCESS. Reloading after a failure would
                          // replace the error the feedback is showing with a fresh
                          // render of the unchanged list, which reads as though the
                          // revoke worked.
                          .then((ok: boolean) => {
                            if (ok) {
                              reloadClearingToken();
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
    </div>
  );
}
