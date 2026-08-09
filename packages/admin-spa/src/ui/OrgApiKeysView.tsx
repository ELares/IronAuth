// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The API keys of one organization (issue #99, criterion 6).
//
// A PANEL of the organization detail view, because a key belongs to an organization
// and the list is meaningless without one selected.
//
// It creates, rotates and revokes as well as listing. The comment here once said READ
// ONLY, describing a first slice that the controls below had already outgrown, which is
// how a doc comment becomes the least reliable thing in a file.
//
// The create and rotate controls have a requirement no other panel here has: the key is
// returned exactly once, so the panel holds it as display-once state. See the note on
// `issued` for the exact rule, which is narrower than "a reload clears it".
//
// It carries NO key material by construction: the listing endpoint has no digest to
// return, and `ApiKeyView` has no field for one. A management surface that showed
// verifiers would hand a credential-equivalent to everyone allowed to LOOK, which is
// a strictly larger set than those allowed to USE.
//
// Revoked keys are shown rather than filtered. An operator investigating a leak has
// to be able to tell "revoked at 14:02" from "no such key", and hiding the row makes
// a rotation look like a replacement.

import { useState } from "preact/hooks";
import {
  type ApiKeyView,
  createOrgApiKey,
  fetchOrgApiKeys,
  revokeOrgApiKey,
  rotateOrgApiKey,
} from "../api/client";
import { AsyncBoundary, ConfirmButton, MutationFeedback } from "./ResourceView";
import { type OrgScope, inputValue, sudoFor } from "./orgPanels";
import { useAsyncResource, useMutation } from "./useResource";

export function OrgApiKeysPanel({
  tenantId,
  environmentId,
  organizationId,
}: OrgScope) {
  const { state, reload } = useAsyncResource<ApiKeyView[]>(
    () => fetchOrgApiKeys(tenantId, environmentId, organizationId),
    [tenantId, environmentId, organizationId],
  );
  // Held ABOVE the AsyncBoundary. A successful revoke reloads the list, the reload
  // flips the boundary back to loading, and anything holding state under it is
  // unmounted, so a mutation owned by a row would have its outcome destroyed by its
  // own success. Same placement, and same reason, as OrgDefaultRolePanel.
  const mutation = useMutation();
  // DISPLAY ONCE, and the exact rule matters because I got the comment wrong first.
  //
  // The created key lives here and nowhere else. Its OWN creation reloads the list
  // WITHOUT clearing it, because the whole point is that the operator can still see
  // it beside the row that now exists. Every OTHER reload clears it: revoking, or
  // remounting under a different scope.
  //
  // It is deliberately not part of the list rows. A row is re-rendered from the
  // server on every reload, and a key held there would either vanish inconsistently
  // or, worse, survive in the DOM long after the operator stopped looking at it. The
  // server cannot return it again, so the panel must not behave as though it could.
  const [issued, setIssued] = useState<{ id: string; key: string } | null>(null);
  const [name, setName] = useState("");
  const reloadClearingKey = () => {
    setIssued(null);
    reload();
  };

  return (
    <div class="resource-subsection">
      <h3>API keys</h3>
      <p class="resource-note">
        The keys that authenticate as this organization. The key itself is shown once,
        when it is created, and is never recoverable afterwards: this list carries only
        the handle. Revoked keys stay listed so a rotation is legible.
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
              const created = await createOrgApiKey(
                tenantId,
                environmentId,
                organizationId,
                trimmed,
              );
              // `key` is absent on an idempotent replay. Showing nothing is correct
              // there: the key was issued once and this is not that once.
              setIssued(
                created.key === undefined || created.key === null
                  ? null
                  : { id: created.id, key: created.key },
              );
            }, "Key created.")
            .then((ok) => {
              if (ok) {
                setName("");
                reload();
              }
            });
        }}
      >
        <label>
          New key name
          <input
            type="text"
            value={name}
            disabled={mutation.state.pending}
            onInput={(event) => setName(inputValue(event))}
          />
        </label>
        <button type="submit" disabled={mutation.state.pending}>
          Create key
        </button>
      </form>
      {issued === null ? null : (
        <div class="resource-callout">
          <p>
            Copy this key now. It is shown once and cannot be recovered, including by
            reloading this page.
          </p>
          <code class="resource-secret">{issued.key}</code>
        </div>
      )}
      <AsyncBoundary
        state={state}
        loadingLabel="Loading the API keys of the organization"
        empty={{
          when: (keys) => keys.length === 0,
          render: () => (
            <p class="resource-empty">
              This organization has no API keys.
            </p>
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
                {/* No control on an already revoked key. Revoking twice is a no-op at
                    the store, but offering the button suggests there is something left
                    to stop, which is the opposite of what the row says. */}
                {key.revoked_at_unix_ms === undefined ||
                key.revoked_at_unix_ms === null ? (
                  <>
                  <ConfirmButton
                    label="Rotate"
                    prompt="Rotate this key? The current key stops authenticating immediately and a replacement is issued in the same transaction, inheriting this key's name and expiry. The new key is shown ONCE and cannot be recovered."
                    confirmLabel="Confirm rotate"
                    disabled={mutation.state.pending}
                    onConfirm={() =>
                      void mutation
                        .run(async () => {
                          const created = await rotateOrgApiKey(
                            tenantId,
                            environmentId,
                            organizationId,
                            key.id,
                          );
                          // Same display-once rule as create, and the same replay
                          // case: a replay answers with no key, and showing an empty
                          // secret box would claim material the operator does not
                          // have.
                          setIssued(
                            created.key === undefined || created.key === null
                              ? null
                              : { id: created.id, key: created.key },
                          );
                        }, "Key rotated.")
                        .then((ok) => {
                          if (ok) {
                            // Plain `reload`, NOT `reloadClearingKey`: the
                            // replacement key must survive the reload its own
                            // rotation triggers, exactly as on create.
                            reload();
                          }
                        })
                    }
                  />
                  <ConfirmButton
                    label="Revoke"
                    prompt="Revoke this key? Anything using it stops authenticating on its very next request, and the key cannot be recovered or un-revoked. The row stays listed so the revocation is legible."
                    confirmLabel="Confirm revoke"
                    danger
                    disabled={mutation.state.pending}
                    onConfirm={() =>
                      void mutation
                        .run(async () => {
                          await revokeOrgApiKey(
                            tenantId,
                            environmentId,
                            organizationId,
                            key.id,
                          );
                        }, "Key revoked.")
                        // Reload only on SUCCESS. Reloading after a failure would
                        // replace the error the boundary is showing with a fresh
                        // render of the unchanged list, which reads as though the
                        // revoke worked.
                        .then((ok) => {
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
    </div>
  );
}

// What to say about one key's lifecycle, in words rather than a raw timestamp.
//
// Revoked wins over expired: a key that was revoked and then passed its expiry is
// revoked, and reporting the expiry would suggest it lapsed on its own rather than
// that somebody killed it.
export function describe(key: ApiKeyView): string {
  if (key.revoked_at_unix_ms !== undefined && key.revoked_at_unix_ms !== null) {
    return `Revoked ${formatWhen(key.revoked_at_unix_ms)}`;
  }
  if (key.expires_at_unix_ms !== undefined && key.expires_at_unix_ms !== null) {
    return `Expires ${formatWhen(key.expires_at_unix_ms)}`;
  }
  return "Live, no expiry";
}

function formatWhen(unixMs: number): string {
  return new Date(unixMs).toISOString().replace("T", " ").slice(0, 19) + " UTC";
}
