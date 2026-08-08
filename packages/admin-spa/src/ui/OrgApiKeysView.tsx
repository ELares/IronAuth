// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The API keys of one organization (issue #99, criterion 6).
//
// A PANEL of the organization detail view, because a key belongs to an organization
// and the list is meaningless without one selected.
//
// READ ONLY, and that is a deliberate first slice rather than an unfinished one. The
// create control has a requirement no other panel here has: the key is returned
// exactly once, so the panel would have to hold it as display-once state that a
// reload destroys. Shipping the listing first gives an operator the thing they most
// need during an incident, which is to see what exists and what was already revoked.
//
// It carries NO key material by construction: the listing endpoint has no digest to
// return, and `OrgApiKeyView` has no field for one. A management surface that showed
// verifiers would hand a credential-equivalent to everyone allowed to LOOK, which is
// a strictly larger set than those allowed to USE.
//
// Revoked keys are shown rather than filtered. An operator investigating a leak has
// to be able to tell "revoked at 14:02" from "no such key", and hiding the row makes
// a rotation look like a replacement.

import {
  type OrgApiKeyView,
  fetchOrgApiKeys,
  revokeOrgApiKey,
} from "../api/client";
import { AsyncBoundary, ConfirmButton, MutationFeedback } from "./ResourceView";
import { type OrgScope, sudoFor } from "./orgPanels";
import { useAsyncResource, useMutation } from "./useResource";

export function OrgApiKeysPanel({
  tenantId,
  environmentId,
  organizationId,
}: OrgScope) {
  const { state, reload } = useAsyncResource<OrgApiKeyView[]>(
    () => fetchOrgApiKeys(tenantId, environmentId, organizationId),
    [tenantId, environmentId, organizationId],
  );
  // Held ABOVE the AsyncBoundary. A successful revoke reloads the list, the reload
  // flips the boundary back to loading, and anything holding state under it is
  // unmounted, so a mutation owned by a row would have its outcome destroyed by its
  // own success. Same placement, and same reason, as OrgDefaultRolePanel.
  const mutation = useMutation();

  return (
    <div class="resource-subsection">
      <h3>API keys</h3>
      <p class="resource-note">
        The keys that authenticate as this organization. The key itself is shown once,
        when it is created, and is never recoverable afterwards: this list carries only
        the handle. Revoked keys stay listed so a rotation is legible.
      </p>
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
                            reload();
                          }
                        })
                    }
                  />
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
export function describe(key: OrgApiKeyView): string {
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
