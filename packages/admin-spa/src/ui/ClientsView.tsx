// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The clients surface (issue #90, PR 6), SCOPED to the active {tenant, environment}
// from the switcher. This is DYNAMIC CLIENT REGISTRATION (DCR, RFC 7591, issue
// #31), NOT generic client CRUD: the management contract documents NO list,
// create, update, or delete of a client, so this surface invents none. What the
// contract DOES document, and what this surface offers, is:
//
//   1. Look up a registered client by id (getDcrClient) and VERIFY it
//      (verifyDcrClient): lift the unverified-client quarantine.
//   2. List and create the reusable DCR policies (listDcrPolicies /
//      createDcrPolicy) a minted token's chain references by name.
//   3. Mint an initial access token (createDcrInitialAccessToken): the copy-once
//      bearer an operator hands to a registrant. The token value is surfaced
//      exactly ONCE and is NEVER persisted or logged (memory-only state), matching
//      the server's redact-in-Debug posture.
//
// Connectors and this surface both live UNDER an environment, so it reads BOTH the
// active tenant and environment from the scope store and injects them into every
// call. When no {tenant, environment} is in scope it prompts and makes ZERO calls.
// It reads and writes ONLY through the named wrappers in src/api/client.ts (the
// single funnel), stands on the same reusable resource hooks and views, and
// renders every failure through the verbatim ErrorView boundary, including the RFC
// 9470 sudo path on a max_age challenge.

import { useState } from "preact/hooks";
import {
  type ClientAllowedScopesView,
  type ClientVerificationView,
  type CreateDcrPolicyRequest,
  type CreateInitialAccessTokenRequest,
  type DcrPolicyView,
  type InitialAccessTokenCreated,
  type SigningRecommendationView,
  createDcrInitialAccessToken,
  createDcrPolicy,
  fetchDcrPolicies,
  fetchSigningRecommendations,
  getClientAllowedScopes,
  getDcrClient,
  setClientAllowedScopes,
  setClientSigningAlgorithm,
  verifyDcrClient,
} from "../api/client";
import { activeScope } from "../scope/store";
import type { SudoRecovery } from "./ErrorView";
import { AsyncBoundary, ConfirmButton, MutationFeedback } from "./ResourceView";
import { ClientServiceAccountKeysPanel } from "./ClientServiceAccountKeysView";
import { useAsyncResource, useMutation } from "./useResource";

function inputValue(event: Event): string {
  return (event.target as HTMLInputElement).value;
}

// Parse a textarea as a JSON array (the shape the policy primitives take).
// Returns the array on success or null on any parse or shape fault; the caller
// shows a client side field error, never a network error channel.
function parseJsonArray(text: string): unknown[] | null {
  try {
    const value: unknown = JSON.parse(text);
    return Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
}

// The clients (DCR) surface root, scoped to the active {tenant, environment}. When
// no scope is selected there is nothing to act on, so it prompts and makes ZERO
// calls (the list, lookup, and mint all defer to the scoped child).
export function ClientsList() {
  const scope = activeScope.value;
  if (scope === null) {
    return (
      <section class="resource" aria-labelledby="clients-heading">
        <h2 id="clients-heading">Clients (dynamic client registration)</h2>
        <p class="resource-empty">
          Select a tenant and environment to manage dynamic client registration.
        </p>
      </section>
    );
  }
  return (
    <ClientsForScope
      tenantId={scope.tenantId}
      environmentId={scope.environmentId}
    />
  );
}

function ClientsForScope({
  tenantId,
  environmentId,
}: {
  tenantId: string;
  environmentId: string;
}) {
  return (
    <section class="resource" aria-labelledby="clients-heading">
      <h2 id="clients-heading">Clients (dynamic client registration)</h2>
      <p class="resource-note">
        Dynamic client registration (RFC 7591). Look up and verify a registered
        client, manage the reusable registration policies, and mint an initial
        access token. There is no generic client create or edit here; a client is
        registered by a registrant presenting an initial access token.
      </p>
      <DcrClientLookup tenantId={tenantId} environmentId={environmentId} />
      <SigningAlgorithmWizard
        tenantId={tenantId}
        environmentId={environmentId}
      />
      <AllowedScopesPanel tenantId={tenantId} environmentId={environmentId} />
      <ClientServiceAccountKeysPanel
        tenantId={tenantId}
        environmentId={environmentId}
      />
      <DcrPoliciesPanel tenantId={tenantId} environmentId={environmentId} />
      <DcrInitialAccessTokenPanel
        tenantId={tenantId}
        environmentId={environmentId}
      />
    </section>
  );
}

// The token signing compatibility wizard (issue #93). An operator who has a
// registered client id picks what will verify the client ID tokens (the
// verifier); the wizard shows the recommended JOSE algorithm, a one line reason,
// and the alternatives and supported sets for that verifier; on confirm it pins
// the recommended algorithm onto the client. The interop table is server owned:
// single source of truth (unit tested in Rust), so this panel renders exactly the
// rows the read returns and hardcodes NO matrix. The read is unscoped, so it fires
// once; the write injects the active {tenant, environment} plus the client id.
function SigningAlgorithmWizard({
  tenantId,
  environmentId,
}: {
  tenantId: string;
  environmentId: string;
}) {
  const { state } = useAsyncResource<SigningRecommendationView[]>(
    () => fetchSigningRecommendations(),
    [],
  );
  return (
    <div class="resource-subsection">
      <h3>Token signing compatibility wizard</h3>
      <p class="resource-note">
        Pick what will verify the ID tokens of a registered client. The wizard shows
        the recommended signing algorithm for that verifier and, on confirm, pins
        it onto the client. The recommendations come from the server; nothing here
        is hardcoded.
      </p>
      <AsyncBoundary
        state={state}
        loadingLabel="Loading recommendations"
        empty={{
          when: (rows) => rows.length === 0,
          render: () => (
            <p class="resource-empty">
              No verifier recommendations are available.
            </p>
          ),
        }}
      >
        {(rows) => (
          <SigningAlgorithmWizardForm
            tenantId={tenantId}
            environmentId={environmentId}
            rows={rows}
          />
        )}
      </AsyncBoundary>
    </div>
  );
}

function SigningAlgorithmWizardForm({
  tenantId,
  environmentId,
  rows,
}: {
  tenantId: string;
  environmentId: string;
  rows: SigningRecommendationView[];
}) {
  const [clientId, setClientId] = useState("");
  const [verifier, setVerifier] = useState(rows[0]?.verifier ?? "");
  const mutation = useMutation();
  const scope = activeScope.value;
  const sudo: SudoRecovery | undefined =
    scope === null ? undefined : { scope, retry: mutation.retry };

  // The selected row drives the whole recommendation panel. It is derived from
  // the verifier state, so switching the verifier re-renders the recommended
  // algorithm, reason, and sets from what the server returned, never a client
  // computed value. A verifier that is no longer in the rows falls back to the
  // first row so the panel never renders a stale selection.
  const selected =
    rows.find((row) => row.verifier === verifier) ?? rows[0] ?? null;

  function onConfirm(event: Event): void {
    event.preventDefault();
    if (selected === null) {
      return;
    }
    const trimmed = clientId.trim();
    if (trimmed === "") {
      return;
    }
    void mutation.run(async () => {
      await setClientSigningAlgorithm(
        tenantId,
        environmentId,
        trimmed,
        selected.recommended,
      );
    }, `Signing algorithm set to ${selected.recommended}.`);
  }

  return (
    <form
      class="resource-form"
      onSubmit={onConfirm}
      aria-label="Set the signing algorithm for a client"
    >
      <div class="resource-field">
        <label for="signing-client-id">Client id</label>
        <input
          id="signing-client-id"
          type="text"
          value={clientId}
          onInput={(event) => setClientId(inputValue(event))}
        />
      </div>
      <div class="resource-field">
        <label for="signing-verifier">Token verifier</label>
        <select
          id="signing-verifier"
          value={verifier}
          onInput={(event) =>
            setVerifier((event.target as HTMLSelectElement).value)
          }
        >
          {rows.map((row) => (
            <option key={row.verifier} value={row.verifier}>
              {row.label}
            </option>
          ))}
        </select>
      </div>
      {selected === null ? null : (
        <dl class="resource-detail" aria-label="Recommendation">
          <dt>Recommended algorithm</dt>
          <dd>
            <code class="signing-recommended">{selected.recommended}</code>
          </dd>
          <dt>Reason</dt>
          <dd class="signing-reason">{selected.reason}</dd>
          <dt>Alternatives</dt>
          <dd>
            {selected.alternatives.length === 0
              ? "none"
              : selected.alternatives.join(", ")}
          </dd>
          <dt>Supported</dt>
          <dd>{selected.supported.join(", ")}</dd>
        </dl>
      )}
      <button
        type="submit"
        class="resource-btn resource-btn-primary"
        disabled={
          mutation.state.pending ||
          selected === null ||
          clientId.trim() === ""
        }
      >
        Set signing algorithm
      </button>
      <MutationFeedback state={mutation.state} sudo={sudo} />
    </form>
  );
}

// The per client OAuth SCOPE allowlist (issue #98): which scope tokens a machine
// grant (client_credentials, jwt-bearer) may request for one client.
//
// THREE states, and the panel keeps them distinct because the server does:
//
//   * no allowlist   the field is empty and "Clear the allowlist" was used, or the
//                    client was never configured. Every scope passes the machine
//                    grant denylist floor.
//   * a list         the client may request exactly these tokens.
//   * the EMPTY list the client may request no scope at all. Reached by submitting
//                    an empty field with "Set", NOT by clearing.
//
// The last two are one keystroke apart and mean opposite things, so the panel offers
// two separate buttons rather than one that guesses. A read that answers the empty
// list on a client the operator believes is unrestricted is not a bug in this panel:
// the server reads a stored value it cannot parse as the empty allowlist (deny
// everything), and the panel shows what is in force rather than a repaired value.
//
// What this is NOT, because the console is where the confusion would land: it is a
// DELEGATION restriction on what a machine may ask for. It is not the permission set
// (machine principal permissions are issue #99), and it can never re admit openid or
// offline_access, which the token endpoint refuses whatever this list says.
function AllowedScopesPanel({
  tenantId,
  environmentId,
}: {
  tenantId: string;
  environmentId: string;
}) {
  const [clientId, setClientId] = useState("");
  const [lookupId, setLookupId] = useState<string | null>(null);

  function onSubmit(event: Event): void {
    event.preventDefault();
    const trimmed = clientId.trim();
    setLookupId(trimmed === "" ? null : trimmed);
  }

  return (
    <div class="resource-subsection">
      <h3>Machine grant scope allowlist</h3>
      <p class="resource-note">
        Which scope tokens a client may request on a machine grant. Leave it unset
        and every scope is allowed; set a list and the client is restricted to
        exactly those tokens; set an EMPTY list and it may request none. `openid`
        and `offline_access` are refused on a machine grant whatever this list says,
        and this is not the permission set.
      </p>
      <form
        class="resource-form"
        onSubmit={onSubmit}
        aria-label="Look up a client scope allowlist"
      >
        <div class="resource-field">
          <label for="allowed-scopes-client-id">Client id</label>
          <input
            id="allowed-scopes-client-id"
            type="text"
            value={clientId}
            onInput={(event) => setClientId(inputValue(event))}
          />
        </div>
        <button type="submit" class="resource-btn resource-btn-primary">
          Load allowlist
        </button>
      </form>
      {lookupId === null ? null : (
        <AllowedScopesEditor
          key={lookupId}
          tenantId={tenantId}
          environmentId={environmentId}
          clientId={lookupId}
        />
      )}
    </div>
  );
}

function AllowedScopesEditor({
  tenantId,
  environmentId,
  clientId,
}: {
  tenantId: string;
  environmentId: string;
  clientId: string;
}) {
  const { state } = useAsyncResource<ClientAllowedScopesView>(
    () => getClientAllowedScopes(tenantId, environmentId, clientId),
    [tenantId, environmentId, clientId],
  );
  return (
    <AsyncBoundary state={state} loadingLabel="Loading the allowlist">
      {(view) => (
        <AllowedScopesForm
          tenantId={tenantId}
          environmentId={environmentId}
          clientId={clientId}
          view={view}
        />
      )}
    </AsyncBoundary>
  );
}

function AllowedScopesForm({
  tenantId,
  environmentId,
  clientId,
  view,
}: {
  tenantId: string;
  environmentId: string;
  clientId: string;
  view: ClientAllowedScopesView;
}) {
  // One scope token per line, which is the only editor shape that can express the
  // empty list distinctly from a single blank token. A space separated field could
  // not, and a space inside one entry is exactly what the server refuses.
  const [text, setText] = useState((view.allowed_scopes ?? []).join("\n"));
  const mutation = useMutation();
  const scope = activeScope.value;
  const sudo: SudoRecovery | undefined =
    scope === null ? undefined : { scope, retry: mutation.retry };

  function entries(): string[] {
    return text
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line !== "");
  }

  function onSet(event: Event): void {
    event.preventDefault();
    const list = entries();
    void mutation.run(async () => {
      await setClientAllowedScopes(tenantId, environmentId, clientId, list);
    }, `Allowlist set to ${list.length} scope${list.length === 1 ? "" : "s"}.`);
  }

  function onClear(): void {
    void mutation.run(async () => {
      await setClientAllowedScopes(tenantId, environmentId, clientId, null);
      setText("");
    }, "Allowlist cleared: every scope now passes the machine grant floor.");
  }

  return (
    <form
      class="resource-form"
      onSubmit={onSet}
      aria-label="Set the scope allowlist for a client"
    >
      <dl class="resource-detail" aria-label="Stored allowlist">
        <dt>Currently</dt>
        <dd>
          {view.allowed_scopes === null || view.allowed_scopes === undefined
            ? "no allowlist: every scope passes the machine grant floor"
            : view.allowed_scopes.length === 0
              ? "the empty allowlist: this client may request no scope at all"
              : view.allowed_scopes.join(", ")}
        </dd>
      </dl>
      <div class="resource-field">
        <label for="allowed-scopes-list">Allowed scopes (one per line)</label>
        <textarea
          id="allowed-scopes-list"
          rows={5}
          value={text}
          onInput={(event) =>
            setText((event.target as HTMLTextAreaElement).value)
          }
        />
      </div>
      <button
        type="submit"
        class="resource-btn resource-btn-primary"
        disabled={mutation.state.pending}
      >
        Set allowlist
      </button>
      <ConfirmButton
        label="Clear the allowlist"
        prompt="Clearing removes the restriction entirely: this client will then be able to request any scope the machine grant floor allows. To let it request NOTHING, submit an EMPTY list with Set instead."
        confirmLabel="Confirm clear"
        onConfirm={onClear}
        disabled={mutation.state.pending}
      />
      <MutationFeedback state={mutation.state} sudo={sudo} />
    </form>
  );
}

// Look up a registered client by id (operationId getDcrClient) and verify it
// (operationId verifyDcrClient). The lookup is submitted explicitly, so no call
// fires until an operator enters a client id.
function DcrClientLookup({
  tenantId,
  environmentId,
}: {
  tenantId: string;
  environmentId: string;
}) {
  const [clientId, setClientId] = useState("");
  const [lookupId, setLookupId] = useState<string | null>(null);

  function onSubmit(event: Event): void {
    event.preventDefault();
    const trimmed = clientId.trim();
    if (trimmed === "") {
      return;
    }
    setLookupId(trimmed);
  }

  return (
    <div class="resource-subsection">
      <h3>Registered client</h3>
      <form
        class="resource-form"
        onSubmit={onSubmit}
        aria-label="Look up a registered client"
      >
        <div class="resource-field">
          <label for="dcr-client-id">Client id</label>
          <input
            id="dcr-client-id"
            type="text"
            value={clientId}
            onInput={(event) => setClientId(inputValue(event))}
          />
        </div>
        <button
          type="submit"
          class="resource-btn"
          disabled={clientId.trim() === ""}
        >
          Look up client
        </button>
      </form>
      {lookupId === null ? null : (
        <DcrClientCard
          tenantId={tenantId}
          environmentId={environmentId}
          clientId={lookupId}
        />
      )}
    </div>
  );
}

function DcrClientCard({
  tenantId,
  environmentId,
  clientId,
}: {
  tenantId: string;
  environmentId: string;
  clientId: string;
}) {
  const { state, reload } = useAsyncResource<ClientVerificationView>(
    () => getDcrClient(tenantId, environmentId, clientId),
    [tenantId, environmentId, clientId],
  );
  const mutation = useMutation();
  const scope = activeScope.value;
  const sudo: SudoRecovery | undefined =
    scope === null ? undefined : { scope, retry: mutation.retry };

  function onVerify(): void {
    void mutation
      .run(async () => {
        await verifyDcrClient(tenantId, environmentId, clientId);
      }, "Client verified.")
      .then((ok) => {
        if (ok) {
          reload();
        }
      });
  }

  return (
    <AsyncBoundary state={state} loadingLabel="Loading client">
      {(client) => (
        <div>
          <dl class="resource-detail">
            <dt>Identifier</dt>
            <dd>
              <code>{client.id}</code>
            </dd>
            <dt>Quarantined</dt>
            <dd>{client.quarantined ? "yes" : "no"}</dd>
            <dt>Verified</dt>
            <dd>{client.verified ? "yes" : "no"}</dd>
            <dt>Verified at</dt>
            <dd>
              {client.verified_at_unix_ms === null ||
              client.verified_at_unix_ms === undefined
                ? "never"
                : new Date(client.verified_at_unix_ms).toISOString()}
            </dd>
          </dl>
          <div
            class="resource-actions"
            role="group"
            aria-label="Verify client"
          >
            <ConfirmButton
              label="Verify client"
              prompt="Verify this client and lift its quarantine?"
              confirmLabel="Confirm verify"
              disabled={mutation.state.pending || client.verified}
              onConfirm={onVerify}
            />
          </div>
          <MutationFeedback state={mutation.state} sudo={sudo} />
        </div>
      )}
    </AsyncBoundary>
  );
}

// The reusable DCR policies (operationIds listDcrPolicies / createDcrPolicy): the
// named registration policies a minted token's chain references. The contract
// documents only the list and the create (no get or delete of a single policy),
// so this surface offers exactly those.
function DcrPoliciesPanel({
  tenantId,
  environmentId,
}: {
  tenantId: string;
  environmentId: string;
}) {
  const { state, reload } = useAsyncResource<DcrPolicyView[]>(
    () => fetchDcrPolicies(tenantId, environmentId),
    [tenantId, environmentId],
  );
  return (
    <div class="resource-subsection">
      <h3>Registration policies</h3>
      <DcrPolicyCreateForm
        tenantId={tenantId}
        environmentId={environmentId}
        onCreated={reload}
      />
      <AsyncBoundary
        state={state}
        loadingLabel="Loading policies"
        empty={{
          when: (items) => items.length === 0,
          render: () => (
            <p class="resource-empty">
              No registration policies yet. Create the first one above.
            </p>
          ),
        }}
      >
        {(items) => (
          <ul class="resource-list">
            {items.map((policy) => (
              <li key={policy.id} class="resource-row">
                <span class="resource-link">{policy.name}</span>
                <code class="resource-id">{policy.id}</code>
                <span class="resource-status">
                  {policy.primitives.length} primitive
                  {policy.primitives.length === 1 ? "" : "s"}
                </span>
              </li>
            ))}
          </ul>
        )}
      </AsyncBoundary>
    </div>
  );
}

function DcrPolicyCreateForm({
  tenantId,
  environmentId,
  onCreated,
}: {
  tenantId: string;
  environmentId: string;
  onCreated: () => void;
}) {
  const mutation = useMutation();
  const [name, setName] = useState("");
  const [primitives, setPrimitives] = useState("");
  const [invalid, setInvalid] = useState(false);

  function onSubmit(event: Event): void {
    event.preventDefault();
    const parsed = parseJsonArray(primitives);
    if (parsed === null) {
      setInvalid(true);
      return;
    }
    setInvalid(false);
    // The contract types `primitives` as an array of freeform primitive objects;
    // the parsed array is that list, cast to the generated field type so the call
    // stays typed against the contract rather than reaching for `any`.
    const request: CreateDcrPolicyRequest = {
      name: name.trim(),
      primitives: parsed as CreateDcrPolicyRequest["primitives"],
    };
    void mutation
      .run(async () => {
        await createDcrPolicy(tenantId, environmentId, request);
      }, "Policy created.")
      .then((ok) => {
        if (ok) {
          setName("");
          setPrimitives("");
          onCreated();
        }
      });
  }

  return (
    <form
      class="resource-form"
      onSubmit={onSubmit}
      aria-label="Create a registration policy"
    >
      <div class="resource-field">
        <label for="dcr-policy-name">Policy name</label>
        <input
          id="dcr-policy-name"
          type="text"
          required
          value={name}
          onInput={(event) => setName(inputValue(event))}
        />
      </div>
      <div class="resource-field">
        <label for="dcr-policy-primitives">
          Primitives (JSON array of force / restrict / reject / default objects)
        </label>
        <textarea
          id="dcr-policy-primitives"
          rows={5}
          value={primitives}
          onInput={(event) =>
            setPrimitives((event.target as HTMLTextAreaElement).value)
          }
        />
        {invalid ? (
          <p class="resource-field-error" role="alert">
            Enter a valid JSON array of policy primitives.
          </p>
        ) : null}
      </div>
      <button
        type="submit"
        class="resource-btn resource-btn-primary"
        disabled={
          mutation.state.pending ||
          name.trim() === "" ||
          primitives.trim() === ""
        }
      >
        Create policy
      </button>
      <MutationFeedback state={mutation.state} />
    </form>
  );
}

// Mint a DCR initial access token (operationId createDcrInitialAccessToken). The
// returned token is a CREDENTIAL the server returns exactly ONCE (on the genuine
// 201 create); this panel holds it in component state (memory only) and renders it
// a single time as copy-once. It is NEVER written to localStorage or
// sessionStorage and NEVER logged, matching the server's redact-in-Debug posture.
// A new mint replaces the displayed value; leaving the surface drops it entirely.
function DcrInitialAccessTokenPanel({
  tenantId,
  environmentId,
}: {
  tenantId: string;
  environmentId: string;
}) {
  const mutation = useMutation();
  const [expiresIn, setExpiresIn] = useState("86400");
  const [maxUses, setMaxUses] = useState("");
  const [policyNames, setPolicyNames] = useState("");
  const [created, setCreated] = useState<InitialAccessTokenCreated | null>(
    null,
  );

  function onSubmit(event: Event): void {
    event.preventDefault();
    const seconds = Number(expiresIn.trim());
    if (!Number.isFinite(seconds) || seconds < 0) {
      return;
    }
    const request: CreateInitialAccessTokenRequest = {
      expires_in_secs: seconds,
    };
    if (maxUses.trim() !== "") {
      request.max_uses = Number(maxUses.trim());
    }
    const names = policyNames
      .split(",")
      .map((name) => name.trim())
      .filter((name) => name !== "");
    if (names.length > 0) {
      request.policy_names = names;
    }
    // Clear any previously displayed token BEFORE the call so a stale credential
    // is never on screen while the next mint is in flight.
    setCreated(null);
    void mutation.run(async () => {
      const result = await createDcrInitialAccessToken(
        tenantId,
        environmentId,
        request,
      );
      // Hold the result in memory only. This is the ONLY place the token value
      // lives; it is never persisted or logged.
      setCreated(result);
    }, "Initial access token minted.");
  }

  return (
    <div class="resource-subsection">
      <h3>Initial access token</h3>
      <form
        class="resource-form"
        onSubmit={onSubmit}
        aria-label="Mint an initial access token"
      >
        <div class="resource-field">
          <label for="dcr-iat-expires">Lifetime (seconds)</label>
          <input
            id="dcr-iat-expires"
            type="number"
            required
            min={0}
            value={expiresIn}
            onInput={(event) => setExpiresIn(inputValue(event))}
          />
        </div>
        <div class="resource-field">
          <label for="dcr-iat-max-uses">Max uses (optional, blank for unlimited)</label>
          <input
            id="dcr-iat-max-uses"
            type="number"
            min={0}
            value={maxUses}
            onInput={(event) => setMaxUses(inputValue(event))}
          />
        </div>
        <div class="resource-field">
          <label for="dcr-iat-policies">
            Policy names (optional, comma separated)
          </label>
          <input
            id="dcr-iat-policies"
            type="text"
            value={policyNames}
            onInput={(event) => setPolicyNames(inputValue(event))}
          />
        </div>
        <button
          type="submit"
          class="resource-btn resource-btn-primary"
          disabled={mutation.state.pending || expiresIn.trim() === ""}
        >
          Mint token
        </button>
      </form>
      {created === null ? null : <IssuedToken created={created} />}
      <MutationFeedback state={mutation.state} />
    </div>
  );
}

// Render a freshly minted initial access token. When the server returned the
// plaintext token (a genuine first create), it is shown ONCE as copy-once: an
// operator copies it now because it is never retrievable again. An idempotent
// replay omits the token and reports it was already issued. The token value is
// rendered as TEXT (Preact escapes text children) and is held only in the parent's
// memory state, never persisted or logged.
function IssuedToken({ created }: { created: InitialAccessTokenCreated }) {
  const hasToken = typeof created.token === "string" && created.token !== "";
  return (
    <div class="resource-token" role="status" aria-live="polite">
      <dl class="resource-detail">
        <dt>Token id</dt>
        <dd>
          <code>{created.id}</code>
        </dd>
        <dt>Expires at</dt>
        <dd>{new Date(created.expires_at_unix_ms).toISOString()}</dd>
        <dt>Max uses</dt>
        <dd>
          {created.max_uses === null || created.max_uses === undefined
            ? "unlimited"
            : created.max_uses}
        </dd>
      </dl>
      {hasToken ? (
        <div class="resource-token-secret">
          <p class="resource-token-warning">
            Copy this token now. It is shown only once and cannot be retrieved
            again. Present it as an Authorization Bearer header at registration.
          </p>
          <code class="resource-token-value">{created.token}</code>
        </div>
      ) : (
        <p class="resource-token-warning">
          {created.token_already_issued
            ? "This token was already issued; the value is not shown again."
            : "No token value was returned."}
        </p>
      )}
    </div>
  );
}
