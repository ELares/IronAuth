// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The connectors CRUD surface (issue #90, PR 6), SCOPED to the active
// {tenant, environment} from the switcher: the list, the create form, the detail,
// the full-replace PUT update, the delete, and the live health and capabilities
// diagnostics reads. Connectors live UNDER an environment, so this surface reads
// BOTH the active tenant and the active environment from the scope store and
// injects them into every call, exactly as the users surface does. When no
// {tenant, environment} is in scope it shows a prompt and makes ZERO calls. It
// reads and writes ONLY through the named wrappers in src/api/client.ts (the
// single funnel), stands on the same reusable resource hooks and views the users
// and environments surfaces use, and renders every failure through the verbatim
// ErrorView boundary, including the RFC 9470 sudo path on a max_age challenge.
//
// A connector's definition is a declarative JSON document (the authoritative JSON
// Schema is published at docs/connector-schema.json), parsed server side with the
// strict `ironauth-connector` layer. So the create and full-replace update author
// it as a JSON object in a textarea (the same client side JSON validation the
// user claims form uses), rather than a partial form that could not express the
// whole document. The create body carries a client_secret by indirection; the
// read views are SECRET-FREE, so the update is a deliberate full replacement that
// re-supplies it.

import { useLocation } from "preact-iso";
import { useState } from "preact/hooks";
import {
  type ConnectorCapabilitiesView,
  type ConnectorHealthView,
  type ConnectorView,
  type CreateConnectorRequest,
  createConnector,
  deleteConnector,
  fetchConnectors,
  getConnector,
  getConnectorCapabilities,
  getConnectorHealth,
  updateConnector,
} from "../api/client";
import { activeScope } from "../scope/store";
import type { SudoRecovery } from "./ErrorView";
import { AsyncBoundary, ConfirmButton, MutationFeedback } from "./ResourceView";
import { useAsyncResource, useMutation } from "./useResource";

// Parse a textarea as a JSON object (not an array, not a scalar). Returns the
// object on success or null on any parse or shape fault; the caller shows a client
// side field error, never a network error channel.
function parseJsonObject(text: string): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(text);
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      return null;
    }
    return value as Record<string, unknown>;
  } catch {
    return null;
  }
}

// The connectors list, scoped to the active {tenant, environment}. When no scope
// is selected there is nothing to list, so the surface prompts rather than
// fetching an empty path: ZERO calls.
export function ConnectorsList() {
  const scope = activeScope.value;
  if (scope === null) {
    return (
      <section class="resource" aria-labelledby="connectors-heading">
        <h2 id="connectors-heading">Connectors</h2>
        <p class="resource-empty">
          Select a tenant and environment to view its connectors.
        </p>
      </section>
    );
  }
  return (
    <ConnectorsForScope
      tenantId={scope.tenantId}
      environmentId={scope.environmentId}
    />
  );
}

function ConnectorsForScope({
  tenantId,
  environmentId,
}: {
  tenantId: string;
  environmentId: string;
}) {
  const { state, reload } = useAsyncResource<ConnectorView[]>(
    () => fetchConnectors(tenantId, environmentId),
    [tenantId, environmentId],
  );
  return (
    <section class="resource" aria-labelledby="connectors-heading">
      <h2 id="connectors-heading">Connectors</h2>
      <ConnectorCreateForm
        tenantId={tenantId}
        environmentId={environmentId}
        onCreated={reload}
      />
      <AsyncBoundary
        state={state}
        loadingLabel="Loading connectors"
        empty={{
          when: (items) => items.length === 0,
          render: () => (
            <p class="resource-empty">
              No connectors yet. Create the first one above.
            </p>
          ),
        }}
      >
        {(items) => (
          <ul class="resource-list">
            {items.map((connector) => (
              <li key={connector.id} class="resource-row">
                <a
                  class="resource-link"
                  href={`/connectors/${connector.id}`}
                >
                  {connector.connector_slug}
                </a>
                <code class="resource-id">{connector.id}</code>
                <span class="resource-status">
                  {connector.enabled ? "enabled" : "disabled"}
                </span>
              </li>
            ))}
          </ul>
        )}
      </AsyncBoundary>
    </section>
  );
}

function ConnectorCreateForm({
  tenantId,
  environmentId,
  onCreated,
}: {
  tenantId: string;
  environmentId: string;
  onCreated: () => void;
}) {
  const mutation = useMutation();
  const [definition, setDefinition] = useState("");
  const [invalid, setInvalid] = useState(false);

  function onSubmit(event: Event): void {
    event.preventDefault();
    const parsed = parseJsonObject(definition);
    if (parsed === null) {
      setInvalid(true);
      return;
    }
    setInvalid(false);
    // The contract's CreateConnectorRequest is the declarative definition
    // document; the parsed object is that document, cast to the generated field
    // type so the call stays typed against the contract rather than reaching for
    // `any`. The server's strict validator words any fault as a verbatim error.
    const request = parsed as unknown as CreateConnectorRequest;
    void mutation
      .run(async () => {
        await createConnector(tenantId, environmentId, request);
      }, "Connector created.")
      .then((ok) => {
        if (ok) {
          setDefinition("");
          onCreated();
        }
      });
  }

  return (
    <form
      class="resource-form"
      onSubmit={onSubmit}
      aria-label="Create a connector"
    >
      <div class="resource-field">
        <label for="connector-definition">Connector definition (JSON)</label>
        <textarea
          id="connector-definition"
          rows={8}
          value={definition}
          onInput={(event) =>
            setDefinition((event.target as HTMLTextAreaElement).value)
          }
        />
        {invalid ? (
          <p class="resource-field-error" role="alert">
            Enter a valid JSON object for the connector definition.
          </p>
        ) : null}
      </div>
      <button
        type="submit"
        class="resource-btn resource-btn-primary"
        disabled={mutation.state.pending || definition.trim() === ""}
      >
        Create connector
      </button>
      <MutationFeedback state={mutation.state} />
    </form>
  );
}

// One connector: its fields and embedded capability matrix, the live diagnostics
// reads (health and capabilities, each its own documented endpoint), the
// full-replace PUT update, and the delete. The tenant and environment come from
// the active scope; a delete returns to the list. A max_age failure on any write
// drives the RFC 9470 sudo recovery, elevating within the active scope and
// replaying the write.
export function ConnectorDetail({ connectorId }: { connectorId?: string }) {
  const scope = activeScope.value;
  if (scope === null) {
    return (
      <section class="resource" aria-labelledby="connector-detail-heading">
        <h2 id="connector-detail-heading">Connector</h2>
        <p class="resource-empty">
          Select a tenant and environment to view this connector.
        </p>
      </section>
    );
  }
  return (
    <ConnectorDetailFor
      tenantId={scope.tenantId}
      environmentId={scope.environmentId}
      connectorId={connectorId ?? ""}
    />
  );
}

function ConnectorDetailFor({
  tenantId,
  environmentId,
  connectorId,
}: {
  tenantId: string;
  environmentId: string;
  connectorId: string;
}) {
  const location = useLocation();
  const { state, reload } = useAsyncResource<ConnectorView>(
    () => getConnector(tenantId, environmentId, connectorId),
    [tenantId, environmentId, connectorId],
  );
  const mutation = useMutation();
  const scope = activeScope.value;
  const sudo: SudoRecovery | undefined =
    scope === null ? undefined : { scope, retry: mutation.retry };

  function onDelete(): void {
    void mutation.run(async () => {
      await deleteConnector(tenantId, environmentId, connectorId);
      if (typeof location.route === "function") {
        location.route("/connectors");
      }
    }, "Connector deleted.");
  }

  return (
    <section class="resource" aria-labelledby="connector-detail-heading">
      <p>
        <a class="resource-back" href="/connectors">
          Back to connectors
        </a>
      </p>
      <AsyncBoundary state={state} loadingLabel="Loading connector">
        {(connector) => (
          <div>
            <h2 id="connector-detail-heading">{connector.connector_slug}</h2>
            <dl class="resource-detail">
              <dt>Identifier</dt>
              <dd>
                <code>{connector.id}</code>
              </dd>
              <dt>Slug</dt>
              <dd>{connector.connector_slug}</dd>
              <dt>Enabled</dt>
              <dd>{connector.enabled ? "yes" : "no"}</dd>
              <dt>Created</dt>
              <dd>{new Date(connector.created_at_unix_ms).toISOString()}</dd>
              <dt>Updated</dt>
              <dd>{new Date(connector.updated_at_unix_ms).toISOString()}</dd>
            </dl>

            <CapabilityMatrix capabilities={connector.capabilities} />

            <ConnectorCapabilitiesPanel
              tenantId={tenantId}
              environmentId={environmentId}
              connectorId={connectorId}
            />

            <ConnectorHealthPanel
              tenantId={tenantId}
              environmentId={environmentId}
              connectorId={connectorId}
            />

            <ConnectorUpdateForm
              tenantId={tenantId}
              environmentId={environmentId}
              connectorId={connectorId}
              mutation={mutation}
              onUpdated={reload}
            />

            <div
              class="resource-actions"
              role="group"
              aria-label="Connector actions"
            >
              <ConfirmButton
                label="Delete"
                prompt="Delete this connector? This removes the federation upstream."
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

// The capability matrix embedded in a connector view (or read live from the
// dedicated endpoint): a plain yes or no per capability, plus the email_verified
// trust level, so the conservative defaults are visible at a glance.
function CapabilityMatrix({
  capabilities,
}: {
  capabilities: ConnectorCapabilitiesView;
}) {
  return (
    <div class="resource-subsection">
      <h3>Capabilities</h3>
      <dl class="resource-detail">
        <dt>Refresh tokens</dt>
        <dd>{capabilities.refresh ? "yes" : "no"}</dd>
        <dt>Groups</dt>
        <dd>{capabilities.groups ? "yes" : "no"}</dd>
        <dt>Logout propagation</dt>
        <dd>{capabilities.logout_propagation ? "yes" : "no"}</dd>
        <dt>Email verified trust</dt>
        <dd>{capabilities.email_verified_trust}</dd>
      </dl>
    </div>
  );
}

// The live capability matrix from the dedicated endpoint (operationId
// getConnectorCapabilities): the authoritative derived matrix, re-read on its own
// so a diagnostics view never depends on a stale embedded copy.
function ConnectorCapabilitiesPanel({
  tenantId,
  environmentId,
  connectorId,
}: {
  tenantId: string;
  environmentId: string;
  connectorId: string;
}) {
  const { state } = useAsyncResource<ConnectorCapabilitiesView>(
    () => getConnectorCapabilities(tenantId, environmentId, connectorId),
    [tenantId, environmentId, connectorId],
  );
  return (
    <div class="resource-subsection">
      <h3>Capabilities (live)</h3>
      <AsyncBoundary state={state} loadingLabel="Loading capabilities">
        {(capabilities) => (
          <dl class="resource-detail">
            <dt>Refresh tokens</dt>
            <dd>{capabilities.refresh ? "yes" : "no"}</dd>
            <dt>Groups</dt>
            <dd>{capabilities.groups ? "yes" : "no"}</dd>
            <dt>Logout propagation</dt>
            <dd>{capabilities.logout_propagation ? "yes" : "no"}</dd>
            <dt>Email verified trust</dt>
            <dd>{capabilities.email_verified_trust}</dd>
          </dl>
        )}
      </AsyncBoundary>
    </div>
  );
}

// The live per-connector health from the dedicated endpoint (operationId
// getConnectorHealth): THIS node's in-memory federation health for diagnostics. A
// connector never exercised on this node reports state "unknown" with no
// timestamps, so every timestamp is rendered defensively.
function ConnectorHealthPanel({
  tenantId,
  environmentId,
  connectorId,
}: {
  tenantId: string;
  environmentId: string;
  connectorId: string;
}) {
  const { state } = useAsyncResource<ConnectorHealthView>(
    () => getConnectorHealth(tenantId, environmentId, connectorId),
    [tenantId, environmentId, connectorId],
  );
  function instant(value: number | null | undefined): string {
    return value === null || value === undefined
      ? "none"
      : new Date(value).toISOString();
  }
  return (
    <div class="resource-subsection">
      <h3>Health</h3>
      <AsyncBoundary state={state} loadingLabel="Loading health">
        {(health) => (
          <dl class="resource-detail">
            <dt>State</dt>
            <dd>
              <span class={`resource-status resource-status-${health.state}`}>
                {health.state}
              </span>
            </dd>
            <dt>Consecutive failures</dt>
            <dd>{health.consecutive_failures}</dd>
            <dt>Recent error rate</dt>
            <dd>{health.recent_error_rate}</dd>
            <dt>Successes</dt>
            <dd>{health.success_total}</dd>
            <dt>Errors</dt>
            <dd>{health.error_total}</dd>
            <dt>Last error kind</dt>
            <dd>{health.last_error_kind ?? "none"}</dd>
            <dt>Last success</dt>
            <dd>{instant(health.last_success_at_unix_ms)}</dd>
            <dt>Last failure</dt>
            <dd>{instant(health.last_failure_at_unix_ms)}</dd>
            <dt>Next retry</dt>
            <dd>{instant(health.next_retry_at_unix_ms)}</dd>
          </dl>
        )}
      </AsyncBoundary>
    </div>
  );
}

// The full-replace PUT update (operationId updateConnector). The contract reuses
// CreateConnectorRequest as the update body, so this REPLACES the whole
// definition, not a merge: an omitted field takes its documented default. Because
// the read views are SECRET-FREE, the operator re-authors the full definition
// (including the client_secret by indirection) here, so the textarea starts empty
// and is clearly labelled a full replacement.
function ConnectorUpdateForm({
  tenantId,
  environmentId,
  connectorId,
  mutation,
  onUpdated,
}: {
  tenantId: string;
  environmentId: string;
  connectorId: string;
  mutation: ReturnType<typeof useMutation>;
  onUpdated: () => void;
}) {
  const [definition, setDefinition] = useState("");
  const [invalid, setInvalid] = useState(false);

  function onSubmit(event: Event): void {
    event.preventDefault();
    const parsed = parseJsonObject(definition);
    if (parsed === null) {
      setInvalid(true);
      return;
    }
    setInvalid(false);
    const request = parsed as unknown as CreateConnectorRequest;
    void mutation
      .run(async () => {
        await updateConnector(tenantId, environmentId, connectorId, request);
      }, "Connector replaced.")
      .then((ok) => {
        if (ok) {
          setDefinition("");
          onUpdated();
        }
      });
  }

  return (
    <div class="resource-subsection">
      <h3>Replace definition</h3>
      <form
        class="resource-form"
        onSubmit={onSubmit}
        aria-label="Replace connector definition"
      >
        <div class="resource-field">
          <label for="connector-update-definition">
            Full connector definition (JSON, replaces the whole connector)
          </label>
          <textarea
            id="connector-update-definition"
            rows={8}
            value={definition}
            onInput={(event) =>
              setDefinition((event.target as HTMLTextAreaElement).value)
            }
          />
          {invalid ? (
            <p class="resource-field-error" role="alert">
              Enter a valid JSON object for the connector definition.
            </p>
          ) : null}
        </div>
        <button
          type="submit"
          class="resource-btn"
          disabled={mutation.state.pending || definition.trim() === ""}
        >
          Replace connector
        </button>
      </form>
    </div>
  );
}
