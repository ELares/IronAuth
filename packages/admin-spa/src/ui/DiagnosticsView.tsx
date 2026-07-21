// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The diagnostics surface (issue #91, M9 flow inspector), SCOPED to the active
// {tenant, environment} from the switcher. PR7 wired the nav and route seam behind
// an inert placeholder; this fills in the client-authentication panel: a filterable
// list of the rich, structured records of WHY a client authentication failed, which
// the token endpoint deliberately keeps OFF the wire (every such failure returns the
// uniform, opaque invalid_client). The panel shows the SPECIFIC reason, the assertion
// key id and algorithm, the derived clock skew, and when the failure happened, so an
// operator can debug a broken client integration the wire response cannot reveal.
//
// Diagnostics live UNDER an environment, so this surface reads BOTH the active tenant
// and environment from the scope store and injects them into every call, exactly as
// the connectors and users surfaces do. When no {tenant, environment} is in scope it
// shows a prompt and makes ZERO calls. It reads ONLY through the named wrapper in
// src/api/client.ts (the single funnel), stands on the same reusable resource hooks
// and views the other surfaces use, and renders every failure through the verbatim
// ErrorView boundary.
//
// Every rendered field is attacker INFLUENCED but non secret (the client id and the
// assertion kid are values the failed attempt itself presented): they are rendered as
// TEXT children, which Preact escapes by construction, so a hostile-looking kid or
// client id renders INERT (never HTML). This view uses NO dangerouslySetInnerHTML.

import { useState } from "preact/hooks";
import {
  type ClientAuthDiagnosticView,
  type ClientAuthDiagnosticsFilter,
  fetchClientAuthDiagnostics,
} from "../api/client";
import { activeScope } from "../scope/store";
import { AsyncBoundary } from "./ResourceView";
import { useAsyncResource } from "./useResource";

// Render an epoch-microseconds instant as an ISO string, defensively (a value the
// server never omits, but rendered through a guard so a malformed number is inert
// text rather than an "Invalid Date").
function instant(unixMicros: number): string {
  const date = new Date(unixMicros / 1000);
  return Number.isNaN(date.getTime()) ? String(unixMicros) : date.toISOString();
}

// The diagnostics surface. When no scope is selected there is nothing to read, so it
// prompts rather than fetching an empty path: ZERO calls.
export function DiagnosticsView() {
  const scope = activeScope.value;
  if (scope === null) {
    return (
      <section class="resource" aria-labelledby="diagnostics-heading">
        <h2 id="diagnostics-heading">Diagnostics</h2>
        <p class="resource-empty">
          Select a tenant and environment to view its diagnostics.
        </p>
      </section>
    );
  }
  return (
    <section class="resource" aria-labelledby="diagnostics-heading">
      <h2 id="diagnostics-heading">Diagnostics</h2>
      <ClientAuthDiagnosticsPanel
        tenantId={scope.tenantId}
        environmentId={scope.environmentId}
      />
    </section>
  );
}

// The client-authentication failure panel: a client-id filter over the scope's
// recorded failures, each rendered with its specific reason, kid, algorithm, skew,
// and instant. The wire response for each of these failures stayed the opaque
// invalid_client; this is the out-of-band detail.
function ClientAuthDiagnosticsPanel({
  tenantId,
  environmentId,
}: {
  tenantId: string;
  environmentId: string;
}) {
  // The APPLIED filter drives the read; the form edits a draft and applies it on
  // submit, so a keystroke does not refetch. The applied filter is part of the read's
  // dependency key, so applying a new one refetches.
  const [applied, setApplied] = useState<ClientAuthDiagnosticsFilter>({});
  const { state } = useAsyncResource<ClientAuthDiagnosticView[]>(
    () => fetchClientAuthDiagnostics(tenantId, environmentId, applied),
    [tenantId, environmentId, JSON.stringify(applied)],
  );
  return (
    <div class="resource-subsection">
      <h3>Client authentication failures</h3>
      <p class="resource-hint">
        The specific reason a client authentication failed, kept off the wire. The
        token endpoint returns a uniform invalid_client for every one of these.
      </p>
      <ClientAuthFilterForm onApply={setApplied} />
      <AsyncBoundary
        state={state}
        loadingLabel="Loading diagnostics"
        empty={{
          when: (items) => items.length === 0,
          render: () => (
            <p class="resource-empty">
              No recorded client authentication failures for this filter.
            </p>
          ),
        }}
      >
        {(items) => (
          <ul class="resource-list">
            {items.map((record, index) => (
              // The records have no id field (append-only diagnostics), so the key is
              // the stable (instant, index) position within this page.
              <li
                key={`${record.occurred_at_unix_micros}-${index}`}
                class="resource-row"
              >
                <dl class="resource-detail">
                  <dt>Client</dt>
                  <dd>
                    <code class="resource-id">{record.client_id}</code>
                  </dd>
                  <dt>Reason</dt>
                  <dd>
                    <code class="resource-status">{record.reason}</code>
                  </dd>
                  <dt>Method</dt>
                  <dd>{record.auth_method}</dd>
                  <dt>Key id (kid)</dt>
                  <dd>
                    <code>{record.key_id ?? "none"}</code>
                  </dd>
                  <dt>Algorithm</dt>
                  <dd>{record.signing_alg ?? "none"}</dd>
                  <dt>Clock skew (seconds)</dt>
                  <dd>
                    {record.skew_seconds === undefined ||
                    record.skew_seconds === null
                      ? "none"
                      : String(record.skew_seconds)}
                  </dd>
                  <dt>Expectation</dt>
                  <dd>{record.expected ?? "none"}</dd>
                  <dt>Occurred</dt>
                  <dd>{instant(record.occurred_at_unix_micros)}</dd>
                </dl>
              </li>
            ))}
          </ul>
        )}
      </AsyncBoundary>
    </div>
  );
}

// The filter form: a single client-id text field, applied on submit. Kept minimal (a
// client id is the debugging entry point); the server bounds the window and the row
// count, so an empty filter is a safe whole-scope read.
function ClientAuthFilterForm({
  onApply,
}: {
  onApply: (filter: ClientAuthDiagnosticsFilter) => void;
}) {
  const [clientId, setClientId] = useState("");

  function onSubmit(event: Event): void {
    event.preventDefault();
    const trimmed = clientId.trim();
    onApply(trimmed === "" ? {} : { clientId: trimmed });
  }

  return (
    <form
      class="resource-form"
      onSubmit={onSubmit}
      aria-label="Filter client authentication diagnostics"
    >
      <div class="resource-field">
        <label for="diagnostics-client-id">Client id</label>
        <input
          id="diagnostics-client-id"
          type="text"
          value={clientId}
          onInput={(event) =>
            setClientId((event.target as HTMLInputElement).value)
          }
        />
      </div>
      <button type="submit" class="resource-btn">
        Apply filter
      </button>
    </form>
  );
}
