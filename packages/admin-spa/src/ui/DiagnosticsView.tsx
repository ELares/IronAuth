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
  type ClientAuthDiagnosticsFilter,
  type ClientAuthDiagnosticsPage,
  type PolicyTracesFilter,
  type PolicyTracesPage,
  type WarningItemView,
  fetchClientAuthDiagnostics,
  fetchDiagnosticsWarnings,
  fetchPolicyTraces,
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
      <PolicyTracesPanel
        tenantId={scope.tenantId}
        environmentId={scope.environmentId}
      />
      <WarningsPanel
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
  const { state } = useAsyncResource<ClientAuthDiagnosticsPage>(
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
          when: (page) => page.items.length === 0,
          render: () => (
            <p class="resource-empty">
              No recorded client authentication failures for this filter.
            </p>
          ),
        }}
      >
        {(page) => (
          <ul class="resource-list">
            {page.truncated ? (
              <li class="resource-note">
                Showing the most recent failures only. Older matching failures were
                left out; narrow the client or time window to see more.
              </li>
            ) : null}
            {page.items.map((record, index) => (
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

// The policy decision traces panel: the step up, risk, and claim mapping decisions recorded
// off the request path, filterable by policy, newest first. Each field is bounded and non
// secret; decision_inputs is the redacted safe field projection (a JSON string), rendered as
// escaped text in a code block, never HTML. No dangerouslySetInnerHTML.
function PolicyTracesPanel({
  tenantId,
  environmentId,
}: {
  tenantId: string;
  environmentId: string;
}) {
  const [applied, setApplied] = useState<PolicyTracesFilter>({});
  const { state } = useAsyncResource<PolicyTracesPage>(
    () => fetchPolicyTraces(tenantId, environmentId, applied),
    [tenantId, environmentId, JSON.stringify(applied)],
  );
  return (
    <div class="resource-subsection">
      <h3>Policy decision traces</h3>
      <p class="resource-hint">
        Why a step up, risk, or claim mapping decision came out the way it did, recorded off
        the request path. Only bounded, non secret fields are kept.
      </p>
      <PolicyTraceFilterForm onApply={setApplied} />
      <AsyncBoundary
        state={state}
        loadingLabel="Loading policy traces"
        empty={{
          when: (page) => page.items.length === 0,
          render: () => (
            <p class="resource-empty">
              No recorded policy decision traces for this filter.
            </p>
          ),
        }}
      >
        {(page) => (
          <ul class="resource-list">
            {page.truncated ? (
              <li class="resource-note">
                Showing the most recent traces only. Older matching traces were left out;
                narrow the policy or time window to see more.
              </li>
            ) : null}
            {page.items.map((record, index) => (
              // The traces have no id field (append-only), so the key is the stable
              // (instant, index) position within this page.
              <li
                key={`${record.occurred_at_unix_micros}-${index}`}
                class="resource-row"
              >
                <dl class="resource-detail">
                  <dt>Policy</dt>
                  <dd>
                    <code class="resource-id">{record.policy}</code>
                  </dd>
                  <dt>Outcome</dt>
                  <dd>
                    <code class="resource-status">{record.outcome}</code>
                  </dd>
                  <dt>Subject</dt>
                  <dd>
                    <code>{record.subject ?? "none"}</code>
                  </dd>
                  <dt>Reason</dt>
                  <dd>{record.reason ?? "none"}</dd>
                  <dt>Inputs</dt>
                  <dd>
                    <code class="resource-id">{record.decision_inputs}</code>
                  </dd>
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

// The policy filter: a single select over the closed policy set, applied on change. The
// server bounds the window and the row count, so an empty filter is a safe whole-scope read.
function PolicyTraceFilterForm({
  onApply,
}: {
  onApply: (filter: PolicyTracesFilter) => void;
}) {
  const [policy, setPolicy] = useState("");

  function onChange(event: Event): void {
    const value = (event.target as HTMLSelectElement).value;
    setPolicy(value);
    onApply(value === "" ? {} : { policy: value });
  }

  return (
    <form class="resource-form" aria-label="Filter policy decision traces">
      <div class="resource-field">
        <label for="diagnostics-policy">Policy</label>
        <select id="diagnostics-policy" value={policy} onChange={onChange}>
          <option value="">All</option>
          <option value="step_up">Step up</option>
          <option value="risk">Risk</option>
          <option value="claim_mapping">Claim mapping</option>
        </select>
      </div>
    </form>
  );
}

// The operational warnings panel: the connector health and token size (claim bloat)
// warnings, COMPUTED LIVE by the server, grouped by kind. Every field is bounded and non
// secret, rendered as escaped text. No dangerouslySetInnerHTML.
function WarningsPanel({
  tenantId,
  environmentId,
}: {
  tenantId: string;
  environmentId: string;
}) {
  const { state } = useAsyncResource<WarningItemView[]>(
    () => fetchDiagnosticsWarnings(tenantId, environmentId),
    [tenantId, environmentId],
  );
  return (
    <div class="resource-subsection">
      <h3>Operational warnings</h3>
      <p class="resource-hint">
        Live warnings computed from the connector health and the recent token sizes. Nothing
        here is stored to go stale (except the bounded token size events).
      </p>
      <AsyncBoundary
        state={state}
        loadingLabel="Loading warnings"
        empty={{
          when: (items) => items.length === 0,
          render: () => (
            <p class="resource-empty">No operational warnings for this environment.</p>
          ),
        }}
      >
        {(items) => <WarningGroups items={items} />}
      </AsyncBoundary>
    </div>
  );
}

// Group the flat warning list by kind, so warnings of the same kind read together. The kind
// is a bounded server value; it is rendered as escaped text.
function WarningGroups({ items }: { items: WarningItemView[] }) {
  const byKind = new Map<string, WarningItemView[]>();
  for (const item of items) {
    const group = byKind.get(item.kind) ?? [];
    group.push(item);
    byKind.set(item.kind, group);
  }
  return (
    <ul class="resource-list">
      {[...byKind.entries()].map(([kind, group]) => (
        <li key={kind} class="resource-row">
          <h4>
            <code class="resource-status">{kind}</code>
          </h4>
          <ul class="resource-list">
            {group.map((item, index) => (
              <li key={`${item.subject}-${index}`}>
                <code class="resource-id">{item.subject}</code>: {item.detail}
              </li>
            ))}
          </ul>
        </li>
      ))}
    </ul>
  );
}
