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
  type FlowDryRunRequest,
  type FlowDryRunResponse,
  type FlowObserveResponse,
  type PolicyTracesFilter,
  type PolicyTracesPage,
  type WarningItemView,
  fetchClientAuthDiagnostics,
  fetchDiagnosticsWarnings,
  fetchFlowDryRun,
  fetchFlowObservation,
  fetchPolicyTraces,
} from "../api/client";
import { activeScope } from "../scope/store";
import { AsyncBoundary, MutationFeedback } from "./ResourceView";
import { useAsyncResource, useMutation } from "./useResource";

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
      <FlowInspectorPanel
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

// The flow inspector panel (issue #91, PR4): the read only step through UI. It has two
// modes, and NEITHER mutates a flow. OBSERVE loads an existing flow by id and renders its
// current position, the journey plan, the redacted context, the current node render, and the
// recorded policy traces. DRY REPLAY submits a supplied context and renders the per step
// evaluations of the real step up and risk evaluators, computed SIDE EFFECT FREE by the
// server (it writes no row). Every value is a bounded server projection rendered as escaped
// text children (Preact escapes by construction); this panel uses NO dangerouslySetInnerHTML,
// and every call goes through the named typed client wrappers.
function FlowInspectorPanel({
  tenantId,
  environmentId,
}: {
  tenantId: string;
  environmentId: string;
}) {
  return (
    <div class="resource-subsection">
      <h3>Flow inspector</h3>
      <p class="resource-hint">
        Observe an existing flow read only, or dry run a supplied context through a journey
        plan. Neither mutates a flow: observe never drives the engine, and a dry run writes no
        row (it evaluates the real step up and risk policies with every write disabled).
      </p>
      <FlowObserveForm tenantId={tenantId} environmentId={environmentId} />
      <FlowDryRunForm tenantId={tenantId} environmentId={environmentId} />
    </div>
  );
}

// The OBSERVE form: a flow id, applied on submit. The read only projection is fetched through
// the typed client and rendered escaped.
function FlowObserveForm({
  tenantId,
  environmentId,
}: {
  tenantId: string;
  environmentId: string;
}) {
  const [flowId, setFlowId] = useState("");
  const [observed, setObserved] = useState<FlowObserveResponse | null>(null);
  const mutation = useMutation();

  function onSubmit(event: Event): void {
    event.preventDefault();
    const trimmed = flowId.trim();
    if (trimmed === "") {
      return;
    }
    void mutation.run(async () => {
      const result = await fetchFlowObservation(tenantId, environmentId, trimmed);
      setObserved(result);
    }, "Loaded the flow.");
  }

  return (
    <div class="resource-row">
      <h4>Observe a flow</h4>
      <form class="resource-form" onSubmit={onSubmit} aria-label="Observe a flow by id">
        <div class="resource-field">
          <label for="inspector-flow-id">Flow id</label>
          <input
            id="inspector-flow-id"
            type="text"
            value={flowId}
            onInput={(event) =>
              setFlowId((event.target as HTMLInputElement).value)
            }
          />
        </div>
        <button type="submit" class="resource-btn">
          Observe
        </button>
      </form>
      <MutationFeedback state={mutation.state} />
      {observed !== null && mutation.state.error === null ? (
        <FlowObservation observation={observed} />
      ) : null}
    </div>
  );
}

// Render a read only flow observation: the current position, the plan, the redacted context,
// the current node render, and the recorded policy traces.
function FlowObservation({ observation }: { observation: FlowObserveResponse }) {
  return (
    <dl class="resource-detail">
      <dt>Flow</dt>
      <dd>
        <code class="resource-id">{observation.flow_id}</code>
      </dd>
      <dt>Journey</dt>
      <dd>
        <code class="resource-status">{observation.journey}</code> (
        {observation.transport})
      </dd>
      <dt>Current state</dt>
      <dd>
        <code class="resource-status">{observation.current}</code>
        {observation.completed ? " (completed)" : ""}
        {observation.expired ? " (expired)" : ""}
      </dd>
      <dt>Plan</dt>
      <dd>
        <PlanSteps plan={observation.plan} current={observation.current} />
      </dd>
      <dt>Context</dt>
      <dd>
        <ContextView context={observation.context} />
      </dd>
      <dt>Current node render</dt>
      <dd>
        {observation.nodes.length === 0 ? (
          "none"
        ) : (
          <ul class="resource-list">
            {observation.nodes.map((node, index) => (
              <li key={`${node.group}-${index}`}>
                <code>{node.group}</code>: {node.kind}
                {node.name !== undefined && node.name !== null
                  ? ` (${node.name})`
                  : ""}
              </li>
            ))}
          </ul>
        )}
      </dd>
      <dt>Recorded policy traces</dt>
      <dd>
        {observation.traces.length === 0 ? (
          "none recorded for this subject"
        ) : (
          <ul class="resource-list">
            {observation.traces.map((trace, index) => (
              <li key={`${trace.occurred_at_unix_micros}-${index}`}>
                <code class="resource-id">{trace.policy}</code>:{" "}
                <code class="resource-status">{trace.outcome}</code>
                {trace.reason !== undefined && trace.reason !== null
                  ? ` (${trace.reason})`
                  : ""}{" "}
                at {instant(trace.occurred_at_unix_micros)}
              </li>
            ))}
          </ul>
        )}
      </dd>
    </dl>
  );
}

// Render the ordered plan, marking the current state.
function PlanSteps({ plan, current }: { plan: string[]; current?: string }) {
  return (
    <ol class="resource-list">
      {plan.map((step, index) => (
        <li key={`${step}-${index}`}>
          <code class={step === current ? "resource-status" : "resource-id"}>
            {step}
          </code>
          {step === current ? " (current)" : ""}
        </li>
      ))}
    </ol>
  );
}

// Render a redacted flow context (never a secret: only the step, method tokens, the blind
// subject handle, and two booleans).
function ContextView({
  context,
}: {
  context: FlowObserveResponse["context"];
}) {
  return (
    <dl class="resource-detail">
      <dt>Step</dt>
      <dd>
        <code class="resource-status">{context.step}</code>
      </dd>
      <dt>Methods</dt>
      <dd>{context.methods.length === 0 ? "none" : context.methods.join(", ")}</dd>
      <dt>Subject</dt>
      <dd>
        <code>{context.subject ?? "none"}</code>
      </dd>
      <dt>Has identifier</dt>
      <dd>{context.has_identifier ? "yes" : "no"}</dd>
      <dt>Enrolling</dt>
      <dd>{context.enrolling ? "yes" : "no"}</dd>
      <dt>Connector</dt>
      <dd>{context.connector ?? "none"}</dd>
    </dl>
  );
}

// The dry run form's editable draft. Every field is optional except the journey and the
// achieved acr; the server defaults the rest to the deployment posture.
interface DryRunDraft {
  journey: string;
  achievedAcr: string;
  requiredAcr: string;
  maxAuthAgeSecs: string;
  riskEnabled: boolean;
  requireMfaAt: string;
  newDevice: boolean;
  signalName: string;
  signalLevel: string;
  signalHardDeny: boolean;
}

const EMPTY_DRAFT: DryRunDraft = {
  journey: "login",
  achievedAcr: "pwd",
  requiredAcr: "",
  maxAuthAgeSecs: "",
  riskEnabled: false,
  requireMfaAt: "off",
  newDevice: false,
  signalName: "",
  signalLevel: "med",
  signalHardDeny: false,
};

// Build the typed dry run request from the draft, omitting the fields the operator left blank.
function draftToRequest(draft: DryRunDraft): FlowDryRunRequest {
  const request: FlowDryRunRequest = {
    journey: draft.journey,
    achieved_acr: draft.achievedAcr.trim(),
  };
  if (draft.requiredAcr.trim() !== "") {
    request.required_acr = draft.requiredAcr.trim();
  }
  const maxAge = Number.parseInt(draft.maxAuthAgeSecs, 10);
  if (draft.maxAuthAgeSecs.trim() !== "" && !Number.isNaN(maxAge)) {
    request.max_auth_age_secs = maxAge;
  }
  if (draft.riskEnabled) {
    const signals =
      draft.signalName.trim() === ""
        ? []
        : [
            {
              name: draft.signalName.trim(),
              level: draft.signalLevel,
              hard_deny: draft.signalHardDeny,
            },
          ];
    request.risk = {
      new_device: draft.newDevice,
      require_mfa_at: draft.requireMfaAt,
      signals,
    };
  }
  return request;
}

// The DRY REPLAY form: a supplied context submitted through the typed client. The result is
// the per step evaluation of the real step up and risk evaluators, computed side effect free.
function FlowDryRunForm({
  tenantId,
  environmentId,
}: {
  tenantId: string;
  environmentId: string;
}) {
  const [draft, setDraft] = useState<DryRunDraft>(EMPTY_DRAFT);
  const [result, setResult] = useState<FlowDryRunResponse | null>(null);
  const mutation = useMutation();

  function set<K extends keyof DryRunDraft>(key: K, value: DryRunDraft[K]): void {
    setDraft((current) => ({ ...current, [key]: value }));
  }

  function onSubmit(event: Event): void {
    event.preventDefault();
    if (draft.achievedAcr.trim() === "") {
      return;
    }
    const request = draftToRequest(draft);
    void mutation.run(async () => {
      const response = await fetchFlowDryRun(tenantId, environmentId, request);
      setResult(response);
    }, "Dry run complete (no row was written).");
  }

  return (
    <div class="resource-row">
      <h4>Dry run a context</h4>
      <form class="resource-form" onSubmit={onSubmit} aria-label="Dry run a flow context">
        <div class="resource-field">
          <label for="dryrun-journey">Journey</label>
          <select
            id="dryrun-journey"
            value={draft.journey}
            onChange={(event) =>
              set("journey", (event.target as HTMLSelectElement).value)
            }
          >
            <option value="login">Login</option>
            <option value="registration">Registration</option>
            <option value="recovery">Recovery</option>
            <option value="federation">Federation</option>
          </select>
        </div>
        <div class="resource-field">
          <label for="dryrun-achieved">Achieved acr</label>
          <input
            id="dryrun-achieved"
            type="text"
            value={draft.achievedAcr}
            onInput={(event) =>
              set("achievedAcr", (event.target as HTMLInputElement).value)
            }
          />
        </div>
        <div class="resource-field">
          <label for="dryrun-required">Required acr floor</label>
          <input
            id="dryrun-required"
            type="text"
            value={draft.requiredAcr}
            onInput={(event) =>
              set("requiredAcr", (event.target as HTMLInputElement).value)
            }
          />
        </div>
        <div class="resource-field">
          <label for="dryrun-maxage">Max auth age (seconds)</label>
          <input
            id="dryrun-maxage"
            type="number"
            value={draft.maxAuthAgeSecs}
            onInput={(event) =>
              set("maxAuthAgeSecs", (event.target as HTMLInputElement).value)
            }
          />
        </div>
        <div class="resource-field">
          <label>
            <input
              type="checkbox"
              checked={draft.riskEnabled}
              onChange={(event) =>
                set("riskEnabled", (event.target as HTMLInputElement).checked)
              }
            />{" "}
            Evaluate a risk scenario
          </label>
        </div>
        {draft.riskEnabled ? (
          <fieldset class="resource-field">
            <legend>Risk scenario</legend>
            <div class="resource-field">
              <label for="dryrun-threshold">Require MFA at</label>
              <select
                id="dryrun-threshold"
                value={draft.requireMfaAt}
                onChange={(event) =>
                  set("requireMfaAt", (event.target as HTMLSelectElement).value)
                }
              >
                <option value="off">Off</option>
                <option value="low">Low</option>
                <option value="med">Med</option>
                <option value="high">High</option>
              </select>
            </div>
            <div class="resource-field">
              <label>
                <input
                  type="checkbox"
                  checked={draft.newDevice}
                  onChange={(event) =>
                    set("newDevice", (event.target as HTMLInputElement).checked)
                  }
                />{" "}
                New device fired
              </label>
            </div>
            <div class="resource-field">
              <label for="dryrun-signal-name">Signal name</label>
              <input
                id="dryrun-signal-name"
                type="text"
                value={draft.signalName}
                onInput={(event) =>
                  set("signalName", (event.target as HTMLInputElement).value)
                }
              />
            </div>
            <div class="resource-field">
              <label for="dryrun-signal-level">Signal level</label>
              <select
                id="dryrun-signal-level"
                value={draft.signalLevel}
                onChange={(event) =>
                  set("signalLevel", (event.target as HTMLSelectElement).value)
                }
              >
                <option value="low">Low</option>
                <option value="med">Med</option>
                <option value="high">High</option>
              </select>
            </div>
            <div class="resource-field">
              <label>
                <input
                  type="checkbox"
                  checked={draft.signalHardDeny}
                  onChange={(event) =>
                    set(
                      "signalHardDeny",
                      (event.target as HTMLInputElement).checked,
                    )
                  }
                />{" "}
                Hard deny
              </label>
            </div>
          </fieldset>
        ) : null}
        <button type="submit" class="resource-btn">
          Dry run
        </button>
      </form>
      <MutationFeedback state={mutation.state} />
      {result !== null && mutation.state.error === null ? (
        <DryRunResult result={result} />
      ) : null}
    </div>
  );
}

// Render the dry run result: the plan, the terminal state, and the per step evaluations.
function DryRunResult({ result }: { result: FlowDryRunResponse }) {
  return (
    <div>
      <dl class="resource-detail">
        <dt>Journey</dt>
        <dd>
          <code class="resource-status">{result.journey}</code>
        </dd>
        <dt>Terminal state</dt>
        <dd>
          <code class="resource-status">{result.terminal}</code>
        </dd>
        <dt>Plan</dt>
        <dd>
          <PlanSteps plan={result.plan} />
        </dd>
      </dl>
      <ul class="resource-list">
        {result.steps.map((step, index) => (
          <li key={`${step.step}-${index}`} class="resource-row">
            <dl class="resource-detail">
              <dt>Step</dt>
              <dd>
                <code class="resource-status">{step.step}</code>{" "}
                {step.reached ? "(reached)" : "(not reached)"}
              </dd>
              {step.policy !== undefined && step.policy !== null ? (
                <>
                  <dt>Policy</dt>
                  <dd>
                    <code class="resource-id">{step.policy}</code>
                  </dd>
                </>
              ) : null}
              {step.step_up !== undefined && step.step_up !== null ? (
                <>
                  <dt>Step up</dt>
                  <dd>
                    <code class="resource-status">{step.step_up.outcome}</code>
                    {step.step_up.acr_unmet ? " acr_unmet" : ""}
                    {step.step_up.age_lapsed ? " age_lapsed" : ""} (achieved{" "}
                    {step.step_up.achieved_acr})
                  </dd>
                </>
              ) : null}
              {step.risk !== undefined && step.risk !== null ? (
                <>
                  <dt>Risk</dt>
                  <dd>
                    <code class="resource-status">{step.risk.level}</code> /{" "}
                    <code class="resource-status">{step.risk.action}</code>
                    {step.risk.signals.length > 0
                      ? ` [${step.risk.signals
                          .map((signal) => `${signal.name}:${signal.level}`)
                          .join(", ")}]`
                      : ""}
                  </dd>
                </>
              ) : null}
              <dt>Context</dt>
              <dd>
                methods:{" "}
                {step.context.methods.length === 0
                  ? "none"
                  : step.context.methods.join(", ")}
              </dd>
            </dl>
          </li>
        ))}
      </ul>
    </div>
  );
}
