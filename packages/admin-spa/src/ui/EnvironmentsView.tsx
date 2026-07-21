// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The environments CRUD surface (issue #90, PR 4), SCOPED to the active tenant
// from the switcher: the list, the create form, the detail, and the delete for
// the environments of the tenant the scope store currently holds. Creating or
// deleting an environment refreshes the switcher's environment list through the
// store (selectTenant), so the single-environment collapse recomputes. It reads
// and writes ONLY through the named wrappers in src/api/client.ts, stands on the
// same reusable resource hooks and views the tenants surface uses, and renders
// every failure through the verbatim ErrorView boundary. There is NO environment
// update operation in the management contract, so this surface has none.

import { useLocation } from "preact-iso";
import { useState } from "preact/hooks";
import {
  type CreateEnvironmentRequest,
  type EnvironmentView,
  createEnvironment,
  deleteEnvironment,
  fetchEnvironments,
  getEnvironment,
} from "../api/client";
import { activeScope, selectTenant } from "../scope/store";
import type { SudoRecovery } from "./ErrorView";
import { AsyncBoundary, ConfirmButton, MutationFeedback } from "./ResourceView";
import { useAsyncResource, useMutation } from "./useResource";

const ENV_KINDS = ["dev", "staging", "prod"] as const;

function inputValue(event: Event): string {
  return (event.target as HTMLInputElement).value;
}

// The environments list, scoped to the active tenant. When no tenant is in scope
// (a principal with no tenants yet) there is nothing to list, so the surface says
// so rather than fetching an empty path.
export function EnvironmentsList() {
  const scope = activeScope.value;
  const tenantId = scope?.tenantId ?? null;
  if (tenantId === null) {
    return (
      <section class="resource" aria-labelledby="environments-heading">
        <h2 id="environments-heading">Environments</h2>
        <p class="resource-empty">Select a tenant to view its environments.</p>
      </section>
    );
  }
  return <EnvironmentsForTenant tenantId={tenantId} />;
}

function EnvironmentsForTenant({ tenantId }: { tenantId: string }) {
  const { state, reload } = useAsyncResource<EnvironmentView[]>(
    () => fetchEnvironments(tenantId),
    [tenantId],
  );
  function onChanged(): void {
    reload();
    // Refresh the switcher's environment list for the active tenant so the
    // single-environment collapse recomputes; keep the current selection when it
    // still exists, else the store falls back to the first environment.
    void selectTenant(tenantId, activeScope.value?.environmentId ?? null);
  }
  return (
    <section class="resource" aria-labelledby="environments-heading">
      <h2 id="environments-heading">Environments</h2>
      <EnvironmentCreateForm tenantId={tenantId} onCreated={onChanged} />
      <AsyncBoundary
        state={state}
        loadingLabel="Loading environments"
        empty={{
          when: (items) => items.length === 0,
          render: () => (
            <p class="resource-empty">
              No environments yet. Create the first one above.
            </p>
          ),
        }}
      >
        {(items) => (
          <ul class="resource-list">
            {items.map((env) => (
              <li key={env.id} class="resource-row">
                <a class="resource-link" href={`/environments/${env.id}`}>
                  {env.display_name}
                </a>
                <code class="resource-id">{env.id}</code>
                <span class="resource-kind">{env.kind}</span>
              </li>
            ))}
          </ul>
        )}
      </AsyncBoundary>
    </section>
  );
}

function EnvironmentCreateForm({
  tenantId,
  onCreated,
}: {
  tenantId: string;
  onCreated: () => void;
}) {
  const mutation = useMutation();
  const [displayName, setDisplayName] = useState("");
  const [kind, setKind] = useState<string>("dev");
  const [customDomain, setCustomDomain] = useState("");
  const [region, setRegion] = useState("");

  function onSubmit(event: Event): void {
    event.preventDefault();
    const request: CreateEnvironmentRequest = {
      display_name: displayName.trim(),
      kind,
    };
    if (customDomain.trim() !== "") {
      request.custom_domain = customDomain.trim();
    }
    if (region.trim() !== "") {
      request.region = region.trim();
    }
    void mutation
      .run(async () => {
        await createEnvironment(tenantId, request);
      }, "Environment created.")
      .then((ok) => {
        if (ok) {
          setDisplayName("");
          setKind("dev");
          setCustomDomain("");
          setRegion("");
          onCreated();
        }
      });
  }

  return (
    <form
      class="resource-form"
      onSubmit={onSubmit}
      aria-label="Create an environment"
    >
      <div class="resource-field">
        <label for="env-display-name">Display name</label>
        <input
          id="env-display-name"
          type="text"
          required
          value={displayName}
          onInput={(event) => setDisplayName(inputValue(event))}
        />
      </div>
      <div class="resource-field">
        <label for="env-kind">Kind</label>
        <select
          id="env-kind"
          value={kind}
          onChange={(event) => setKind((event.target as HTMLSelectElement).value)}
        >
          {ENV_KINDS.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
      </div>
      {kind === "prod" ? (
        <div class="resource-field">
          <label for="env-custom-domain">Custom domain</label>
          <input
            id="env-custom-domain"
            type="text"
            required
            value={customDomain}
            onInput={(event) => setCustomDomain(inputValue(event))}
          />
        </div>
      ) : null}
      <div class="resource-field">
        <label for="env-region">Region (optional)</label>
        <input
          id="env-region"
          type="text"
          value={region}
          onInput={(event) => setRegion(inputValue(event))}
        />
      </div>
      <button
        type="submit"
        class="resource-btn resource-btn-primary"
        disabled={mutation.state.pending || displayName.trim() === ""}
      >
        Create environment
      </button>
      <MutationFeedback state={mutation.state} />
    </form>
  );
}

// One environment: its fields, its typed guardrails, and the delete. The tenant
// comes from the active scope; a delete refreshes the switcher through the store
// and returns to the list. A max_age failure drives the RFC 9470 sudo recovery.
export function EnvironmentDetail({
  environmentId,
}: {
  environmentId?: string;
}) {
  const scope = activeScope.value;
  const tenantId = scope?.tenantId ?? null;
  if (tenantId === null) {
    return (
      <section class="resource" aria-labelledby="environment-detail-heading">
        <h2 id="environment-detail-heading">Environment</h2>
        <p class="resource-empty">Select a tenant to view this environment.</p>
      </section>
    );
  }
  return (
    <EnvironmentDetailFor
      tenantId={tenantId}
      environmentId={environmentId ?? ""}
    />
  );
}

function EnvironmentDetailFor({
  tenantId,
  environmentId,
}: {
  tenantId: string;
  environmentId: string;
}) {
  const location = useLocation();
  const { state } = useAsyncResource<EnvironmentView>(
    () => getEnvironment(tenantId, environmentId),
    [tenantId, environmentId],
  );
  const mutation = useMutation();
  const scope = activeScope.value;
  const sudo: SudoRecovery | undefined =
    scope === null ? undefined : { scope, retry: mutation.retry };

  function onDelete(): void {
    void mutation.run(async () => {
      await deleteEnvironment(tenantId, environmentId);
      void selectTenant(tenantId, null);
      if (typeof location.route === "function") {
        location.route("/environments");
      }
    }, "Environment deleted.");
  }

  return (
    <section class="resource" aria-labelledby="environment-detail-heading">
      <p>
        <a class="resource-back" href="/environments">
          Back to environments
        </a>
      </p>
      <AsyncBoundary state={state} loadingLabel="Loading environment">
        {(env) => (
          <div>
            <h2 id="environment-detail-heading">{env.display_name}</h2>
            <dl class="resource-detail">
              <dt>Identifier</dt>
              <dd>
                <code>{env.id}</code>
              </dd>
              <dt>Tenant</dt>
              <dd>
                <code>{env.tenant_id}</code>
              </dd>
              <dt>Kind</dt>
              <dd>{env.kind}</dd>
              <dt>Guardrail class</dt>
              <dd>{env.guardrail_class}</dd>
              <dt>Custom domain</dt>
              <dd>{env.custom_domain ?? "none"}</dd>
              <dt>Region</dt>
              <dd>{env.region ?? "none"}</dd>
              <dt>Created</dt>
              <dd>{new Date(env.created_at_unix_ms).toISOString()}</dd>
            </dl>
            <GuardrailList guardrails={env.guardrails} />
            <div class="resource-actions" role="group" aria-label="Environment actions">
              <ConfirmButton
                label="Delete"
                prompt="Delete this environment? This cannot be undone."
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

// The typed guardrails an environment enforces (issue #42), rendered as a plain
// yes or no per rule so the production asymmetry is visible at a glance.
function GuardrailList({
  guardrails,
}: {
  guardrails: EnvironmentView["guardrails"];
}) {
  const entries: ReadonlyArray<[string, boolean]> = [
    ["Allow insecure redirect URIs", guardrails.allow_insecure_redirect_uris],
    ["Require HTTPS redirect URIs", guardrails.require_https_redirect_uris],
    ["Require custom domain", guardrails.require_custom_domain],
    ["One time view secrets", guardrails.one_time_view_secrets],
    ["Hosted pages noindex", guardrails.hosted_pages_noindex],
    ["Show environment banner", guardrails.show_environment_banner],
  ];
  return (
    <div class="resource-guardrails">
      <h3>Guardrails</h3>
      <dl class="resource-detail">
        {entries.map(([label, value]) => (
          <div key={label} class="resource-guardrail">
            <dt>{label}</dt>
            <dd>{value ? "yes" : "no"}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
