// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The tenants CRUD surface (issue #90, PR 4): the list, the create form, the
// detail, the delete, and the suspend, resume, and restore lifecycle. It reads
// and writes ONLY through the named wrappers in src/api/client.ts (the single
// funnel), stands on the reusable resource hooks and views, and renders every
// failure through the verbatim ErrorView boundary. There is NO tenant update
// operation in the management contract, so this surface has none: a tenant is
// created, read, listed, deleted, and moved through its lifecycle.

import { useLocation } from "preact-iso";
import { consoleHref } from "./routing";
import { useState } from "preact/hooks";
import {
  type CreateTenantRequest,
  type TenantView,
  createTenant,
  deleteTenant,
  fetchTenants,
  getTenant,
  restoreTenant,
  resumeTenant,
  suspendTenant,
} from "../api/client";
import { activeScope, reloadTenants } from "../scope/store";
import type { SudoRecovery } from "./ErrorView";
import {
  AsyncBoundary,
  ConfirmButton,
  MutationFeedback,
  ResourceHeading,
  ResourceCreateAction,
  ResourceFormIntro,
  ResourceCollection,
  resourceLabel,
} from "./ResourceView";
import { useAsyncResource, useMutation } from "./useResource";

// The environment kinds the create form offers, matching the management contract
// (issue #42): dev and staging are relaxed non production; prod adds the hard
// production guardrail set (a custom domain is then required).
const ENV_KINDS = ["dev", "staging", "prod"] as const;

function inputValue(event: Event): string {
  return (event.target as HTMLInputElement).value;
}

// The tenants list plus the create form. Creating or deleting a tenant reloads
// this list AND refreshes the switcher's tenant list through the store.
export function TenantsList() {
  const [notice, setNotice] = useState<string | null>(null);
  const { state, reload } = useAsyncResource<TenantView[]>(
    () => fetchTenants(),
    [],
  );
  function onChanged(): void {
    reload();
    void reloadTenants();
  }
  return (
    <section class="resource" aria-labelledby="tenants-heading">
      <ResourceHeading
        id="tenants-heading"
        title="Tenants"
        description="Manage your tenants and the environments where your applications run."
        actions={
          <ResourceCreateAction label="Create tenant">
            {(close) => (
              <TenantCreateForm
                onCreated={() => {
                  setNotice("Tenant created.");
                  onChanged();
                  close();
                }}
              />
            )}
          </ResourceCreateAction>
        }
      />
      {notice === null ? null : (
        <p class="resource-success" role="status" aria-live="polite">
          {notice}
        </p>
      )}
      <AsyncBoundary
        state={state}
        loadingLabel="Loading tenants"
        empty={{
          when: (items) => items.length === 0,
          render: () => <p class="resource-empty">No tenants yet.</p>,
        }}
      >
        {(items) => (
          <ResourceCollection
            items={items}
            noun="tenants"
            searchText={(tenant) =>
              [tenant.display_name, tenant.id, tenant.status].join(" ")
            }
          >
            {(visible) => (
              <ul class="resource-list">
                {visible.map((tenant) => (
                  <li key={tenant.id} class="resource-row">
                    <a
                      class="resource-link"
                      href={consoleHref(`/tenants/${tenant.id}`)}
                    >
                      {tenant.display_name}
                    </a>
                    <code class="resource-id">{tenant.id}</code>
                    <span
                      class={`resource-status resource-status-${tenant.status}`}
                    >
                      {tenant.status}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </ResourceCollection>
        )}
      </AsyncBoundary>
    </section>
  );
}

function TenantCreateForm({ onCreated }: { onCreated: () => void }) {
  const mutation = useMutation();
  const [displayName, setDisplayName] = useState("");
  const [envName, setEnvName] = useState("");
  const [envKind, setEnvKind] = useState<string>("dev");
  const [customDomain, setCustomDomain] = useState("");
  const [homeRegion, setHomeRegion] = useState("");

  function onSubmit(event: Event): void {
    event.preventDefault();
    const request: CreateTenantRequest = {
      display_name: displayName.trim(),
      environment_kind: envKind,
    };
    if (envName.trim() !== "") {
      request.environment_display_name = envName.trim();
    }
    if (customDomain.trim() !== "") {
      request.environment_custom_domain = customDomain.trim();
    }
    if (homeRegion.trim() !== "") {
      request.home_region = homeRegion.trim();
    }
    void mutation
      .run(async () => {
        await createTenant(request);
      }, "Tenant created.")
      .then((ok) => {
        if (ok) {
          setDisplayName("");
          setEnvName("");
          setEnvKind("dev");
          setCustomDomain("");
          setHomeRegion("");
          onCreated();
        }
      });
  }

  return (
    <form
      class="resource-form"
      onSubmit={onSubmit}
      aria-label="Create a tenant"
    >
      <ResourceFormIntro
        title="Create tenant"
        description="Add a tenant and its first environment. You can create additional environments later."
      />
      <div class="resource-field">
        <label for="tenant-display-name">Display name</label>
        <input
          id="tenant-display-name"
          placeholder={"Acme"}
          type="text"
          required
          value={displayName}
          onInput={(event) => setDisplayName(inputValue(event))}
        />
      </div>
      <div class="resource-field">
        <label for="tenant-env-name">First environment name</label>
        <input
          id="tenant-env-name"
          type="text"
          placeholder="development"
          value={envName}
          onInput={(event) => setEnvName(inputValue(event))}
        />
      </div>
      <div class="resource-field">
        <label for="tenant-env-kind">First environment kind</label>
        <select
          id="tenant-env-kind"
          value={envKind}
          onChange={(event) =>
            setEnvKind((event.target as HTMLSelectElement).value)
          }
        >
          {ENV_KINDS.map((kind) => (
            <option key={kind} value={kind}>
              {resourceLabel(kind)}
            </option>
          ))}
        </select>
      </div>
      {envKind === "prod" ? (
        <div class="resource-field">
          <label for="tenant-custom-domain">Custom domain</label>
          <input
            id="tenant-custom-domain"
            placeholder={"auth.example.com"}
            type="text"
            required
            value={customDomain}
            onInput={(event) => setCustomDomain(inputValue(event))}
          />
        </div>
      ) : null}
      <div class="resource-field">
        <label for="tenant-home-region">Home region (optional)</label>
        <input
          id="tenant-home-region"
          placeholder={"us-west-2"}
          type="text"
          value={homeRegion}
          onInput={(event) => setHomeRegion(inputValue(event))}
        />
      </div>
      <button
        type="submit"
        class="resource-btn resource-btn-primary"
        disabled={mutation.state.pending || displayName.trim() === ""}
      >
        Create tenant
      </button>
      <MutationFeedback state={mutation.state} />
    </form>
  );
}

// One tenant: its fields, the suspend or resume lifecycle (by current status),
// restore, and delete. A max_age failure on a write drives the RFC 9470 sudo
// recovery, elevating within the active scope and replaying the write.
export function TenantDetail({ tenantId }: { tenantId?: string }) {
  const id = tenantId ?? "";
  const location = useLocation();
  const { state, reload } = useAsyncResource<TenantView>(
    () => getTenant(id),
    [id],
  );
  const mutation = useMutation();
  const scope = activeScope.value;
  const sudo: SudoRecovery | undefined =
    scope === null ? undefined : { scope, retry: mutation.retry };

  function afterLifecycle(): void {
    reload();
    void reloadTenants();
  }

  function onDelete(): void {
    void mutation.run(async () => {
      await deleteTenant(id);
      void reloadTenants();
      if (typeof location.route === "function") {
        location.route(consoleHref("/tenants"));
      }
    }, "Tenant deleted.");
  }

  return (
    <section class="resource" aria-labelledby="tenant-detail-heading">
      <p>
        <a class="resource-back" href={consoleHref("/tenants")}>
          Back to tenants
        </a>
      </p>
      <AsyncBoundary state={state} loadingLabel="Loading tenant">
        {(tenant) => (
          <div>
            <ResourceHeading
              id="tenant-detail-heading"
              title={tenant.display_name}
              description="Review tenant details and manage its availability."
            />
            <dl class="resource-detail">
              <dt>Identifier</dt>
              <dd>
                <code>{tenant.id}</code>
              </dd>
              <dt>Status</dt>
              <dd>{tenant.status}</dd>
              <dt>Home region</dt>
              <dd>{tenant.home_region ?? "none"}</dd>
              <dt>Created</dt>
              <dd>{new Date(tenant.created_at_unix_ms).toISOString()}</dd>
            </dl>
            <div
              class="resource-actions"
              role="group"
              aria-label="Tenant lifecycle"
            >
              {tenant.status === "active" ? (
                <ConfirmButton
                  label="Suspend"
                  prompt="Suspend this tenant?"
                  confirmLabel="Confirm suspend"
                  danger
                  disabled={mutation.state.pending}
                  onConfirm={() => {
                    void mutation.run(async () => {
                      await suspendTenant(id);
                      afterLifecycle();
                    }, "Tenant suspended.");
                  }}
                />
              ) : (
                <ConfirmButton
                  label="Resume"
                  prompt="Resume this tenant?"
                  confirmLabel="Confirm resume"
                  disabled={mutation.state.pending}
                  onConfirm={() => {
                    void mutation.run(async () => {
                      await resumeTenant(id);
                      afterLifecycle();
                    }, "Tenant resumed.");
                  }}
                />
              )}
              <ConfirmButton
                label="Restore"
                prompt="Restore this tenant?"
                confirmLabel="Confirm restore"
                disabled={mutation.state.pending}
                onConfirm={() => {
                  void mutation.run(async () => {
                    await restoreTenant(id);
                    afterLifecycle();
                  }, "Tenant restored.");
                }}
              />
              <ConfirmButton
                label="Delete"
                prompt="Delete this tenant? This cannot be undone."
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
