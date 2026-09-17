// SPDX-License-Identifier: MIT OR Apache-2.0

import {
  activeScope,
  environments,
  scopeError,
  scopeLoaded,
  tenants,
} from "../scope/store";
import { Icon, type IconName } from "./Icon";
import { consoleHref } from "./routing";

const RESOURCES: ReadonlyArray<{
  href: string;
  icon: IconName;
  title: string;
  description: string;
  label: string;
}> = [
  {
    href: "/clients",
    icon: "clients",
    title: "Applications",
    description:
      "Connect the applications that rely on IronAuth for secure sign in.",
    label: "Manage clients",
  },
  {
    href: "/users",
    icon: "users",
    title: "People",
    description: "Manage user accounts, access, and account security.",
    label: "Manage users",
  },
  {
    href: "/connectors",
    icon: "connectors",
    title: "Identity connections",
    description:
      "Bring your identity providers together in a single sign-in experience.",
    label: "Manage connectors",
  },
  {
    href: "/organizations",
    icon: "organizations",
    title: "Organizations",
    description: "Organize your customers and teams with groups and roles.",
    label: "Manage organizations",
  },
  {
    href: "/permissions",
    icon: "permissions",
    title: "Access permissions",
    description:
      "Define the permissions your applications use to grant access.",
    label: "Manage permissions",
  },
  {
    href: "/diagnostics",
    icon: "diagnostics",
    title: "Diagnostics",
    description:
      "Investigate authentication issues and understand your sign-in flows.",
    label: "Open diagnostics",
  },
];

export function OverviewView() {
  const scope = activeScope.value;
  const tenant = tenants.value.find((item) => item.id === scope?.tenantId);
  const environment = environments.value.find(
    (item) => item.id === scope?.environmentId,
  );
  const loaded = scopeLoaded.value && scopeError.value === null;
  return (
    <section class="overview" aria-labelledby="overview-heading">
      <div class="overview-heading">
        <div>
          <span class="eyebrow">YOUR WORKSPACE</span>
          <h1 id="overview-heading">Overview</h1>
          <p class="page-description">
            A clear view of your identity platform. A good place to get started.
          </p>
        </div>
        <a class="resource-btn" href={consoleHref("/environments")}>
          <Icon name="environments" /> Manage environments
        </a>
      </div>
      {scopeError.value === null ? (
        <div class="overview-stats">
          <a class="stat-card" href={consoleHref("/tenants")}>
            <span class="stat-icon">
              <Icon name="tenants" />
            </span>
            <div>
              <span class="stat-label">Accessible tenants</span>
              <strong class="stat-value">
                {loaded ? tenants.value.length : "…"}
              </strong>
              <span class="stat-footnote">In the loaded tenant list</span>
            </div>
            <Icon name="arrow" class="stat-arrow" />
          </a>
          <a class="stat-card" href={consoleHref("/environments")}>
            <span class="stat-icon">
              <Icon name="environments" />
            </span>
            <div>
              <span class="stat-label">Environments</span>
              <strong class="stat-value">
                {loaded ? environments.value.length : "…"}
              </strong>
              <span class="stat-footnote">
                {tenant
                  ? `In ${tenant.display_name}`
                  : "For the selected tenant"}
              </span>
            </div>
            <Icon name="arrow" class="stat-arrow" />
          </a>
          <div class="stat-card">
            <span class="stat-icon">
              <Icon name="shield" />
            </span>
            <div>
              <span class="stat-label">Active environment</span>
              <strong class="stat-value stat-value-name">
                {environment?.display_name ??
                  (loaded ? "None selected" : "Loading…")}
              </strong>
              <span
                class={`environment-badge environment-badge-${environment?.kind ?? "none"}`}
              >
                {environment?.kind === "prod"
                  ? "Production"
                  : environment?.kind === "staging"
                    ? "Staging"
                    : environment?.kind === "dev"
                      ? "Development"
                      : "Select an environment"}
              </span>
            </div>
          </div>
        </div>
      ) : null}
      {loaded && tenants.value.length === 0 ? (
        <div class="overview-setup">
          <Icon name="tenants" />
          <div>
            <h2>Create your first workspace</h2>
            <p>
              Start with a tenant, then add an environment to connect your
              applications and users.
            </p>
          </div>
          <a
            class="resource-btn resource-btn-primary"
            href={consoleHref("/tenants")}
          >
            Create a tenant <Icon name="arrow" />
          </a>
        </div>
      ) : null}
      <div class="overview-section-heading">
        <h2>Manage your platform</h2>
        <span>Everything you need, in one place</span>
      </div>
      <div class="overview-resource-grid">
        {RESOURCES.map((resource) => (
          <a
            class="overview-resource-card"
            href={consoleHref(resource.href)}
            key={resource.href}
          >
            <span class="overview-resource-icon">
              <Icon name={resource.icon} />
            </span>
            <h3>{resource.title}</h3>
            <p>{resource.description}</p>
            <span class="overview-resource-link">
              {resource.label}
              <Icon name="arrow" />
            </span>
          </a>
        ))}
      </div>
      <div class="overview-bottom-grid">
        <section class="overview-context" aria-labelledby="context-heading">
          <div class="panel-heading">
            <Icon name="environments" />
            <h2 id="context-heading">Your current context</h2>
          </div>
          <p>Changes apply to the tenant and environment you select.</p>
          <dl>
            <div>
              <dt>Tenant</dt>
              <dd>{tenant?.display_name ?? "No tenant selected"}</dd>
            </div>
            <div>
              <dt>Environment</dt>
              <dd>{environment?.display_name ?? "No environment selected"}</dd>
            </div>
            <div>
              <dt>Domain</dt>
              <dd>{environment?.custom_domain ?? "Default issuer domain"}</dd>
            </div>
          </dl>
          <a href={consoleHref("/environments")}>
            View environment settings <Icon name="arrow" />
          </a>
        </section>
        <section class="overview-guide" aria-labelledby="guide-heading">
          <span class="eyebrow">NEXT STEPS</span>
          <h2 id="guide-heading">Make your first connection</h2>
          <p>A simple path from a new workspace to your first sign in.</p>
          <ol>
            <li>
              <a href={consoleHref("/environments")}>
                <span>1</span>
                <div>
                  <strong>Choose an environment</strong>
                  <small>Keep development and production separate.</small>
                </div>
                <Icon name="arrow" />
              </a>
            </li>
            <li>
              <a href={consoleHref("/clients")}>
                <span>2</span>
                <div>
                  <strong>Register an application</strong>
                  <small>Configure a client and its redirect addresses.</small>
                </div>
                <Icon name="arrow" />
              </a>
            </li>
            <li>
              <a href={consoleHref("/users")}>
                <span>3</span>
                <div>
                  <strong>Bring your people in</strong>
                  <small>Create accounts and manage their access.</small>
                </div>
                <Icon name="arrow" />
              </a>
            </li>
          </ol>
        </section>
      </div>
    </section>
  );
}
