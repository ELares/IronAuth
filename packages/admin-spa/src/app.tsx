// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The console shell delegates authentication and reads to the audited client
// through the login module and scope store. Credentials remain in memory.

import { LocationProvider, Route, Router, useLocation } from "preact-iso";
import { signal } from "@preact/signals";
import { useEffect, useRef, useState } from "preact/hooks";
import { beginLogin, canSignIn, completeLoginFromRedirect } from "./auth/login";
import { clearAccessToken, isSignedIn } from "./auth/session";
import { loadScope, resetScope, scopeError } from "./scope/store";
import { SECTIONS } from "./ui/sections";
import { Switcher } from "./ui/Switcher";
import { CommandPalette } from "./ui/CommandPalette";
import { ErrorView } from "./ui/ErrorView";
import { Icon, type IconName } from "./ui/Icon";
import { consoleHref } from "./ui/routing";
import { OverviewView } from "./ui/OverviewView";
import { TenantDetail, TenantsList } from "./ui/TenantsView";
import { EnvironmentDetail, EnvironmentsList } from "./ui/EnvironmentsView";
import { UserDetail, UsersList } from "./ui/UsersView";
import { ConnectorDetail, ConnectorsList } from "./ui/ConnectorsView";
import { ClientsList } from "./ui/ClientsView";
import { OrganizationDetail, OrganizationsList } from "./ui/OrganizationsView";
import { InvitationsList } from "./ui/InvitationsView";
import { PermissionsList } from "./ui/PermissionsView";
import { DiagnosticsView } from "./ui/DiagnosticsView";

const signedIn = signal(isSignedIn());
const authError = signal("");
const signingIn = signal(false);

function onSignIn(): void {
  if (signingIn.value) return;
  authError.value = "";
  signingIn.value = true;
  void beginLogin().catch((error: unknown) => {
    signingIn.value = false;
    authError.value =
      error instanceof Error
        ? error.message
        : "Sign in failed. Please try again.";
  });
}

function Brand() {
  return (
    <span class="brand">
      <span class="brand-mark">
        <Icon name="shield" />
      </span>
      IronAuth
    </span>
  );
}

const NAV_GROUPS = [
  { label: "Workspace", paths: ["/", "/tenants", "/environments"] },
  {
    label: "Identity",
    paths: [
      "/clients",
      "/users",
      "/connectors",
      "/organizations",
      "/permissions",
      "/invitations",
    ],
  },
  { label: "Operations", paths: ["/diagnostics"] },
];

function sectionIcon(href: string): IconName {
  return (href === "/" ? "overview" : href.slice(1)) as IconName;
}

function Nav({ open, close }: { open: boolean; close: () => void }) {
  const location = useLocation();
  return (
    <>
      {open ? (
        <button
          class="nav-scrim"
          aria-label="Close navigation"
          onClick={close}
        />
      ) : null}
      <aside
        class={`sidebar${open ? " sidebar-open" : ""}`}
        id="console-navigation"
      >
        <a
          class="brand-link"
          href={consoleHref("/")}
          aria-label="IronAuth overview"
          onClick={close}
        >
          <Brand />
        </a>
        <span class="sidebar-caption">IDENTITY MANAGEMENT</span>
        <nav class="nav" aria-label="Console sections">
          {NAV_GROUPS.map((group) => (
            <div class="nav-group" key={group.label}>
              <p class="nav-group-label">{group.label}</p>
              <ul>
                {SECTIONS.filter((section) =>
                  group.paths.includes(section.href),
                ).map((section) => {
                  const href = consoleHref(section.href);
                  const active =
                    section.href === "/"
                      ? location.path === href.replace(/\/$/, "") ||
                        location.path === href
                      : location.path === href ||
                        location.path.startsWith(`${href}/`);
                  return (
                    <li key={section.href}>
                      <a
                        href={href}
                        aria-current={active ? "page" : undefined}
                        onClick={close}
                      >
                        <Icon name={sectionIcon(section.href)} />
                        <span>{section.label}</span>
                        {active ? <span class="nav-active-dot" /> : null}
                      </a>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </nav>
        <div class="sidebar-footer">
          <span class="sidebar-avatar">
            <Icon name="shield" />
          </span>
          <div>
            <strong>Admin console</strong>
            <span>Identity, under your control.</span>
          </div>
        </div>
      </aside>
    </>
  );
}

function SignIn() {
  const ready = canSignIn();
  return (
    <div class="signin-layout">
      <section class="signin-story" aria-labelledby="welcome-heading">
        <Brand />
        <div class="signin-story-content">
          <span class="eyebrow">YOUR IDENTITY WORKSPACE</span>
          <h1 id="welcome-heading">
            Good security.
            <br />A better experience.
          </h1>
          <p>
            Bring your applications, people, and sign-in experiences together in
            one place.
          </p>
          <div class="identity-illustration" aria-hidden="true">
            <div class="illustration-orbit orbit-one" />
            <div class="illustration-orbit orbit-two" />
            <div class="illustration-core">
              <Icon name="shield" />
            </div>
            <div class="illustration-node node-users">
              <Icon name="users" />
            </div>
            <div class="illustration-node node-clients">
              <Icon name="clients" />
            </div>
            <div class="illustration-node node-connectors">
              <Icon name="connectors" />
            </div>
            <span class="illustration-label label-users">People</span>
            <span class="illustration-label label-clients">Applications</span>
            <span class="illustration-label label-connectors">Connections</span>
          </div>
        </div>
        <p class="signin-story-footer">
          <Icon name="check" /> Open standards. Complete control.
        </p>
      </section>
      <main class="signin-main" id="main-content">
        <section class="signin" aria-labelledby="signin-heading">
          <span class="signin-icon">
            <Icon name="shield" />
          </span>
          <span class="eyebrow">ADMIN CONSOLE</span>
          <h1 id="signin-heading">Welcome back</h1>
          <p>Sign in to manage your identity platform.</p>
          {authError.value === "" ? null : (
            <p class="signin-error" role="alert">
              {authError.value}
            </p>
          )}
          {ready ? null : (
            <div class="signin-setup" role="status">
              <strong>Your console needs a little setup</strong>
              <p>
                Configure the admin issuer and console client to enable sign in.
              </p>
            </div>
          )}
          <button
            type="button"
            class="signin-button"
            disabled={!ready || signingIn.value}
            onClick={onSignIn}
          >
            {signingIn.value ? "Connecting…" : "Sign in"}
            <Icon name="arrow" />
          </button>
          <p class="signin-security">
            <Icon name="permissions" /> Secure sign in with IronAuth
          </p>
        </section>
        <p class="signin-footer">IronAuth · Identity, under your control.</p>
      </main>
    </div>
  );
}

function NotFound() {
  return (
    <section class="not-found">
      <span class="eyebrow">404</span>
      <h1>We couldn’t find that page</h1>
      <p>The address may have changed. Your workspace is still here.</p>
      <a class="resource-btn resource-btn-primary" href={consoleHref("/")}>
        Back to overview <Icon name="arrow" />
      </a>
    </section>
  );
}

export function Routes() {
  return (
    <Router>
      <Route path={consoleHref("/")} component={OverviewView} />
      <Route path={consoleHref("/tenants")} component={TenantsList} />
      <Route
        path={consoleHref("/tenants/:tenantId")}
        component={TenantDetail}
      />
      <Route path={consoleHref("/environments")} component={EnvironmentsList} />
      <Route
        path={consoleHref("/environments/:environmentId")}
        component={EnvironmentDetail}
      />
      <Route path={consoleHref("/clients")} component={ClientsList} />
      <Route path={consoleHref("/users")} component={UsersList} />
      <Route path={consoleHref("/users/:userId")} component={UserDetail} />
      <Route path={consoleHref("/connectors")} component={ConnectorsList} />
      <Route
        path={consoleHref("/connectors/:connectorId")}
        component={ConnectorDetail}
      />
      <Route
        path={consoleHref("/organizations")}
        component={OrganizationsList}
      />
      <Route
        path={consoleHref("/organizations/:organizationId")}
        component={OrganizationDetail}
      />
      <Route path={consoleHref("/permissions")} component={PermissionsList} />
      <Route path={consoleHref("/invitations")} component={InvitationsList} />
      <Route path={consoleHref("/diagnostics")} component={DiagnosticsView} />
      <Route default component={NotFound} />
    </Router>
  );
}

function Shell() {
  const location = useLocation();
  const previousPath = useRef(location.path);
  const [navOpen, setNavOpen] = useState(false);
  useEffect(() => {
    void completeLoginFromRedirect()
      .then((ok) => {
        if (ok) signedIn.value = true;
        if (signedIn.value) void loadScope();
      })
      .catch((error: unknown) => {
        signingIn.value = false;
        authError.value =
          error instanceof Error
            ? error.message
            : "Sign in failed. Please try again.";
      });
  }, []);
  useEffect(() => {
    if (!navOpen) return;
    const onEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setNavOpen(false);
        document.getElementById("navigation-toggle")?.focus();
      }
    };
    window.addEventListener("keydown", onEscape);
    return () => window.removeEventListener("keydown", onEscape);
  }, [navOpen]);
  const activeSection = SECTIONS.find(
    (section) =>
      section.href !== "/" &&
      (location.path === consoleHref(section.href) ||
        location.path.startsWith(`${consoleHref(section.href)}/`)),
  );
  const pageLabel =
    activeSection?.label ??
    (location.path === consoleHref("/").replace(/\/$/, "") ||
    location.path === consoleHref("/")
      ? "Overview"
      : "Page not found");
  useEffect(() => {
    document.title = signedIn.value
      ? `${pageLabel} · IronAuth`
      : "Sign in · IronAuth";
    if (signedIn.value && previousPath.current !== location.path) {
      document.getElementById("main-content")?.focus();
    }
    previousPath.current = location.path;
  }, [pageLabel, location.path, signedIn.value]);
  function signOut() {
    clearAccessToken();
    resetScope();
    signedIn.value = false;
    signingIn.value = false;
    authError.value = "";
    location.route(consoleHref("/"));
  }
  return (
    <>
      <a class="skip-link" href="#main-content">
        Skip to content
      </a>
      {signedIn.value ? (
        <div class="app-frame">
          <Nav open={navOpen} close={() => setNavOpen(false)} />
          <div class="workspace">
            <header class="app-header">
              <button
                class="icon-button navigation-toggle"
                id="navigation-toggle"
                type="button"
                aria-label={navOpen ? "Close navigation" : "Open navigation"}
                aria-expanded={navOpen}
                aria-controls="console-navigation"
                onClick={() => setNavOpen(!navOpen)}
              >
                <Icon name={navOpen ? "close" : "menu"} />
              </button>
              <div class="breadcrumb">
                <span>Workspace</span>
                <span aria-hidden="true">/</span>
                <strong>{pageLabel}</strong>
              </div>
              <div class="header-actions">
                <Switcher />
                <CommandPalette />
                <button
                  type="button"
                  class="icon-button signout-button"
                  aria-label="Sign out of console"
                  title="Sign out of console"
                  onClick={signOut}
                >
                  <Icon name="logout" />
                </button>
              </div>
            </header>
            <main
              class="app-main"
              id="main-content"
              tabIndex={-1}
              key={location.path}
            >
              {scopeError.value === null ? null : (
                <ErrorView error={scopeError.value} />
              )}
              <Routes />
            </main>
            <footer class="workspace-footer">
              <span>IronAuth admin console</span>
              <span>Open standards. Complete control.</span>
            </footer>
          </div>
        </div>
      ) : (
        <SignIn />
      )}
    </>
  );
}

export function App() {
  return (
    <LocationProvider>
      <Shell />
    </LocationProvider>
  );
}
