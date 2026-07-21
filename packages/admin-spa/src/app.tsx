// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The admin console app shell (issue #90, PR 3). The PR2 login stays intact: the
// sign in button starts an Authorization Code + PKCE flow against the admin
// issuer and the callback exchange yields a short lived at+jwt held in memory
// (src/auth/session.ts). PR3 builds the real console FRAME around it: a header
// carrying the tenant/environment context switcher, a sidebar nav of the resource
// sections, routed content (placeholder views until the CRUD lands in PR4-6), a
// keyboard command palette, and the verbatim management ErrorBody boundary.
//
// This module performs NO network call and names NO server API path (the route
// audit enforces both): it delegates to src/auth/login.ts and the scope store,
// which reach the server only through the one audited client (src/api/client.ts).

import { LocationProvider, Route, Router } from "preact-iso";
import { signal } from "@preact/signals";
import { useEffect } from "preact/hooks";
import { loadConfig } from "./config";
import { beginLogin, canSignIn, completeLoginFromRedirect } from "./auth/login";
import { isSignedIn } from "./auth/session";
import { loadScope, scopeError } from "./scope/store";
import { SECTIONS } from "./ui/sections";
import { Switcher } from "./ui/Switcher";
import { CommandPalette } from "./ui/CommandPalette";
import { ErrorView } from "./ui/ErrorView";
import { TenantDetail, TenantsList } from "./ui/TenantsView";
import { EnvironmentDetail, EnvironmentsList } from "./ui/EnvironmentsView";
import { UserDetail, UsersList } from "./ui/UsersView";

// UI state lives in signals (the locked state primitive). `signedIn` flips true
// once a token is held; `authError` surfaces a failed login verbatim.
const signedIn = signal(isSignedIn());
const authError = signal<string>("");

// Start the login. A failure (discovery or redirect) surfaces as an error rather
// than a silent no op.
function onSignIn(): void {
  authError.value = "";
  void beginLogin().catch((error: unknown) => {
    authError.value = error instanceof Error ? error.message : "sign in failed";
  });
}

function Nav() {
  return (
    <nav class="nav" aria-label="Console sections">
      <ul>
        {SECTIONS.map((section) => (
          <li key={section.href}>
            <a href={section.href}>{section.label}</a>
          </li>
        ))}
      </ul>
    </nav>
  );
}

function SignIn() {
  const config = loadConfig();
  const ready = canSignIn();
  const target = config.adminIssuer || config.issuerBase || "this origin";
  return (
    <section class="signin" aria-labelledby="signin-heading">
      <h2 id="signin-heading">Not signed in</h2>
      <p>
        The admin console signs in against <code>{target}</code> using the
        IronAuth OIDC provider. {ready ? "" : "Sign in is unavailable until the admin issuer and console client are configured."}
      </p>
      {authError.value === "" ? null : (
        <p class="error" role="alert">
          {authError.value}
        </p>
      )}
      <button type="button" disabled={!ready} onClick={onSignIn}>
        Sign in
      </button>
    </section>
  );
}

// A placeholder resource view for the sections not yet wired (Clients and
// Connectors land in PR6). Tenants, Environments, and Users now render their real
// CRUD surfaces below. The active scope is already resolved in the store, so each
// remaining PR only swaps its body.
function SectionView({ label }: { label: string }) {
  return (
    <section class="placeholder">
      <h2>{label}</h2>
      <p>
        This section lists {label.toLowerCase()} for the active scope once the
        console is wired to the management API in a later change.
      </p>
    </section>
  );
}

function Routes() {
  return (
    <Router>
      <Route path="/" component={() => <SectionView label="Overview" />} />
      <Route path="/tenants" component={TenantsList} />
      <Route path="/tenants/:tenantId" component={TenantDetail} />
      <Route path="/environments" component={EnvironmentsList} />
      <Route
        path="/environments/:environmentId"
        component={EnvironmentDetail}
      />
      <Route path="/clients" component={() => <SectionView label="Clients" />} />
      <Route path="/users" component={UsersList} />
      <Route path="/users/:userId" component={UserDetail} />
      <Route
        path="/connectors"
        component={() => <SectionView label="Connectors" />}
      />
      <Route default component={() => <SectionView label="Overview" />} />
    </Router>
  );
}

function Shell() {
  // Complete an authorization callback if the URL carries one, then reflect
  // whether a token is held and, when signed in, load the scope. A failed
  // exchange leaves the console signed out with the error shown, never a half
  // authenticated state.
  useEffect(() => {
    void completeLoginFromRedirect()
      .then((ok) => {
        if (ok) {
          signedIn.value = true;
        }
        if (signedIn.value) {
          void loadScope();
        }
      })
      .catch((error: unknown) => {
        authError.value =
          error instanceof Error ? error.message : "sign in failed";
      });
  }, []);

  return (
    <div class="app-frame">
      <header class="app-header">
        <span class="brand">IronAuth</span>
        <span class="subtitle">admin console</span>
        {signedIn.value ? <Switcher /> : null}
        {signedIn.value ? (
          <span class="cmdk-hint" aria-hidden="true">
            Ctrl or Cmd K
          </span>
        ) : null}
      </header>
      <div class="app-body">
        {signedIn.value ? <Nav /> : null}
        <main class="app-main">
          {signedIn.value ? (
            <>
              {scopeError.value === null ? null : (
                <ErrorView error={scopeError.value} />
              )}
              <Routes />
            </>
          ) : (
            <SignIn />
          )}
        </main>
      </div>
      {signedIn.value ? <CommandPalette /> : null}
    </div>
  );
}

export function App() {
  return (
    <LocationProvider>
      <Shell />
    </LocationProvider>
  );
}
