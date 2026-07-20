// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The admin console app shell. PR2 wires the real login: the sign in button
// starts an Authorization Code + PKCE flow against the admin issuer, and on the
// authorization callback the shell exchanges the code for a short lived at+jwt it
// holds in memory (src/auth/session.ts). Nothing in this module performs a
// network call or names a server API path directly (the route audit enforces
// both): it delegates to src/auth/login.ts, which delegates to the one audited
// client. The typed management client attaches the in memory bearer per request.

import { LocationProvider, Route, Router } from "preact-iso";
import { signal } from "@preact/signals";
import { loadConfig } from "./config";
import { beginLogin, canSignIn, completeLoginFromRedirect } from "./auth/login";
import { isSignedIn } from "./auth/session";

// UI state lives in signals (the locked state primitive). `signedIn` flips true
// once a token is held; `authError` surfaces a failed login verbatim.
const signedIn = signal(isSignedIn());
const authError = signal<string>("");

const config = loadConfig();

// On load, complete an authorization callback if the URL carries one, then
// reflect whether a token is held. A failed exchange leaves the console signed
// out with the error shown, never a half authenticated state.
void completeLoginFromRedirect()
  .then((ok) => {
    if (ok) {
      signedIn.value = true;
    }
  })
  .catch((error: unknown) => {
    authError.value = error instanceof Error ? error.message : "sign in failed";
  });

// Start the login. A failure (discovery or redirect) surfaces as an error rather
// than a silent no op.
function onSignIn(): void {
  authError.value = "";
  void beginLogin().catch((error: unknown) => {
    authError.value = error instanceof Error ? error.message : "sign in failed";
  });
}

// The nav placeholders. These are the future console sections; PR1 renders them
// as inert labels so the frame reads as the real console without wiring any
// data. The hrefs are in app route space (under the /admin mount), never server
// API paths.
const SECTIONS: ReadonlyArray<{ readonly href: string; readonly label: string }> = [
  { href: "/", label: "Overview" },
  { href: "/tenants", label: "Tenants" },
  { href: "/environments", label: "Environments" },
  { href: "/clients", label: "Clients" },
  { href: "/users", label: "Users" },
];

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

function Placeholder() {
  return (
    <section class="placeholder">
      <p>This section renders once the console is wired to the management API.</p>
    </section>
  );
}

function Shell() {
  return (
    <div class="app-frame">
      <header class="app-header">
        <span class="brand">IronAuth</span>
        <span class="subtitle">admin console</span>
      </header>
      <div class="app-body">
        <Nav />
        <main class="app-main">
          {signedIn.value ? (
            <Router>
              <Route path="/" component={Placeholder} />
              <Route default component={Placeholder} />
            </Router>
          ) : (
            <SignIn />
          )}
        </main>
      </div>
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
