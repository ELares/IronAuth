// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The admin console app shell. PR1 ships the frame ONLY: a layout with a nav
// and a "not signed in" placeholder. There is NO real auth here. The sign in
// button is inert; performing the OIDC login, holding the bearer token, and
// attaching it to the typed management client all land in PR2. Nothing in this
// module performs a network call or names a server API path (the route audit
// enforces both), so the shell is a pure static frame over the future client.

import { LocationProvider, Route, Router } from "preact-iso";
import { signal } from "@preact/signals";
import { loadConfig } from "./config";

// UI state lives in signals (the locked state primitive). PR1 has one flag: the
// session is always signed out because there is no login yet.
const signedIn = signal(false);

const config = loadConfig();

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

function SignInPlaceholder() {
  const target = config.issuerBase || "this origin";
  return (
    <section class="signin" aria-labelledby="signin-heading">
      <h2 id="signin-heading">Not signed in</h2>
      <p>
        The admin console signs in against <code>{target}</code>. Sign in is not
        wired yet; it arrives in the next change together with the management
        proxy.
      </p>
      <button type="button" disabled>
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
            <SignInPlaceholder />
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
