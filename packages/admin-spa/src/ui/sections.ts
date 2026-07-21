// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The console's resource sections (issue #90, PR 3). Shared by the sidebar nav
// and the command palette so both draw from one list. The hrefs are APP ROUTE
// space under the /admin mount (client side navigation), never server API paths:
// the route audit forbids a server path here, and the scoped data each section
// shows is fetched by the one typed client in the resource views that land in the
// later PRs. Overview, Tenants, and Environments read the console-wide and
// tenant lists; Clients, Users, and Connectors read the active environment scope.
// Diagnostics is the entry point PR7 wires; its content lands under issue #91.

export interface Section {
  readonly href: string;
  readonly label: string;
}

export const SECTIONS: ReadonlyArray<Section> = [
  { href: "/", label: "Overview" },
  { href: "/tenants", label: "Tenants" },
  { href: "/environments", label: "Environments" },
  { href: "/clients", label: "Clients" },
  { href: "/users", label: "Users" },
  { href: "/connectors", label: "Connectors" },
  { href: "/diagnostics", label: "Diagnostics" },
];
