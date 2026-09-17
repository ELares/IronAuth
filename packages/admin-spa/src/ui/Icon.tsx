// SPDX-License-Identifier: MIT OR Apache-2.0

export type IconName =
  | "shield"
  | "overview"
  | "tenants"
  | "environments"
  | "clients"
  | "users"
  | "connectors"
  | "organizations"
  | "permissions"
  | "invitations"
  | "diagnostics"
  | "search"
  | "arrow"
  | "menu"
  | "close"
  | "plus"
  | "logout"
  | "check";

const paths: Record<IconName, string> = {
  shield: "M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3Z M9 12l2 2 4-4",
  overview: "M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z",
  tenants:
    "M4 21V5l8-2v18 M12 8h8v13 M2 21h20 M7 7v1 M7 12v1 M7 17v1 M16 12h1 M16 17h1",
  environments: "m12 3 9 5-9 5-9-5 9-5Z M3 12l9 5 9-5 M3 16l9 5 9-5",
  clients: "M4 4h16v12H4z M8 20h8 M12 16v4 M8 8l-2 2 2 2 M16 8l2 2-2 2",
  users:
    "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M9 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z M17 4a4 4 0 0 1 0 8 M22 21v-2a4 4 0 0 0-3-4",
  connectors: "M8 3v5 M16 3v5 M5 8h14v3a7 7 0 0 1-14 0V8Z M12 18v3",
  organizations:
    "M9 3h6v6H9z M3 15h6v6H3z M15 15h6v6h-6z M12 9v3 M6 15v-3h12v3",
  permissions: "M8 11V7a4 4 0 0 1 8 0v4 M5 11h14v10H5z M12 15v2",
  invitations: "M3 5h18v14H3z m0 0 9 7 9-7",
  diagnostics: "M3 12h4l3-8 4 16 3-8h4",
  search: "M11 3a8 8 0 1 0 0 16 8 8 0 0 0 0-16Z m6 14 4 4",
  arrow: "M5 12h14 m-5-5 5 5-5 5",
  menu: "M4 6h16 M4 12h16 M4 18h16",
  close: "m6 6 12 12 M18 6 6 18",
  plus: "M12 5v14 M5 12h14",
  logout: "M9 4H4v16h5 M9 12h12 m-4-4 4 4-4 4",
  check: "m5 12 4 4L19 6",
};

export function Icon({
  name,
  class: className = "",
}: {
  name: IconName;
  class?: string;
}) {
  return (
    <svg
      class={`icon ${className}`}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="1.7"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <path d={paths[name]} />
    </svg>
  );
}
