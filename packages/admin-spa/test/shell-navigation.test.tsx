// SPDX-License-Identifier: MIT OR Apache-2.0

import { afterEach, expect, it, vi } from "vitest";
import { render } from "preact";
import { App } from "../src/app";
import { activeScope, resetScope } from "../src/scope/store";

vi.mock("../src/auth/session", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/auth/session")>()),
  isSignedIn: () => true,
}));
vi.mock("../src/auth/login", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/auth/login")>()),
  completeLoginFromRedirect: async () => false,
}));
vi.mock("../src/scope/store", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/scope/store")>()),
  loadScope: async () => {},
}));

let container: HTMLDivElement | null = null;
let managementBase: HTMLMetaElement | null = null;

async function flush(): Promise<void> {
  for (let index = 0; index < 6; index += 1) {
    await new Promise<void>((resolve) =>
      requestAnimationFrame(() => resolve()),
    );
  }
}

afterEach(() => {
  if (container !== null) {
    render(null, container);
    container.remove();
    container = null;
  }
  resetScope();
  managementBase?.remove();
  managementBase = null;
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  window.history.replaceState({}, "", "/");
});

it("opens the next resource page at the top with keyboard focus while discarding the prior route", async () => {
  window.history.replaceState({}, "", "/admin/tenants");
  managementBase = document.createElement("meta");
  managementBase.name = "ironauth-management-base";
  managementBase.content = "http://management.test/admin/api";
  document.head.appendChild(managementBase);
  activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
  const tenants = Array.from({ length: 40 }, (_, index) => ({
    id: `ten_${index}`,
    display_name: `Tenant ${index}`,
    status: "active",
    created_at_unix_ms: 0,
  }));
  const users = Array.from({ length: 40 }, (_, index) => ({
    id: `usr_${index}`,
    tenant_id: "ten_a",
    environment_id: "env_a",
    identifier: `user${index}@example.test`,
    state: "active",
    external_id: null,
    created_at_unix_ms: 0,
    updated_at_unix_ms: 0,
  }));
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request) => {
      const items = input.url.endsWith("/users") ? users : tenants;
      return new Response(JSON.stringify({ items }), {
        headers: { "content-type": "application/json" },
      });
    }),
  );
  // jsdom has no layout or scrolling; retain a nonzero scroll position until
  // the mounted shell resets it after the actual sidebar route transition.
  let scrollPosition = 1800;
  vi.spyOn(window, "scrollY", "get").mockImplementation(() => scrollPosition);
  vi.spyOn(window, "scrollTo").mockImplementation((x, y) => {
    scrollPosition = typeof x === "number" ? (y ?? 0) : (x.top ?? 0);
  });
  const focus = vi.spyOn(HTMLElement.prototype, "focus");
  container = document.createElement("div");
  document.body.appendChild(container);
  render(<App />, container);
  await flush();
  const previousMain = container.querySelector("#main-content");
  expect(previousMain?.querySelectorAll(".resource-row")).toHaveLength(40);
  expect(window.scrollY).toBe(1800);

  const usersLink = container.querySelector<HTMLAnchorElement>(
    'nav[aria-label="Console sections"] a[href="/admin/users"]',
  )!;
  usersLink.focus();
  usersLink.click();
  await flush();

  const nextMain = container.querySelector("#main-content");
  expect(window.location.pathname).toBe("/admin/users");
  expect(nextMain?.querySelector("h1")?.textContent).toBe("Users");
  expect(nextMain?.querySelectorAll(".resource-row")).toHaveLength(40);
  expect(nextMain).not.toBe(previousMain);
  expect(window.scrollY).toBe(0);
  expect(document.activeElement).toBe(nextMain);
  expect(focus).toHaveBeenLastCalledWith({ preventScroll: true });
});
