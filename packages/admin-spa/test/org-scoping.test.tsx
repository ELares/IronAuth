// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The admin console shows a SCOPED administrator only in-scope resources
// (issue #102, acceptance criterion 6).
//
// The criterion has two halves and they belong to different layers. "Direct API
// calls outside scope fail server-side" is the server's, and it holds:
// `getOrganization` answers the uniform not-found for a sibling organization,
// and `listOrganizations` narrows to the caller's own organization for a
// confined credential, so the console is never handed an out-of-scope row to
// begin with.
//
// That makes the CLIENT's obligation narrow and precise, which is what this
// file pins: having been given a scoped answer, the console must not widen it
// again. There are exactly two ways it could, and both are real bug classes
// rather than hypotheticals:
//
//   1. RETENTION. A list rendered under one scope survives a switch to another,
//      so an administrator sees the previous scope's rows under the new scope's
//      heading. Nothing about the server's narrowing prevents this; the rows
//      were legitimately delivered, once.
//   2. SYNTHESIS. The view invents a row the server did not send (a placeholder,
//      a default, an optimistic entry that outlives its failed write).
//
// Asserting "the view renders what the API returned" would be close to
// tautological. Asserting that it renders NOTHING ELSE, across a scope change,
// is the part that can actually break.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render } from "preact";
import { OrganizationsList } from "../src/ui/OrganizationsView";
import { activeScope, resetScope } from "../src/scope/store";

interface Call {
  url: string;
  method: string;
}

let container: HTMLDivElement | null = null;
const realFetch = globalThis.fetch;

function mount(node: Parameters<typeof render>[0]): HTMLDivElement {
  container = document.createElement("div");
  document.body.appendChild(container);
  render(node, container);
  return container;
}

function setManagementBase(url: string): void {
  let el = document.querySelector('meta[name="ironauth-management-base"]');
  if (el === null) {
    el = document.createElement("meta");
    el.setAttribute("name", "ironauth-management-base");
    document.head.appendChild(el);
  }
  el.setAttribute("content", url);
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/// One organization row in the shape the list endpoint returns.
function org(id: string, displayName: string): Record<string, unknown> {
  return {
    id,
    tenant_id: "ten_a",
    environment_id: "env_a",
    display_name: displayName,
    active: true,
    created_at_unix_ms: 1,
  };
}

/// Answer each organizations list with whatever the current scope maps to, so a
/// scope switch changes the server's answer exactly as it would in production.
function stubByScope(byEnvironment: Record<string, unknown[]>): Call[] {
  const calls: Call[] = [];
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.toString()
          : (input as Request).url;
    calls.push({ url, method: "GET" });
    const environment = Object.keys(byEnvironment).find((id) =>
      url.includes(`/environments/${id}/`),
    );
    return json({ items: environment ? byEnvironment[environment] : [], next_cursor: null });
  }) as typeof globalThis.fetch;
  return calls;
}

async function flush(): Promise<void> {
  for (let i = 0; i < 6; i += 1) {
    await Promise.resolve();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
  }
}

beforeEach(() => {
  setManagementBase("http://management.test/admin/api");
  activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
});

afterEach(() => {
  if (container !== null) {
    render(null, container);
    container.remove();
    container = null;
  }
  globalThis.fetch = realFetch;
  resetScope();
  vi.restoreAllMocks();
});

describe("the console shows a scoped administrator only in-scope resources", () => {
  it("renders exactly the organizations the server returned and invents none", async () => {
    stubByScope({ env_a: [org("org_only", "Globex")] });
    const root = mount(<OrganizationsList />);
    await flush();

    expect(root.textContent).toContain("Globex");
    // A confined credential's page is ONE row. Any second row would be the
    // console's own invention, since the server sent exactly one. Counted on the
    // class the list actually renders (`li.resource-row`); the first draft of
    // this looked for a `data-testid` that does not exist, so the assertion sat
    // behind a branch that never ran.
    expect(root.querySelectorAll("li.resource-row").length).toBe(1);
  });

  it("does not keep the previous scope's organizations after a scope switch", async () => {
    stubByScope({
      env_a: [org("org_a", "Alpha Corp")],
      env_b: [org("org_b", "Beta Corp")],
    });
    const root = mount(<OrganizationsList />);
    await flush();
    expect(root.textContent).toContain("Alpha Corp");

    // Switch to a scope whose answer shares NOTHING with the first.
    activeScope.value = { tenantId: "ten_a", environmentId: "env_b" };
    await flush();

    expect(root.textContent).toContain("Beta Corp");
    expect(root.textContent).not.toContain("Alpha Corp");
  });

  it("shows nothing rather than a stale row when the new scope administers none", async () => {
    stubByScope({ env_a: [org("org_a", "Alpha Corp")], env_b: [] });
    const root = mount(<OrganizationsList />);
    await flush();
    expect(root.textContent).toContain("Alpha Corp");

    // A confined credential whose organization is not live gets an EMPTY page
    // (see the server change in #605). The console must render that emptiness
    // rather than the rows it happened to be holding.
    //
    // What this pins, measured rather than assumed: the EMPTY-STATE path, which
    // is a different path from the one above. The list has an `empty` branch
    // keyed on `page.items.length === 0`, so when the new scope answers with
    // nothing the row rendering never runs at all. A retention bug injected into
    // that row rendering is caught by the previous test and NOT by this one; the
    // two cover different halves and neither is redundant.
    activeScope.value = { tenantId: "ten_a", environmentId: "env_b" };
    await flush();

    expect(root.textContent).not.toContain("Alpha Corp");
  });
});
