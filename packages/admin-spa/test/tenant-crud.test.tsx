// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The tenants CRUD surface (issue #90, PR 4), exercised through the ONE typed
// client with a stubbed fetch so every assertion is a concrete URL, body, or DOM
// node: the list renders items and an empty state, the create form submits the
// documented POST with the right body, a delete only fires after an explicit
// confirm and targets the documented path, and a mutation failure renders the
// verbatim ErrorView (a hostile message stays inert text).

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render } from "preact";
import { TenantDetail, TenantsList } from "../src/ui/TenantsView";
import { resetScope } from "../src/scope/store";

interface Call {
  url: string;
  method: string;
  body: string | null;
}

let container: HTMLDivElement | null = null;
const realFetch = globalThis.fetch;

function mount(node: Parameters<typeof render>[0]): HTMLDivElement {
  container = document.createElement("div");
  document.body.appendChild(container);
  render(node, container);
  return container;
}

// The app never hardcodes a base; this feeds loadConfig's <meta> reader so jsdom
// can parse the absolute URL the client forms inside the test DOM.
function setManagementBase(url: string): void {
  let el = document.querySelector('meta[name="ironauth-management-base"]');
  if (el === null) {
    el = document.createElement("meta");
    el.setAttribute("name", "ironauth-management-base");
    document.head.appendChild(el);
  }
  el.setAttribute("content", url);
}

function stubFetch(respond: (call: Call) => Response): Call[] {
  const calls: Call[] = [];
  globalThis.fetch = vi.fn(
    async (input: RequestInfo | URL): Promise<Response> => {
      const request = input as Request;
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : request.url;
      const method = input instanceof Request ? request.method : "GET";
      let body: string | null = null;
      if (input instanceof Request) {
        const text = await input.clone().text();
        body = text === "" ? null : text;
      }
      const call: Call = { url, method, body };
      calls.push(call);
      return respond(call);
    },
  ) as typeof globalThis.fetch;
  return calls;
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function noContent(): Response {
  return new Response(null, { status: 204, headers: { "content-length": "0" } });
}

// Flush Preact's scheduled renders and the chained fetch/json microtasks.
async function flush(): Promise<void> {
  for (let i = 0; i < 6; i += 1) {
    await Promise.resolve();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
  }
}

function button(root: HTMLElement, label: string): HTMLButtonElement {
  const found = Array.from(root.querySelectorAll("button")).find(
    (element) => element.textContent === label,
  );
  if (found === undefined) {
    throw new Error(`no button labelled ${label}`);
  }
  return found;
}

beforeEach(() => {
  setManagementBase("http://management.test/admin/api");
});

afterEach(() => {
  if (container !== null) {
    render(null, container);
    container.remove();
    container = null;
  }
  globalThis.fetch = realFetch;
  resetScope();
});

const tenant = {
  id: "ten_a",
  display_name: "Acme",
  status: "active",
  created_at_unix_ms: 0,
};

describe("the tenants list", () => {
  it("renders each tenant with a detail link", async () => {
    stubFetch(() =>
      json({
        items: [
          tenant,
          {
            id: "ten_b",
            display_name: "Globex",
            status: "suspended",
            created_at_unix_ms: 0,
          },
        ],
      }),
    );
    const root = mount(<TenantsList />);
    await flush();
    expect(root.textContent).toContain("Acme");
    expect(root.textContent).toContain("Globex");
    const links = Array.from(root.querySelectorAll(".resource-link")).map((a) =>
      a.getAttribute("href"),
    );
    expect(links).toEqual(["/tenants/ten_a", "/tenants/ten_b"]);
  });

  it("shows the empty state when there are no tenants", async () => {
    stubFetch(() => json({ items: [] }));
    const root = mount(<TenantsList />);
    await flush();
    expect(root.textContent).toContain("No tenants yet");
    expect(root.querySelector(".resource-list")).toBeNull();
  });
});

describe("creating a tenant", () => {
  it("submits createTenant to POST /v1/tenants with the entered body", async () => {
    const calls = stubFetch((call) =>
      call.method === "POST"
        ? json({ tenant, environment: {} }, 201)
        : json({ items: [] }),
    );
    const root = mount(<TenantsList />);
    await flush();

    const input = root.querySelector("#tenant-display-name") as HTMLInputElement;
    input.value = "Acme";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();

    const form = root.querySelector(".resource-form") as HTMLFormElement;
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await flush();

    const post = calls.find((call) => call.method === "POST");
    expect(post).toBeDefined();
    expect(post?.url).toContain("/v1/tenants");
    const body = JSON.parse(post?.body ?? "{}") as Record<string, unknown>;
    expect(body.display_name).toBe("Acme");
    expect(body.environment_kind).toBe("dev");
    expect(root.textContent).toContain("Tenant created.");
  });
});

describe("deleting a tenant", () => {
  it("fires DELETE /v1/tenants/:id only after an explicit confirm", async () => {
    const calls = stubFetch((call) => {
      if (call.method === "DELETE") {
        return noContent();
      }
      if (call.method === "GET") {
        return json(tenant);
      }
      return json({ items: [] });
    });
    const root = mount(<TenantDetail tenantId="ten_a" />);
    await flush();
    expect(root.textContent).toContain("Acme");

    // Arming the delete does not call the server ...
    button(root, "Delete").click();
    await flush();
    expect(calls.some((call) => call.method === "DELETE")).toBe(false);

    // ... the explicit confirm does.
    button(root, "Confirm delete").click();
    await flush();
    const del = calls.find((call) => call.method === "DELETE");
    expect(del).toBeDefined();
    expect(del?.url).toContain("/v1/tenants/ten_a");
  });
});

describe("a mutation failure", () => {
  it("renders the verbatim ErrorView, a hostile message staying inert text", async () => {
    const hostile = '<img src=x onerror="steal()"> and <script>evil()</script>';
    stubFetch((call) => {
      if (call.method === "DELETE") {
        return json({ error: "forbidden", message: hostile }, 403);
      }
      if (call.method === "GET") {
        return json(tenant);
      }
      return json({ items: [] });
    });
    const root = mount(<TenantDetail tenantId="ten_a" />);
    await flush();
    button(root, "Delete").click();
    await flush();
    button(root, "Confirm delete").click();
    await flush();

    expect(root.querySelector(".errorbody")).not.toBeNull();
    expect(root.textContent).toContain(hostile);
    expect(root.querySelector("img")).toBeNull();
    expect(root.querySelector("script")).toBeNull();
  });
});
