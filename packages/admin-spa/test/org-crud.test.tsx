// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The organizations CRUD surface (issue #94), exercised through the ONE typed
// client with a stubbed fetch so every assertion is a concrete URL, body, or DOM
// node: the list renders items and an empty state, the create form submits the
// documented POST with the right body, the disable and enable lifecycle target
// the documented paths, a delete only fires after an explicit confirm, the nested
// memberships panel adds/lists/removes a member, a keyset next_cursor surfaces a
// "more exist" note (no silent truncation), the scoped wrapper forms a fully
// substituted path (no leftover placeholder), and a mutation failure renders the
// verbatim ErrorView (a hostile message stays inert text).

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render } from "preact";
import {
  OrganizationDetail,
  OrganizationsList,
} from "../src/ui/OrganizationsView";
import { activeScope, resetScope } from "../src/scope/store";

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

function setManagementBase(url: string): void {
  let el = document.querySelector('meta[name="ironauth-management-base"]');
  if (el === null) {
    el = document.createElement("meta");
    el.setAttribute("name", "ironauth-management-base");
    document.head.appendChild(el);
  }
  el.setAttribute("content", url);
}

// Set an active {tenant, environment} scope so the env-scoped surface makes its
// calls (with no scope it prompts and makes zero calls, tested separately).
function setScope(): void {
  activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
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
  setScope();
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

const org = {
  id: "org_a",
  display_name: "Globex",
  active: true,
  tenant_id: "ten_a",
  environment_id: "env_a",
  created_at_unix_ms: 0,
};

describe("the organizations list", () => {
  it("prompts and makes zero calls when no scope is selected", async () => {
    resetScope();
    const calls = stubFetch(() => json({ items: [] }));
    const root = mount(<OrganizationsList />);
    await flush();
    expect(root.textContent).toContain("Select a tenant and environment");
    expect(calls.length).toBe(0);
  });

  it("renders each organization with a detail link", async () => {
    stubFetch(() =>
      json({
        items: [
          org,
          { ...org, id: "org_b", display_name: "Initech", active: false },
        ],
      }),
    );
    const root = mount(<OrganizationsList />);
    await flush();
    expect(root.textContent).toContain("Globex");
    expect(root.textContent).toContain("Initech");
    const links = Array.from(root.querySelectorAll(".resource-link")).map((a) =>
      a.getAttribute("href"),
    );
    expect(links).toEqual(["/organizations/org_a", "/organizations/org_b"]);
  });

  it("shows the empty state when there are no organizations", async () => {
    stubFetch(() => json({ items: [] }));
    const root = mount(<OrganizationsList />);
    await flush();
    expect(root.textContent).toContain("No organizations yet");
    expect(root.querySelector(".resource-list")).toBeNull();
  });

  it("surfaces a more-exist note when the read returns a next cursor", async () => {
    stubFetch(() => json({ items: [org], next_cursor: "opaque_cursor_2" }));
    const root = mount(<OrganizationsList />);
    await flush();
    expect(root.textContent).toContain("More organizations exist");
    // The cursor is a pagination token, never surfaced as a value to copy.
    expect(root.textContent).not.toContain("opaque_cursor_2");
  });
});

describe("creating an organization", () => {
  it("submits createOrganization to the documented POST with the entered body", async () => {
    const calls = stubFetch((call) =>
      call.method === "POST" ? json(org, 201) : json({ items: [] }),
    );
    const root = mount(<OrganizationsList />);
    await flush();

    const input = root.querySelector(
      "#organization-display-name",
    ) as HTMLInputElement;
    input.value = "Globex";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();

    button(root, "Create organization").click();
    await flush();

    const post = calls.find((call) => call.method === "POST");
    expect(post).toBeDefined();
    expect(post?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/organizations",
    );
    const bodyObj = JSON.parse(post?.body ?? "{}") as Record<string, unknown>;
    expect(bodyObj.display_name).toBe("Globex");
    expect(root.textContent).toContain("Organization created.");
  });
});

describe("the organization detail", () => {
  it("forms a fully substituted path with no leftover placeholder", async () => {
    const calls = stubFetch(() => json(org));
    const root = mount(<OrganizationDetail organizationId="org_a" />);
    await flush();
    const get = calls.find(
      (call) => call.method === "GET" && !call.url.includes("/memberships"),
    );
    expect(get?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/organizations/org_a",
    );
    // No unsubstituted path parameter survives into the wire URL.
    expect(get?.url).not.toContain("{");
    expect(get?.url).not.toContain("}");
  });

  it("disables an active organization via the documented path after confirm", async () => {
    const calls = stubFetch((call) => {
      if (call.method === "POST") {
        return json({ ...org, active: false });
      }
      if (call.url.includes("/memberships")) {
        return json({ items: [] });
      }
      return json(org);
    });
    const root = mount(<OrganizationDetail organizationId="org_a" />);
    await flush();

    button(root, "Disable").click();
    await flush();
    expect(calls.some((call) => call.method === "POST")).toBe(false);

    button(root, "Confirm disable").click();
    await flush();
    const post = calls.find((call) => call.method === "POST");
    expect(post?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/organizations/org_a/disable",
    );
    expect(root.textContent).toContain("Organization disabled.");
  });

  it("enables a disabled organization via the documented path after confirm", async () => {
    const calls = stubFetch((call) => {
      if (call.method === "POST") {
        return json({ ...org, active: true });
      }
      if (call.url.includes("/memberships")) {
        return json({ items: [] });
      }
      return json({ ...org, active: false });
    });
    const root = mount(<OrganizationDetail organizationId="org_a" />);
    await flush();

    button(root, "Enable").click();
    await flush();
    button(root, "Confirm enable").click();
    await flush();
    const post = calls.find((call) => call.method === "POST");
    expect(post?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/organizations/org_a/enable",
    );
    expect(root.textContent).toContain("Organization enabled.");
  });

  it("fires DELETE only after an explicit confirm", async () => {
    const calls = stubFetch((call) => {
      if (call.method === "DELETE") {
        return noContent();
      }
      if (call.url.includes("/memberships")) {
        return json({ items: [] });
      }
      return json(org);
    });
    const root = mount(<OrganizationDetail organizationId="org_a" />);
    await flush();

    button(root, "Delete").click();
    await flush();
    expect(calls.some((call) => call.method === "DELETE")).toBe(false);

    button(root, "Confirm delete").click();
    await flush();
    const del = calls.find((call) => call.method === "DELETE");
    expect(del).toBeDefined();
    expect(del?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/organizations/org_a",
    );
    expect(del?.url).not.toContain("/disable");
  });

  it("renders the verbatim ErrorView, a hostile message staying inert text", async () => {
    const hostile = '<img src=x onerror="steal()"> and <script>evil()</script>';
    stubFetch((call) => {
      if (call.method === "DELETE") {
        return json({ error: "forbidden", message: hostile }, 403);
      }
      if (call.url.includes("/memberships")) {
        return json({ items: [] });
      }
      return json(org);
    });
    const root = mount(<OrganizationDetail organizationId="org_a" />);
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

describe("the organization memberships panel", () => {
  const member = {
    id: "omb_a",
    user_id: "usr_a",
    organization_id: "org_a",
    state: "active",
    metadata: {},
    created_at_unix_ms: 0,
  };

  it("lists members, adds by user id, and removes after confirm", async () => {
    const calls = stubFetch((call) => {
      if (call.method === "POST") {
        return json(member, 201);
      }
      if (call.method === "DELETE") {
        return noContent();
      }
      if (call.url.includes("/memberships")) {
        return json({ items: [member] });
      }
      return json(org);
    });
    const root = mount(<OrganizationDetail organizationId="org_a" />);
    await flush();

    // The existing member is listed.
    expect(root.textContent).toContain("usr_a");
    expect(root.textContent).toContain("omb_a");

    // Add a member: POST the documented memberships path with the user id body.
    const input = root.querySelector(
      "#membership-user-id",
    ) as HTMLInputElement;
    input.value = "usr_b";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();
    button(root, "Add member").click();
    await flush();
    const post = calls.find((call) => call.method === "POST");
    expect(post?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/organizations/org_a/memberships",
    );
    const addBody = JSON.parse(post?.body ?? "{}") as Record<string, unknown>;
    expect(addBody.user_id).toBe("usr_b");

    // Remove a member: DELETE the documented membership path only after confirm.
    button(root, "Remove").click();
    await flush();
    expect(calls.some((call) => call.method === "DELETE")).toBe(false);
    button(root, "Confirm remove").click();
    await flush();
    const del = calls.find((call) => call.method === "DELETE");
    expect(del?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/organizations/org_a/memberships/omb_a",
    );
  });
});
