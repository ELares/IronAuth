// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The environments CRUD surface (issue #90, PR 4) is SCOPED to the active tenant
// from the switcher. These tests set the scope store's active tenant and assert
// the list targets that tenant's documented path, that no call is made when there
// is no tenant in scope, and that a create submits the documented POST body.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render } from "preact";
import { EnvironmentsList } from "../src/ui/EnvironmentsView";
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

async function flush(): Promise<void> {
  for (let i = 0; i < 6; i += 1) {
    await Promise.resolve();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
  }
}

const environment = {
  id: "env_a",
  tenant_id: "ten_a",
  display_name: "development",
  kind: "dev",
  guardrail_class: "non-production",
  guardrails: {
    allow_insecure_redirect_uris: true,
    require_https_redirect_uris: false,
    require_custom_domain: false,
    one_time_view_secrets: false,
    hosted_pages_noindex: true,
    show_environment_banner: true,
  },
  created_at_unix_ms: 0,
};

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

describe("the environments list", () => {
  it("scopes the list to the active tenant from the switcher", async () => {
    activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
    const calls = stubFetch(() => json({ items: [environment] }));
    const root = mount(<EnvironmentsList />);
    await flush();

    const get = calls.find((call) => call.method === "GET");
    expect(get).toBeDefined();
    expect(get?.url).toContain("/v1/tenants/ten_a/environments");
    expect(root.textContent).toContain("development");
  });

  it("prompts to select a tenant and makes no call when no scope is active", async () => {
    activeScope.value = null;
    const calls = stubFetch(() => json({ items: [] }));
    const root = mount(<EnvironmentsList />);
    await flush();

    expect(root.textContent).toContain("Select a tenant");
    expect(calls).toHaveLength(0);
  });
});

describe("creating an environment", () => {
  it("submits createEnvironment to the tenant scoped POST with the body", async () => {
    activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
    const calls = stubFetch((call) =>
      call.method === "POST"
        ? json(environment, 201)
        : json({ items: [environment] }),
    );
    const root = mount(<EnvironmentsList />);
    await flush();

    const input = root.querySelector("#env-display-name") as HTMLInputElement;
    input.value = "staging";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();

    const form = root.querySelector(".resource-form") as HTMLFormElement;
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await flush();

    const post = calls.find((call) => call.method === "POST");
    expect(post).toBeDefined();
    expect(post?.url).toContain("/v1/tenants/ten_a/environments");
    const body = JSON.parse(post?.body ?? "{}") as Record<string, unknown>;
    expect(body.display_name).toBe("staging");
    expect(body.kind).toBe("dev");
  });
});
