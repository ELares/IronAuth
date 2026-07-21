// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The connectors CRUD surface (issue #90, PR 6) is SCOPED to the active
// {tenant, environment} from the switcher. These tests set the scope store and
// assert, through a stubbed fetch, that every assertion is a concrete URL, body,
// or DOM node: the list targets the active env's documented path and makes NO
// call with no scope, a create submits the documented POST body (a JSON
// definition) with an Idempotency-Key, the full-replace PUT update submits the
// definition to the documented connector path, and a mutation failure renders the
// verbatim ErrorView (a hostile message stays inert text).

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render } from "preact";
import { ConnectorDetail, ConnectorsList } from "../src/ui/ConnectorsView";
import { activeScope, resetScope } from "../src/scope/store";

interface Call {
  url: string;
  method: string;
  body: string | null;
  idempotencyKey: string | null;
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
      let idempotencyKey: string | null = null;
      if (input instanceof Request) {
        const text = await input.clone().text();
        body = text === "" ? null : text;
        idempotencyKey = input.headers.get("idempotency-key");
      }
      const call: Call = { url, method, body, idempotencyKey };
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

function button(root: HTMLElement, label: string): HTMLButtonElement {
  const found = Array.from(root.querySelectorAll("button")).find(
    (element) => element.textContent === label,
  );
  if (found === undefined) {
    throw new Error(`no button labelled ${label}`);
  }
  return found;
}

const connector = {
  id: "cnr_a",
  connector_slug: "acme-oidc",
  definition: {},
  enabled: true,
  capabilities: {
    refresh: true,
    groups: false,
    logout_propagation: false,
    email_verified_trust: "untrusted",
  },
  created_at_unix_ms: 0,
  updated_at_unix_ms: 0,
};

const health = {
  id: "cnr_a",
  state: "healthy",
  consecutive_failures: 0,
  recent_error_rate: 0,
  success_total: 5,
  error_total: 0,
};

// Answer the three detail reads (connector, capabilities, health) by URL suffix.
function detailRead(call: Call): Response {
  if (call.url.endsWith("/health")) {
    return json(health);
  }
  if (call.url.endsWith("/capabilities")) {
    return json(connector.capabilities);
  }
  return json(connector);
}

const definitionJson = JSON.stringify({
  connector_id: "acme-oidc",
  display_name: "Acme",
  protocol: "oidc",
  endpoints: { issuer: "https://issuer.test" },
  scopes: ["openid"],
  client_id: "abc",
  client_secret: "shh",
});

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

describe("the connectors list", () => {
  it("scopes the list to the active tenant and environment", async () => {
    activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
    const calls = stubFetch(() => json({ items: [connector] }));
    const root = mount(<ConnectorsList />);
    await flush();

    const get = calls.find((call) => call.method === "GET");
    expect(get).toBeDefined();
    expect(get?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/connectors",
    );
    expect(root.textContent).toContain("acme-oidc");
    const links = Array.from(root.querySelectorAll(".resource-link")).map((a) =>
      a.getAttribute("href"),
    );
    expect(links).toEqual(["/connectors/cnr_a"]);
  });

  it("prompts to select a scope and makes no call when none is active", async () => {
    activeScope.value = null;
    const calls = stubFetch(() => json({ items: [] }));
    const root = mount(<ConnectorsList />);
    await flush();

    expect(root.textContent).toContain("Select a tenant and environment");
    expect(calls).toHaveLength(0);
  });
});

describe("creating a connector", () => {
  it("submits createConnector to the env scoped POST with the body and key", async () => {
    activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
    const calls = stubFetch((call) =>
      call.method === "POST"
        ? json(connector, 201)
        : json({ items: [connector] }),
    );
    const root = mount(<ConnectorsList />);
    await flush();

    const textarea = root.querySelector(
      "#connector-definition",
    ) as HTMLTextAreaElement;
    textarea.value = definitionJson;
    textarea.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();

    const form = root.querySelector(".resource-form") as HTMLFormElement;
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await flush();

    const post = calls.find((call) => call.method === "POST");
    expect(post).toBeDefined();
    expect(post?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/connectors",
    );
    expect(post?.idempotencyKey).toBeTruthy();
    const body = JSON.parse(post?.body ?? "{}") as Record<string, unknown>;
    expect(body.connector_id).toBe("acme-oidc");
    expect(body.client_secret).toBe("shh");
  });
});

describe("replacing a connector", () => {
  it("PUTs the full definition to the documented connector path", async () => {
    activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
    const calls = stubFetch((call) =>
      call.method === "PUT" ? json(connector) : detailRead(call),
    );
    const root = mount(<ConnectorDetail connectorId="cnr_a" />);
    await flush();

    const textarea = root.querySelector(
      "#connector-update-definition",
    ) as HTMLTextAreaElement;
    textarea.value = definitionJson;
    textarea.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();

    button(root, "Replace connector").click();
    await flush();

    const put = calls.find((call) => call.method === "PUT");
    expect(put).toBeDefined();
    expect(put?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/connectors/cnr_a",
    );
    // The PUT replace is idempotent by construction, so no Idempotency-Key.
    expect(put?.idempotencyKey).toBeNull();
    const body = JSON.parse(put?.body ?? "{}") as Record<string, unknown>;
    expect(body.connector_id).toBe("acme-oidc");
  });
});

describe("a mutation failure", () => {
  it("renders the verbatim ErrorView, a hostile message staying inert text", async () => {
    activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
    const hostile = '<img src=x onerror="steal()"> and <script>evil()</script>';
    stubFetch((call) => {
      if (call.method === "DELETE") {
        return json({ error: "forbidden", message: hostile }, 403);
      }
      return detailRead(call);
    });
    const root = mount(<ConnectorDetail connectorId="cnr_a" />);
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
