// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The diagnostics client-authentication panel (issue #91, M9 flow inspector) is
// SCOPED to the active {tenant, environment} from the switcher. These tests set the
// scope store and assert, through a stubbed fetch, that every assertion is a concrete
// URL or DOM node: the list targets the active env's documented path and makes NO
// call with no scope, applying a client-id filter adds the documented query param,
// the records render their rich reason / kid / alg / skew / instant, an attacker
// influenced kid and client id render as INERT text, and both a verbatim ErrorBody
// and a bodyless non-2xx render the ErrorView boundary.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render } from "preact";
import { DiagnosticsView } from "../src/ui/DiagnosticsView";
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
      const call: Call = { url, method };
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

const record = {
  client_id: "cli_acme",
  auth_method: "private_key_jwt",
  reason: "assertion_kid_unknown",
  key_id: "kid-42",
  signing_alg: "EdDSA",
  occurred_at_unix_micros: 1_700_000_000_000_000,
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

describe("the diagnostics client-auth panel", () => {
  it("scopes the read to the active tenant and environment and renders the records", async () => {
    activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
    const calls = stubFetch(() => json({ items: [record] }));
    const root = mount(<DiagnosticsView />);
    await flush();

    const get = calls.find((call) => call.method === "GET");
    expect(get).toBeDefined();
    expect(get?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/diagnostics/client-auth",
    );
    // The rich, off-the-wire detail is rendered.
    expect(root.textContent).toContain("assertion_kid_unknown");
    expect(root.textContent).toContain("kid-42");
    expect(root.textContent).toContain("EdDSA");
    expect(root.textContent).toContain("cli_acme");
    expect(root.textContent).toContain("2023-11-14T");
  });

  it("flags a truncated result so the cap is never silent", async () => {
    activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
    stubFetch(() => json({ items: [record], truncated: true }));
    const root = mount(<DiagnosticsView />);
    await flush();

    expect(root.textContent).toContain("Older matching failures were left out");
  });

  it("prompts to select a scope and makes no call when none is active", async () => {
    activeScope.value = null;
    const calls = stubFetch(() => json({ items: [] }));
    const root = mount(<DiagnosticsView />);
    await flush();

    expect(root.textContent).toContain("Select a tenant and environment");
    expect(calls).toHaveLength(0);
  });

  it("adds the client_id query param when a filter is applied", async () => {
    activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
    const calls = stubFetch(() => json({ items: [record] }));
    const root = mount(<DiagnosticsView />);
    await flush();

    const input = root.querySelector(
      "#diagnostics-client-id",
    ) as HTMLInputElement;
    input.value = "cli_acme";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();

    button(root, "Apply filter").click();
    await flush();

    const filtered = calls.find((call) => call.url.includes("client_id="));
    expect(filtered).toBeDefined();
    expect(filtered?.url).toContain("client_id=cli_acme");
    expect(filtered?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/diagnostics/client-auth",
    );
  });

  it("renders an attacker influenced kid and client id as inert text", async () => {
    activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
    const hostile = {
      client_id: '<img src=x onerror="steal()">',
      auth_method: "private_key_jwt",
      reason: "assertion_kid_unknown",
      key_id: "<script>evil()</script>",
      signing_alg: "EdDSA",
      occurred_at_unix_micros: 1_700_000_000_000_000,
    };
    stubFetch(() => json({ items: [hostile] }));
    const root = mount(<DiagnosticsView />);
    await flush();

    // The hostile strings appear VERBATIM as text, but never as live DOM nodes.
    expect(root.textContent).toContain('<img src=x onerror="steal()">');
    expect(root.textContent).toContain("<script>evil()</script>");
    expect(root.querySelector("img")).toBeNull();
    expect(root.querySelector("script")).toBeNull();
  });

  it("renders a verbatim ErrorBody, a hostile message staying inert text", async () => {
    activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
    const hostile = '<img src=x onerror="steal()"> and <script>evil()</script>';
    stubFetch(() => json({ error: "forbidden", message: hostile }, 403));
    const root = mount(<DiagnosticsView />);
    await flush();

    expect(root.querySelector(".errorbody")).not.toBeNull();
    expect(root.textContent).toContain(hostile);
    expect(root.querySelector("img")).toBeNull();
    expect(root.querySelector("script")).toBeNull();
  });

  it("treats a bodyless non-2xx as a failure, not an empty list", async () => {
    activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
    // A 502 with NO body (Content-Length 0): openapi-fetch yields error undefined, so
    // only the response.ok guard catches it. It must render the error boundary, never
    // a silent empty list read as success.
    stubFetch(() => new Response(null, { status: 502 }));
    const root = mount(<DiagnosticsView />);
    await flush();

    expect(root.querySelector(".errorbody")).not.toBeNull();
    expect(root.textContent).not.toContain(
      "No recorded client authentication failures",
    );
  });
});
