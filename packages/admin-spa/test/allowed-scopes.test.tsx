// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The per client scope allowlist panel (issue #98) is a step on the clients (DCR)
// surface, SCOPED to the active {tenant, environment}. These tests set the scope
// store and assert, through a stubbed fetch, that the panel keeps the THREE server
// states distinct end to end: `null` (no allowlist), a list, and the EMPTY list. The
// last two are one keystroke apart in the editor and mean opposite things, so both
// are driven separately and the request BODY is asserted, not just the status.
//
// The fail safe read is covered here too, because the console is where a repaired
// value would mislead: a server that answers `[]` (which is what it answers for a
// stored value it could not parse) must render as "may request no scope at all", not
// as unrestricted.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render } from "preact";
import { ClientsList } from "../src/ui/ClientsView";
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

function button(root: HTMLElement, label: string): HTMLButtonElement {
  const found = Array.from(root.querySelectorAll("button")).find(
    (element) => element.textContent === label,
  );
  if (found === undefined) {
    throw new Error(`no button labelled ${label}`);
  }
  return found;
}

/// Load the allowlist of `cli_a` into the panel, with the server answering `stored`.
async function loadPanel(stored: string[] | null): Promise<{
  root: HTMLDivElement;
  calls: Call[];
}> {
  activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
  const calls = stubFetch((call) => {
    if (call.url.includes("/allowed-scopes")) {
      if (call.method === "PUT") {
        const sent = JSON.parse(call.body ?? "{}") as {
          allowed_scopes: string[] | null;
        };
        return json({ client_id: "cli_a", allowed_scopes: sent.allowed_scopes });
      }
      return json({ client_id: "cli_a", allowed_scopes: stored });
    }
    if (call.url.includes("/interop/signing-recommendations")) {
      return json([]);
    }
    return json({ items: [] });
  });
  const root = mount(<ClientsList />);
  await flush();
  const input = root.querySelector(
    "#allowed-scopes-client-id",
  ) as HTMLInputElement;
  input.value = "cli_a";
  input.dispatchEvent(new Event("input", { bubbles: true }));
  await flush();
  button(root, "Load allowlist").click();
  await flush();
  return { root, calls };
}

/// The most recent PUT to the allowed-scopes path.
function lastPut(calls: Call[]): Call {
  const puts = calls.filter(
    (call) => call.method === "PUT" && call.url.includes("/allowed-scopes"),
  );
  const put = puts.at(-1);
  if (put === undefined) {
    throw new Error("no PUT to the allowed-scopes path");
  }
  return put;
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
  vi.restoreAllMocks();
});

describe("the panel keeps the three server states distinct", () => {
  it("renders a null allowlist as unrestricted and a stored list verbatim", async () => {
    const { root } = await loadPanel(["read:orders", "write:orders"]);
    expect(root.textContent).toContain("read:orders, write:orders");

    const editor = root.querySelector(
      "#allowed-scopes-list",
    ) as HTMLTextAreaElement;
    expect(editor.value).toBe("read:orders\nwrite:orders");
  });

  it("renders an EMPTY allowlist as 'no scope at all', never as unrestricted", async () => {
    // This is the fail safe direction as the console sees it: the server answers
    // `[]` for a stored value it could not parse, and the panel must say the client
    // is locked down rather than repairing it to "unrestricted".
    const { root } = await loadPanel([]);
    expect(root.textContent).toContain("may request no scope at all");
    expect(root.textContent).not.toContain(
      "every scope passes the machine grant floor",
    );
  });

  it("renders a null allowlist as unrestricted", async () => {
    const { root } = await loadPanel(null);
    expect(root.textContent).toContain(
      "no allowlist: every scope passes the machine grant floor",
    );
  });
});

describe("the two write paths are distinct requests", () => {
  it("PUTs the documented path with the entered list, one scope per line", async () => {
    const { root, calls } = await loadPanel(null);
    const editor = root.querySelector(
      "#allowed-scopes-list",
    ) as HTMLTextAreaElement;
    // Blank lines and stray whitespace are dropped rather than sent as entries the
    // server would refuse.
    editor.value = "read:orders\n\n  write:orders  \n";
    editor.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();
    button(root, "Set allowlist").click();
    await flush();

    const put = lastPut(calls);
    expect(put.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/clients/cli_a/allowed-scopes",
    );
    expect(JSON.parse(put.body ?? "{}")).toEqual({
      allowed_scopes: ["read:orders", "write:orders"],
    });
    expect(root.textContent).toContain("Allowlist set to 2 scopes.");
  });

  it("SETTING an empty editor sends [] and CLEARING sends null: two different bodies", async () => {
    const { root, calls } = await loadPanel(["read:orders"]);
    const editor = root.querySelector(
      "#allowed-scopes-list",
    ) as HTMLTextAreaElement;
    editor.value = "";
    editor.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();
    button(root, "Set allowlist").click();
    await flush();
    expect(JSON.parse(lastPut(calls).body ?? "{}")).toEqual({
      allowed_scopes: [],
    });

    // CLEAR is a different button and a different body. It is confirm gated,
    // because it removes the restriction entirely.
    button(root, "Clear the allowlist").click();
    await flush();
    button(root, "Confirm clear").click();
    await flush();
    expect(JSON.parse(lastPut(calls).body ?? "{}")).toEqual({
      allowed_scopes: null,
    });
  });
});

describe("a failing write renders through the ErrorView boundary", () => {
  it("renders the verbatim server refusal of an unmatchable entry", async () => {
    activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
    const message =
      "the allowed_scopes entry `read orders` contains whitespace: a requested scope is split on whitespace, so this entry could never match. List each scope token separately";
    stubFetch((call) => {
      if (call.url.includes("/allowed-scopes")) {
        if (call.method === "PUT") {
          return json({ error: "bad_request", message }, 400);
        }
        return json({ client_id: "cli_a", allowed_scopes: null });
      }
      if (call.url.includes("/interop/signing-recommendations")) {
        return json([]);
      }
      return json({ items: [] });
    });
    const root = mount(<ClientsList />);
    await flush();
    const input = root.querySelector(
      "#allowed-scopes-client-id",
    ) as HTMLInputElement;
    input.value = "cli_a";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();
    button(root, "Load allowlist").click();
    await flush();

    const editor = root.querySelector(
      "#allowed-scopes-list",
    ) as HTMLTextAreaElement;
    editor.value = "read orders";
    editor.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();
    button(root, "Set allowlist").click();
    await flush();

    expect(root.textContent).toContain(message);
  });
});
