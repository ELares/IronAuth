// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The invitations CRUD surface (issue #94, issue #60), exercised through the ONE
// typed client with a stubbed fetch so every assertion is a concrete URL, body,
// or DOM node: the list renders items, the state filter narrows the read, the
// create form surfaces the copy-once token exactly once (and never leaks it into a
// URL), and a pending invitation resends (minting a fresh token) and revokes after
// an explicit confirm through the documented paths.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render } from "preact";
import { InvitationsList } from "../src/ui/InvitationsView";
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

const invitation = {
  id: "inv_a",
  target_identifier: "ada@example.test",
  state: "pending",
  credential_type: "password",
  tenant_id: "ten_a",
  environment_id: "env_a",
  user_id: "usr_a",
  expires_at_unix_ms: 0,
  created_at_unix_ms: 0,
  updated_at_unix_ms: 0,
};

describe("the invitations list", () => {
  it("prompts and makes zero calls when no scope is selected", async () => {
    resetScope();
    const calls = stubFetch(() => json({ items: [] }));
    const root = mount(<InvitationsList />);
    await flush();
    expect(root.textContent).toContain("Select a tenant and environment");
    expect(calls.length).toBe(0);
  });

  it("renders each invitation with its identifier and state", async () => {
    stubFetch(() => json({ items: [invitation] }));
    const root = mount(<InvitationsList />);
    await flush();
    expect(root.textContent).toContain("ada@example.test");
    expect(root.textContent).toContain("inv_a");
  });

  it("narrows the read to the selected lifecycle state", async () => {
    const calls = stubFetch(() => json({ items: [invitation] }));
    const root = mount(<InvitationsList />);
    await flush();

    const select = root.querySelector(
      "#invitation-state-filter",
    ) as HTMLSelectElement;
    select.value = "pending";
    select.dispatchEvent(new Event("change", { bubbles: true }));
    await flush();

    const filtered = calls.find(
      (call) => call.method === "GET" && call.url.includes("state=pending"),
    );
    expect(filtered).toBeDefined();
    expect(filtered?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/invitations",
    );
  });
});

describe("creating an invitation", () => {
  it("surfaces the copy-once token once and never puts it in a URL", async () => {
    const secret = "ira_inv_super_secret_value";
    const calls = stubFetch((call) =>
      call.method === "POST"
        ? json({ invitation, token: secret }, 201)
        : json({ items: [] }),
    );
    const root = mount(<InvitationsList />);
    await flush();

    const input = root.querySelector(
      "#invitation-identifier",
    ) as HTMLInputElement;
    input.value = "ada@example.test";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();

    button(root, "Create invitation").click();
    await flush();

    const post = calls.find((call) => call.method === "POST");
    expect(post?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/invitations",
    );
    const bodyObj = JSON.parse(post?.body ?? "{}") as Record<string, unknown>;
    expect(bodyObj.identifier).toBe("ada@example.test");

    // The raw token is surfaced exactly once as copy-once text ...
    expect(root.textContent).toContain(secret);
    expect(root.textContent).toContain("shown only once");
    // ... and never leaks into any request URL (memory-only, never in a URL).
    expect(calls.every((call) => !call.url.includes(secret))).toBe(true);
  });

  it("drops the copy-once token when the scope switches", async () => {
    const secret = "ira_inv_scope_bound_secret";
    stubFetch((call) =>
      call.method === "POST"
        ? json({ invitation, token: secret }, 201)
        : json({ items: [] }),
    );
    const root = mount(<InvitationsList />);
    await flush();

    const input = root.querySelector(
      "#invitation-identifier",
    ) as HTMLInputElement;
    input.value = "ada@example.test";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();
    button(root, "Create invitation").click();
    await flush();
    expect(root.textContent).toContain(secret);

    // Switching tenant/environment in place (a signal update, not a route
    // change) must remount the subtree and drop the prior scope token, never
    // display it under the new scope.
    activeScope.value = { tenantId: "ten_b", environmentId: "env_b" };
    await flush();
    expect(root.textContent).not.toContain(secret);
  });
});

describe("acting on a pending invitation", () => {
  it("resends and surfaces the fresh copy-once token", async () => {
    const fresh = "ira_inv_freshly_minted";
    const calls = stubFetch((call) => {
      if (call.method === "POST") {
        return json({ invitation, token: fresh });
      }
      return json({ items: [invitation] });
    });
    const root = mount(<InvitationsList />);
    await flush();

    button(root, "Resend").click();
    await flush();

    const post = calls.find((call) => call.method === "POST");
    expect(post?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/invitations/inv_a/resend",
    );
    expect(root.textContent).toContain(fresh);
    expect(root.textContent).toContain("Invitation resent.");
  });

  it("revokes only after an explicit confirm through the documented path", async () => {
    // The list read reflects the revoke once it has fired: the reloaded page
    // shows the invitation in its revoked state (and so no longer offers Revoke).
    let revoked = false;
    const calls = stubFetch((call) => {
      if (call.method === "POST") {
        revoked = true;
        return json({ id: "inv_a", state: "revoked" });
      }
      return json({
        items: [{ ...invitation, state: revoked ? "revoked" : "pending" }],
      });
    });
    const root = mount(<InvitationsList />);
    await flush();

    button(root, "Revoke").click();
    await flush();
    expect(calls.some((call) => call.method === "POST")).toBe(false);

    button(root, "Confirm revoke").click();
    await flush();
    const post = calls.find((call) => call.method === "POST");
    expect(post?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/invitations/inv_a/revoke",
    );
    // The reloaded list now shows the invitation as revoked, and a revoked
    // invitation offers no further Revoke action.
    expect(root.textContent).toContain("revoked");
    expect(
      Array.from(root.querySelectorAll("button")).some(
        (b) => b.textContent === "Revoke",
      ),
    ).toBe(false);
  });
});
