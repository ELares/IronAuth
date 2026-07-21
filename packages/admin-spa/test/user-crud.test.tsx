// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The users CRUD surface (issue #90, PR 5) is SCOPED to the active
// {tenant, environment} from the switcher. These tests set the scope store and
// assert, through a stubbed fetch, that every assertion is a concrete URL, body,
// or DOM node: the list targets the active env's documented path and makes NO
// call with no scope, a create submits the documented POST body with an
// Idempotency-Key, a PATCH update submits only the accepted `claims`, a session
// revoke fires the documented POST only after an explicit confirm, and a mutation
// failure renders the verbatim ErrorView (a hostile message stays inert text).

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render } from "preact";
import { UserDetail, UsersList } from "../src/ui/UsersView";
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

const user = {
  id: "usr_a",
  tenant_id: "ten_a",
  environment_id: "env_a",
  identifier: "ada@example.test",
  state: "active",
  external_id: null,
  created_at_unix_ms: 0,
  updated_at_unix_ms: 0,
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

describe("the users list", () => {
  it("scopes the list to the active tenant and environment", async () => {
    activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
    const calls = stubFetch(() => json({ items: [user] }));
    const root = mount(<UsersList />);
    await flush();

    const get = calls.find((call) => call.method === "GET");
    expect(get).toBeDefined();
    expect(get?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/users",
    );
    expect(root.textContent).toContain("ada@example.test");
    const links = Array.from(root.querySelectorAll(".resource-link")).map((a) =>
      a.getAttribute("href"),
    );
    expect(links).toEqual(["/users/usr_a"]);
  });

  it("prompts to select a scope and makes no call when none is active", async () => {
    activeScope.value = null;
    const calls = stubFetch(() => json({ items: [] }));
    const root = mount(<UsersList />);
    await flush();

    expect(root.textContent).toContain("Select a tenant and environment");
    expect(calls).toHaveLength(0);
  });
});

describe("creating a user", () => {
  it("submits createUser to the env scoped POST with the body and key", async () => {
    activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
    const calls = stubFetch((call) =>
      call.method === "POST" ? json(user, 201) : json({ items: [user] }),
    );
    const root = mount(<UsersList />);
    await flush();

    const input = root.querySelector("#user-identifier") as HTMLInputElement;
    input.value = "grace@example.test";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();

    const form = root.querySelector(".resource-form") as HTMLFormElement;
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await flush();

    const post = calls.find((call) => call.method === "POST");
    expect(post).toBeDefined();
    expect(post?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/users",
    );
    expect(post?.idempotencyKey).toBeTruthy();
    const body = JSON.parse(post?.body ?? "{}") as Record<string, unknown>;
    expect(body.identifier).toBe("grace@example.test");
    expect(body.state).toBe("active");
  });
});

describe("updating a user's claims", () => {
  it("PATCHes only the claims merge patch to the documented path", async () => {
    activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
    const calls = stubFetch((call) =>
      call.method === "PATCH" ? json(user) : json(user),
    );
    const root = mount(<UserDetail userId="usr_a" />);
    await flush();

    const textarea = root.querySelector("#user-claims") as HTMLTextAreaElement;
    textarea.value = '{"given_name":"Ada"}';
    textarea.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();

    button(root, "Update claims").click();
    await flush();

    const patch = calls.find((call) => call.method === "PATCH");
    expect(patch).toBeDefined();
    expect(patch?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/users/usr_a",
    );
    const body = JSON.parse(patch?.body ?? "{}") as Record<string, unknown>;
    expect(Object.keys(body)).toEqual(["claims"]);
    expect(body.claims).toEqual({ given_name: "Ada" });
  });
});

describe("revoking a user's sessions", () => {
  it("fires the documented POST only after an explicit confirm", async () => {
    activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
    const calls = stubFetch((call) => {
      if (call.method === "POST") {
        return json({ subject: "usr_a", revoked: true, hard_kill: false });
      }
      return json(user);
    });
    const root = mount(<UserDetail userId="usr_a" />);
    await flush();

    // Arming the revoke does not call the server ...
    button(root, "Revoke sessions").click();
    await flush();
    expect(calls.some((call) => call.method === "POST")).toBe(false);

    // ... the explicit confirm does.
    button(root, "Confirm revoke").click();
    await flush();
    const post = calls.find((call) => call.method === "POST");
    expect(post).toBeDefined();
    expect(post?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/users/usr_a/sessions/revoke",
    );
    expect(post?.idempotencyKey).toBeTruthy();
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
      return json(user);
    });
    const root = mount(<UserDetail userId="usr_a" />);
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
