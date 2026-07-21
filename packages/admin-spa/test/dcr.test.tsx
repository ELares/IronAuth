// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The clients (DCR) surface (issue #90, PR 6) is SCOPED to the active
// {tenant, environment} and is DYNAMIC CLIENT REGISTRATION, not generic client
// CRUD. These tests set the scope store and assert, through a stubbed fetch, that
// every assertion is a concrete URL, body, or DOM node: a registered-client
// lookup GETs the documented client path and the verify POSTs the documented
// verify path; a policy create submits the documented path and body; and minting
// an initial access token surfaces the returned token value ONCE in the UI while
// NEVER writing it to localStorage or sessionStorage (the copy-once, memory-only
// credential posture).

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render } from "preact";
import { ClientsList } from "../src/ui/ClientsView";
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

const noPolicies = { items: [] };

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

describe("looking up and verifying a registered client", () => {
  it("GETs the documented client path, then POSTs the verify path on confirm", async () => {
    activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
    const calls = stubFetch((call) => {
      if (call.url.endsWith("/verify")) {
        return json({ id: "cli_a", quarantined: false, verified: true });
      }
      if (call.url.includes("/clients/cli_a")) {
        return json({ id: "cli_a", quarantined: true, verified: false });
      }
      return json(noPolicies);
    });
    const root = mount(<ClientsList />);
    await flush();

    const input = root.querySelector("#dcr-client-id") as HTMLInputElement;
    input.value = "cli_a";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();

    button(root, "Look up client").click();
    await flush();

    const get = calls.find(
      (call) => call.method === "GET" && call.url.includes("/clients/cli_a"),
    );
    expect(get).toBeDefined();
    expect(get?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/clients/cli_a",
    );

    button(root, "Verify client").click();
    await flush();
    button(root, "Confirm verify").click();
    await flush();

    const post = calls.find((call) => call.method === "POST");
    expect(post).toBeDefined();
    expect(post?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/clients/cli_a/verify",
    );
    expect(post?.idempotencyKey).toBeTruthy();
  });
});

describe("creating a DCR policy", () => {
  it("submits createDcrPolicy to the documented path with the name and primitives", async () => {
    activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
    const calls = stubFetch((call) =>
      call.method === "POST"
        ? json(
            { id: "pol_a", name: "force-pkce", primitives: [], created_at_unix_ms: 0 },
            201,
          )
        : json(noPolicies),
    );
    const root = mount(<ClientsList />);
    await flush();

    const name = root.querySelector("#dcr-policy-name") as HTMLInputElement;
    name.value = "force-pkce";
    name.dispatchEvent(new Event("input", { bubbles: true }));
    const primitives = root.querySelector(
      "#dcr-policy-primitives",
    ) as HTMLTextAreaElement;
    primitives.value = '[{"kind":"reject","property":"redirect_uris"}]';
    primitives.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();

    button(root, "Create policy").click();
    await flush();

    const post = calls.find((call) => call.method === "POST");
    expect(post).toBeDefined();
    expect(post?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/dcr/policies",
    );
    expect(post?.idempotencyKey).toBeTruthy();
    const body = JSON.parse(post?.body ?? "{}") as Record<string, unknown>;
    expect(body.name).toBe("force-pkce");
    expect(body.primitives).toEqual([
      { kind: "reject", property: "redirect_uris" },
    ]);
  });
});

describe("minting an initial access token", () => {
  it("surfaces the returned token once and never writes it to storage", async () => {
    activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
    const secret = "iat-plaintext-bearer-value";
    const calls = stubFetch((call) => {
      if (call.url.endsWith("/initial-access-tokens")) {
        return json(
          {
            id: "iat_a",
            token: secret,
            token_already_issued: false,
            expires_at_unix_ms: 1000,
            created_at_unix_ms: 0,
          },
          201,
        );
      }
      return json(noPolicies);
    });
    // Watch every storage write: the credential must never be persisted.
    const setItem = vi.spyOn(Storage.prototype, "setItem");

    const root = mount(<ClientsList />);
    await flush();

    button(root, "Mint token").click();
    await flush();

    const post = calls.find(
      (call) =>
        call.method === "POST" && call.url.endsWith("/initial-access-tokens"),
    );
    expect(post).toBeDefined();
    expect(post?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/dcr/initial-access-tokens",
    );

    // The token value is surfaced ONCE in the UI ...
    expect(root.textContent).toContain(secret);
    const tokenCell = root.querySelector(".resource-token-value");
    expect(tokenCell?.textContent).toBe(secret);

    // ... but is NEVER written to localStorage or sessionStorage.
    const persistedTheToken = setItem.mock.calls.some((args) =>
      args.some((arg) => typeof arg === "string" && arg.includes(secret)),
    );
    expect(persistedTheToken).toBe(false);
  });
});
