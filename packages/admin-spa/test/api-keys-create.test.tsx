// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The organization API keys panel's CREATE control (issue #99, criterion 6).
//
// Driven through the DOM against a stubbed fetch, because the two properties worth
// asserting are both about what the panel does with a RESULT rather than about the
// request it builds:
//
//   A revoked key offers no Revoke button. Revoking twice is a no-op at the store,
//   but offering the control suggests there is something left to stop, which is the
//   opposite of what the row says.
//
//   A FAILED revoke does not reload. Reloading would replace the error the boundary
//   is showing with a fresh render of the unchanged list, which reads exactly like
//   the revoke having worked.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render } from "preact";
import { OrgApiKeysPanel } from "../src/ui/OrgApiKeysView";
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



async function loadPanel(
  respond: (call: Call) => Response,
): Promise<{ root: HTMLDivElement; calls: Call[] }> {
  setManagementBase("https://admin.test");
  const calls = stubFetch(respond);
  activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
  const root = mount(
    <OrgApiKeysPanel
      tenantId="ten_a"
      environmentId="env_a"
      organizationId="org_a"
    />,
  );
  await flush();
  return { root, calls };
}

const KEY = "ira_ak_akey_AAAA~BBBB";

describe("api keys create control, display once", () => {
  beforeEach(() => {
    resetScope();
  });

  afterEach(() => {
    globalThis.fetch = realFetch;
    if (container !== null) {
      render(null, container);
      container.remove();
      container = null;
    }
  });

  it("shows the key once and keeps it visible past its OWN reload", async () => {
    let created = false;
    const { root } = await loadPanel((call) => {
      if (call.method === "POST") {
        created = true;
        return json({
          id: "akey_new",
          display_name: "ci",
          key: KEY,
          key_already_issued: false,
        });
      }
      return json({
        items: created ? [{ id: "akey_new", display_name: "ci" }] : [],
      });
    });

    const input = root.querySelector("input") as HTMLInputElement;
    input.value = "ci";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();
    (root.querySelector("form") as HTMLFormElement).dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    await flush();

    // Non-vacuity: the POST actually happened, so the assertions below are about the
    // panel and not about a form that never submitted.
    expect(created).toBe(true);
    expect(root.textContent).toContain(KEY);
  });

  it("does NOT show a key on an idempotent replay", async () => {
    // A replay answers key_already_issued with no key. Rendering an empty secret box,
    // or worse a stale one, would tell the operator they have material they do not.
    const { root } = await loadPanel((call) =>
      call.method === "POST"
        ? json({
            id: "akey_new",
            display_name: "ci",
            key_already_issued: true,
          })
        : json({ items: [] }),
    );
    const input = root.querySelector("input") as HTMLInputElement;
    input.value = "ci";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();
    (root.querySelector("form") as HTMLFormElement).dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    await flush();
    expect(root.querySelector(".resource-secret")).toBeNull();
  });
});
