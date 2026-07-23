// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The token signing compatibility wizard (issue #93) is a step on the clients
// (DCR) surface, SCOPED to the active {tenant, environment}. These tests set the
// scope store and assert, through a stubbed fetch, that the wizard renders the
// recommendation the SERVER returned (never a hardcoded matrix): choosing AWS API
// Gateway shows RS256 with its reason, choosing a modern JOSE library shows
// EdDSA, confirming PUTs the documented signing-algorithm path with the body
// { algorithm } and an Idempotency-Key, and a failing write renders through the
// verbatim ErrorView boundary.

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

// The interop table the server returns. The wizard renders these rows verbatim;
// the two AC rows (AWS API Gateway and a modern JOSE library) pin the exact
// recommended algorithm and reason the panel must show.
const awsReason = "AWS API Gateway JWT authorizers verify RS256, not EdDSA";
const joseReason =
  "modern JOSE libraries verify Ed25519; smaller and faster than RSA";
const matrix = [
  {
    verifier: "aws_api_gateway",
    label: "AWS API Gateway JWT authorizers",
    recommended: "RS256",
    reason: awsReason,
    alternatives: [],
    supported: ["RS256"],
  },
  {
    verifier: "modern_jose",
    label: "Modern JOSE library",
    recommended: "EdDSA",
    reason: joseReason,
    alternatives: ["ES256", "RS256"],
    supported: ["EdDSA", "ES256", "RS256"],
  },
];

const noPolicies = { items: [] };

// Route the wizard's read to the interop matrix and everything else (the
// sibling DCR panels' policy list) to an empty list, unless the caller overrides.
function respondDefault(call: Call): Response {
  if (call.url.includes("/interop/signing-recommendations")) {
    return json(matrix);
  }
  return json(noPolicies);
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

describe("the signing compatibility wizard renders the server's recommendation", () => {
  it("shows RS256 and its reason when AWS API Gateway is the verifier", async () => {
    activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
    stubFetch(respondDefault);
    const root = mount(<ClientsList />);
    await flush();

    // AWS API Gateway is the first (default) row, so RS256 and its reason are
    // shown without any interaction. The value comes from the mocked GET, not a
    // hardcoded TypeScript matrix.
    const recommended = root.querySelector(".signing-recommended");
    expect(recommended?.textContent).toBe("RS256");
    const reason = root.querySelector(".signing-reason");
    expect(reason?.textContent).toBe(awsReason);
  });

  it("shows EdDSA and its reason when a modern JOSE library is the verifier", async () => {
    activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
    stubFetch(respondDefault);
    const root = mount(<ClientsList />);
    await flush();

    const select = root.querySelector("#signing-verifier") as HTMLSelectElement;
    select.value = "modern_jose";
    select.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();

    const recommended = root.querySelector(".signing-recommended");
    expect(recommended?.textContent).toBe("EdDSA");
    const reason = root.querySelector(".signing-reason");
    expect(reason?.textContent).toBe(joseReason);
  });
});

describe("confirming the wizard pins the recommended algorithm", () => {
  it("PUTs the documented client path with the body { algorithm } and an Idempotency-Key", async () => {
    activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
    const calls = stubFetch((call) => {
      if (call.method === "PUT" && call.url.includes("/signing-algorithm")) {
        return json({
          client_id: "cli_a",
          id_token_signed_response_alg: "RS256",
        });
      }
      return respondDefault(call);
    });
    const root = mount(<ClientsList />);
    await flush();

    const clientId = root.querySelector(
      "#signing-client-id",
    ) as HTMLInputElement;
    clientId.value = "cli_a";
    clientId.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();

    button(root, "Set signing algorithm").click();
    await flush();

    const put = calls.find(
      (call) => call.method === "PUT" && call.url.includes("/signing-algorithm"),
    );
    expect(put).toBeDefined();
    expect(put?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/clients/cli_a/signing-algorithm",
    );
    expect(put?.idempotencyKey).toBeTruthy();
    const body = JSON.parse(put?.body ?? "{}") as Record<string, unknown>;
    // AWS API Gateway (the default verifier) recommends RS256, so that is the
    // pinned algorithm.
    expect(body.algorithm).toBe("RS256");

    // The success confirmation is surfaced.
    expect(root.textContent).toContain("Signing algorithm set to RS256.");
  });
});

describe("a failing write renders through the ErrorView boundary", () => {
  it("renders the verbatim server error when the environment cannot sign the algorithm", async () => {
    activeScope.value = { tenantId: "ten_a", environmentId: "env_a" };
    const message = "The environment cannot sign RS256 tokens.";
    stubFetch((call) => {
      if (call.method === "PUT" && call.url.includes("/signing-algorithm")) {
        return json(
          { error: "env_cannot_sign", message },
          422,
        );
      }
      return respondDefault(call);
    });
    const root = mount(<ClientsList />);
    await flush();

    const clientId = root.querySelector(
      "#signing-client-id",
    ) as HTMLInputElement;
    clientId.value = "cli_a";
    clientId.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();

    button(root, "Set signing algorithm").click();
    await flush();

    // The failure reaches the verbatim ErrorView boundary: the error code and the
    // server's message are both shown, unchanged.
    const boundary = root.querySelector(".errorbody");
    expect(boundary).not.toBeNull();
    expect(boundary?.textContent).toContain("env_cannot_sign");
    expect(boundary?.textContent).toContain(message);
  });
});
