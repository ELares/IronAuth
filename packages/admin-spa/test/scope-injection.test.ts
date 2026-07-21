// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Scope injection: the active {tenant, environment} is substituted into the path
// parameters of every scoped management call. This is tested two ways: the pure
// helper, and faithfully through the ONE typed client (a stubbed fetch records the
// concrete URL the wrapper forms), so a call under scope T/E provably targets
// `/v1/tenants/T/environments/E/...`.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { scopePathParams } from "../src/scope/logic";
import { elevateAdminSudo, fetchEnvironments } from "../src/api/client";

const realFetch = globalThis.fetch;

// Give the config an absolute management base so jsdom's Request/URL can parse
// the concrete URL the client forms (a browser resolves a relative base against
// the document; jsdom needs it absolute). The app itself never hardcodes a base;
// this only feeds loadConfig's <meta> reader inside the test DOM.
function setManagementBase(url: string): void {
  let el = document.querySelector('meta[name="ironauth-management-base"]');
  if (el === null) {
    el = document.createElement("meta");
    el.setAttribute("name", "ironauth-management-base");
    document.head.appendChild(el);
  }
  el.setAttribute("content", url);
}

beforeEach(() => {
  setManagementBase("http://management.test/admin/api");
});

function captureFetch(): { urls: string[] } {
  const urls: string[] = [];
  globalThis.fetch = vi.fn(
    (input: RequestInfo | URL): Promise<Response> => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;
      urls.push(url);
      return Promise.resolve(
        new Response(JSON.stringify({ items: [] }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      );
    },
  ) as typeof globalThis.fetch;
  return { urls };
}

afterEach(() => {
  globalThis.fetch = realFetch;
});

describe("scopePathParams", () => {
  it("maps a scope to the management path parameter names", () => {
    expect(scopePathParams({ tenantId: "T", environmentId: "E" })).toEqual({
      tenant_id: "T",
      environment_id: "E",
    });
  });
});

describe("scope injection through the one typed client", () => {
  it("targets the tenant scope for a tenant-scoped list", async () => {
    const captured = captureFetch();
    await fetchEnvironments("T");
    expect(captured.urls).toHaveLength(1);
    expect(captured.urls[0]).toContain("/v1/tenants/T/environments");
    expect(captured.urls[0]).not.toContain("{tenant_id}");
  });

  it("targets the environment scope for an env-scoped mutation", async () => {
    const captured = captureFetch();
    await elevateAdminSudo("T", "E");
    expect(captured.urls).toHaveLength(1);
    expect(captured.urls[0]).toContain(
      "/v1/tenants/T/environments/E/admin/sudo/elevate",
    );
  });
});
