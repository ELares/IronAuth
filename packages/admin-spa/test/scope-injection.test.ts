// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Scope injection: the active {tenant, environment} is substituted into the path
// parameters of every scoped management call, tested faithfully through the ONE
// typed client (a stubbed fetch records the concrete URL the wrapper forms), so a
// call under scope T/E provably targets `/v1/tenants/T/environments/E/...`. The
// wrappers also reject a bodyless non 2xx (a proxy or gateway error) rather than
// reading it as success.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ManagementError,
  elevateAdminSudo,
  fetchEnvironments,
  fetchTenants,
} from "../src/api/client";

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

describe("a bodyless non 2xx is a failure, never silent success", () => {
  it("rejects a list with an empty bodied 401 instead of returning an empty list", async () => {
    globalThis.fetch = vi.fn(
      async () =>
        new Response(null, {
          status: 401,
          headers: { "content-length": "0" },
        }),
    );
    await expect(fetchTenants()).rejects.toBeInstanceOf(ManagementError);
  });

  it("rejects a sudo elevation with an empty bodied 403 instead of reporting success", async () => {
    globalThis.fetch = vi.fn(
      async () =>
        new Response(null, {
          status: 403,
          headers: { "content-length": "0" },
        }),
    );
    await expect(elevateAdminSudo("T", "E")).rejects.toBeInstanceOf(
      ManagementError,
    );
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
