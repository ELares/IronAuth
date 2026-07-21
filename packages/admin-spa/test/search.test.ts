// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Global search (issue #90, PR 7): the cross-resource search built ENTIRELY from
// the public LIST operations. These unit tests drive searchAll through the ONE
// typed client (a stubbed fetch records the concrete URLs the wrappers form), so
// they prove: it aggregates hits across multiple list ops and filters by the
// query; it respects the active scope (a scoped resource is queried only under a
// scope, and never with no scope); a query below the minimum length fires NO
// call; a bodyless non 2xx during search surfaces as a thrown ManagementError
// (never a silent empty); and a hit navigates to the documented client side
// route. There is NO server search endpoint here: every call is a documented list.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ManagementError } from "../src/api/client";
import {
  MIN_QUERY_LENGTH,
  resultsFromConnectors,
  resultsFromEnvironments,
  resultsFromTenants,
  resultsFromUsers,
  searchAll,
  shouldSearch,
  toCommand,
} from "../src/ui/search";

const realFetch = globalThis.fetch;

// An absolute management base so jsdom's Request/URL parses the concrete URL the
// client forms (mirrors scope-injection.test.ts). The app never hardcodes a base.
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

afterEach(() => {
  globalThis.fetch = realFetch;
});

// Route a stubbed fetch by the URL the wrapper formed, returning the documented
// {items:[...]} list body for each list op. Records every URL so the scope
// assertions can prove which paths a search touched.
function stubLists(bodies: {
  tenants?: unknown[];
  environments?: unknown[];
  users?: unknown[];
  connectors?: unknown[];
}): { urls: string[] } {
  const urls: string[] = [];
  globalThis.fetch = vi.fn((input: RequestInfo | URL): Promise<Response> => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.toString()
          : input.url;
    urls.push(url);
    let items: unknown[] = [];
    if (url.includes("/connectors")) {
      items = bodies.connectors ?? [];
    } else if (url.includes("/users")) {
      items = bodies.users ?? [];
    } else if (url.includes("/environments")) {
      items = bodies.environments ?? [];
    } else if (url.includes("/v1/tenants")) {
      items = bodies.tenants ?? [];
    }
    return Promise.resolve(
      new Response(JSON.stringify({ items }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
  }) as typeof globalThis.fetch;
  return { urls };
}

describe("searchAll aggregates across list ops and filters by the query", () => {
  it("returns hits from more than one resource, keeping only those matching", async () => {
    stubLists({
      tenants: [{ id: "ten_1", display_name: "Acme" }],
      environments: [{ id: "env_1", display_name: "Production" }],
      users: [{ id: "usr_1", identifier: "alice@acme.test" }],
      connectors: [{ id: "cnr_1", connector_slug: "google" }],
    });
    const results = await searchAll("acme", {
      tenantId: "T",
      environmentId: "E",
    });
    // "acme" matches the tenant (display name) and the user (login handle), and
    // NOT the "Production" environment or the "google" connector: aggregation
    // across ops plus a client side filter.
    const kinds = results.map((r) => r.kind).sort();
    expect(kinds).toEqual(["tenant", "user"]);
    expect(results.find((r) => r.kind === "tenant")?.href).toBe(
      "/tenants/ten_1",
    );
    expect(results.find((r) => r.kind === "user")?.href).toBe("/users/usr_1");
  });
});

describe("searchAll respects the active scope", () => {
  it("queries the scoped list ops on the scoped paths when a scope is active", async () => {
    const { urls } = stubLists({});
    await searchAll("query", { tenantId: "T", environmentId: "E" });
    // Tenants (global) plus the three scoped lists, each on the documented
    // scoped path with the active ids substituted in.
    expect(urls.some((u) => u.endsWith("/v1/tenants"))).toBe(true);
    expect(
      urls.some((u) => u.includes("/v1/tenants/T/environments") && !u.includes("/users") && !u.includes("/connectors")),
    ).toBe(true);
    expect(
      urls.some((u) => u.includes("/v1/tenants/T/environments/E/users")),
    ).toBe(true);
    expect(
      urls.some((u) => u.includes("/v1/tenants/T/environments/E/connectors")),
    ).toBe(true);
  });

  it("queries ONLY the global tenants list when there is no scope", async () => {
    const { urls } = stubLists({});
    await searchAll("query", null);
    expect(urls).toHaveLength(1);
    expect(urls[0]).toContain("/v1/tenants");
    // No scoped resource is queried with no scope: no environments, users, or
    // connectors path is ever formed.
    expect(urls.some((u) => u.includes("/environments"))).toBe(false);
    expect(urls.some((u) => u.includes("/users"))).toBe(false);
    expect(urls.some((u) => u.includes("/connectors"))).toBe(false);
  });
});

describe("searchAll gates on the minimum query length", () => {
  it("makes NO call and returns nothing below the minimum length", async () => {
    const { urls } = stubLists({ tenants: [{ id: "ten_1", display_name: "Acme" }] });
    const short = "a".repeat(MIN_QUERY_LENGTH - 1);
    expect(shouldSearch(short)).toBe(false);
    const results = await searchAll(short, { tenantId: "T", environmentId: "E" });
    expect(results).toEqual([]);
    expect(urls).toHaveLength(0);
  });
});

describe("searchAll surfaces a failure rather than a silent empty", () => {
  it("rejects with a ManagementError on a bodyless non 2xx list", async () => {
    globalThis.fetch = vi.fn(
      async () =>
        new Response(null, {
          status: 401,
          headers: { "content-length": "0" },
        }),
    ) as typeof globalThis.fetch;
    await expect(searchAll("acme", null)).rejects.toBeInstanceOf(
      ManagementError,
    );
  });
});

describe("a hit navigates to the documented client side route", () => {
  it("maps each resource to its detail route", () => {
    expect(resultsFromTenants([{ id: "ten_9", display_name: "T" }] as never)[0].href).toBe(
      "/tenants/ten_9",
    );
    expect(
      resultsFromEnvironments([{ id: "env_9", display_name: "E" }] as never)[0]
        .href,
    ).toBe("/environments/env_9");
    expect(
      resultsFromUsers([{ id: "usr_9", identifier: "bob" }] as never)[0].href,
    ).toBe("/users/usr_9");
    expect(
      resultsFromConnectors([{ id: "cnr_9", connector_slug: "okta" }] as never)[0]
        .href,
    ).toBe("/connectors/cnr_9");
  });

  it("builds a command whose run navigates to the hit's route", () => {
    const navigate = vi.fn();
    const command = toCommand(
      {
        kind: "user",
        id: "usr_9",
        label: "bob",
        hint: "usr_9",
        href: "/users/usr_9",
      },
      navigate,
    );
    command.run();
    expect(navigate).toHaveBeenCalledTimes(1);
    expect(navigate).toHaveBeenCalledWith("/users/usr_9");
  });
});
