// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The new tenant + environment CRUD wrappers (issue #90, PR 4), tested at the ONE
// typed client boundary: a create carries the documented path, body, and
// Idempotency-Key header, and every wrapper rejects a bodyless non 2xx (a proxy
// or gateway error) as a ManagementError rather than reading it as success (the
// PR3 idiom, extended to the write and detail wrappers).

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ManagementError,
  createTenant,
  deleteEnvironment,
  getTenant,
  suspendTenant,
} from "../src/api/client";

const realFetch = globalThis.fetch;

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

describe("createTenant posts the documented request", () => {
  it("targets POST /v1/tenants with an Idempotency-Key and the body", async () => {
    let captured: {
      url: string;
      method: string;
      idempotencyKey: string | null;
      body: string;
    } | null = null;
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const request = input as Request;
      captured = {
        url: request.url,
        method: request.method,
        idempotencyKey: request.headers.get("idempotency-key"),
        body: await request.clone().text(),
      };
      return new Response(
        JSON.stringify({
          tenant: {
            id: "ten_a",
            display_name: "Acme",
            status: "active",
            created_at_unix_ms: 0,
          },
          environment: {},
        }),
        { status: 201, headers: { "content-type": "application/json" } },
      );
    }) as typeof globalThis.fetch;

    const result = await createTenant({
      display_name: "Acme",
      environment_kind: "dev",
    });

    expect(captured).not.toBeNull();
    const seen = captured as unknown as {
      url: string;
      method: string;
      idempotencyKey: string | null;
      body: string;
    };
    expect(seen.method).toBe("POST");
    expect(seen.url).toContain("/v1/tenants");
    expect(seen.idempotencyKey).toBeTruthy();
    expect((JSON.parse(seen.body) as Record<string, unknown>).display_name).toBe(
      "Acme",
    );
    expect(result.tenant.id).toBe("ten_a");
  });
});

describe("a bodyless non 2xx is a failure, never silent success", () => {
  function emptyStatus(status: number): void {
    globalThis.fetch = vi.fn(
      async () =>
        new Response(null, { status, headers: { "content-length": "0" } }),
    ) as typeof globalThis.fetch;
  }

  it("rejects getTenant on an empty bodied 404", async () => {
    emptyStatus(404);
    await expect(getTenant("ten_a")).rejects.toBeInstanceOf(ManagementError);
  });

  it("rejects createTenant on an empty bodied 401", async () => {
    emptyStatus(401);
    await expect(
      createTenant({ display_name: "Acme", environment_kind: "dev" }),
    ).rejects.toBeInstanceOf(ManagementError);
  });

  it("rejects suspendTenant on an empty bodied 403", async () => {
    emptyStatus(403);
    await expect(suspendTenant("ten_a")).rejects.toBeInstanceOf(ManagementError);
  });

  it("rejects deleteEnvironment on an empty bodied 502", async () => {
    emptyStatus(502);
    await expect(deleteEnvironment("ten_a", "env_a")).rejects.toBeInstanceOf(
      ManagementError,
    );
  });
});
