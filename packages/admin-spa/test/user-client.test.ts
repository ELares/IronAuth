// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The new user CRUD wrappers (issue #90, PR 5), tested at the ONE typed client
// boundary: a create carries the documented env scoped path, body, and
// Idempotency-Key header; the PATCH update submits ONLY the fields the contract's
// UpdateUserRequest accepts (claims) to the documented path; and every wrapper
// rejects a bodyless non 2xx (a proxy or gateway error) as a ManagementError
// rather than reading it as success (the PR3 idiom, extended to the user
// wrappers). Users are ENVIRONMENT scoped, so every path carries both the tenant
// and the environment.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ManagementError,
  createUser,
  getUser,
  revokeUserSessions,
  setUserState,
  unlinkUserExternalId,
  updateUser,
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

interface Captured {
  url: string;
  method: string;
  idempotencyKey: string | null;
  body: string;
}

function captureFetch(response: () => Response): () => Captured | null {
  let captured: Captured | null = null;
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
    const request = input as Request;
    captured = {
      url: request.url,
      method: request.method,
      idempotencyKey: request.headers.get("idempotency-key"),
      body: await request.clone().text(),
    };
    return response();
  }) as typeof globalThis.fetch;
  return () => captured;
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const user = {
  id: "usr_a",
  tenant_id: "ten_a",
  environment_id: "env_a",
  identifier: "ada@example.test",
  state: "active",
  created_at_unix_ms: 0,
  updated_at_unix_ms: 0,
};

beforeEach(() => {
  setManagementBase("http://management.test/admin/api");
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

describe("createUser posts the documented request", () => {
  it("targets the env scoped users path with an Idempotency-Key and body", async () => {
    const read = captureFetch(() => json(user, 201));
    const result = await createUser("ten_a", "env_a", {
      identifier: "ada@example.test",
      state: "active",
    });
    const seen = read();
    expect(seen).not.toBeNull();
    expect(seen?.method).toBe("POST");
    expect(seen?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/users",
    );
    expect(seen?.idempotencyKey).toBeTruthy();
    const body = JSON.parse(seen?.body ?? "{}") as Record<string, unknown>;
    expect(body.identifier).toBe("ada@example.test");
    expect(result.id).toBe("usr_a");
  });
});

describe("updateUser is the PATCH of only the accepted fields", () => {
  it("PATCHes the documented path with only the claims merge patch", async () => {
    const read = captureFetch(() => json(user));
    await updateUser("ten_a", "env_a", "usr_a", {
      claims: { given_name: "Ada" },
    });
    const seen = read();
    expect(seen?.method).toBe("PATCH");
    expect(seen?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/users/usr_a",
    );
    const body = JSON.parse(seen?.body ?? "{}") as Record<string, unknown>;
    // Only `claims` is sent: the state and external id have their own operations.
    expect(Object.keys(body)).toEqual(["claims"]);
    expect(body.claims).toEqual({ given_name: "Ada" });
  });
});

describe("setUserState posts the state transition", () => {
  it("targets the documented state path with an Idempotency-Key", async () => {
    const read = captureFetch(() =>
      json({ id: "usr_a", state: "blocked", hard_kill: false }),
    );
    await setUserState("ten_a", "env_a", "usr_a", { state: "blocked" });
    const seen = read();
    expect(seen?.method).toBe("POST");
    expect(seen?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/users/usr_a/state",
    );
    expect(seen?.idempotencyKey).toBeTruthy();
    const body = JSON.parse(seen?.body ?? "{}") as Record<string, unknown>;
    expect(body.state).toBe("blocked");
  });
});

describe("a bodyless non 2xx is a failure, never silent success", () => {
  function emptyStatus(status: number): void {
    globalThis.fetch = vi.fn(
      async () =>
        new Response(null, { status, headers: { "content-length": "0" } }),
    ) as typeof globalThis.fetch;
  }

  it("rejects getUser on an empty bodied 404", async () => {
    emptyStatus(404);
    await expect(getUser("ten_a", "env_a", "usr_a")).rejects.toBeInstanceOf(
      ManagementError,
    );
  });

  it("rejects setUserState on an empty bodied 403", async () => {
    emptyStatus(403);
    await expect(
      setUserState("ten_a", "env_a", "usr_a", { state: "blocked" }),
    ).rejects.toBeInstanceOf(ManagementError);
  });

  it("rejects revokeUserSessions on an empty bodied 502", async () => {
    emptyStatus(502);
    await expect(
      revokeUserSessions("ten_a", "env_a", "usr_a", {}),
    ).rejects.toBeInstanceOf(ManagementError);
  });

  it("rejects unlinkUserExternalId on an empty bodied 401", async () => {
    emptyStatus(401);
    await expect(
      unlinkUserExternalId("ten_a", "env_a", "usr_a"),
    ).rejects.toBeInstanceOf(ManagementError);
  });
});
