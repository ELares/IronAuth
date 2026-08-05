// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The organization disable/enable wrappers, at the ONE typed client boundary.
//
// Both were shipped WITHOUT the Idempotency-Key the server requires, under comments
// asserting that neither endpoint takes one. The server disagrees: `set_organization_state`
// calls `idempotency::required_key` and the published spec marks the header required on both
// operations, so every disable and enable issued from the console was refused before it
// reached the toggle. Nothing tested these two wrappers, which is why a false comment and a
// broken call could sit next to each other; TypeScript 6 is what finally surfaced it, because
// the generated bindings had typed the header as required all along.
//
// So the assertion here is the header, on both halves of the toggle.

import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { disableOrganization, enableOrganization } from "../src/api/client";

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
}

function captureFetch(body: unknown): () => Captured | null {
  let captured: Captured | null = null;
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
    const request = input as Request;
    captured = {
      url: request.url,
      method: request.method,
      idempotencyKey: request.headers.get("idempotency-key"),
    };
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof globalThis.fetch;
  return () => captured;
}

beforeEach(() => {
  setManagementBase("http://management.test/admin/api");
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

const organization = {
  id: "org_a",
  display_name: "Acme",
  active: true,
  created_at_unix_ms: 0,
};

it("disabling an organization sends the Idempotency-Key the server requires", async () => {
  const captured = captureFetch({ ...organization, active: false });
  await disableOrganization("ten_a", "env_a", "org_a");
  const request = captured();
  expect(request?.method).toBe("POST");
  expect(request?.url).toBe(
    "http://management.test/admin/api/v1/tenants/ten_a/environments/env_a/organizations/org_a/disable",
  );
  // Without this the server answers 400 before the toggle is ever reached.
  expect(request?.idempotencyKey).toBeTruthy();
});

it("enabling an organization sends the Idempotency-Key the server requires", async () => {
  const captured = captureFetch(organization);
  await enableOrganization("ten_a", "env_a", "org_a");
  const request = captured();
  expect(request?.method).toBe("POST");
  expect(request?.url).toBe(
    "http://management.test/admin/api/v1/tenants/ten_a/environments/env_a/organizations/org_a/enable",
  );
  expect(request?.idempotencyKey).toBeTruthy();
});

it("the two calls do not share one key, so a replay cannot cross them", async () => {
  // The key is per CALL, not per module. A shared constant would make an enable replay the
  // stored response of the disable that preceded it, since the fingerprint binds the key to
  // the path and the server would see a second request under a key it already answered.
  const first = captureFetch({ ...organization, active: false });
  await disableOrganization("ten_a", "env_a", "org_a");
  const disableKey = first()?.idempotencyKey;
  const second = captureFetch(organization);
  await enableOrganization("ten_a", "env_a", "org_a");
  expect(second()?.idempotencyKey).not.toBe(disableKey);
});
