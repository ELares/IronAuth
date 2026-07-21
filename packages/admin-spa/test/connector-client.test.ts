// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The new connector and DCR wrappers (issue #90, PR 6), tested at the ONE typed
// client boundary: a connector create carries the documented env scoped path,
// body, and Idempotency-Key header; the full-replace PUT update targets the
// documented connector path with the definition body (and, being idempotent by
// construction, carries NO Idempotency-Key); a DCR policy create submits the
// documented path and body with a key; getDcrClient / verifyDcrClient target the
// documented client paths; createDcrInitialAccessToken posts the documented body;
// and every wrapper rejects a bodyless non 2xx (a proxy or gateway error) as a
// ManagementError rather than reading it as success (the PR3 idiom, extended to
// the PR6 wrappers). Connectors and DCR are ENVIRONMENT scoped, so every path
// carries both the tenant and the environment.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ManagementError,
  createConnector,
  createDcrInitialAccessToken,
  createDcrPolicy,
  getConnector,
  getDcrClient,
  updateConnector,
  verifyDcrClient,
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

const connector = {
  id: "cnr_a",
  connector_slug: "acme-oidc",
  definition: {},
  enabled: true,
  capabilities: {
    refresh: true,
    groups: false,
    logout_propagation: false,
    email_verified_trust: "untrusted",
  },
  created_at_unix_ms: 0,
  updated_at_unix_ms: 0,
};

const definition = {
  connector_id: "acme-oidc",
  display_name: "Acme",
  protocol: "oidc",
  endpoints: { issuer: "https://issuer.test" },
  scopes: ["openid"],
  client_id: "abc",
  client_secret: "shh",
};

beforeEach(() => {
  setManagementBase("http://management.test/admin/api");
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

describe("createConnector posts the documented request", () => {
  it("targets the env scoped connectors path with an Idempotency-Key and body", async () => {
    const read = captureFetch(() => json(connector, 201));
    const result = await createConnector("ten_a", "env_a", definition);
    const seen = read();
    expect(seen).not.toBeNull();
    expect(seen?.method).toBe("POST");
    expect(seen?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/connectors",
    );
    expect(seen?.idempotencyKey).toBeTruthy();
    const body = JSON.parse(seen?.body ?? "{}") as Record<string, unknown>;
    expect(body.connector_id).toBe("acme-oidc");
    expect(body.client_secret).toBe("shh");
    expect(result.id).toBe("cnr_a");
  });
});

describe("updateConnector is a full-replace PUT", () => {
  it("PUTs the definition to the documented connector path with no key", async () => {
    const read = captureFetch(() => json(connector));
    await updateConnector("ten_a", "env_a", "cnr_a", {
      ...definition,
      enabled: false,
    });
    const seen = read();
    expect(seen?.method).toBe("PUT");
    expect(seen?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/connectors/cnr_a",
    );
    // A PUT replace is idempotent by construction, so no Idempotency-Key is sent.
    expect(seen?.idempotencyKey).toBeNull();
    const body = JSON.parse(seen?.body ?? "{}") as Record<string, unknown>;
    expect(body.connector_id).toBe("acme-oidc");
    expect(body.enabled).toBe(false);
  });
});

describe("createDcrPolicy posts the documented request", () => {
  it("targets the env scoped policies path with the name, primitives, and a key", async () => {
    const read = captureFetch(() =>
      json({ id: "pol_a", name: "force-pkce", primitives: [], created_at_unix_ms: 0 }, 201),
    );
    await createDcrPolicy("ten_a", "env_a", {
      name: "force-pkce",
      primitives: [{ kind: "force", property: "token_endpoint_auth_method", value: "private_key_jwt" }],
    });
    const seen = read();
    expect(seen?.method).toBe("POST");
    expect(seen?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/dcr/policies",
    );
    expect(seen?.idempotencyKey).toBeTruthy();
    const body = JSON.parse(seen?.body ?? "{}") as Record<string, unknown>;
    expect(body.name).toBe("force-pkce");
    expect(Array.isArray(body.primitives)).toBe(true);
  });
});

describe("getDcrClient and verifyDcrClient target the client paths", () => {
  it("GETs the documented client path", async () => {
    const read = captureFetch(() =>
      json({ id: "cli_a", quarantined: true, verified: false }),
    );
    await getDcrClient("ten_a", "env_a", "cli_a");
    const seen = read();
    expect(seen?.method).toBe("GET");
    expect(seen?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/clients/cli_a",
    );
  });

  it("POSTs the documented verify path with an Idempotency-Key", async () => {
    const read = captureFetch(() =>
      json({ id: "cli_a", quarantined: false, verified: true }),
    );
    await verifyDcrClient("ten_a", "env_a", "cli_a");
    const seen = read();
    expect(seen?.method).toBe("POST");
    expect(seen?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/clients/cli_a/verify",
    );
    expect(seen?.idempotencyKey).toBeTruthy();
  });
});

describe("createDcrInitialAccessToken posts the documented request", () => {
  it("targets the env scoped IAT path with the lifetime body and a key", async () => {
    const read = captureFetch(() =>
      json(
        {
          id: "iat_a",
          token: "the-secret-bearer",
          token_already_issued: false,
          expires_at_unix_ms: 1000,
          created_at_unix_ms: 0,
        },
        201,
      ),
    );
    const result = await createDcrInitialAccessToken("ten_a", "env_a", {
      expires_in_secs: 3600,
    });
    const seen = read();
    expect(seen?.method).toBe("POST");
    expect(seen?.url).toContain(
      "/v1/tenants/ten_a/environments/env_a/dcr/initial-access-tokens",
    );
    expect(seen?.idempotencyKey).toBeTruthy();
    const body = JSON.parse(seen?.body ?? "{}") as Record<string, unknown>;
    expect(body.expires_in_secs).toBe(3600);
    // The wrapper returns the body so the UI can surface the token once.
    expect(result.token).toBe("the-secret-bearer");
  });
});

describe("a bodyless non 2xx is a failure, never silent success", () => {
  function emptyStatus(status: number): void {
    globalThis.fetch = vi.fn(
      async () =>
        new Response(null, { status, headers: { "content-length": "0" } }),
    ) as typeof globalThis.fetch;
  }

  it("rejects getConnector on an empty bodied 404", async () => {
    emptyStatus(404);
    await expect(
      getConnector("ten_a", "env_a", "cnr_a"),
    ).rejects.toBeInstanceOf(ManagementError);
  });

  it("rejects createConnector on an empty bodied 403", async () => {
    emptyStatus(403);
    await expect(
      createConnector("ten_a", "env_a", definition),
    ).rejects.toBeInstanceOf(ManagementError);
  });

  it("rejects updateConnector on an empty bodied 502", async () => {
    emptyStatus(502);
    await expect(
      updateConnector("ten_a", "env_a", "cnr_a", definition),
    ).rejects.toBeInstanceOf(ManagementError);
  });

  it("rejects createDcrInitialAccessToken on an empty bodied 401", async () => {
    emptyStatus(401);
    await expect(
      createDcrInitialAccessToken("ten_a", "env_a", { expires_in_secs: 60 }),
    ).rejects.toBeInstanceOf(ManagementError);
  });
});
