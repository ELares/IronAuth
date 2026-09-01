// SPDX-License-Identifier: MIT OR Apache-2.0

// The MCP authorization conformance driver (issue #129).
//
// Runs every checklist item against a REAL IronAuth and two REAL sample resource servers,
// and writes a machine-readable result per item. The published page is GENERATED from that
// file rather than written by hand, so a claim on the page cannot outlive the test that
// supports it. A conformance page whose prose and evidence can drift apart is the failure
// this whole bundle exists to avoid.

import { writeFileSync } from "node:fs";
import { login } from "./login.js";
import { start, type SampleServerConfig } from "./server.js";

/** One checklist item's outcome. */
interface ItemResult {
  id: string;
  title: string;
  requirement: string;
  outcome: "pass" | "fail";
  evidence: string;
}

const results: ItemResult[] = [];

function record(item: Omit<ItemResult, "outcome" | "evidence">, ok: boolean, evidence: string) {
  results.push({ ...item, outcome: ok ? "pass" : "fail", evidence });
  console.log(`  ${ok ? "pass" : "FAIL"}  ${item.id}  ${item.title}`);
  if (!ok) {
    console.log(`        ${evidence}`);
  }
}

async function json(response: Response): Promise<Record<string, unknown>> {
  return (await response.json()) as Record<string, unknown>;
}

function randomKey(): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("hex");
}

async function main(): Promise<void> {
  const [issuer, operatorToken, managementBase, redirectUri, devUser, devPassword] =
    process.argv.slice(2);
  if (!issuer || !operatorToken || !managementBase || !redirectUri || !devUser || !devPassword) {
    console.error(
      "usage: conformance <issuer> <operator-token> <management-base> <redirect-uri> <user> <password>",
    );
    process.exit(2);
  }

  // DISCOVERY FIRST, and every endpoint read out of it. An IronAuth issuer carries a
  // `/t/<tenant>/e/<environment>` path while its endpoints sit at the host root, so a driver
  // that composes `${issuer}/token` gets a 404. That exact defect shipped twice in this repo,
  // so nothing here concatenates an endpoint.
  const discovery = await json(await fetch(`${issuer}/.well-known/openid-configuration`));
  const tokenEndpoint = discovery["token_endpoint"] as string;
  const registrationEndpoint = discovery["registration_endpoint"] as string | undefined;
  const jwks = (await json(await fetch(discovery["jwks_uri"] as string))) as {
    keys: Array<Record<string, unknown>>;
  };

  const scopePath = issuer.slice(issuer.indexOf("/t/"));
  const host = issuer.slice(0, issuer.indexOf("/t/"));
  const resourceA = `${issuer}/mcp-a`;
  const resourceB = `${issuer}/mcp-b`;

  const configFor = (resource: string): SampleServerConfig => ({
    issuer,
    resource,
    resourceMetadataUrl: `${host}/.well-known/oauth-protected-resource${scopePath}/${resource.slice(resource.lastIndexOf("/") + 1)}`,
    requiredScope: "mcp.tools",
    jwks,
  });
  const serverA = await start(configFor(resourceA), 18242);
  const serverB = await start(configFor(resourceB), 18243);

  const tenant = scopePath.split("/")[2] ?? "";
  const environment = scopePath.split("/")[4] ?? "";
  const scopeBase = `${managementBase}/v1/tenants/${tenant}/environments/${environment}`;

  try {
    // ---- an unauthenticated call challenges, and says where the authorization server is ----
    const anonymous = await fetch("http://127.0.0.1:18242/mcp");
    const anonymousChallenge = anonymous.headers.get("www-authenticate") ?? "";
    record(
      {
        id: "MCP-401-METADATA",
        title: "An unauthenticated call is a 401 naming where the authorization server is",
        requirement: "MCP authorization; RFC 9728 section 5.1",
      },
      anonymous.status === 401 && anonymousChallenge.includes("resource_metadata="),
      `status=${anonymous.status} www-authenticate=${anonymousChallenge}`,
    );

    // ---- the pointer resolves to a document naming this authorization server ----
    const metadataUrl = /resource_metadata="([^"]+)"/.exec(anonymousChallenge)?.[1] ?? "";
    const metadata = metadataUrl ? await fetch(metadataUrl) : null;
    const metadataBody = metadata?.ok ? await json(metadata) : {};
    const servers = (metadataBody["authorization_servers"] as string[] | undefined) ?? [];
    record(
      {
        id: "MCP-PRM-RESOLVES",
        title: "The pointer resolves to protected resource metadata naming the issuer",
        requirement: "RFC 9728 section 3",
      },
      metadata?.ok === true && servers.includes(issuer),
      `url=${metadataUrl} status=${metadata?.status ?? "none"} authorization_servers=${JSON.stringify(servers)}`,
    );

    // ---- DYNAMIC CLIENT REGISTRATION, gated by a management-minted initial access token ----
    const iatResponse = await fetch(`${scopeBase}/dcr/initial-access-tokens`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${operatorToken}`,
        "content-type": "application/json",
        "idempotency-key": randomKey(),
      },
      body: JSON.stringify({ expires_in_secs: 600 }),
    });
    const iat = (await json(iatResponse))["token"] as string | undefined;
    let clientId = "";
    if (registrationEndpoint && iat) {
      const registered = await fetch(registrationEndpoint, {
        method: "POST",
        headers: { authorization: `Bearer ${iat}`, "content-type": "application/json" },
        body: JSON.stringify({
          client_name: "mcp conformance client",
          // An MCP client is a PUBLIC client whose user is at a browser, so it registers
          // for the authorization-code grant. That is also the only grant this
          // registration endpoint accepts, which is the same answer arrived at twice.
          grant_types: ["authorization_code"],
          response_types: ["code"],
          token_endpoint_auth_method: "none",
          // NATIVE, because an MCP client is a local process that receives its code on a
          // loopback redirect. Registering as "web" refuses a plain-HTTP redirect, which is
          // correct for a web client and wrong for this one: OIDC allows loopback precisely
          // for the native case, and that is the case an MCP client is.
          application_type: "native",
          redirect_uris: [redirectUri],
        }),
      });
      const body = await json(registered);
      clientId = (body["client_id"] as string) ?? "";
      record(
        {
          id: "MCP-DCR",
          title: "A client registers dynamically and receives an identifier",
          requirement: "RFC 7591; MCP authorization registration",
        },
        registered.status === 201 && clientId !== "",
        `status=${registered.status} body=${JSON.stringify(body).slice(0, 240)}`,
      );
    } else {
      record(
        {
          id: "MCP-DCR",
          title: "A client registers dynamically and receives an identifier",
          requirement: "RFC 7591; MCP authorization registration",
        },
        false,
        `registration_endpoint=${registrationEndpoint ?? "absent"} iat=${iat ? "minted" : `absent (${iatResponse.status})`}`,
      );
    }

    // ---- the operator arms the registered client ----
    //
    // A dynamically registered client cannot be authorized until an operator pre-authorizes
    // its scopes, and a PUBLIC client must be exempted from the DPoP-by-default posture
    // before it can present a bearer token. Both are deliberate gates rather than
    // obstacles, and both are invisible from the spec alone, so each is a measured item:
    // an MCP integrator meets them immediately and the page should say so.
    if (clientId) {
      const consent = await fetch(`${scopeBase}/applications/${clientId}/admin-consent`, {
        method: "PUT",
        headers: {
          authorization: `Bearer ${operatorToken}`,
          "content-type": "application/json",
          "idempotency-key": randomKey(),
        },
        body: JSON.stringify({ scope: "openid mcp.tools" }),
      });
      record(
        {
          id: "MCP-ADMIN-CONSENT",
          title: "An operator pre-authorizes the registered client's scopes",
          requirement: "IronAuth admin consent; MCP authorization client approval",
        },
        consent.status === 200,
        `status=${consent.status} body=${JSON.stringify(await json(consent)).slice(0, 200)}`,
      );

      const bearer = await fetch(`${scopeBase}/clients/${clientId}/bearer-tokens`, {
        method: "PUT",
        headers: {
          authorization: `Bearer ${operatorToken}`,
          "content-type": "application/json",
          "idempotency-key": randomKey(),
        },
        body: JSON.stringify({ allowed: true }),
      });
      record(
        {
          id: "MCP-BEARER-EXEMPTION",
          title: "A public client is exempted from the DPoP-by-default posture",
          requirement: "RFC 9449; IronAuth DPoP-by-default (issue #124)",
        },
        bearer.status === 200,
        `status=${bearer.status} body=${JSON.stringify(await json(bearer)).slice(0, 200)}`,
      );
    }

    // ---- an AUDIENCE-BOUND token, through the flow a real MCP client runs ----
    let tokenForA = "";
    if (clientId) {
      const outcome = await login({
        issuer,
        authorizationEndpoint: discovery["authorization_endpoint"] as string,
        tokenEndpoint,
        clientId,
        redirectUri,
        resource: resourceA,
        scope: "openid mcp.tools",
        identifier: devUser,
        password: devPassword,
      });
      tokenForA = outcome.accessToken ?? "";
      record(
        {
          id: "MCP-AUDIENCE-BOUND",
          title: "A login yields a token bound to the MCP server it was requested for",
          requirement: "RFC 8707; MCP authorization audience binding",
        },
        tokenForA !== "",
        outcome.detail,
      );
    }

    if (tokenForA) {
      const atA = await fetch("http://127.0.0.1:18242/mcp", {
        headers: { authorization: `Bearer ${tokenForA}` },
      });
      record(
        {
          id: "MCP-CALL-SUCCEEDS",
          title: "The bound token is accepted by the server it names",
          requirement: "RFC 9068 section 4",
        },
        atA.status === 200,
        `status=${atA.status} body=${(await atA.text()).slice(0, 160)}`,
      );

      // THE REPLAY. Same issuer, same signing key, same unexpired token: only the audience
      // separates these two servers, which is exactly the property being demonstrated.
      const atB = await fetch("http://127.0.0.1:18243/mcp", {
        headers: { authorization: `Bearer ${tokenForA}` },
      });
      record(
        {
          id: "MCP-REPLAY-REFUSED",
          title: "The same token replayed at another MCP server is refused",
          requirement: "MCP authorization strict audience validation",
        },
        atB.status === 401,
        `status=${atB.status} www-authenticate=${atB.headers.get("www-authenticate") ?? ""}`,
      );
    }

    // ---- insufficient scope is a 403 carrying the scope to ask for ----
    if (clientId) {
      const narrow = await login({
        issuer,
        authorizationEndpoint: discovery["authorization_endpoint"] as string,
        tokenEndpoint,
        clientId,
        redirectUri,
        resource: resourceA,
        // `openid` only: a token that is valid in every way EXCEPT the tool scope, which is
        // what separates a 403 from a 401 and is the whole point of this item.
        scope: "openid",
        identifier: devUser,
        password: devPassword,
      });
      const refused = await fetch("http://127.0.0.1:18242/mcp", {
        headers: { authorization: `Bearer ${narrow.accessToken ?? ""}` },
      });
      const refusedChallenge = refused.headers.get("www-authenticate") ?? "";
      record(
        {
          id: "MCP-INSUFFICIENT-SCOPE",
          title: "A call missing the tool scope is a 403 naming the scope to request",
          requirement: "RFC 6750 section 3.1; MCP authorization step-up",
        },
        refused.status === 403 &&
          refusedChallenge.includes('error="insufficient_scope"') &&
          refusedChallenge.includes('scope="mcp.tools"'),
        `status=${refused.status} www-authenticate=${refusedChallenge} login=${narrow.detail}`,
      );
    }

  } finally {
    serverA.close();
    serverB.close();
  }

  const failures = results.filter((item) => item.outcome === "fail");
  writeFileSync(
    "docs/conformance/mcp-results.json",
    `${JSON.stringify({ spec_revision: "2026-07-28", items: results }, null, 2)}\n`,
  );
  console.log(`mcp-conformance: ${results.length - failures.length}/${results.length} items pass`);
  if (failures.length > 0) {
    process.exit(1);
  }
}

await main();
