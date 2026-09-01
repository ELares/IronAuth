// SPDX-License-Identifier: MIT OR Apache-2.0

// A sample MCP resource server secured by IronAuth (issue #129).
//
// Deliberately small and deliberately REAL: it verifies a token the way a resource server
// must, and its refusals carry the parameters an MCP client needs to recover. The
// conformance bundle drives THIS, so anything it fakes is something the bundle stops
// proving. It fakes nothing about authorization.

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { verifyAccessToken, type Refusal, type VerifiedToken } from "./verify.js";

/** What the server needs to know about the authorization server and itself. */
export interface SampleServerConfig {
  /** The authorization server's issuer, as discovery reports it. */
  issuer: string;
  /** THIS server's resource identifier: what a token's `aud` must contain. */
  resource: string;
  /**
   * The RFC 9728 protected-resource-metadata URL a challenge points at.
   *
   * A 401 that does not say where to look leaves a client with nothing to do but guess which
   * authorization server to talk to, which is the problem RFC 9728 exists to solve and the
   * reason the MCP authorization spec requires the pointer.
   */
  resourceMetadataUrl: string;
  /** The tool scope a call must carry. */
  requiredScope: string;
  /** The issuer's JWKS, fetched once at start. */
  jwks: { keys: Array<Record<string, unknown>> };
}

/**
 * The `WWW-Authenticate` challenge for a refusal.
 *
 * Every branch carries `resource_metadata`, including the bare missing-credential one: a
 * client that has no token yet is exactly the client that most needs to be told where the
 * authorization server is.
 */
export function challenge(config: SampleServerConfig, refusal: Refusal): string {
  const parts = [`Bearer realm="${config.resource}"`];
  if (refusal.kind === "invalid_token") {
    parts.push(`error="invalid_token"`, `error_description="${refusal.description}"`);
  }
  if (refusal.kind === "insufficient_scope") {
    // RFC 6750 section 3.1: the `scope` parameter tells the client WHICH scope to ask for.
    // Without it an insufficient-scope refusal is unactionable, and the step-up the MCP
    // spec expects cannot be driven from the challenge alone.
    parts.push(
      `error="insufficient_scope"`,
      `scope="${refusal.required}"`,
      `error_description="the credential does not carry the required tool scope"`,
    );
  }
  parts.push(`resource_metadata="${config.resourceMetadataUrl}"`);
  return parts.join(", ");
}

/** The status a refusal is delivered with (RFC 6750 section 3.1). */
export function statusFor(refusal: Refusal): number {
  return refusal.kind === "insufficient_scope" ? 403 : 401;
}

/** Decide whether a request may proceed, without touching HTTP. */
export async function authorize(
  config: SampleServerConfig,
  authorization: string | undefined,
): Promise<VerifiedToken | Refusal> {
  if (authorization === undefined || !authorization.toLowerCase().startsWith("bearer ")) {
    return { kind: "missing" };
  }
  const verified = await verifyAccessToken(authorization.slice("bearer ".length).trim(), {
    issuer: config.issuer,
    jwks: config.jwks as never,
    resource: config.resource,
  });
  if ("kind" in verified) {
    return verified;
  }
  if (!verified.scope.includes(config.requiredScope)) {
    return { kind: "insufficient_scope", required: config.requiredScope };
  }
  return verified;
}

/** Start the sample server on `port`, resolving once it is accepting connections. */
export function start(config: SampleServerConfig, port: number): Promise<{ close: () => void }> {
  const server = createServer((request: IncomingMessage, response: ServerResponse) => {
    void (async () => {
      try {
        await handle(config, request, response);
      } catch (error) {
        // An EXCEPTION MUST STILL BE AN ANSWER. Without this an unexpected throw inside
        // verification leaves the socket open with no response, the driver hangs until its
        // timeout, and an unhandled rejection takes the process down: the conformance run
        // reports nothing at all rather than reporting a failure. A resource server that
        // cannot answer is not a safer resource server.
        if (!response.headersSent) {
          response.writeHead(500, { "content-type": "application/json" });
        }
        response.end(JSON.stringify({ error: "server_error", detail: String(error) }));
      }
    })();
  });
  return new Promise((resolve) => {
    server.listen(port, "127.0.0.1", () => resolve({ close: () => server.close() }));
  });
}

/** The request path proper, so `start` owns only the error boundary around it. */
async function handle(
  config: SampleServerConfig,
  request: IncomingMessage,
  response: ServerResponse,
): Promise<void> {
  {
    {
      const outcome = await authorize(config, request.headers.authorization);
      if ("kind" in outcome) {
        response.writeHead(statusFor(outcome), {
          "www-authenticate": challenge(config, outcome),
          "content-type": "application/json",
        });
        response.end(JSON.stringify({ error: outcome.kind }));
        return;
      }
      response.writeHead(200, { "content-type": "application/json" });
      response.end(
        JSON.stringify({
          tool: "echo",
          resource: config.resource,
          subject: outcome.sub,
          scope: outcome.scope,
          // Echoed so the conformance bundle can assert the AGENT attribution (issue #130)
          // survives all the way to a resource server, not just into the token.
          agent: outcome.raw["agent_id"] ?? null,
        }),
      );
    }
  }
}
