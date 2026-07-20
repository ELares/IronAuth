// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The ONE module in the reference app that performs a network call. Every fetch
// targets a documented public flow endpoint built through expandEndpoint (see
// endpoints.ts); scripts/route-audit.sh asserts no other module calls fetch/XHR
// and that the only paths reachable are the public ones. The app never talks to
// a private or management endpoint, and it holds no secret: the submit token the
// server issued is the only per-flow credential.

import { type EndpointName, type Scope, expandEndpoint } from "./endpoints.js";
import type { Flow } from "./contract/flow.gen.js";

// The API envelopes the server returns (crates/ironauth-oidc/src/flow/
// transport.rs): a render continuation carries the next flow object plus the
// rotated submit token; a terminal continuation carries only a redirect target;
// an error carries the numeric message id (the localization key) plus fallback
// text. These are the transport-neutral shapes the reference app renders.
export interface FlowEnvelope {
  flow: Flow;
  submit_token: string;
}

export interface ContinueEnvelope {
  state: "completed" | "redirect";
  continue_with: { redirect_to: string | null };
}

export interface ApiError {
  id?: number;
  text: string;
}

export type FlowResult =
  | { kind: "render"; envelope: FlowEnvelope }
  | { kind: "continue"; envelope: ContinueEnvelope }
  | { kind: "error"; error: ApiError };

function join(issuerBase: string, path: string): string {
  // issuerBase is operator config (possibly empty for a same-origin deploy);
  // path is a scope-filled PUBLIC endpoint. No path text originates here.
  return issuerBase ? `${issuerBase}${path}` : path;
}

async function post(
  issuerBase: string,
  path: string,
  body: unknown,
): Promise<FlowResult> {
  const response = await fetch(join(issuerBase, path), {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    // A first-party same-origin deploy carries the session cookie the server
    // sets on completion; a cross-origin fork relies on the redirect target.
    credentials: "same-origin",
    body: JSON.stringify(body),
  });

  let payload: unknown = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  return classify(response.ok, payload);
}

function classify(ok: boolean, payload: unknown): FlowResult {
  const obj = (payload ?? {}) as Record<string, unknown>;
  if (!ok || obj.error) {
    const err = (obj.error ?? {}) as Record<string, unknown>;
    return {
      kind: "error",
      error: {
        id: typeof err.id === "number" ? err.id : undefined,
        text: typeof err.text === "string" ? err.text : "The request could not be processed.",
      },
    };
  }
  if (obj.state === "completed" || obj.state === "redirect") {
    return { kind: "continue", envelope: obj as unknown as ContinueEnvelope };
  }
  return { kind: "render", envelope: obj as unknown as FlowEnvelope };
}

// Create a flow (POST the public create route) and return its first render.
export function createFlow(issuerBase: string, scope: Scope): Promise<FlowResult> {
  return post(issuerBase, endpoint("flowCreateApi", scope), {});
}

// Submit node values plus the current submit token (POST the public submit
// route) and return the continuation: the next flow, a completion redirect, or
// a typed error.
export function submitFlow(
  issuerBase: string,
  scope: Scope,
  flowId: string,
  submitToken: string,
  nodes: Record<string, string>,
): Promise<FlowResult> {
  return post(issuerBase, endpoint("flowSubmitApi", scope), {
    id: flowId,
    submit_token: submitToken,
    nodes,
  });
}

function endpoint(name: EndpointName, scope: Scope): string {
  return expandEndpoint(name, scope);
}
