// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The reference app entry point. It drives the headless flow contract over the
// public flow API and nothing else:
//
//   1. create a flow  (POST the public create route)
//   2. render its ui.nodes generically (render.ts, no journey-specific code)
//   3. submit node values plus the current submit token (POST the public submit
//      route)
//   4. follow the continuation: render the next flow, or navigate to the
//      server-issued completion/redirect target.
//
// The server is the source of truth for the contract and ALL security; this app
// enforces nothing. It renders and submits, and a malicious fork of it cannot
// bypass any server gate because the server validates every submission.

import { createFlow, submitFlow, type FlowResult } from "./api.js";
import { loadConfig } from "./config.js";
import { Copy } from "./messages.js";
import { renderFlow } from "./render.js";
import { MESSAGE_TEXT } from "./contract/messages.gen.js";
import { asFlow } from "./validate.js";
import type { Scope } from "./endpoints.js";

interface Session {
  flowId: string;
  submitToken: string;
}

function mount(): HTMLElement {
  const existing = document.getElementById("flow-root");
  if (existing) {
    return existing;
  }
  const root = document.createElement("main");
  root.id = "flow-root";
  document.body.appendChild(root);
  return root;
}

function showStatus(root: HTMLElement, text: string): void {
  root.replaceChildren();
  const p = document.createElement("p");
  p.className = "flow-status";
  // textContent, never innerHTML.
  p.textContent = text;
  root.appendChild(p);
}

// Navigate to a server-issued continuation target (the /authorize resume, or the
// federation launcher URL). The server validates this target (return_to is
// parse_resume-checked server-side), so the app just follows it. A missing
// target means the server minted a session with no resume; show a success note.
function follow(root: HTMLElement, redirectTo: string | null): void {
  if (redirectTo) {
    window.location.assign(redirectTo);
  } else {
    showStatus(root, "Signed in.");
  }
}

function errorText(id: number | undefined, fallback: string): string {
  return (id !== undefined ? MESSAGE_TEXT[id] : undefined) ?? fallback;
}

async function start(): Promise<void> {
  const config = loadConfig();
  const copy = new Copy();
  const root = mount();
  showStatus(root, "Loading...");

  const first = await createFlow(config.issuerBase, config.scope);
  await handle(root, config.issuerBase, config.scope, copy, first);
}

async function handle(
  root: HTMLElement,
  issuerBase: string,
  scope: Scope,
  copy: Copy,
  result: FlowResult,
): Promise<void> {
  if (result.kind === "continue") {
    follow(root, result.envelope.continue_with.redirect_to);
    return;
  }
  if (result.kind === "error") {
    showStatus(root, errorText(result.error.id, result.error.text));
    return;
  }

  const flow = asFlow(result.envelope.flow);
  if (!flow) {
    showStatus(root, "The server returned an unexpected response.");
    return;
  }
  const session: Session = {
    flowId: flow.id,
    submitToken: result.envelope.submit_token,
  };

  renderFlow(root, flow, copy, (values) => {
    void onSubmit(root, issuerBase, scope, copy, session, values);
  });
}

async function onSubmit(
  root: HTMLElement,
  issuerBase: string,
  scope: Scope,
  copy: Copy,
  session: Session,
  values: Record<string, string>,
): Promise<void> {
  const next = await submitFlow(
    issuerBase,
    scope,
    session.flowId,
    session.submitToken,
    values,
  );
  await handle(root, issuerBase, scope, copy, next);
}

document.addEventListener("DOMContentLoaded", () => {
  void start();
});
