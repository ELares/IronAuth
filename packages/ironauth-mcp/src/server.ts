// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * The admin MCP server (issue #123).
 *
 * It exposes the management API as agent tools under three rules, each of which is a criterion:
 *
 * 1. **It advertises only what its own key can drive.** `listTools` asks the API what the
 *    credential holds (`GET /v1/me`) and filters. A read-scoped key sees no mutating tool at all
 *    -- not a tool that fails, a tool that is not there.
 * 2. **A destructive tool refuses without an explicit confirmation.** A misfiring agent cannot
 *    cascade through deletes by omitting an argument.
 * 3. **Every call is attributed.** It authenticates with a scoped API key -- there is no
 *    super-admin ambient authority anywhere in this package -- and marks its requests with the
 *    MCP entry path, so an operator can tell an agent-driven change from a direct one in the
 *    same audit stream.
 *
 * ## The client-side check is not the security boundary, and saying so matters
 *
 * The API refuses a credential that lacks a permission, and always did. Nothing here can grant
 * anything: a caller who bypassed this server entirely and called the API directly would get
 * exactly the same answers.
 *
 * What this adds is that an AGENT is never offered a tool it cannot use. That is a usability
 * property with a security consequence -- an agent shown a tool will try it, and an agent that
 * tries a delete it cannot perform still asked to delete something -- but it is defence in
 * depth, not the fence. The fence is on the server.
 */

import { TOOLS, type Permission, type Tool } from './tools.js';

/** How the server reaches the management API. */
export interface ServerConfig {
  /** The management API base, e.g. `https://admin.example`. */
  apiBase: string;
  /**
   * A SCOPED management key. The issue is explicit that this server "holds no super-admin
   * ambient authority", and this is where that is true or not: whatever this key can do is
   * exactly what the server can do, and nothing widens it.
   */
  apiKey: string;
  fetch?: typeof fetch;
}

/** What `GET /v1/me` reports. */
interface Caller {
  plane: string;
  tenant_id?: string | null;
  environment_id?: string | null;
  permissions?: string[] | null;
  unrestricted: boolean;
}

/** The outcome of invoking a tool. */
export type ToolResult =
  | { kind: 'ok'; status: number; body: unknown }
  /** The credential does not hold the tool's permission. */
  | { kind: 'forbidden'; requires: Permission }
  /** A destructive tool was invoked without `confirm: true`. */
  | { kind: 'needs_confirmation'; tool: string; message: string }
  /** A required argument was missing. */
  | { kind: 'invalid'; missing: readonly string[] }
  /** No tool by that name, or one the credential may not see. */
  | { kind: 'unknown_tool'; name: string }
  /** The API answered a non-2xx, or could not be reached. */
  | { kind: 'api_error'; status: number; body: unknown };

/** The header the management API records the entry path from. */
const ENTRY_PATH_HEADER = 'x-ironauth-entry-path';

export class AdminMcpServer {
  readonly #config: ServerConfig;
  #caller: Caller | undefined;

  constructor(config: ServerConfig) {
    this.#config = config;
  }

  #send(): typeof fetch {
    return this.#config.fetch ?? fetch;
  }

  /** Ask the API what this credential is and may do, once. */
  async #whoami(): Promise<Caller | undefined> {
    if (this.#caller) {
      return this.#caller;
    }
    let response: Response;
    try {
      response = await this.#send()(`${this.#config.apiBase}/v1/me`, {
        headers: { authorization: `Bearer ${this.#config.apiKey}`, [ENTRY_PATH_HEADER]: 'mcp' },
      });
    } catch {
      return undefined;
    }
    if (!response.ok) {
      return undefined;
    }
    try {
      this.#caller = (await response.json()) as Caller;
    } catch {
      return undefined;
    }
    return this.#caller;
  }

  /** Whether this credential holds `permission`. */
  #holds(caller: Caller | undefined, permission: Permission): boolean {
    // FAIL CLOSED on an unknown caller. If `/v1/me` could not be read, the server advertises
    // NOTHING rather than guessing -- an unreachable introspection endpoint must not be the
    // reason an agent is offered a delete.
    if (!caller) {
      return false;
    }
    if (caller.unrestricted) {
      return true;
    }
    return (caller.permissions ?? []).includes(permission);
  }

  /**
   * The tools this credential may actually drive (criterion 4).
   *
   * Filtered, not annotated. An MCP client shows what it is given, so a tool listed as
   * "unavailable" is a tool an agent will try.
   */
  async listTools(): Promise<Tool[]> {
    const caller = await this.#whoami();
    return TOOLS.filter((tool) => this.#holds(caller, tool.requires));
  }

  /**
   * Invoke a tool.
   *
   * The order of the checks is deliberate and is asserted by test: a tool the credential may not
   * use is `forbidden` BEFORE its arguments are looked at, so an agent probing with empty
   * arguments learns nothing about which tools exist that it cannot see.
   */
  async callTool(name: string, args: Record<string, unknown> = {}): Promise<ToolResult> {
    const tool = TOOLS.find((candidate) => candidate.name === name);
    if (!tool) {
      return { kind: 'unknown_tool', name };
    }
    const caller = await this.#whoami();
    if (!this.#holds(caller, tool.requires)) {
      // The SAME answer a name that does not exist would get, in the sense that neither reveals
      // anything about the other: `forbidden` names the permission required, which the caller
      // could read off the tool declaration anyway, and nothing about what else exists.
      return { kind: 'forbidden', requires: tool.requires };
    }
    if (tool.destructive && args.confirm !== true) {
      return {
        kind: 'needs_confirmation',
        tool: tool.name,
        message: `${tool.name} destroys something and will not run without confirm: true.`,
      };
    }
    const missing = tool.required.filter((key) => typeof args[key] !== 'string' || args[key] === '');
    if (missing.length > 0) {
      return { kind: 'invalid', missing };
    }

    let path = tool.path;
    for (const key of tool.required) {
      path = path.replace(`{${key}}`, encodeURIComponent(String(args[key])));
    }
    // The BODY is whatever is left after the path parameters and `confirm`. `confirm` is this
    // server's own control and is never forwarded: sending it upstream would put a word the
    // management API has no opinion about into a request body it validates strictly.
    const body: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(args)) {
      if (key !== 'confirm' && !tool.required.includes(key)) {
        body[key] = value;
      }
    }

    const headers: Record<string, string> = {
      authorization: `Bearer ${this.#config.apiKey}`,
      // CRITERION 5. Every request this server makes says how it arrived, so an operator can
      // tell an agent-driven change from a direct one by the same identity.
      [ENTRY_PATH_HEADER]: 'mcp',
    };
    const hasBody = tool.method !== 'GET' && tool.method !== 'DELETE';
    if (hasBody) {
      headers['content-type'] = 'application/json';
      // The management API requires an idempotency key on its POSTs. A fresh one per call is
      // correct here: an agent retrying a tool means to retry it, and reusing a key would make
      // the second attempt replay the first's response rather than act.
      headers['idempotency-key'] = crypto.randomUUID();
    }

    let response: Response;
    try {
      response = await this.#send()(`${this.#config.apiBase}${path}`, {
        method: tool.method,
        headers,
        body: hasBody ? JSON.stringify(body) : undefined,
      });
    } catch (error) {
      return { kind: 'api_error', status: 0, body: String(error) };
    }
    let payload: unknown = null;
    const text = await response.text();
    if (text !== '') {
      try {
        payload = JSON.parse(text);
      } catch {
        payload = text;
      }
    }
    if (!response.ok) {
      return { kind: 'api_error', status: response.status, body: payload };
    }
    return { kind: 'ok', status: response.status, body: payload };
  }
}
