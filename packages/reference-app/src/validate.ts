// SPDX-License-Identifier: MIT OR Apache-2.0
//
// A lightweight structural guard that a server response really is a flow object
// shaped like the published contract before the renderer trusts it. The checks
// are driven by constants GENERATED from docs/flow-schema.json (REQUIRED_FLOW_KEYS,
// KNOWN_NODE_TYPES, ...), so the guard cannot drift from the schema. It is a
// defence-in-depth sanity check, not the security boundary: the server validates
// every submission and owns all authentication. A fork that wants full JSON
// Schema validation can drop the committed docs/flow-schema.json into an ajv
// validator; this dependency-free guard keeps the reference app minimal.

import { REQUIRED_FLOW_KEYS, KNOWN_NODE_TYPES } from "./contract/flow.gen.js";
import type { Flow } from "./contract/flow.gen.js";

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// Return the flow if the payload is structurally a flow object, else null.
// Rendering is generic over node attributes, so an UNKNOWN node group or state
// is intentionally NOT rejected (forward compatibility); only a payload that is
// not a flow at all, or a node whose node_type the renderer cannot dispatch on,
// fails here.
export function asFlow(payload: unknown): Flow | null {
  if (!isObject(payload)) {
    return null;
  }
  for (const key of REQUIRED_FLOW_KEYS) {
    if (!(key in payload)) {
      return null;
    }
  }
  const ui = payload.ui;
  if (!isObject(ui) || !Array.isArray(ui.nodes)) {
    return null;
  }
  for (const node of ui.nodes) {
    if (!isObject(node) || !isObject(node.attributes)) {
      return null;
    }
    const nodeType = node.attributes.node_type;
    if (typeof nodeType !== "string" || !(KNOWN_NODE_TYPES as readonly string[]).includes(nodeType)) {
      return null;
    }
  }
  return payload as unknown as Flow;
}
