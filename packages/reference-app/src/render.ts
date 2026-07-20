// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The generic, contract-driven renderer. It dispatches on each node's TYPED
// attributes (node_type, then input_type/group) and never on the journey, so
// login, registration, MFA challenge and enrollment, recovery, and federation
// all render from the same code with NO journey-specific branches: a new auth
// method that adds a new node group renders here without a code change (the
// forward-compatibility property the acceptance criteria require, matching the
// server-side renderer).
//
// Every string that originates on the server (message copy, node labels, prefill
// values, errors) is written with textContent or set as a DOM attribute value,
// NEVER assigned to innerHTML. So a reference app fork inherits a safe rendering
// pattern: server data cannot become markup, and there is no XSS sink to copy.

import type { Flow, Message, Node } from "./contract/flow.gen.js";
import type { Copy } from "./messages.js";

export interface RenderedForm {
  // The collected input values, keyed by node name, ready to POST as `nodes`.
  collect(): Record<string, string>;
}

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  return node;
}

function messageLine(copy: Copy, message: Message): HTMLParagraphElement {
  const p = el("p", `flow-message flow-message-${message.kind}`);
  // textContent, never innerHTML: server copy is rendered as text.
  p.textContent = copy.text(message);
  return p;
}

// Dispatch a single node to its DOM. Returns the created form control (if any)
// so the collector can read its value.
function renderNode(copy: Copy, node: Node): { field: HTMLInputElement | null; dom: HTMLElement } {
  const attrs = node.attributes;

  if (attrs.node_type === "text") {
    const wrap = el("div", "flow-node flow-node-text");
    wrap.appendChild(messageLine(copy, attrs.message));
    return { field: null, dom: wrap };
  }

  // attrs.node_type === "input"
  const wrap = el("div", `flow-node flow-node-input flow-group-${node.group}`);

  if (attrs.input_type === "submit") {
    const button = el("button");
    button.type = "submit";
    button.name = attrs.name;
    button.textContent = node.label ? copy.text(node.label) : "Continue";
    button.disabled = attrs.disabled;
    wrap.appendChild(button);
    return { field: null, dom: wrap };
  }

  const field = el("input");
  // input_type is a hint from the contract; an unknown value degrades to text.
  field.type = attrs.input_type === "hidden" ? "hidden" : coerceInputType(attrs.input_type);
  field.name = attrs.name;
  field.required = attrs.required;
  field.disabled = attrs.disabled;
  if (attrs.autocomplete) {
    // setAttribute takes a plain string, avoiding a dependency on the exact
    // AutoFill token union the DOM lib models.
    field.setAttribute("autocomplete", attrs.autocomplete);
  }
  if (typeof attrs.value === "string" && attrs.input_type !== "password") {
    // A server prefill (never a secret) set as an attribute value, not markup.
    field.value = attrs.value;
  }

  if (attrs.input_type === "hidden") {
    wrap.appendChild(field);
  } else {
    const label = el("label", "flow-label");
    if (node.label) {
      const span = el("span", "flow-label-text");
      span.textContent = copy.text(node.label);
      label.appendChild(span);
    }
    label.appendChild(field);
    wrap.appendChild(label);
  }

  for (const message of node.messages) {
    wrap.appendChild(messageLine(copy, message));
  }
  return { field, dom: wrap };
}

function coerceInputType(inputType: string): string {
  // The browser only needs a valid <input type>; anything unrecognized is a
  // plain text field (forward compatible with a future input type).
  switch (inputType) {
    case "password":
    case "email":
    case "tel":
    case "checkbox":
    case "text":
      return inputType;
    default:
      return "text";
  }
}

// Render the whole flow into `container`, wiring the form submission to
// onSubmit(collectedValues). Clears any previous render first.
export function renderFlow(
  container: HTMLElement,
  flow: Flow,
  copy: Copy,
  onSubmit: (values: Record<string, string>) => void,
): void {
  container.replaceChildren();

  const form = el("form", "flow-form");
  form.method = "post";
  form.noValidate = false;

  // Flow-level messages (errors and info not attached to a single node).
  for (const message of flow.ui.messages) {
    form.appendChild(messageLine(copy, message));
  }

  const fields: HTMLInputElement[] = [];
  for (const node of flow.ui.nodes) {
    const { field, dom } = renderNode(copy, node);
    if (field) {
      fields.push(field);
    }
    form.appendChild(dom);
  }

  const rendered: RenderedForm = {
    collect() {
      const values: Record<string, string> = {};
      for (const field of fields) {
        if (field.type === "checkbox") {
          if (field.checked) {
            values[field.name] = field.value || "on";
          }
        } else if (field.name) {
          values[field.name] = field.value;
        }
      }
      return values;
    },
  };

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    onSubmit(rendered.collect());
  });

  container.appendChild(form);
}
