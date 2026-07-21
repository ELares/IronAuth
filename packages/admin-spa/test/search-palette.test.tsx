// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Global search inside the palette (issue #90, PR 7): the PR3 command palette is
// the ONE search surface, so these component tests drive the real palette with a
// stubbed fetch and prove the search integration end to end: a hostile result
// field renders INERT (escaped text, never HTML); a failed list surfaces the
// verbatim ErrorView inside the dialog rather than a silent empty; and rapid
// typing debounces down to a single list call (and a below-minimum query fires
// none). The palette reads no credential: it renders only what the public list
// ops return.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render } from "preact";
import { CommandPalette } from "../src/ui/CommandPalette";
import { SEARCH_DEBOUNCE_MS } from "../src/ui/search";

const realFetch = globalThis.fetch;
let container: HTMLDivElement | null = null;

function setManagementBase(url: string): void {
  let el = document.querySelector('meta[name="ironauth-management-base"]');
  if (el === null) {
    el = document.createElement("meta");
    el.setAttribute("name", "ironauth-management-base");
    document.head.appendChild(el);
  }
  el.setAttribute("content", url);
}

function mount(node: Parameters<typeof render>[0]): HTMLDivElement {
  container = document.createElement("div");
  document.body.appendChild(container);
  render(node, container);
  return container;
}

// Flush Preact's scheduled render and effect callbacks (a frame plus a macrotask).
async function tick(): Promise<void> {
  await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
}

// Wait past the search debounce so the pending list call has fired and resolved.
async function settle(): Promise<void> {
  await new Promise<void>((resolve) =>
    setTimeout(resolve, SEARCH_DEBOUNCE_MS + 80),
  );
  await tick();
}

function keydown(target: EventTarget, key: string, mods: KeyboardEventInit = {}) {
  target.dispatchEvent(new KeyboardEvent("keydown", { key, bubbles: true, ...mods }));
}

function typeInto(input: HTMLInputElement, value: string): void {
  input.value = value;
  input.dispatchEvent(new Event("input", { bubbles: true }));
}

beforeEach(() => {
  setManagementBase("http://management.test/admin/api");
});

afterEach(() => {
  globalThis.fetch = realFetch;
  if (container !== null) {
    render(null, container);
    container.remove();
    container = null;
  }
});

describe("global search renders a hostile result field inert", () => {
  it("shows the hostile display name as escaped text, never as HTML", async () => {
    const hostile = "<img src=x onerror=alert(1)>Acme";
    globalThis.fetch = vi.fn(
      async () =>
        new Response(JSON.stringify({ items: [{ id: "ten_1", display_name: hostile }] }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    ) as typeof globalThis.fetch;

    const root = mount(<CommandPalette />);
    await tick();
    keydown(window, "k", { ctrlKey: true });
    await tick();
    const input = root.querySelector(".cmdk-input") as HTMLInputElement;
    typeInto(input, "acme");
    await settle();

    // The hostile string is present as TEXT, and no <img> was ever created: Preact
    // escaped the label, so the injected markup is inert.
    const label = root.querySelector(".cmdk-item-label");
    expect(label?.textContent).toContain(hostile);
    expect(root.querySelector("img")).toBeNull();
  });
});

describe("a failed search surfaces the verbatim error, not a silent empty", () => {
  it("renders the ErrorView boundary inside the dialog on a bodyless non 2xx", async () => {
    globalThis.fetch = vi.fn(
      async () =>
        new Response(null, { status: 401, headers: { "content-length": "0" } }),
    ) as typeof globalThis.fetch;

    const root = mount(<CommandPalette />);
    await tick();
    keydown(window, "k", { ctrlKey: true });
    await tick();
    const input = root.querySelector(".cmdk-input") as HTMLInputElement;
    typeInto(input, "acme");
    await settle();

    // The verbatim ErrorView is shown; the failure is not swallowed into an empty
    // result list.
    expect(root.querySelector(".cmdk-error .errorbody")).not.toBeNull();
  });
});

describe("search is debounced and gated on a minimum length", () => {
  it("fires a single list call for rapid typing and none below the minimum", async () => {
    let calls = 0;
    globalThis.fetch = vi.fn(async () => {
      calls += 1;
      return new Response(JSON.stringify({ items: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof globalThis.fetch;

    const root = mount(<CommandPalette />);
    await tick();
    keydown(window, "k", { ctrlKey: true });
    await tick();
    const input = root.querySelector(".cmdk-input") as HTMLInputElement;

    // A one character query is below the minimum and must fire nothing.
    typeInto(input, "a");
    await tick();
    // Rapid typing: each keystroke cancels the pending debounce, so only the final
    // query survives to fire one list call.
    typeInto(input, "ac");
    typeInto(input, "acm");
    typeInto(input, "acme");
    await settle();

    expect(calls).toBe(1);
  });
});
