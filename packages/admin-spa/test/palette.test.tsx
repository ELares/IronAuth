// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The command palette: the pure filter and index wrap, and the keyboard flow
// (Cmd/Ctrl-K opens, ArrowDown moves the selection, Enter runs it, Escape
// closes). The component test injects explicit commands so it exercises the
// keyboard mechanics without the store or a live router.

import { afterEach, describe, expect, it, vi } from "vitest";
import { render } from "preact";
import { type Command, filterCommands, wrapIndex } from "../src/ui/commands";
import { CommandPalette } from "../src/ui/CommandPalette";

let container: HTMLDivElement | null = null;

function mount(node: Parameters<typeof render>[0]): HTMLDivElement {
  container = document.createElement("div");
  document.body.appendChild(container);
  render(node, container);
  return container;
}

// Flush Preact's scheduled render and effect callbacks. Preact commits renders on
// a microtask and runs effects after paint (requestAnimationFrame, with a timer
// fallback), so a robust flush awaits both a frame and a macrotask.
async function tick(): Promise<void> {
  await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
}

afterEach(() => {
  if (container !== null) {
    render(null, container);
    container.remove();
    container = null;
  }
});

describe("filterCommands", () => {
  const commands: Command[] = [
    { id: "1", label: "Go to Tenants", run: () => undefined },
    { id: "2", label: "Switch to tenant Acme", hint: "ten_acme", run: () => undefined },
    { id: "3", label: "Go to Users", run: () => undefined },
  ];

  it("returns everything for an empty query", () => {
    expect(filterCommands(commands, "")).toHaveLength(3);
  });

  it("matches case-insensitively over label and hint", () => {
    expect(filterCommands(commands, "TENANT").map((c) => c.id)).toEqual(["1", "2"]);
    expect(filterCommands(commands, "ten_acme").map((c) => c.id)).toEqual(["2"]);
    expect(filterCommands(commands, "users").map((c) => c.id)).toEqual(["3"]);
  });
});

describe("wrapIndex", () => {
  it("wraps around both ends and clamps an empty list to zero", () => {
    expect(wrapIndex(0, 3)).toBe(0);
    expect(wrapIndex(3, 3)).toBe(0);
    expect(wrapIndex(-1, 3)).toBe(2);
    expect(wrapIndex(5, 0)).toBe(0);
  });
});

describe("command palette keyboard flow", () => {
  function keydown(target: EventTarget, key: string, mods: KeyboardEventInit = {}) {
    target.dispatchEvent(
      new KeyboardEvent("keydown", { key, bubbles: true, ...mods }),
    );
  }

  it("opens on Ctrl-K, moves with ArrowDown, runs on Enter, and closes", async () => {
    const alpha = vi.fn();
    const bravo = vi.fn();
    const commands: Command[] = [
      { id: "a", label: "Alpha action", run: alpha },
      { id: "b", label: "Bravo action", run: bravo },
    ];
    const root = mount(<CommandPalette commands={commands} />);
    await tick();
    expect(root.querySelector('[role="dialog"]')).toBeNull();

    keydown(window, "k", { ctrlKey: true });
    await tick();
    const dialog = root.querySelector('[role="dialog"]');
    expect(dialog).not.toBeNull();

    const input = root.querySelector(".cmdk-input") as HTMLInputElement;
    // First option is active on open.
    expect(root.querySelector('[aria-selected="true"]')?.textContent).toContain(
      "Alpha action",
    );

    keydown(input, "ArrowDown");
    await tick();
    expect(root.querySelector('[aria-selected="true"]')?.textContent).toContain(
      "Bravo action",
    );

    keydown(input, "Enter");
    await tick();
    expect(bravo).toHaveBeenCalledTimes(1);
    expect(alpha).not.toHaveBeenCalled();
    // Running a command closes the palette.
    expect(root.querySelector('[role="dialog"]')).toBeNull();
  });

  it("closes on Escape without running a command", async () => {
    const alpha = vi.fn();
    const commands: Command[] = [{ id: "a", label: "Alpha action", run: alpha }];
    const root = mount(<CommandPalette commands={commands} />);
    await tick();

    keydown(window, "k", { metaKey: true });
    await tick();
    expect(root.querySelector('[role="dialog"]')).not.toBeNull();

    const input = root.querySelector(".cmdk-input") as HTMLInputElement;
    keydown(input, "Escape");
    await tick();
    expect(root.querySelector('[role="dialog"]')).toBeNull();
    expect(alpha).not.toHaveBeenCalled();
  });
});
