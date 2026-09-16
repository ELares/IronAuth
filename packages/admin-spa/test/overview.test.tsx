// SPDX-License-Identifier: MIT OR Apache-2.0

import { afterEach, describe, expect, it } from "vitest";
import { render } from "preact";
import { OverviewView } from "../src/ui/OverviewView";
import {
  resetScope,
  scopeError,
  scopeLoaded,
  tenants,
} from "../src/scope/store";

let container: HTMLDivElement | null = null;
function mount() {
  container = document.createElement("div");
  document.body.appendChild(container);
  render(<OverviewView />, container);
  return container;
}
afterEach(() => {
  if (container !== null) {
    render(null, container);
    container.remove();
    container = null;
  }
  resetScope();
});

describe("overview scope summary", () => {
  it("uses loaded tenant data and makes the list boundary visible", () => {
    tenants.value = [
      {
        id: "ten_example",
        display_name: "Example",
        status: "active",
        created_at_unix_ms: 0,
      },
    ];
    scopeLoaded.value = true;
    const root = mount();
    expect(root.querySelector(".stat-value")?.textContent).toBe("1");
    expect(root.textContent).toContain("In the loaded tenant list");
    expect(root.querySelector(".overview-setup")).toBeNull();
  });
  it("does not show zero counts or a first-workspace prompt after a failed load", () => {
    scopeLoaded.value = true;
    scopeError.value = {
      error: "scope_load_failed",
      message: "Failed to load scope",
    };
    const root = mount();
    expect(root.querySelector(".overview-stats")).toBeNull();
    expect(root.querySelector(".overview-setup")).toBeNull();
    expect(root.querySelectorAll(".overview-resource-card")).toHaveLength(6);
  });
});
