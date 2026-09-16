// SPDX-License-Identifier: MIT OR Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { render } from "preact";
import { fetchClientServiceAccount } from "../src/api/client";
import { ClientServiceAccountKeysPanel } from "../src/ui/ClientServiceAccountKeysView";
import {
  ConfirmButton,
  ResourceCollection,
  SecretCopyButton,
} from "../src/ui/ResourceView";

vi.mock("../src/api/client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../src/api/client")>()),
  fetchClientServiceAccount: vi.fn(),
}));

let container: HTMLDivElement | null = null;
const originalClipboard = Object.getOwnPropertyDescriptor(
  navigator,
  "clipboard",
);

function mount(node: Parameters<typeof render>[0]): HTMLDivElement {
  container = document.createElement("div");
  document.body.appendChild(container);
  render(node, container);
  return container;
}

async function flush(): Promise<void> {
  for (let i = 0; i < 4; i += 1) {
    await Promise.resolve();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    await new Promise<void>((resolve) =>
      requestAnimationFrame(() => resolve()),
    );
  }
}

afterEach(() => {
  if (container !== null) {
    render(null, container);
    container.remove();
    container = null;
  }
  if (originalClipboard === undefined) {
    delete (navigator as unknown as { clipboard?: unknown }).clipboard;
  } else {
    Object.defineProperty(navigator, "clipboard", originalClipboard);
  }
  vi.clearAllMocks();
});

describe("resource collection search", () => {
  const items = [
    { id: "ten_a", name: "Acme" },
    { id: "ten_b", name: "Globex" },
  ];

  it("filters the loaded page by name and ID without changing the source items", async () => {
    const root = mount(
      <ResourceCollection
        items={items}
        noun="tenants"
        searchText={(item) => `${item.name} ${item.id}`}
        paginated
      >
        {(visible) => (
          <ul>
            {visible.map((item) => (
              <li key={item.id}>{item.name}</li>
            ))}
          </ul>
        )}
      </ResourceCollection>,
    );
    await flush();
    const search = root.querySelector(
      'input[type="search"]',
    ) as HTMLInputElement;
    search.value = "TEN_B";
    search.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();
    expect(root.querySelector("ul")?.textContent).toBe("Globex");
    expect(root.querySelector(".resource-count")?.textContent).toBe(
      "1 of 2 tenants on this page",
    );
    expect(items).toHaveLength(2);
  });

  it("offers a clear action for no matches and returns focus to search", async () => {
    const root = mount(
      <ResourceCollection
        items={items}
        noun="tenants"
        searchText={(item) => item.name}
      >
        {(visible) => (
          <ul>
            {visible.map((item) => (
              <li key={item.id}>{item.name}</li>
            ))}
          </ul>
        )}
      </ResourceCollection>,
    );
    await flush();
    const search = root.querySelector("input") as HTMLInputElement;
    search.value = "unknown";
    search.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();
    expect(root.textContent).toContain("No matching tenants");
    (root.querySelector("button") as HTMLButtonElement).click();
    await flush();
    expect(search.value).toBe("");
    expect(root.querySelectorAll("li")).toHaveLength(2);
    expect(document.activeElement).toBe(search);
  });
});

describe("confirmation keyboard behavior", () => {
  it("focuses confirmation, describes its consequence and restores focus on Escape", async () => {
    const onConfirm = vi.fn();
    const root = mount(
      <ConfirmButton
        label="Delete"
        prompt="Delete this identity?"
        confirmLabel="Confirm delete"
        danger
        onConfirm={onConfirm}
      />,
    );
    await flush();
    (root.querySelector("button") as HTMLButtonElement).click();
    await flush();
    const confirm = root.querySelector("button") as HTMLButtonElement;
    expect(document.activeElement).toBe(confirm);
    const descriptionId = confirm.getAttribute("aria-describedby");
    expect(document.getElementById(descriptionId ?? "")?.textContent).toBe(
      "Delete this identity?",
    );
    confirm.dispatchEvent(
      new KeyboardEvent("keydown", { key: "Escape", bubbles: true }),
    );
    await flush();
    expect(document.activeElement).toBe(root.querySelector("button"));
    expect(root.querySelector("button")?.textContent).toBe("Delete");
    expect(onConfirm).not.toHaveBeenCalled();
  });
});

describe("one-time credential copying", () => {
  it("copies the displayed credential and reports completion", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    const root = mount(
      <SecretCopyButton value="test-credential" label="Copy key" />,
    );
    await flush();
    (root.querySelector("button") as HTMLButtonElement).click();
    await flush();
    expect(writeText).toHaveBeenCalledWith("test-credential");
    expect(root.querySelector('[role="status"]')?.textContent).toBe(
      "Copied to clipboard.",
    );
  });

  it("explains manual copying when clipboard access is unavailable", async () => {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: undefined,
    });
    const root = mount(<SecretCopyButton value="test-credential" />);
    await flush();
    (root.querySelector("button") as HTMLButtonElement).click();
    await flush();
    expect(root.textContent).toContain(
      "Select the value and copy it manually.",
    );
    expect(root.textContent).not.toContain("test-credential");
  });
});

it("explains when a client has not yet created a service account", async () => {
  vi.mocked(fetchClientServiceAccount).mockResolvedValue(null);
  const root = mount(
    <ClientServiceAccountKeysPanel tenantId="ten_a" environmentId="env_a" />,
  );
  await flush();
  const input = root.querySelector("input") as HTMLInputElement;
  input.value = "cli_a";
  input.dispatchEvent(new Event("input", { bubbles: true }));
  await flush();
  (root.querySelector("form") as HTMLFormElement).dispatchEvent(
    new Event("submit", { bubbles: true, cancelable: true }),
  );
  await flush();
  expect(fetchClientServiceAccount).toHaveBeenCalledWith(
    "ten_a",
    "env_a",
    "cli_a",
  );
  expect(root.textContent).toContain("This client has no service account yet.");
  expect(root.textContent).not.toContain("This service account has no keys.");
});
