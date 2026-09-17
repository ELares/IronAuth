// SPDX-License-Identifier: MIT OR Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { render } from "preact";
import { useState } from "preact/hooks";
import { MutationFeedback, ResourceCreateAction } from "../src/ui/ResourceView";
import { useMutation } from "../src/ui/useResource";
import { ManagementError } from "../src/api/client";

let container: HTMLDivElement | null = null;

async function flush(): Promise<void> {
  for (let index = 0; index < 4; index += 1) {
    await new Promise<void>((resolve) =>
      requestAnimationFrame(() => resolve()),
    );
  }
}

function CreationForm({
  operation,
  onCreated,
}: {
  operation: () => Promise<void>;
  onCreated: () => void;
}) {
  const mutation = useMutation();
  const [name, setName] = useState("");
  return (
    <form
      aria-label="Create a user"
      onSubmit={(event) => {
        event.preventDefault();
        void mutation.run(operation, "User created.").then((ok) => {
          if (ok) onCreated();
        });
      }}
    >
      <label>
        Name
        <input
          aria-label="Name"
          value={name}
          onInput={(event) => {
            setName(event.currentTarget.value);
          }}
        />
      </label>
      <button type="submit" disabled={mutation.state.pending}>
        Save user
      </button>
      <MutationFeedback state={mutation.state} />
    </form>
  );
}

function mount(operation: () => Promise<void>): HTMLDivElement {
  container = document.createElement("div");
  document.body.appendChild(container);
  render(
    <section>
      <h1>Users</h1>
      <ResourceCreateAction label="Create user">
        {(close) => <CreationForm operation={operation} onCreated={close} />}
      </ResourceCreateAction>
      <ul aria-label="Existing users">
        <li>Existing user</li>
      </ul>
    </section>,
    container,
  );
  return container;
}

afterEach(() => {
  if (container !== null) {
    render(null, container);
    container.remove();
    container = null;
  }
  document.body.classList.remove("resource-dialog-open");
});

describe("explicit resource creation", () => {
  it("restores focus when a shared mutation requests close before it settles", async () => {
    let resolveRequest!: () => void;
    const request = new Promise<void>((resolve) => {
      resolveRequest = resolve;
    });
    function SharedCreation() {
      const mutation = useMutation();
      return (
        <ResourceCreateAction
          label="Grant role"
          pending={mutation.state.pending}
        >
          {(close) => (
            <form
              onSubmit={(event) => {
                event.preventDefault();
                void mutation.run(async () => {
                  await request;
                  close();
                }, "Role granted.");
              }}
            >
              <input aria-label="Role ID" />
              <button type="submit">Grant</button>
              <MutationFeedback state={mutation.state} />
            </form>
          )}
        </ResourceCreateAction>
      );
    }
    container = document.createElement("div");
    document.body.appendChild(container);
    render(<SharedCreation />, container);
    const trigger = container.querySelector("button")!;
    trigger.click();
    await flush();
    container
      .querySelector("form")!
      .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await flush();
    expect(trigger.disabled).toBe(true);
    resolveRequest();
    await flush();
    expect(container.querySelector("dialog")).toBeNull();
    expect(trigger.disabled).toBe(false);
    expect(document.activeElement).toBe(trigger);
  });

  it("shows the list first and discards a cancelled creation draft", async () => {
    const operation = vi.fn(async () => {});
    const root = mount(operation);
    await flush();
    expect(root.querySelector("form")).toBeNull();
    expect(root.querySelector("ul")?.textContent).toBe("Existing user");
    const trigger = root.querySelector("button")!;
    trigger.click();
    await flush();
    const name = root.querySelector("input")!;
    expect(document.activeElement).toBe(name);
    name.value = "Unsaved user";
    name.dispatchEvent(new Event("input", { bubbles: true }));
    await flush();
    root
      .querySelector<HTMLButtonElement>(
        ".resource-create-dialog-footer button",
      )!
      .click();
    await flush();
    expect(root.querySelector("form")).toBeNull();
    expect(document.activeElement).toBe(trigger);
    expect(operation).not.toHaveBeenCalled();
    trigger.click();
    await flush();
    expect(root.querySelector("input")!.value).toBe("");
    expect(root.querySelector("ul")?.textContent).toBe("Existing user");
  });

  it("closes with Escape and restores focus to an unfocused touch trigger", async () => {
    const root = mount(async () => {});
    const trigger = root.querySelector("button")!;
    trigger.click();
    await flush();
    expect(document.body.classList.contains("resource-dialog-open")).toBe(true);
    root.querySelector("input")!.dispatchEvent(
      new KeyboardEvent("keydown", {
        key: "Escape",
        bubbles: true,
      }),
    );
    await flush();
    expect(root.querySelector("dialog")).toBeNull();
    expect(document.activeElement).toBe(trigger);
    expect(document.body.classList.contains("resource-dialog-open")).toBe(
      false,
    );
  });

  it("keeps a submitted request open while pending, shows errors, then closes on success", async () => {
    let rejectRequest!: (reason: unknown) => void;
    const request = new Promise<void>((_, reject) => {
      rejectRequest = reject;
    });
    const operation = vi
      .fn()
      .mockReturnValueOnce(request)
      .mockResolvedValueOnce(undefined);
    const root = mount(operation);
    root.querySelector("button")!.click();
    await flush();
    root
      .querySelector("form")!
      .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    expect(
      root.querySelector<HTMLButtonElement>(
        ".resource-create-dialog-footer button",
      )!.disabled,
    ).toBe(true);
    root
      .querySelector("input")!
      .dispatchEvent(
        new KeyboardEvent("keydown", { key: "Escape", bubbles: true }),
      );
    await flush();
    expect(root.querySelector("dialog")).not.toBeNull();
    rejectRequest(
      new ManagementError(
        { error: "conflict", message: "This user already exists." },
        409,
      ),
    );
    await flush();
    expect(root.querySelector("dialog")?.textContent).toContain(
      "This user already exists.",
    );
    expect(
      root.querySelector<HTMLButtonElement>(
        ".resource-create-dialog-footer button",
      )!.disabled,
    ).toBe(false);
    root
      .querySelector("form")!
      .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await flush();
    expect(root.querySelector("dialog")).toBeNull();
    expect(operation).toHaveBeenCalledTimes(2);
    expect(root.querySelector("ul")?.textContent).toBe("Existing user");
  });
});
