// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The verbatim management ErrorBody boundary (a hard acceptance criterion: API
// and SPA users see identical errors). Every present field renders verbatim, and
// a hostile-looking message renders as INERT TEXT (Preact escapes it; no HTML
// node is created, and the component uses no dangerouslySetInnerHTML).

import { afterEach, describe, expect, it } from "vitest";
import { render } from "preact";
import type { ErrorBody } from "../src/api/client";
import { toErrorBody } from "../src/api/client";
import { ErrorView } from "../src/ui/ErrorView";

let container: HTMLDivElement | null = null;

function mount(node: Parameters<typeof render>[0]): HTMLDivElement {
  container = document.createElement("div");
  document.body.appendChild(container);
  render(node, container);
  return container;
}

afterEach(() => {
  if (container !== null) {
    render(null, container);
    container.remove();
    container = null;
  }
});

describe("ErrorView renders the ErrorBody verbatim", () => {
  it("shows error, message, scopes, and guardrails as the server worded them", () => {
    const error: ErrorBody = {
      error: "wrong_scope",
      message: "the credential is not authorized for this scope",
      actual_scope: "tenant:acme env:staging",
      expected_scope: "tenant:acme env:production",
      failed_guardrails: ["custom_domain_required", "https_only_redirect_uris"],
    };
    const root = mount(<ErrorView error={error} />);
    const text = root.textContent ?? "";
    expect(text).toContain("wrong_scope");
    expect(text).toContain("the credential is not authorized for this scope");
    expect(text).toContain("tenant:acme env:staging");
    expect(text).toContain("tenant:acme env:production");
    expect(text).toContain("custom_domain_required");
    expect(text).toContain("https_only_redirect_uris");
  });

  it("renders a hostile message as inert text, never as HTML", () => {
    const hostile =
      '<img src=x onerror="steal()"> and <script>evil()</script>';
    const root = mount(
      <ErrorView error={{ error: "bad_request", message: hostile }} />,
    );
    // The raw text is present verbatim ...
    expect(root.textContent).toContain(hostile);
    // ... but NO element was injected from it.
    expect(root.querySelector("img")).toBeNull();
    expect(root.querySelector("script")).toBeNull();
  });

  it("omits the optional sections when the server did not include them", () => {
    const root = mount(
      <ErrorView error={{ error: "not_found", message: "resource not found" }} />,
    );
    expect(root.querySelector(".errorbody-scope")).toBeNull();
    expect(root.querySelector(".errorbody-guardrails")).toBeNull();
    expect(root.querySelector(".errorbody-sudo")).toBeNull();
  });

  it("shows the sudo re-authentication affordance on a max_age challenge", () => {
    const root = mount(
      <ErrorView
        error={{
          error: "sudo_required",
          message: "this change requires a fresh sign in",
          max_age: 300,
        }}
        sudo={{
          scope: { tenantId: "T", environmentId: "E" },
          retry: () => Promise.resolve(),
        }}
      />,
    );
    expect(root.querySelector(".errorbody-sudo")).not.toBeNull();
    expect(root.querySelector(".errorbody-reauth")).not.toBeNull();
    expect(root.textContent).toContain("300");
  });
});

describe("toErrorBody maps a raw body verbatim", () => {
  it("preserves every present field and only present fields", () => {
    const mapped = toErrorBody({
      error: "wrong_scope",
      message: "nope",
      actual_scope: "a",
      expected_scope: "b",
      failed_guardrails: ["g1", 7, "g2"],
      max_age: 120,
    });
    expect(mapped).toEqual({
      error: "wrong_scope",
      message: "nope",
      actual_scope: "a",
      expected_scope: "b",
      failed_guardrails: ["g1", "g2"],
      max_age: 120,
    });
  });

  it("falls back to a generic shape when the body is empty", () => {
    expect(toErrorBody(null)).toEqual({
      error: "unknown_error",
      message: "The request could not be processed.",
    });
  });
});
