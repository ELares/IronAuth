// SPDX-License-Identifier: MIT OR Apache-2.0

import { afterEach, describe, expect, it } from "vitest";
import { consoleHref } from "../src/ui/routing";

const originalUrl = window.location.href;
afterEach(() => window.history.replaceState({}, "", originalUrl));

describe("console navigation mount", () => {
  it("keeps links and route patterns in the embedded console on deep pages", () => {
    window.history.replaceState({}, "", "/admin/users/usr_example");
    expect(consoleHref("/")).toBe("/admin/");
    expect(consoleHref("/users/usr_example")).toBe("/admin/users/usr_example");
    expect(consoleHref("/users/:userId")).toBe("/admin/users/:userId");
  });

  it("supports a standalone console without confusing similarly named paths", () => {
    window.history.replaceState({}, "", "/users/usr_example");
    expect(consoleHref("/users")).toBe("/users");
    window.history.replaceState({}, "", "/administrator");
    expect(consoleHref("/tenants")).toBe("/tenants");
  });
});
