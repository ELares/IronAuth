// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The single-environment collapse (a hard acceptance criterion): a tenant with
// exactly one environment and no cross-tenant reach hides the switcher entirely;
// any richer shape shows it.

import { describe, expect, it } from "vitest";
import {
  hasCrossTenantReach,
  shouldCollapseSwitcher,
} from "../src/scope/logic";

const oneTenant = [{ id: "t1" }];
const oneEnv = [{ id: "e1" }];

describe("shouldCollapseSwitcher", () => {
  it("collapses for a single tenant with a single environment", () => {
    expect(
      shouldCollapseSwitcher({
        tenants: oneTenant,
        environments: oneEnv,
        crossTenantReach: false,
      }),
    ).toBe(true);
  });

  it("shows the switcher when the tenant has more than one environment", () => {
    expect(
      shouldCollapseSwitcher({
        tenants: oneTenant,
        environments: [{ id: "e1" }, { id: "e2" }],
        crossTenantReach: false,
      }),
    ).toBe(false);
  });

  it("shows the switcher when the principal reaches more than one tenant", () => {
    expect(
      shouldCollapseSwitcher({
        tenants: [{ id: "t1" }, { id: "t2" }],
        environments: oneEnv,
        crossTenantReach: true,
      }),
    ).toBe(false);
  });

  it("does not collapse when there are zero environments (no scope to imply)", () => {
    expect(
      shouldCollapseSwitcher({
        tenants: oneTenant,
        environments: [],
        crossTenantReach: false,
      }),
    ).toBe(false);
  });
});

describe("hasCrossTenantReach", () => {
  it("is false for one tenant and true for more than one", () => {
    expect(hasCrossTenantReach(oneTenant)).toBe(false);
    expect(hasCrossTenantReach([{ id: "t1" }, { id: "t2" }])).toBe(true);
  });
});
