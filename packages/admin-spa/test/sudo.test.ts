// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The RFC 9470 sudo re-authentication path: a max_age-bearing error is detected
// as a sudo challenge, and the recovery drives re-authenticate then elevate then
// retry, in that order, short circuiting if a step fails.

import { describe, expect, it, vi } from "vitest";
import {
  isSudoChallenge,
  performSudoElevation,
  sudoMaxAge,
} from "../src/auth/sudo";

describe("sudo challenge detection", () => {
  it("reads max_age from a challenge and null from a plain error", () => {
    expect(sudoMaxAge({ error: "sudo_required", message: "m", max_age: 300 })).toBe(
      300,
    );
    expect(sudoMaxAge({ error: "not_found", message: "m" })).toBeNull();
    expect(isSudoChallenge({ error: "sudo_required", message: "m", max_age: 0 })).toBe(
      true,
    );
    expect(isSudoChallenge({ error: "not_found", message: "m" })).toBe(false);
  });
});

describe("performSudoElevation", () => {
  it("re-authenticates, then elevates, then retries, in order", async () => {
    const calls: string[] = [];
    await performSudoElevation({
      reauthenticate: () => {
        calls.push("reauthenticate");
        return Promise.resolve();
      },
      elevate: () => {
        calls.push("elevate");
        return Promise.resolve();
      },
      retry: () => {
        calls.push("retry");
        return Promise.resolve();
      },
    });
    expect(calls).toEqual(["reauthenticate", "elevate", "retry"]);
  });

  it("short circuits: a failed re-authentication never elevates or retries", async () => {
    const elevate = vi.fn(() => Promise.resolve());
    const retry = vi.fn(() => Promise.resolve());
    await expect(
      performSudoElevation({
        reauthenticate: () => Promise.reject(new Error("redirect blocked")),
        elevate,
        retry,
      }),
    ).rejects.toThrow("redirect blocked");
    expect(elevate).not.toHaveBeenCalled();
    expect(retry).not.toHaveBeenCalled();
  });
});
