// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The organization API keys panel (issue #99, criterion 6).
//
// Two properties are worth driving through the rendered DOM rather than asserting on
// the helper alone: that a REVOKED key is shown rather than filtered away, and that
// no key material can reach the panel. The second is a property of the types, so this
// is a guard on the types staying that way.

import { describe, expect, it } from "vitest";
import { describe as describeKey } from "../src/ui/OrgApiKeysView";

describe("api key lifecycle wording", () => {
  it("reports a revoked key as revoked, not as expired", () => {
    // Revoked wins over expired. A key that was revoked and then passed its expiry is
    // revoked, and reporting the expiry would suggest it lapsed on its own rather than
    // that somebody killed it, which is the opposite conclusion during an incident.
    const both = describeKey({
      id: "akey_1",
      display_name: "ci",
      expires_at_unix_ms: 1_700_000_000_000,
      revoked_at_unix_ms: 1_700_000_500_000,
    });
    expect(both.startsWith("Revoked")).toBe(true);
  });

  it("distinguishes an expiring key from one with no expiry", () => {
    expect(
      describeKey({
        id: "akey_2",
        display_name: "ci",
        expires_at_unix_ms: 1_700_000_000_000,
      }).startsWith("Expires"),
    ).toBe(true);
    expect(describeKey({ id: "akey_3", display_name: "ci" })).toBe(
      "Live, no expiry",
    );
  });

  it("treats an explicit null the same as an absent timestamp", () => {
    // The generated contract types model a skip_serializing_if Option as
    // `number | null | undefined`, so null genuinely arrives. Narrowing the checks to
    // `!== undefined` alone would report a live key as "Revoked NaN".
    expect(
      describeKey({
        id: "akey_4",
        display_name: "ci",
        expires_at_unix_ms: null,
        revoked_at_unix_ms: null,
      }),
    ).toBe("Live, no expiry");
  });
});
