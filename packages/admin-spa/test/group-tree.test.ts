// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The PURE hierarchy logic behind the organization groups panel (issue #97),
// tested without a DOM and without a stubbed network. The property under test is
// the one an operator depends on: EVERY loaded group is rendered exactly once,
// whatever its parent_id points at. The management contract allows three ways for
// a parent pointer to be unresolvable, and each one would silently swallow a
// subtree if the forest were built only from null-parent roots:
//
//   a deleted parent (a delete DETACHES rather than cascading);
//   a parent on a page not read yet (the list is keyset paginated);
//   a parent chain that loops (nothing in the wire types forbids one).

import { describe, expect, it } from "vitest";
import type { OrgGroupView } from "../src/api/client";
import { buildGroupForest, groupAndDescendantIds } from "../src/ui/groupTree";

function group(
  id: string,
  parentId: string | null = null,
): OrgGroupView {
  return {
    id,
    slug: id,
    display_name: id.toUpperCase(),
    organization_id: "org_a",
    parent_id: parentId,
    metadata: {},
    created_at_unix_ms: 0,
    updated_at_unix_ms: 0,
  };
}

// The invariant every case below re-checks: one node per loaded group, no
// duplicates, no drops.
function expectsEveryGroupOnce(
  groups: ReadonlyArray<OrgGroupView>,
): ReturnType<typeof buildGroupForest> {
  const forest = buildGroupForest(groups);
  expect(forest.length).toBe(groups.length);
  const ids = forest.map((node) => node.group.id);
  expect(new Set(ids).size).toBe(groups.length);
  for (const item of groups) {
    expect(ids).toContain(item.id);
  }
  return forest;
}

describe("building the group forest", () => {
  it("nests children under their parent in depth first order", () => {
    const forest = expectsEveryGroupOnce([
      group("a"),
      group("b", "a"),
      group("c", "b"),
      group("d"),
    ]);
    expect(
      forest.map((node) => [node.group.id, node.depth, node.detached]),
    ).toEqual([
      ["a", 0, false],
      ["b", 1, false],
      ["c", 2, false],
      ["d", 0, false],
    ]);
  });

  it("keeps sibling order as the server returned it", () => {
    const forest = expectsEveryGroupOnce([
      group("root"),
      group("first", "root"),
      group("second", "root"),
      group("third", "root"),
    ]);
    expect(forest.map((node) => node.group.id)).toEqual([
      "root",
      "first",
      "second",
      "third",
    ]);
  });

  it("promotes a group whose parent is absent, and marks it detached", () => {
    // `gone` is not among the loaded rows: the parent was deleted, or it is on a
    // page not read yet. Dropping `orphan` here would hide it AND its subtree.
    const forest = expectsEveryGroupOnce([
      group("root"),
      group("orphan", "gone"),
      group("child", "orphan"),
    ]);
    expect(
      forest.map((node) => [node.group.id, node.depth, node.detached]),
    ).toEqual([
      ["root", 0, false],
      ["orphan", 0, true],
      ["child", 1, false],
    ]);
  });

  it("keeps a subtree nested when the page lists a child before its parent", () => {
    // The page is ordered oldest first, and a MOVE can put an old group under a
    // newer one, so a child legitimately arrives before its parent. The detached
    // parent must still anchor its subtree: the child belongs at depth 1 under
    // `orphan`, not promoted alongside it. A build that leans on a sweep over
    // unreachable rows instead of resolving the parent gets this backwards.
    const forest = expectsEveryGroupOnce([
      group("root"),
      group("child", "orphan"),
      group("orphan", "gone"),
    ]);
    expect(
      forest.map((node) => [node.group.id, node.depth, node.detached]),
    ).toEqual([
      ["root", 0, false],
      ["orphan", 0, true],
      ["child", 1, false],
    ]);
  });

  it("does not mark a declared root as detached", () => {
    const forest = buildGroupForest([group("root")]);
    expect(forest[0].detached).toBe(false);
  });

  it("treats a group that names itself as its parent as a detached root", () => {
    const forest = expectsEveryGroupOnce([group("self", "self")]);
    expect(forest[0].depth).toBe(0);
    expect(forest[0].detached).toBe(true);
  });

  it("emits every group of a parent loop rather than hanging or dropping it", () => {
    // A two node loop is reachable from no root at all. Without the completeness
    // net both rows would vanish from the panel.
    const forest = expectsEveryGroupOnce([
      group("x", "y"),
      group("y", "x"),
      group("plain"),
    ]);
    expect(forest.map((node) => node.group.id).sort()).toEqual([
      "plain",
      "x",
      "y",
    ]);
  });

  it("returns nothing for an empty page", () => {
    expect(buildGroupForest([])).toEqual([]);
  });
});

describe("the groups a group may not move under", () => {
  const tree = [
    group("a"),
    group("b", "a"),
    group("c", "b"),
    group("d"),
  ];

  it("blocks the group itself and its whole subtree", () => {
    expect([...groupAndDescendantIds(tree, "a")].sort()).toEqual([
      "a",
      "b",
      "c",
    ]);
  });

  it("blocks only the group itself when it is a leaf", () => {
    expect([...groupAndDescendantIds(tree, "c")]).toEqual(["c"]);
  });

  it("leaves an unrelated group available", () => {
    expect(groupAndDescendantIds(tree, "a").has("d")).toBe(false);
  });

  it("blocks the group itself when it is not among the loaded rows", () => {
    expect([...groupAndDescendantIds(tree, "absent")]).toEqual(["absent"]);
  });
});
