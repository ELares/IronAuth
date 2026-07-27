// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The PURE hierarchy logic behind the organization groups panel (issue #97).
// Kept out of the component, like src/ui/commands.ts and src/scope/logic.ts, so
// the shape of the rendered tree is unit tested without a DOM and without a
// stubbed network. There is NO network call and NO path literal here.
//
// The management contract returns a group page FLAT: every group carries its
// `parent_id`, and the console builds the hierarchy itself. Three properties of
// that contract drive this module, and each one is a way an operator could
// silently lose a row if the build were naive:
//
//   1. A `parent_id` may name a group that has been DELETED. A delete DETACHES
//      the subtree rather than cascading, so a child of a deleted group is a
//      root in every hierarchy walk the server does. Rendering only from
//      null-parent roots would hide that whole subtree.
//
//   2. The page is KEYSET paginated, so a child can load on the first page while
//      its parent loads on a later one. Same failure mode, different cause.
//
//   3. Nothing in the wire types forbids a parent chain that loops. The server
//      refuses cycles at write time, but the console must not hang or drop rows
//      if it is ever handed one.
//
// So the ONE invariant this module guarantees is: every loaded group is emitted
// EXACTLY ONCE, whatever its parent points at. A group whose parent is not among
// the loaded rows is emitted at the top level and MARKED `detached`, so the
// operator is told the hierarchy shown is not the whole story rather than being
// shown a smaller tree that looks complete.

import type { OrgGroupView } from "../api/client";

// One group placed in the rendered hierarchy: the group itself, its nesting
// depth (0 for a top level row), and whether it sits at the top level ONLY
// because its parent could not be resolved among the loaded rows.
export interface GroupNode {
  readonly group: OrgGroupView;
  readonly depth: number;
  readonly detached: boolean;
}

// The parent of a group, or null when it is a declared root. Normalises the
// optional-and-nullable wire field to one value.
function parentOf(group: OrgGroupView): string | null {
  return group.parent_id ?? null;
}

// Flatten the loaded groups into depth-first hierarchy order.
//
// Returns one node per input group, in the order they should be rendered:
// each top level group followed by its subtree. Siblings keep the order the
// server returned them in (oldest first), so two reads of unchanged state
// produce the same rendering.
export function buildGroupForest(
  groups: ReadonlyArray<OrgGroupView>,
): GroupNode[] {
  const byId = new Map<string, OrgGroupView>();
  for (const group of groups) {
    byId.set(group.id, group);
  }

  const children = new Map<string, OrgGroupView[]>();
  const tops: OrgGroupView[] = [];
  for (const group of groups) {
    const parent = parentOf(group);
    // A group is a top level row when it declares no parent, when it points at
    // itself, or when the parent it names is not among the loaded rows (deleted,
    // or on a page not read yet). The last two are the `detached` case.
    //
    // The self-parent clause is NOT redundant with the completeness net below,
    // and the difference is ORDER. Without it a self-parented group is filed as
    // its own child, is reachable from no top level row, and is emitted by the
    // net AFTER every other row instead of in the page position the server gave
    // it. Both spellings emit it once, at depth 0, marked detached, so only a
    // case with another row after it can tell them apart; group-tree.test.ts
    // carries exactly that case.
    if (parent === null || parent === group.id || !byId.has(parent)) {
      tops.push(group);
      continue;
    }
    const siblings = children.get(parent);
    if (siblings === undefined) {
      children.set(parent, [group]);
    } else {
      siblings.push(group);
    }
  }

  const out: GroupNode[] = [];
  const seen = new Set<string>();

  function walk(group: OrgGroupView, depth: number, detached: boolean): void {
    // The cycle guard. A loop among the loaded rows would otherwise recurse
    // forever; with it, the first row of the loop anchors the subtree and every
    // member of the loop is still emitted exactly once.
    if (seen.has(group.id)) {
      return;
    }
    seen.add(group.id);
    out.push({ group, depth, detached });
    for (const child of children.get(group.id) ?? []) {
      walk(child, depth + 1, false);
    }
  }

  for (const top of tops) {
    walk(top, 0, parentOf(top) !== null);
  }

  // The completeness net. Anything still unemitted is in a parent loop, so it is
  // unreachable from any top level row. It is emitted at the top level and
  // marked detached rather than dropped, because a group silently missing from
  // this panel is a group an operator cannot audit or unassign.
  //
  // The `true` here is load bearing and is asserted: a row lifted out of a loop
  // is shown at a level its parent pointer does not justify, so it must carry
  // the marking that tells the operator the hierarchy drawn is not the whole
  // story. group-tree.test.ts asserts the loop anchor is marked detached.
  for (const group of groups) {
    if (!seen.has(group.id)) {
      walk(group, 0, true);
    }
  }

  return out;
}

// The ids of every group under `groupId` in the loaded hierarchy, plus the group
// itself. The reparent control removes these from its options, because moving a
// group under its own descendant is a cycle the server refuses.
//
// This is a CONVENIENCE, never the guarantee: the loaded page may be partial, so
// the server remains the authority on whether a move is admissible and its 422
// refusal is surfaced verbatim when the operator finds a case this missed.
export function groupAndDescendantIds(
  groups: ReadonlyArray<OrgGroupView>,
  groupId: string,
): Set<string> {
  const blocked = new Set<string>([groupId]);
  const forest = buildGroupForest(groups);
  const index = forest.findIndex((node) => node.group.id === groupId);
  if (index < 0) {
    return blocked;
  }
  // The forest is depth first, so a subtree is the contiguous run of rows after
  // its root that are deeper than it.
  const rootDepth = forest[index].depth;
  for (let i = index + 1; i < forest.length; i += 1) {
    if (forest[i].depth <= rootDepth) {
      break;
    }
    blocked.add(forest[i].group.id);
  }
  return blocked;
}
