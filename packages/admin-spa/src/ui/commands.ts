// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The command model and the PURE filter for the command palette (issue #90, PR
// 3). Kept separate from the component so the matching logic is unit tested
// without a DOM. A command is a labelled action; the palette is driven ONLY by
// data the one typed client already loaded (the nav sections plus the tenants and
// environments the store holds), so it names no new endpoint.

export interface Command {
  // A stable id, used for the aria option id and the keyed list.
  id: string;
  // The verbatim label shown and matched.
  label: string;
  // An optional secondary hint (for example a resource id), also matched.
  hint?: string;
  // The action to run when the command is chosen.
  run: () => void;
}

// Filter commands by a case-insensitive substring over the label and hint. An
// empty query returns every command (the palette opens showing all actions).
export function filterCommands(
  commands: ReadonlyArray<Command>,
  query: string,
): Command[] {
  const needle = query.trim().toLowerCase();
  if (needle === "") {
    return commands.slice();
  }
  return commands.filter((command) => {
    const haystack = `${command.label} ${command.hint ?? ""}`.toLowerCase();
    return haystack.includes(needle);
  });
}

// Clamp the active index into range for a list of `length` items, wrapping so
// ArrowUp past the top lands on the last item and ArrowDown past the bottom lands
// on the first. Returns 0 for an empty list.
export function wrapIndex(index: number, length: number): number {
  if (length <= 0) {
    return 0;
  }
  return ((index % length) + length) % length;
}
