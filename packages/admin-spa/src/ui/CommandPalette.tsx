// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The command palette AND the global search surface (issue #90, PR 3 + PR 7):
// ONE keyboard-invoked (Cmd/Ctrl-K) palette. PR3 built it as a synchronous
// navigation palette driven only by data already in hand (the nav sections plus
// the tenants and environments the scope store holds). PR7 extends THIS SAME
// surface into cross-resource search rather than adding a second search box: as
// the operator types, the palette also queries the documented LIST operations
// (tenants, environments, users, connectors) through the one typed client and
// folds the hits in as commands that navigate to the matching resource. So there
// is a single coherent search experience: navigation commands and resource hits
// live in one listbox, keyed and filtered the same way.
//
// The search is CLIENT SIDE aggregation over public list ops (src/ui/search.ts):
// no server search endpoint exists or is invented. It is debounced and gated on a
// minimum length so it never hammers the API on a keystroke, and it queries a
// scoped resource ONLY when a scope is active. A list failure surfaces through the
// verbatim ErrorView boundary inside the dialog, so a failed search is never
// silently shown as an empty result set.
//
// Accessibility: it is an ARIA combobox over a listbox. Focus is trapped by
// design because the only focusable control is the search input; the active
// option is tracked with aria-activedescendant, so ArrowUp/ArrowDown move the
// selection without moving focus, Enter runs it, and Escape closes and restores
// focus to the element that was focused when the palette opened.

import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { useLocation } from "preact-iso";
import { type Command, filterCommands, wrapIndex } from "./commands";
import {
  type SearchResult,
  SEARCH_DEBOUNCE_MS,
  searchAll,
  shouldSearch,
  toCommand,
} from "./search";
import { SECTIONS } from "./sections";
import { ErrorView } from "./ErrorView";
import { type ErrorBody, errorBodyFrom } from "../api/client";
import {
  activeScope,
  environments,
  selectEnvironment,
  selectTenant,
  tenants,
} from "../scope/store";

const LISTBOX_ID = "cmdk-listbox";

function optionId(index: number): string {
  return `cmdk-option-${index}`;
}

export interface CommandPaletteProps {
  // Tests inject an explicit command set; production builds them from the store.
  commands?: ReadonlyArray<Command>;
}

// Build the default commands from data already in hand: navigate to each section,
// switch to any reachable tenant, switch to any environment of the active tenant.
function useDefaultCommands(): Command[] {
  const location = useLocation();
  const tenantList = tenants.value;
  const environmentList = environments.value;
  const scope = activeScope.value;
  return useMemo<Command[]>(() => {
    const navigate = (path: string): void => {
      if (typeof location.route === "function") {
        location.route(path);
      }
    };
    const commands: Command[] = SECTIONS.map((section) => ({
      id: `nav:${section.href}`,
      label: `Go to ${section.label}`,
      run: () => navigate(section.href),
    }));
    for (const tenant of tenantList) {
      commands.push({
        id: `tenant:${tenant.id}`,
        label: `Switch to tenant ${tenant.display_name}`,
        hint: tenant.id,
        run: () => {
          void selectTenant(tenant.id);
        },
      });
    }
    if (scope !== null) {
      for (const env of environmentList) {
        commands.push({
          id: `env:${env.id}`,
          label: `Switch to environment ${env.display_name}`,
          hint: env.id,
          run: () => selectEnvironment(env.id),
        });
      }
    }
    return commands;
    // location.route is stable per navigation; the store values are the deps.
  }, [location, tenantList, environmentList, scope]);
}

// Drive the debounced, scope-aware cross-resource search for the current query.
// Returns the hits (already filtered by search.ts), a verbatim ErrorBody when a
// list failed, and whether a query is in flight. A query below the minimum length
// (or a closed palette) runs no call and clears any prior results; each new query
// cancels the pending one, so a late response never lands on a newer query.
function useSearch(
  query: string,
  open: boolean,
): { results: SearchResult[]; error: ErrorBody | null; searching: boolean } {
  const scope = activeScope.value;
  const [results, setResults] = useState<SearchResult[]>([]);
  const [error, setError] = useState<ErrorBody | null>(null);
  const [searching, setSearching] = useState(false);

  useEffect(() => {
    if (!open || !shouldSearch(query)) {
      setResults([]);
      setError(null);
      setSearching(false);
      return;
    }
    let cancelled = false;
    setSearching(true);
    const timer = setTimeout(() => {
      searchAll(query, scope)
        .then((hits) => {
          if (!cancelled) {
            setResults(hits);
            setError(null);
            setSearching(false);
          }
        })
        .catch((value: unknown) => {
          if (!cancelled) {
            setResults([]);
            setError(errorBodyFrom(value));
            setSearching(false);
          }
        });
    }, SEARCH_DEBOUNCE_MS);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
    // The scope object identity is stable per selection; the query and open state
    // drive the (re)search, and a change to either cancels the pending call.
  }, [query, open, scope]);

  return { results, error, searching };
}

export function CommandPalette({ commands }: CommandPaletteProps) {
  const location = useLocation();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const restoreFocusRef = useRef<Element | null>(null);

  const defaults = useDefaultCommands();
  const source = commands ?? defaults;
  const { results, error, searching } = useSearch(query, open);

  // Fold the resource hits in as navigation commands, so the one listbox holds
  // both the in-memory navigation commands and the cross-resource search hits.
  const navigate = (path: string): void => {
    if (typeof location.route === "function") {
      location.route(path);
    }
  };
  const resultCommands = results.map((result) => toCommand(result, navigate));
  const filtered = [...filterCommands(source, query), ...resultCommands];
  const activeIndex = wrapIndex(active, filtered.length);

  // Cmd/Ctrl-K toggles the palette from anywhere.
  useEffect(() => {
    function onKeyDown(event: KeyboardEvent): void {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setOpen((wasOpen) => !wasOpen);
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  // On open, remember focus, reset the query and selection, and focus the input.
  // On close, restore focus to where it was.
  useEffect(() => {
    if (open) {
      restoreFocusRef.current = document.activeElement;
      setQuery("");
      setActive(0);
      inputRef.current?.focus();
    } else {
      const previous = restoreFocusRef.current;
      if (previous instanceof HTMLElement) {
        previous.focus();
      }
    }
  }, [open]);

  if (!open) {
    return null;
  }

  function close(): void {
    setOpen(false);
  }

  function runActive(): void {
    const command = filtered[activeIndex];
    if (command !== undefined) {
      close();
      command.run();
    }
  }

  function onKeyDown(event: KeyboardEvent): void {
    if (event.key === "Escape") {
      event.preventDefault();
      close();
      return;
    }
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActive(wrapIndex(activeIndex + 1, filtered.length));
      return;
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      setActive(wrapIndex(activeIndex - 1, filtered.length));
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      runActive();
      return;
    }
    if (event.key === "Tab") {
      // The dialog holds exactly one focusable control (the search input); options
      // are driven by aria-activedescendant, not focus. Swallow Tab so focus never
      // escapes the modal to the page behind the overlay (a focus trap).
      event.preventDefault();
      inputRef.current?.focus();
    }
  }

  return (
    <div class="cmdk-overlay" onClick={close}>
      <div
        class="cmdk-dialog"
        role="dialog"
        aria-modal="true"
        aria-label="Command palette and search"
        onClick={(event) => event.stopPropagation()}
        onKeyDown={onKeyDown}
      >
        <input
          ref={inputRef}
          class="cmdk-input"
          type="text"
          role="combobox"
          aria-expanded="true"
          aria-controls={LISTBOX_ID}
          aria-activedescendant={
            filtered.length === 0 ? undefined : optionId(activeIndex)
          }
          aria-label="Search resources and commands"
          placeholder="Search resources and commands"
          value={query}
          onInput={(event) => {
            setQuery((event.target as HTMLInputElement).value);
            setActive(0);
          }}
        />
        {error === null ? null : (
          <div class="cmdk-error">
            <ErrorView error={error} />
          </div>
        )}
        {searching ? (
          <p class="cmdk-searching" role="status" aria-live="polite">
            Searching resources
          </p>
        ) : null}
        <ul class="cmdk-list" id={LISTBOX_ID} role="listbox">
          {filtered.length === 0 ? (
            <li class="cmdk-empty" role="option" aria-selected="false">
              No matching commands or resources
            </li>
          ) : (
            filtered.map((command, index) => (
              <li
                key={command.id}
                id={optionId(index)}
                class={index === activeIndex ? "cmdk-item cmdk-active" : "cmdk-item"}
                role="option"
                aria-selected={index === activeIndex}
                onClick={() => {
                  close();
                  command.run();
                }}
                onMouseEnter={() => setActive(index)}
              >
                <span class="cmdk-item-label">{command.label}</span>
                {command.hint === undefined ? null : (
                  <span class="cmdk-item-hint">{command.hint}</span>
                )}
              </li>
            ))
          )}
        </ul>
      </div>
    </div>
  );
}
