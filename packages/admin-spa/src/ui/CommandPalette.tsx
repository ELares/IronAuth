// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The command palette (issue #90, PR 3): a keyboard-invoked (Cmd/Ctrl-K) palette
// for cross-resource navigation and scope switches. It is hand built (no new
// dependency) and driven ONLY by data the one typed client already loaded: the
// nav sections plus the tenants and environments the scope store holds. It names
// no new endpoint.
//
// Accessibility: it is an ARIA combobox over a listbox. Focus is trapped by
// design because the only focusable control is the search input; the active
// option is tracked with aria-activedescendant, so ArrowUp/ArrowDown move the
// selection without moving focus, Enter runs it, and Escape closes and restores
// focus to the element that was focused when the palette opened.

import { useEffect, useMemo, useRef, useState } from "preact/hooks";
import { useLocation } from "preact-iso";
import { type Command, filterCommands, wrapIndex } from "./commands";
import { SECTIONS } from "./sections";
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

export function CommandPalette({ commands }: CommandPaletteProps) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const restoreFocusRef = useRef<Element | null>(null);

  const defaults = useDefaultCommands();
  const source = commands ?? defaults;
  const filtered = filterCommands(source, query);
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
    }
  }

  return (
    <div class="cmdk-overlay" onClick={close}>
      <div
        class="cmdk-dialog"
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
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
          aria-label="Search commands"
          placeholder="Search commands"
          value={query}
          onInput={(event) => {
            setQuery((event.target as HTMLInputElement).value);
            setActive(0);
          }}
        />
        <ul class="cmdk-list" id={LISTBOX_ID} role="listbox">
          {filtered.length === 0 ? (
            <li class="cmdk-empty" role="option" aria-selected="false">
              No matching commands
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
