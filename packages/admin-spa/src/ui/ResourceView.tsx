// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The reusable resource VIEW primitives (issue #90, PR 4): the presentational
// half of the CRUD pattern the tenants view here and the users and connectors
// views in PR5 and PR6 share. They render only what the resource hooks
// (src/ui/useResource.ts) already resolved and hold NO network call and NO path.
//
//   AsyncBoundary makes every read's loading, empty, and error states EXPLICIT: a
//   loading indicator, an optional empty state, the verbatim ErrorView on
//   failure, or the ready content, so no view hand rolls that ladder.
//
//   MutationFeedback renders a write's outcome: a success confirmation, or the
//   verbatim ErrorView (with the RFC 9470 sudo recovery when the write can be
//   replayed after a re-authentication).
//
//   ConfirmButton gates a destructive action behind an explicit, keyboard
//   reachable confirm step (no browser confirm dialog), so a delete, suspend,
//   resume, or restore is always a deliberate two step.
//
//   MorePageNote states that a keyset read has a tail beyond the page shown, so
//   a list surface never truncates silently.

import type { ComponentChildren } from "preact";
import { useEffect, useId, useRef, useState } from "preact/hooks";
import { ErrorView, type SudoRecovery } from "./ErrorView";
import type { AsyncState, MutationState } from "./useResource";

export function ResourceHeading({
  id,
  title,
  description,
}: {
  id: string;
  title: ComponentChildren;
  description: string;
}) {
  return (
    <header class="resource-heading">
      <h1 id={id}>{title}</h1>
      <p class="resource-description">{description}</p>
    </header>
  );
}

export function ResourceFormIntro({
  title,
  description,
  headingLevel = 2,
}: {
  title: string;
  description: string;
  headingLevel?: 2 | 3;
}) {
  const Heading = headingLevel === 3 ? "h3" : "h2";
  return (
    <div class="resource-form-heading">
      <Heading class="resource-form-title">{title}</Heading>
      <p class="resource-form-help">{description}</p>
    </div>
  );
}

export function ResourceDetailNav({
  items,
}: {
  items: ReadonlyArray<{ id: string; label: string }>;
}) {
  return (
    <nav class="resource-detail-nav" aria-label="On this page">
      {items.map((item) => (
        <a key={item.id} href={`#${item.id}`}>
          {item.label}
        </a>
      ))}
    </nav>
  );
}

export function resourceLabel(value: string): string {
  const labels: Record<string, string> = {
    dev: "Development",
    prod: "Production",
    staging: "Staging",
    pending_verification: "Pending verification",
    scheduled_offboarding: "Scheduled offboarding",
  };
  return (
    labels[value] ??
    value.replace(/_/g, " ").replace(/^./, (letter) => letter.toUpperCase())
  );
}

// Search stays within the rows already returned by the management API. For a
// paginated resource the description makes that boundary visible to operators.
export function ResourceCollection<T>({
  items,
  noun,
  searchText,
  paginated = false,
  headingLevel = 2,
  children,
}: {
  items: ReadonlyArray<T>;
  noun: string;
  searchText: (item: T) => string;
  paginated?: boolean;
  headingLevel?: 2 | 3;
  children: (visible: ReadonlyArray<T>) => ComponentChildren;
}) {
  const Heading = headingLevel === 3 ? "h3" : "h2";
  const [query, setQuery] = useState("");
  const searchRef = useRef<HTMLInputElement>(null);
  const normalized = query.trim().toLocaleLowerCase();
  const countNoun =
    items.length === 1
      ? noun.endsWith("ies")
        ? `${noun.slice(0, -3)}y`
        : noun.replace(/s$/, "")
      : noun;
  const visible =
    normalized === ""
      ? items
      : items.filter((item) =>
          searchText(item).toLocaleLowerCase().includes(normalized),
        );
  return (
    <div class="resource-collection">
      <div class="resource-toolbar">
        <div>
          <Heading class="resource-section-title">All {noun}</Heading>
          <p class="resource-count" role="status" aria-live="polite">
            {normalized === ""
              ? `${items.length} ${countNoun}`
              : `${visible.length} of ${items.length} ${countNoun}`}
            {paginated ? " on this page" : ""}
          </p>
        </div>
        <label class="resource-search">
          <span>Search {noun}</span>
          <input
            ref={searchRef}
            type="search"
            aria-label={`Search ${noun}`}
            placeholder={
              paginated ? "Search this page" : "Search by name, ID or status"
            }
            value={query}
            onInput={(event) =>
              setQuery((event.target as HTMLInputElement).value)
            }
          />
        </label>
      </div>
      {visible.length === 0 ? (
        <div class="resource-empty">
          <p class="resource-empty-title">No matching {noun}</p>
          <p class="resource-empty-description">
            Try another search or clear the search to see all {noun}
            {paginated ? " on this page" : ""}.
          </p>
          <button
            type="button"
            class="resource-btn"
            onClick={() => {
              setQuery("");
              searchRef.current?.focus();
            }}
          >
            Clear search
          </button>
        </div>
      ) : (
        children(visible)
      )}
    </div>
  );
}

// Credentials remain in the caller's memory-only state. This control copies the
// displayed value directly and reports a clipboard failure without logging it.
export function SecretCopyButton({
  value,
  label = "Copy secret",
}: {
  value: string;
  label?: string;
}) {
  const [status, setStatus] = useState<"idle" | "copied" | "error">("idle");
  useEffect(() => setStatus("idle"), [value]);
  async function copy(): Promise<void> {
    try {
      await navigator.clipboard.writeText(value);
      setStatus("copied");
    } catch {
      setStatus("error");
    }
  }
  return (
    <div class="resource-copy-actions">
      <button type="button" class="resource-btn" onClick={() => void copy()}>
        {label}
      </button>
      <span class="resource-hint" role="status" aria-live="polite">
        {status === "copied"
          ? "Copied to clipboard."
          : status === "error"
            ? "Copy unavailable. Select the value and copy it manually."
            : ""}
      </span>
    </div>
  );
}

// The optional empty state of a read: when `when(data)` holds (an empty list),
// `render` supplies the empty message instead of the ready content.
export interface EmptyState<T> {
  when: (data: T) => boolean;
  render: () => ComponentChildren;
}

export interface AsyncBoundaryProps<T> {
  state: AsyncState<T>;
  // The ready content, given the loaded data.
  children: (data: T) => ComponentChildren;
  empty?: EmptyState<T>;
  loadingLabel?: string;
}

// Render the loading, empty, error, or ready state of a read, so every resource
// view surfaces all four explicitly and renders a failure through the ONE
// verbatim ErrorView boundary.
export function AsyncBoundary<T>({
  state,
  children,
  empty,
  loadingLabel,
}: AsyncBoundaryProps<T>) {
  if (state.status === "loading") {
    return (
      <div class="resource-loading" role="status" aria-live="polite">
        <span class="resource-spinner" aria-hidden="true" />
        <span>{loadingLabel ?? "Loading"}</span>
      </div>
    );
  }
  if (state.status === "error" && state.error !== null) {
    return <ErrorView error={state.error} />;
  }
  if (state.data !== null) {
    if (empty !== undefined && empty.when(state.data)) {
      return <>{empty.render()}</>;
    }
    return <>{children(state.data)}</>;
  }
  return null;
}

export interface MorePageNoteProps {
  // The opaque cursor a keyset read reported, or null when this was the last
  // page.
  nextCursor: string | null;
  // The resource named in the sentence ("organizations", "groups").
  noun: string;
}

// A "more exist beyond this page" note, rendered when a keyset read reports a
// next cursor. The list shows the first page; this makes the remainder EXPLICIT
// rather than silently dropping the tail (the no-silent-truncation rule). The
// cursor itself is a pagination token and is never rendered as a value to copy.
export function MorePageNote({ nextCursor, noun }: MorePageNoteProps) {
  if (nextCursor === null) {
    return null;
  }
  return (
    <p class="resource-more" role="status">
      More {noun} exist beyond this page. Only the first page is shown.
    </p>
  );
}

export interface MutationFeedbackProps {
  state: MutationState;
  // The sudo recovery to offer when the failure is a max_age challenge and the
  // write can be replayed. Absent when there is no active scope to elevate in.
  sudo?: SudoRecovery;
}

// Render a write's success confirmation or its verbatim failure. A pending or
// idle write shows nothing.
export function MutationFeedback({ state, sudo }: MutationFeedbackProps) {
  if (state.success !== null) {
    return (
      <p class="resource-success" role="status" aria-live="polite">
        {state.success}
      </p>
    );
  }
  if (state.error !== null) {
    return <ErrorView error={state.error} sudo={sudo} />;
  }
  return null;
}

export interface ConfirmButtonProps {
  label: string;
  // The confirming prompt shown once the button is armed.
  prompt: string;
  // The label of the confirming button.
  confirmLabel: string;
  onConfirm: () => void;
  danger?: boolean;
  disabled?: boolean;
}

// A destructive action gated behind an explicit confirm step. The first press
// arms the control (revealing the prompt, a confirm, and a cancel); confirming
// runs the callback, cancelling disarms it. Keyboard reachable and labelled, so a
// delete or a lifecycle transition is never a single stray click.
export function ConfirmButton({
  label,
  prompt,
  confirmLabel,
  onConfirm,
  danger,
  disabled,
}: ConfirmButtonProps) {
  const [armed, setArmed] = useState(false);
  const promptId = useId();
  const triggerRef = useRef<HTMLButtonElement>(null);
  const confirmRef = useRef<HTMLButtonElement>(null);
  const previouslyArmed = useRef(false);
  useEffect(() => {
    if (armed) {
      confirmRef.current?.focus();
    } else if (previouslyArmed.current) {
      triggerRef.current?.focus();
    }
    previouslyArmed.current = armed;
  }, [armed]);
  const dangerClass = danger === true ? " resource-btn-danger" : "";
  if (!armed) {
    return (
      <button
        ref={triggerRef}
        type="button"
        class={`resource-btn${dangerClass}`}
        disabled={disabled}
        onClick={() => setArmed(true)}
      >
        {label}
      </button>
    );
  }
  return (
    <span
      class="resource-confirm"
      role="group"
      aria-label={prompt}
      onKeyDown={(event) => {
        if (event.key === "Escape") {
          event.preventDefault();
          setArmed(false);
        }
      }}
    >
      <span id={promptId} class="resource-confirm-prompt">
        {prompt}
      </span>
      <button
        ref={confirmRef}
        type="button"
        aria-describedby={promptId}
        class={`resource-btn${dangerClass}`}
        disabled={disabled}
        onClick={() => {
          setArmed(false);
          onConfirm();
        }}
      >
        {confirmLabel}
      </button>
      <button
        type="button"
        class="resource-btn"
        onClick={() => setArmed(false)}
      >
        Cancel
      </button>
    </span>
  );
}
