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

import type { ComponentChildren } from "preact";
import { useState } from "preact/hooks";
import { ErrorView, type SudoRecovery } from "./ErrorView";
import type { AsyncState, MutationState } from "./useResource";

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
  const dangerClass = danger === true ? " resource-btn-danger" : "";
  if (!armed) {
    return (
      <button
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
    <span class="resource-confirm" role="group" aria-label={prompt}>
      <span class="resource-confirm-prompt">{prompt}</span>
      <button
        type="button"
        class="resource-btn resource-btn-danger"
        disabled={disabled}
        onClick={() => {
          setArmed(false);
          onConfirm();
        }}
      >
        {confirmLabel}
      </button>
      <button type="button" class="resource-btn" onClick={() => setArmed(false)}>
        Cancel
      </button>
    </span>
  );
}
