// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The reusable resource hooks (issue #90, PR 4): the shared plumbing every CRUD
// surface stands on, so the tenants view here and the users and connectors views
// in PR5 and PR6 all read the same loading, ready, empty, and error shape. There
// is NO network here: these hooks call the named wrappers in src/api/client.ts
// (the single funnel), and every failure is mapped to the verbatim ErrorBody the
// ErrorView boundary renders, through errorBodyFrom.
//
//   useAsyncResource(load, deps) drives a read (a list or a detail): it holds a
//   loading, ready, or error state and a reload() that refetches.
//
//   useMutation() drives a write (create, delete, or a lifecycle transition): it
//   holds a pending, success, or error state, remembers the last write so the RFC
//   9470 sudo path can replay it after a re-authentication, and never invents an
//   error string (a ManagementError surfaces the server's body unchanged).

import { useCallback, useEffect, useRef, useState } from "preact/hooks";
import { type ErrorBody, errorBodyFrom } from "../api/client";

// The three states a read can be in. A read is never silently empty: an empty
// list is a READY state with an empty array, distinct from an error.
export type AsyncStatus = "loading" | "ready" | "error";

export interface AsyncState<T> {
  status: AsyncStatus;
  // The loaded value when ready, else null.
  data: T | null;
  // The verbatim ErrorBody when the load failed, else null.
  error: ErrorBody | null;
}

export interface AsyncResource<T> {
  state: AsyncState<T>;
  // Refetch (for example after a mutation changed the underlying data).
  reload: () => void;
}

// Load a resource through the one typed client and track its state. `deps` are
// the caller's inputs (a tenant id, an environment id); the load closure itself
// is intentionally NOT a dependency (it is a fresh closure each render), so the
// caller lists the ids that should trigger a refetch, plus an internal nonce the
// reload() bumps. A stale in flight load is ignored (the cancelled guard) so a
// fast switch never lands an earlier tenant's data on a later one.
export function useAsyncResource<T>(
  load: () => Promise<T>,
  deps: ReadonlyArray<unknown>,
): AsyncResource<T> {
  const [state, setState] = useState<AsyncState<T>>({
    status: "loading",
    data: null,
    error: null,
  });
  const [nonce, setNonce] = useState(0);
  const reload = useCallback(() => setNonce((value) => value + 1), []);

  useEffect(() => {
    let cancelled = false;
    setState({ status: "loading", data: null, error: null });
    load()
      .then((data) => {
        if (!cancelled) {
          setState({ status: "ready", data, error: null });
        }
      })
      .catch((value: unknown) => {
        if (!cancelled) {
          setState({ status: "error", data: null, error: errorBodyFrom(value) });
        }
      });
    return () => {
      cancelled = true;
    };
    // The caller's ids plus the reload nonce are the dependencies; `load` is a
    // fresh closure each render and is captured, not tracked.
  }, [...deps, nonce]);

  return { state, reload };
}

// The state a mutation moves through. `success` is a caller supplied confirmation
// message; `error` is the verbatim ErrorBody (a max_age-bearing body is the RFC
// 9470 sudo challenge the ErrorView boundary can recover).
export interface MutationState {
  pending: boolean;
  error: ErrorBody | null;
  success: string | null;
}

export interface Mutation {
  state: MutationState;
  // Run a write. Resolves true on success (the caller then reloads its list) and
  // false on failure (the error is held for the boundary). Never throws.
  run: (op: () => Promise<void>, successMessage: string) => Promise<boolean>;
  // Replay the most recent write. This is the retry the sudo recovery calls after
  // a fresh re-authentication and elevation; a no op when nothing has run yet.
  retry: () => Promise<void>;
  // Clear the state back to idle.
  reset: () => void;
}

const IDLE: MutationState = { pending: false, error: null, success: null };

export function useMutation(): Mutation {
  const [state, setState] = useState<MutationState>(IDLE);
  const last = useRef<{ op: () => Promise<void>; message: string } | null>(null);

  const run = useCallback(
    async (op: () => Promise<void>, successMessage: string): Promise<boolean> => {
      last.current = { op, message: successMessage };
      setState({ pending: true, error: null, success: null });
      try {
        await op();
        setState({ pending: false, error: null, success: successMessage });
        return true;
      } catch (value: unknown) {
        setState({ pending: false, error: errorBodyFrom(value), success: null });
        return false;
      }
    },
    [],
  );

  const retry = useCallback(async (): Promise<void> => {
    const previous = last.current;
    if (previous === null) {
      return;
    }
    await run(previous.op, previous.message);
  }, [run]);

  const reset = useCallback(() => setState(IDLE), []);

  return { state, run, retry, reset };
}
