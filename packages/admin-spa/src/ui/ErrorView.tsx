// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The verbatim management ErrorBody boundary (issue #90, PR 3; a hard acceptance
// criterion: "API and SPA users see identical errors"). Given the ErrorBody the
// ONE typed client surfaced, this renders `error` and `message` VERBATIM, plus
// `actual_scope`/`expected_scope`/`failed_guardrails` when the server included
// them, with NO rewording and NO swallowing. Every value is rendered as TEXT:
// Preact escapes text children by construction, so a hostile-looking `message`
// is inert (never HTML), and this component uses NO dangerouslySetInnerHTML.
//
// A `max_age`-bearing error is the RFC 9470 sudo challenge (issue #73): the
// boundary offers the re-authentication + elevation + retry the mutation needs.

import type { ErrorBody } from "../api/client";
import type { Scope } from "../scope/logic";
import {
  elevateForScope,
  performSudoElevation,
  reauthenticateForSudo,
  sudoMaxAge,
} from "../auth/sudo";

// When the error is a sudo challenge, the boundary needs the active scope (to
// elevate within) and the mutation to replay once the credential is fresh.
export interface SudoRecovery {
  scope: Scope;
  retry: () => Promise<void>;
}

export interface ErrorViewProps {
  error: ErrorBody;
  // Present only when the failing call was a mutation the boundary can retry
  // after a sudo re-authentication. Absent for a read, where a challenge simply
  // shows its message.
  sudo?: SudoRecovery;
}

// Drive the RFC 9470 recovery: re-authenticate (redirect), then elevate, then
// retry. In the real console step one navigates away; the elevate and retry
// resume on return (verified under the runtime embed, issue #323).
function onReauthenticate(maxAge: number, sudo: SudoRecovery): void {
  void performSudoElevation({
    reauthenticate: () => reauthenticateForSudo(maxAge),
    elevate: () => elevateForScope(sudo.scope),
    retry: sudo.retry,
  });
}

export function ErrorView({ error, sudo }: ErrorViewProps) {
  const maxAge = sudoMaxAge(error);
  const guardrails = error.failed_guardrails ?? [];
  // The scope fields are `string | null` on the contract: present means a string,
  // so guard on the string type (a null or absent field is simply not shown).
  const hasExpectedScope = typeof error.expected_scope === "string";
  const hasActualScope = typeof error.actual_scope === "string";
  return (
    <section class="errorbody" role="alert" aria-live="assertive">
      <p class="errorbody-type">
        <span class="errorbody-label">Error</span>
        <code class="errorbody-code">{error.error}</code>
      </p>
      <p class="errorbody-message">{error.message}</p>
      {hasExpectedScope || hasActualScope ? (
        <dl class="errorbody-scope">
          {hasExpectedScope ? (
            <>
              <dt>Expected scope</dt>
              <dd>
                <code>{error.expected_scope}</code>
              </dd>
            </>
          ) : null}
          {hasActualScope ? (
            <>
              <dt>Actual scope</dt>
              <dd>
                <code>{error.actual_scope}</code>
              </dd>
            </>
          ) : null}
        </dl>
      ) : null}
      {guardrails.length === 0 ? null : (
        <div class="errorbody-guardrails">
          <p class="errorbody-label">Failed guardrails</p>
          <ul>
            {guardrails.map((guardrail) => (
              <li key={guardrail}>
                <code>{guardrail}</code>
              </li>
            ))}
          </ul>
        </div>
      )}
      {maxAge === null ? null : (
        <div class="errorbody-sudo">
          <p>
            This change needs a fresh sign in no older than {maxAge} seconds
            before it can proceed.
          </p>
          {sudo === undefined ? null : (
            <button
              type="button"
              class="errorbody-reauth"
              onClick={() => onReauthenticate(maxAge, sudo)}
            >
              Re-authenticate to continue
            </button>
          )}
        </div>
      )}
    </section>
  );
}
