// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The RFC 9470 sudo re-authentication path (issue #90, PR 3; issue #73). When a
// mutation returns a 401 whose verbatim ErrorBody carries `max_age`, the acting
// credential is not fresh enough: the server is asking for a re-authentication no
// older than `max_age` seconds before it will let the mutation through. This
// module detects that challenge and drives the recovery sequence:
//
//   1. RE-AUTHENTICATE: re-run the OIDC login with `max_age` and `prompt=login`
//      so the browser obtains a fresh credential (src/auth/login.ts).
//   2. ELEVATE: call the sudo elevation endpoint through the one typed client.
//   3. RETRY: replay the original mutation, now that the credential is fresh and
//      elevated.
//
// The sequence is dependency injected so it is unit testable without a browser
// redirect or a live server. Step 1 is a full-page redirect in the real console
// (the public client login navigates away), so the live end to end continuity is
// verified under the runtime embed (issue #323); the ORCHESTRATION and the
// challenge detection are what this module makes correct and tested here.

import type { ErrorBody } from "../api/client";
import { elevateAdminSudo } from "../api/client";
import type { Scope } from "../scope/logic";
import { beginLogin } from "./login";

// The `max_age` (seconds) a sudo challenge demands, or null when the error is not
// a sudo challenge. A present `max_age` on the verbatim ErrorBody IS the RFC 9470
// challenge signal (it also rides the WWW-Authenticate header on the wire).
export function sudoMaxAge(error: ErrorBody): number | null {
  return typeof error.max_age === "number" ? error.max_age : null;
}

// Whether an ErrorBody is a sudo re-authentication challenge.
export function isSudoChallenge(error: ErrorBody): boolean {
  return sudoMaxAge(error) !== null;
}

// Step 1 in the real console: re-run the login demanding a fresh credential. The
// public client login is a full-page redirect, so this navigates away; the
// elevate and retry resume once the fresh token is held.
export async function reauthenticateForSudo(maxAge: number): Promise<void> {
  await beginLogin({ maxAge, prompt: "login" });
}

// Step 2 in the real console: elevate the freshly re-authenticated credential to
// sudo within the active scope, through the one typed client.
export async function elevateForScope(scope: Scope): Promise<void> {
  await elevateAdminSudo(scope.tenantId, scope.environmentId);
}

// The injected steps of the sudo recovery, so the sequence is testable and the
// real wiring (redirect login, typed elevate, caller retry) is supplied by the
// error boundary.
export interface SudoElevationSteps {
  // Obtain a fresh credential (RFC 9470 max_age).
  reauthenticate: () => Promise<void>;
  // Elevate the fresh credential to sudo in the active scope.
  elevate: () => Promise<void>;
  // Replay the original mutation.
  retry: () => Promise<void>;
}

// Drive the full recovery in order: re-authenticate, then elevate, then retry.
// Each step awaits the previous, so a failure short circuits (a failed
// re-authentication never blindly elevates or retries).
export async function performSudoElevation(
  steps: SudoElevationSteps,
): Promise<void> {
  await steps.reauthenticate();
  await steps.elevate();
  await steps.retry();
}
