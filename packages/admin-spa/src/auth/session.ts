// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The in-memory bearer holder (issue #90, PR 2). The console's ONLY credential
// is the short lived at+jwt it receives from the OIDC login, and it is held IN
// MEMORY ONLY: never localStorage, never a cookie, never sessionStorage. It lives
// for the page's lifetime and is gone on reload (the login re-runs), so a stolen
// disk or an XSS-readable storage slot never yields the token. The one typed
// management client (src/api/client.ts) reads it here to attach Authorization.

let accessToken: string | null = null;

// Record the access token after a successful code exchange. In memory only.
export function setAccessToken(token: string | null): void {
  accessToken = token;
}

// The current access token, or null when signed out.
export function getAccessToken(): string | null {
  return accessToken;
}

// Whether a token is currently held.
export function isSignedIn(): boolean {
  return accessToken !== null;
}

// Drop the token (sign out). The next management call is then unauthenticated.
export function clearAccessToken(): void {
  accessToken = null;
}
