// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The Authorization Code + PKCE login orchestration (issue #90, PR 2). This is
// dogfooding: the admin console signs in through IronAuth's OWN OIDC as a public
// client, and the short lived at+jwt it receives is the only credential it holds.
//
// The flow: build a PKCE pair and a CSRF `state`, stash them in sessionStorage
// across the redirect (the verifier is a transient, single use secret, not the
// bearer token, and is cleared the instant it is spent), discover the admin
// issuer's endpoints, and redirect to the authorization endpoint requesting
// scope=openid ironauth.manage and resource=<management audience>. On return,
// verify the `state`, exchange the code for the token, and hold the token IN
// MEMORY (src/auth/session.ts). Every network call is delegated to the one
// audited client (src/api/client.ts); this module performs none itself.

import { loadConfig } from "../config";
import { discoverOidc, exchangeCode } from "../api/client";
import { createPkce, randomState } from "./pkce";
import { setAccessToken } from "./session";

// The transient PKCE verifier and CSRF state, held only across the redirect.
const VERIFIER_KEY = "ironauth.pkce.verifier";
const STATE_KEY = "ironauth.oidc.state";
// The scope that authorizes the management plane; an admin issuer token without
// it is rejected by the management API.
const MANAGE_SCOPE = "openid ironauth.manage";
// The registered redirect target: the console mount on this origin.
const REDIRECT_PATH = "/admin/";

// Whether the console has enough config to attempt sign in.
export function canSignIn(): boolean {
  const config = loadConfig();
  return config.adminIssuer !== "" && config.consoleClientId !== "";
}

function redirectUri(): string {
  return `${window.location.origin}${REDIRECT_PATH}`;
}

// Start the login: redirect the browser to the admin issuer's authorization
// endpoint with a fresh PKCE challenge and CSRF state.
export async function beginLogin(): Promise<void> {
  const config = loadConfig();
  const pkce = await createPkce();
  const state = randomState();
  sessionStorage.setItem(VERIFIER_KEY, pkce.verifier);
  sessionStorage.setItem(STATE_KEY, state);

  const discovery = await discoverOidc(config.adminIssuer);
  const params = new URLSearchParams({
    response_type: "code",
    client_id: config.consoleClientId,
    redirect_uri: redirectUri(),
    scope: MANAGE_SCOPE,
    state,
    code_challenge: pkce.challenge,
    code_challenge_method: "S256",
  });
  if (config.managementAudience !== "") {
    params.set("resource", config.managementAudience);
  }
  window.location.assign(`${discovery.authorization_endpoint}?${params.toString()}`);
}

// Complete the login if the current URL is an authorization callback. Returns
// true when a token was obtained. The `code` and `state` are stripped from the
// address bar regardless of outcome, and a missing or mismatched `state` refuses
// the exchange (CSRF defense), consuming the one time verifier either way.
export async function completeLoginFromRedirect(): Promise<boolean> {
  const current = new URL(window.location.href);
  const code = current.searchParams.get("code");
  const returnedState = current.searchParams.get("state");
  if (code === null || returnedState === null) {
    return false;
  }

  const expectedState = sessionStorage.getItem(STATE_KEY);
  const verifier = sessionStorage.getItem(VERIFIER_KEY);
  sessionStorage.removeItem(STATE_KEY);
  sessionStorage.removeItem(VERIFIER_KEY);
  // Clear the code and state from the address bar so a reload cannot replay them.
  window.history.replaceState({}, "", `${current.origin}${current.pathname}`);

  if (expectedState === null || verifier === null || returnedState !== expectedState) {
    return false;
  }

  const config = loadConfig();
  const discovery = await discoverOidc(config.adminIssuer);
  const params = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri(),
    client_id: config.consoleClientId,
    code_verifier: verifier,
  });
  if (config.managementAudience !== "") {
    params.set("resource", config.managementAudience);
  }
  const token = await exchangeCode(discovery.token_endpoint, params);
  setAccessToken(token.access_token);
  return true;
}
