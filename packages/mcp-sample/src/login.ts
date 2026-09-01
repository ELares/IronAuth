// SPDX-License-Identifier: MIT OR Apache-2.0

// The Authorization Code + PKCE login an MCP client actually performs (issue #129).
//
// Driven headlessly against the hosted pages, cookies and all, because that is the flow an
// MCP client runs: a public client, a user at a browser, and an audience-bound token at the
// end. A driver that took a short cut through client_credentials would prove nothing about
// the path real clients take, and specifically nothing about whether a resource indicator
// survives an interactive login, which is where it was found to be dropped.

import { createHash, randomBytes } from "node:crypto";

/** A minimal cookie jar. The hosted pages set a session cookie the resume depends on. */
class Jar {
  private readonly cookies = new Map<string, string>();

  absorb(response: Response): void {
    for (const raw of response.headers.getSetCookie()) {
      const [pair] = raw.split(";");
      const index = pair?.indexOf("=") ?? -1;
      if (pair && index > 0) {
        this.cookies.set(pair.slice(0, index), pair.slice(index + 1));
      }
    }
  }

  header(): string {
    return [...this.cookies].map(([name, value]) => `${name}=${value}`).join("; ");
  }
}

function base64Url(input: Buffer): string {
  return input.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Read one hidden form field out of a hosted page. */
function formField(html: string, name: string): string | null {
  const pattern = new RegExp(`name="${name}"\\s+value="([^"]*)"`);
  const match = pattern.exec(html);
  if (match?.[1] === undefined) {
    return null;
  }
  return match[1]
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">");
}

export interface LoginOutcome {
  /** The audience-bound access token, when the flow completed. */
  accessToken?: string;
  /** The refresh token, when one was issued. */
  refreshToken?: string;
  /** What went wrong, for the evidence column. */
  detail: string;
}

/**
 * Complete an Authorization Code + PKCE login and exchange the code for a token bound to
 * `resource`.
 *
 * Follows redirects by hand so each hop is observable: the evidence a conformance item
 * records has to name the hop that failed, and `fetch`'s automatic following would collapse
 * the whole flow into one opaque outcome.
 */
export async function login(options: {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  clientId: string;
  redirectUri: string;
  resource: string;
  scope: string;
  identifier: string;
  password: string;
}): Promise<LoginOutcome> {
  const jar = new Jar();
  const verifier = base64Url(randomBytes(32));
  const challenge = base64Url(createHash("sha256").update(verifier).digest());
  const host = new URL(options.authorizationEndpoint).origin;

  const authorize = `${options.authorizationEndpoint}?${new URLSearchParams({
    response_type: "code",
    client_id: options.clientId,
    redirect_uri: options.redirectUri,
    scope: options.scope,
    state: base64Url(randomBytes(8)),
    code_challenge: challenge,
    code_challenge_method: "S256",
    resource: options.resource,
  }).toString()}`;

  let location = authorize;
  let code: string | null = null;
  // Bounded, so a redirect loop is a reported failure rather than a hung lane.
  for (let hop = 0; hop < 12 && code === null; hop += 1) {
    const response = await fetch(location, {
      redirect: "manual",
      headers: jar.header() ? { cookie: jar.header() } : {},
    });
    jar.absorb(response);

    if (response.status === 303 || response.status === 302) {
      const next = response.headers.get("location") ?? "";
      const url = new URL(next, host);
      code = url.searchParams.get("code");
      if (code === null && url.searchParams.has("error")) {
        return {
          detail: `authorize refused: ${url.searchParams.get("error")} ${url.searchParams.get("error_description") ?? ""}`,
        };
      }
      location = url.toString();
      continue;
    }

    const body = await response.text();
    const returnTo = formField(body, "return_to");
    if (returnTo === null) {
      return { detail: `unexpected page at ${location.slice(0, 90)} (status ${response.status})` };
    }

    // A login page, or a consent page. Both resume through their own `return_to`.
    const isConsent = body.includes('name="decision"');
    const form = isConsent
      ? new URLSearchParams({ decision: "allow", return_to: returnTo })
      : new URLSearchParams({
          identifier: options.identifier,
          password: options.password,
          return_to: returnTo,
        });
    const posted = await fetch(`${host}${isConsent ? "/consent" : "/login"}`, {
      method: "POST",
      redirect: "manual",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        ...(jar.header() ? { cookie: jar.header() } : {}),
      },
      body: form.toString(),
    });
    jar.absorb(posted);
    if (posted.status !== 303 && posted.status !== 302) {
      return { detail: `${isConsent ? "consent" : "login"} refused with status ${posted.status}` };
    }
    location = new URL(posted.headers.get("location") ?? "", host).toString();
  }

  if (code === null) {
    return { detail: "no authorization code after following the flow" };
  }

  const exchanged = await fetch(options.tokenEndpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: options.redirectUri,
      client_id: options.clientId,
      code_verifier: verifier,
      resource: options.resource,
    }).toString(),
  });
  const payload = (await exchanged.json()) as Record<string, unknown>;
  if (exchanged.status !== 200) {
    return { detail: `token exchange ${exchanged.status}: ${JSON.stringify(payload).slice(0, 200)}` };
  }
  return {
    accessToken: payload["access_token"] as string,
    refreshToken: payload["refresh_token"] as string | undefined,
    detail: `code exchanged, scope=${String(payload["scope"] ?? "")}`,
  };
}
