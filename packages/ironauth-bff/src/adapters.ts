// SPDX-License-Identifier: MIT OR Apache-2.0

/**
 * The two framework adapters (issue #117 criterion 1).
 *
 * Both are thin by construction: the core returns a {@link BffResult} and an adapter's whole job
 * is to render that union in its framework's idiom. Neither adapter makes a security decision,
 * which is why there are two of them and only one set of rules.
 *
 * - {@link fetchAdapter} for any runtime whose handler is `Request -> Response`: Cloudflare
 *   Workers, Deno, Bun, Node's own `fetch` server, Vercel Edge.
 * - {@link nodeAdapter} for the `(req, res)` shape Express and `node:http` share.
 *
 * ## What an adapter may decide, and what it may not
 *
 * It MAY decide how `unauthenticated` renders: a page wants a redirect to login and an XHR wants
 * a 401, and only the caller knows which this route is. That choice is a parameter.
 *
 * It may NOT decide anything else. In particular it does not rewrite the `Set-Cookie` header,
 * because those attributes are the architecture -- `assertHardened` is run over what these
 * adapters actually emit, not over the constant the cookie module exports, precisely so a
 * rewrite here would fail a test.
 */

import type { BffRequest, BffResult } from './core.js';

/** How `unauthenticated` should render on this route. */
export interface UnauthenticatedPolicy {
  /** `401` for an XHR route, or a redirect target for a page route. */
  redirectTo?: string;
}

/** Map a result onto a `Response`. */
export function toResponse(result: BffResult, policy: UnauthenticatedPolicy = {}): Response {
  switch (result.kind) {
    case 'redirect': {
      const headers = new Headers({ location: result.location });
      if (result.setCookie) {
        headers.append('set-cookie', result.setCookie);
      }
      return new Response(null, { status: result.status, headers });
    }
    case 'json': {
      const headers = new Headers({
        'content-type': 'application/json',
        // NEVER CACHED. Every body here is derived from a session, and a shared cache holding one
        // would serve one user's identity to the next.
        'cache-control': 'no-store',
      });
      if (result.setCookie) {
        headers.append('set-cookie', result.setCookie);
      }
      return new Response(JSON.stringify(result.body), { status: result.status, headers });
    }
    case 'proxied':
      return result.response;
    case 'unauthenticated': {
      if (policy.redirectTo !== undefined) {
        return new Response(null, { status: 302, headers: { location: policy.redirectTo } });
      }
      return json(401, { error: 'unauthenticated', reason: result.reason });
    }
    case 'refused':
      // 403 rather than 400: the request was well formed and REFUSED. A 400 would send an
      // integrator looking for a malformed parameter.
      return json(403, { error: 'refused', reason: result.reason });
    case 'upstream_error':
      return json(502, { error: 'upstream_error', detail: result.detail });
  }
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });
}

/**
 * Adapt a `Request -> Response` runtime.
 *
 * The `Request` already IS a {@link BffRequest} structurally, which is why this is a cast rather
 * than a translation: `method`, `url` and `headers.get` are the whole interface, and choosing
 * them to match was the point.
 */
export function fetchAdapter(
  handler: (request: BffRequest) => Promise<BffResult>,
  policy: UnauthenticatedPolicy = {},
): (request: Request) => Promise<Response> {
  return async (request: Request) => {
    const result = await handler({
      method: request.method,
      url: request.url,
      headers: request.headers,
      body: request.body,
    });
    return toResponse(result, policy);
  };
}

/** The `(req, res)` pair `node:http` and Express share, reduced to what this needs. */
export interface NodeRequestLike {
  method?: string;
  url?: string;
  headers: Record<string, string | string[] | undefined>;
}

/** The response side. */
export interface NodeResponseLike {
  statusCode: number;
  setHeader(name: string, value: string | string[]): void;
  end(chunk?: string): void;
}

/**
 * Adapt the `(req, res)` shape.
 *
 * `origin` is required rather than guessed from the `Host` header, and that is a security
 * decision rather than an inconvenience: `Host` is attacker-controlled, and a BFF that builds
 * its own redirect targets from it can be made to send a user's login somewhere else.
 */
export function nodeAdapter(
  handler: (request: BffRequest) => Promise<BffResult>,
  origin: string,
  policy: UnauthenticatedPolicy = {},
): (req: NodeRequestLike, res: NodeResponseLike) => Promise<void> {
  return async (req: NodeRequestLike, res: NodeResponseLike) => {
    const headers = {
      get(name: string): string | null {
        const value = req.headers[name.toLowerCase()];
        if (value === undefined) {
          return null;
        }
        // A repeated header arrives as an array. Joined with `; ` because the one header this
        // package reads that can legally repeat is `Cookie`, whose members are `; ` separated.
        return Array.isArray(value) ? value.join('; ') : value;
      },
    };
    const result = await handler({
      method: req.method ?? 'GET',
      url: new URL(req.url ?? '/', origin).toString(),
      headers,
    });
    const response = toResponse(result, policy);
    res.statusCode = response.status;
    // `getSetCookie` keeps multiple cookies separate; `Headers.get('set-cookie')` would fold
    // them into one comma-joined string, which is not a valid cookie header.
    const cookies = response.headers.getSetCookie();
    // `forEach` rather than `for..of`: the DOM lib this package compiles against types `Headers`
    // without `[Symbol.iterator]`, and reaching for the iterator is a compile error even though
    // every runtime provides one.
    response.headers.forEach((value, name) => {
      if (name.toLowerCase() === 'set-cookie') {
        return;
      }
      res.setHeader(name, value);
    });
    if (cookies.length > 0) {
      res.setHeader('set-cookie', cookies);
    }
    const body = await response.text();
    res.end(body === '' ? undefined : body);
  };
}
