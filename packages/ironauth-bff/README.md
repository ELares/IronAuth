# @ironauth/bff

The IronAuth backend-for-frontend helper: the OAuth 2.0 for Browser-Based Apps BCP's
first-choice architecture, framework-agnostic, with every token held server-side.

`docs/bff.md` ranks this against the two alternatives with their tradeoffs, and states the one
thing this package will never help you do.

## What the browser holds

One cookie. `__Host-ironauth_bff`, `HttpOnly`, `Secure`, `SameSite=Lax`, carrying an opaque
256-bit session id and nothing else. The access token, the refresh token and the PKCE verifier
live in your `SessionStore`.

The attributes are not configurable, because they are the architecture.

## Five handler groups

`login`, `callback`, `logout`, `userinfo`, `proxy`. Each takes a plain request and returns a
typed result; adapters render the result and make no security decision of their own.

```ts
import { MemorySessionStore, fetchAdapter, login, callback, proxy } from '@ironauth/bff';

const config = {
  issuer: 'https://iss.example/t/ten_x/e/env_y',
  clientId: 'cli_bff',
  clientSecret: process.env.CLIENT_SECRET,
  redirectUri: 'https://app.example/auth/callback',
  scope: 'openid profile',
  apiBase: 'https://api.example',
  sessionMaxAgeSeconds: 3600,
  store: new MemorySessionStore(),
};

export const onLogin = fetchAdapter((request) => login(config, request));
export const onCallback = fetchAdapter((request) => callback(config, request));
// A page route wants a redirect where an XHR route wants a 401. That is the adapter's call.
export const onApi = fetchAdapter((request) => proxy(config, request), { redirectTo: '/auth/login' });
```

For Express or `node:http`, swap `fetchAdapter` for `nodeAdapter(handler, origin)`. The origin is
required rather than read from `Host`, which is attacker-controlled.

`MemorySessionStore` is for tests and single-process development: a restart signs everybody out,
and a second replica shares none of the first's sessions. Implement `SessionStore` against Redis
or a database before shipping.

## CSRF

State-changing endpoints (`logout`, and any non-`GET` through `proxy`) require the
`X-IronAuth-BFF` header. Any value. A cross-site form post cannot set one.

## Failure handling

Nothing throws for an expected outcome. `unauthenticated` distinguishes `no_session`,
`session_expired` and `refresh_failed`; a failed refresh destroys the session rather than leaving
a cookie that says "signed in" while nothing works.
