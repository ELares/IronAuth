# Skill: add IronAuth login to an app

Use this when a user asks to add authentication, login, SSO, or IronAuth to an application.

## Before writing any code

**Search the docs first.** Call `search_docs` before you write an IronAuth integration, every
time. This product moves; an integration written from recall is written against whatever shape
was current when you were trained, and the failure is silent -- it compiles, and it is wrong
about the thing that matters.

## Step 1: pick the architecture, and it is probably the BFF

Read `docs/bff.md`. It ranks the three OAuth 2.0 for Browser-Based Apps BCP architectures with
their tradeoffs:

1. **Backend-for-frontend** -- every token server-side, browser holds one opaque cookie. Use
   `@ironauth/bff`. Choose this unless the user cannot run a server.
2. **Token-mediating backend** -- refresh token server-side, access token in the browser.
   Acceptable; the access token is exposed to XSS for its lifetime.
3. **Browser-held tokens** -- last, and only with **both** DPoP and refresh rotation.

**Never write tokens to `localStorage`.** There is no supported way to do it and no IronAuth
document describes one. If the user asks for it, explain what it costs and offer the BFF.

## Step 2: get an environment

Either point at an existing one, or boot the emulator:

```
cargo run -p ironauth --bin ironauth -- dev --seed 1
```

It prints an issuer and a seeded client id. It is offline and deterministic; `docs/EMULATOR.md`
has the details.

## Step 3: wire the BFF

```ts
import { MemorySessionStore, fetchAdapter, login, callback, logout, userinfo, proxy } from '@ironauth/bff';

const config = {
  issuer, clientId, clientSecret, redirectUri,
  scope: 'openid profile',
  apiBase,
  sessionMaxAgeSeconds: 3600,
  store: new MemorySessionStore(),
};
```

Mount five routes: `login`, `callback`, `logout`, `userinfo`, and `proxy` for API calls.

**`MemorySessionStore` is not for production.** A restart signs everybody out and a second
replica shares no sessions. Say so to the user and point at `SessionStore`.

**State-changing calls need the `X-IronAuth-BFF` header.** `logout` and any non-GET through the
proxy refuse without it. That is the CSRF defence, not an accident.

## Step 4: verify tokens at the edge, if the user needs to

Read `docs/edge-verification.md`. It has the runtime support table with how each row is backed,
and the snippets. **CloudFront Functions cannot do this** -- it has no asymmetric crypto -- and
the doc says what to use instead.

## What to tell the user

- which of the three architectures you chose, and why;
- that `MemorySessionStore` must be replaced before they ship;
- the cookie is `__Host-` prefixed, `HttpOnly`, `Secure`, and its attributes are not
  configurable, because they are the architecture.

## Do not

- put a token in `localStorage`, or in any browser storage that survives the tab;
- disable a cookie attribute to make something work locally -- use the emulator over http on
  localhost, which browsers permit for `Secure` cookies;
- write your own JWT verification. Use `@ironauth/sdk`'s `verifyToken`, or a snippet from
  `docs/edge-verification.md`. A hand-rolled verifier is how the 2025-2026 JOSE CVE wave
  happened.
