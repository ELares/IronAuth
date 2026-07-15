# Session Management and Front-Channel Logout: read this before enabling

> **Reliability caveat.** OIDC Session Management 1.0 and Front-Channel Logout 1.0
> are iframe-based mechanisms that are **functionally degraded under modern
> third-party-cookie partitioning**. IronAuth ships them ONLY for certification
> completeness (the Session OP and Front-Channel OP conformance profiles). They are
> **default-off**, and they are **not recommended**. For reliable logout propagation,
> use **back-channel logout** (issue #34).

## Why these mechanisms are degraded

Both specs rely on the end user's browser loading an OP-controlled iframe in a
**third-party context** (the OP origin embedded inside the RP page, or the RP origin
embedded inside the OP logout page) and that iframe being able to read the OP session
cookie. Since 2024-2026 every major browser partitions or blocks third-party cookies
by default, so the iframe cannot see the OP session state.

OIDC Session Management 1.0 **section 5.1** documents this failure mode itself: when
the OP's browser state is unreadable (blocked third-party content), the
`check_session_iframe` can return `changed` on **every** poll, which drives the RP to
re-initiate authentication in a loop. A steady stream of confused-user reports and
CSP breakage in real deployments (for example Keycloak's `checkLoginIframe`) traces
to exactly this.

The field has largely retired these mechanisms: node-oidc-provider removed Session
Management in v8 and ships neither spec in v9; Duende calls the check-session pattern
already broken in production. The only reason to implement them is to match the
four-logout-profile certification badge set, which is what this feature exists for.

## What IronAuth ships, and how it is gated

Both features are gated by an **environment flag AND a per-client opt-in**, so neither
can turn on globally by accident. With the flags off, nothing is mounted and discovery
advertises nothing.

- **Session Management 1.0** (`oidc.session_management_enabled`, default `false`):
  serves the `check_session_iframe` at `{base}/connect/check_session`, advertises
  `check_session_iframe` in discovery, and emits `session_state` on authorization
  responses. `session_state` is a one-way keyed digest of the client id, the RP
  origin, and the OP browser state (itself a one-way digest of the session id): it
  **never carries the session id**. The iframe replies ONLY to the sender's exact
  `postMessage` origin (never `*`) and folds that origin into the recomputed value, so
  a wrong-origin poller learns nothing.

- **Front-Channel Logout 1.0** (`oidc.frontchannel_logout_enabled`, default `false`):
  during the `end_session` flow, renders a page embedding one hidden iframe per
  participating RP that registered a `frontchannel_logout_uri`, passing `iss` and the
  RP's **own** per-(client, session) `sid` when it registered
  `frontchannel_logout_session_required`. An RP only ever receives its own `sid`,
  never a co-scoped client's. Front-channel delivery is **best-effort by
  construction**: it never blocks, replaces, or reorders back-channel logout, which
  remains the authoritative propagation path.

### The framing carve-out

The `check_session_iframe` is the ONE page served without `frame-ancestors 'none'` and
without `X-Frame-Options`, because an RP must embed it cross-origin. The front-channel
logout page keeps its own anti-clickjacking posture (`frame-ancestors 'none'` +
`X-Frame-Options: DENY`) and opens `frame-src` to exactly the participating RPs'
registered `frontchannel_logout_uri` origins. Every other auth page keeps
`frame-ancestors 'none'`. With both flags off, neither carve-out exists.

## Recommendation

**Do not enable these unless you are running the certification profiles.** For
production logout propagation, register a `backchannel_logout_uri` and rely on
back-channel logout (issue #34): it is server-to-server, is unaffected by
third-party-cookie partitioning, and is the authoritative path.
