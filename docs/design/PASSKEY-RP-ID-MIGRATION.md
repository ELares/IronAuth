# Passkey RP ID continuity and related origins

Passkeys are bound to a WebAuthn **Relying Party ID** (RP ID), a registrable
domain. A credential registered against one RP ID cannot be used against another,
and this cannot be worked around: the private key never leaves the authenticator,
and the RP ID is folded into every assertion the authenticator signs. That single
fact drives two product realities this platform takes an explicit, honest posture
on: **RP ID continuity** (so a tenant does not lose passkeys when they move to or
from IronAuth) and **related origins** (so one RP ID can span several origins).

This guide states plainly what survives a domain move, what does not, and how the
two configuration knobs (`oidc.webauthn_rp_id` and `oidc.webauthn_related_origins`)
bridge a transition.

## The two knobs

Both live on the `[oidc]` section (see [CONFIG.md](../CONFIG.md)):

- `oidc.webauthn_rp_id`: the registrable domain a credential is scoped to. When
  unset it is derived from the serving origin's host. It is validated at startup to
  be the serving origin's host **or a parent (registrable-suffix) domain** of it;
  an RP ID outside the serving origin's registrable domain is a boot error, because
  it would fail every ceremony in the browser.
- `oidc.webauthn_related_origins`: additional origins permitted to run a ceremony
  against that RP ID, including origins on a **different** registrable domain. These
  are published at `GET /.well-known/webauthn` as `{"origins": [...]}`.

```toml
[server]
public_url = "https://auth.example.com"

[oidc]
# Scope passkeys to the tenant's registrable domain, NOT the exact serving host,
# so they survive a move between auth.example.com, id.example.com, example.com, ...
webauthn_rp_id = "example.com"
# One RP ID spanning a multi-brand / ccTLD estate (related origin requests).
webauthn_related_origins = ["https://example.de", "https://login.brand2.com"]
```

## RP ID continuity: what survives a hostname change

The RP ID is deliberately settable **independently of the serving hostname**, within
WebAuthn's validity rule (it must stay a registrable-domain suffix of the serving
and related origins the browser will use it from). This is the continuity mechanism.

- **A change of serving host under the same RP ID is transparent.** If passkeys were
  registered against `example.com` (the RP ID), moving the login surface from
  `auth.example.com` to `id.example.com` keeps every passkey working: the RP ID did
  not change, only the origin, and both origins are within `example.com`. Set
  `webauthn_rp_id = "example.com"` on both deployments. A domain-cutover test in the
  suite exercises exactly this (a stable RP ID across a hostname change).
- **Choosing a broad RP ID up front is the continuity investment.** If you serve on
  `auth.example.com` but set the RP ID to `example.com`, you are free to move the
  login surface anywhere under `example.com` later without reprompting users to
  re-register. Serving on `auth.example.com` with the RP ID left to default
  (`auth.example.com`) locks passkeys to that exact host.

## What does NOT survive, and why

- **A change of the RP ID itself.** If the RP ID changes (for example from
  `auth.vendor.com` to `example.com`), the old passkeys are gone: they are bound to
  the old RP ID and no server, ours or anyone's, can re-bind them. Credential rows
  are not portable between RP IDs by design. Users re-register on the new RP ID.
- **Credential rows do not migrate between IdPs.** There is no export/import of
  passkey private keys (impossible) and we do not pretend otherwise. Moving IdP while
  keeping the same RP ID keeps the credentials working *in the browser/authenticator*;
  the new IdP still has to enroll each credential's public key (a re-registration), or
  the estate is bridged during a transition window (below).

## Bridging a transition with related origins

Related origins let one RP ID be used from several origins at once, which is the
bridge during a move:

- To migrate the serving origin from `old.example.com` to `new.example.com` while
  both are live, keep a single RP ID that is a suffix of both (`example.com`) and, if
  either origin is on a different registrable domain, list it in
  `webauthn_related_origins`. During the window a passkey registered from either
  origin asserts from either origin.
- To span a multi-brand estate permanently (`example.com`, `example.de`,
  `brand2.com`), pick one RP ID and list the others as related origins. A passkey
  registered on any listed origin asserts from any other.

The accepted origin set at the ceremony layer is exactly the serving origin plus the
configured related origins. **This is the only thing related origins widen.** The
RP-ID-hash check, the assertion signature verification, and the single-use challenge
are unchanged: an origin absent from the document still fails with the uniform,
non-enumerating ceremony error.

### The browser label budget

Current browser implementations (Chrome 128+, Safari 18+) honor the
`/.well-known/webauthn` document only up to about **five distinct registrable
labels**, silently ignoring origins beyond that. A browser groups origins by the SLD
label of the registrable domain, so **one brand across many ccTLDs** (`example.com`,
`example.de`, `example.co.uk`) is a **single** label, not one per domain. The config
treats the budget as an **advisory soft-guard**: an estate (the serving origin plus
related origins) whose distinct-label count reaches **or exceeds** the budget emits a
startup **warning**, never a boot error (the browser is the real enforcer of its own
cap, and a boot error would wrongly reject the valid multi-brand / ccTLD estate this
feature exists to serve). The label count is a documented conservative approximation
(a curated common multi-part-suffix table, not a full public-suffix-list dependency).
Keep the estate within about five distinct registrable labels.

## The honest lock-in statement

When an RP ID sits on a **vendor-controlled** domain (for example `auth.vendor.com`),
the vendor controls passkey continuity: a tenant that leaves loses every passkey bound
to that RP ID, because only the vendor can serve that origin and its
`/.well-known/webauthn`. This is the lock-in mechanism Auth0's June 2026 customizable
RP ID feature exists to address, and it is why this platform's default posture is the
opposite:

- **Prefer an RP ID on a domain the tenant controls.** A tenant that registers
  passkeys against their own registrable domain (`example.com`) keeps them whether the
  IdP is IronAuth or someone else, as long as they continue to serve
  `https://example.com/.well-known/webauthn` (which this platform serves for them
  while they are here, and which they can serve themselves after they leave).
- **Custom auth domains are passkey continuity, not a moat.** Treating a tenant's own
  domain as the RP ID is what lets them arrive without losing passkeys and leave the
  same way. We document the mechanics here rather than burying them.

See the platform-wide exit posture in [exit-guide.md](../exit-guide.md) and the
covenants in [COVENANTS.md](../../COVENANTS.md).
