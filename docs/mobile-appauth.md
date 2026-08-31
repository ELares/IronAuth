# Mobile: signing in over AppAuth

IronAuth does not ship a mobile SDK. It documents a path over [AppAuth][appauth], which already
implements RFC 8252 correctly, and this page is that path.

[appauth]: https://openid.github.io/AppAuth-Android/

`docs/SDK-POLICY.md` records why, and the short version is that the protocol work on mobile is
the system-browser dance -- Custom Tabs or `ASWebAuthenticationSession`, PKCE, the redirect
plumbing -- and a bespoke SDK would mostly restate a library that does it properly.

## The one thing that will surprise you

**AppAuth cannot do DPoP, and IronAuth requires DPoP from public clients by default.**

A mobile app is a public client: it ships to devices, so it cannot keep a secret. IronAuth's
posture (issue #124) is that such a client must sender-constrain its tokens, and AppAuth has no
DPoP support of any kind -- verified rather than assumed, by unpacking `net.openid:appauth` and
finding no DPoP class, method or parameter anywhere in it.

So an AppAuth token exchange against a default IronAuth client is refused:

```json
{"error":"invalid_dpop_proof","error_description":"the DPoP proof is missing, malformed, or invalid"}
```

This is not a bug in either. It is the case IronAuth's own escape hatch was written for: "a
vendor SDK the operator does not control".

### Granting the exemption

```http
PUT /v1/tenants/{tenant}/environments/{environment}/clients/{client_id}/bearer-tokens
Content-Type: application/json

{"allowed": true}
```

Per **client**, deliberately. A deployment-wide switch would have to be set for the weakest
client and would silently relax every other client with it.

### What it costs, stated plainly

The tokens this client receives stop being sender-constrained. **A stolen access token becomes
replayable by whoever stole it** until it expires, which is precisely the risk DPoP removes. The
environment's `diagnostics/warnings` will report `dpop_posture_relaxed` naming the client for as
long as the exemption stands, and the change is audited (`client.allow_bearer_tokens.set`) and
published on the event stream (`client.bearer_tokens_changed`).

Set it because you have chosen to, not because the login failed and this made it work.

### If you would rather keep the constraint

Two options, neither of which is AppAuth:

- **A DPoP-capable library**, or your own token exchange. The authorization leg can still be
  AppAuth; only the token request needs the proof, and AppAuth will hand you the code.
- **The BFF pattern**, with the mobile app talking to your own backend and the backend holding
  the tokens. `packages/ironauth-bff` does DPoP, and this is the stronger architecture for an
  app that already has a backend.

## Android

The sample is `clients/mobile/android`. It builds to a real APK in CI, and the four steps are all
in `SignInActivity.java`.

### Discovery, not concatenation

An IronAuth issuer carries a tenant and environment path while its endpoints sit at the host
root:

```text
issuer          https://iss.example/t/tnt_x/e/env_y
token_endpoint  https://iss.example/token
```

`AuthorizationServiceConfiguration.fetchFromIssuer` reads the discovery document, which is the
only correct source. Building endpoint URLs from the issuer string produces 404s.

### The redirect scheme is a build placeholder

```kotlin
manifestPlaceholders["appAuthRedirectScheme"] = "dev.ironauth.sample"
```

AppAuth's manifest declares a `RedirectUriReceiverActivity` whose intent filter interpolates
this. Omitting it fails the build at the manifest merge, which is the toolchain telling you a
redirect nothing can deliver is not a redirect. The scheme must match the redirect URI
registered on the client.

### PKCE needs no configuration

`AuthorizationRequest.Builder` applies it. There is no flag and no verifier to manage, and that
is most of the argument for using the library.

## iOS

The sample is `clients/mobile/ios`. It uses [AppAuth-iOS][appauth-ios] and
`ASWebAuthenticationSession`, and the shape is the same: discover, authorize in the system
browser, receive the redirect, exchange the code.

[appauth-ios]: https://openid.github.io/AppAuth-iOS/

It is a **library target**, not an Xcode app project. What is worth verifying is that the
integration code compiles against the real AppAuth API, and a library target gets that under
`xcodebuild -destination 'generic/platform=iOS'` without a hand-written `.xcodeproj` that nothing
would check. Drop the files into an app target and present `SignInViewController`; that is the
whole integration.

**Its verification is weaker than Android's, and here is exactly how.** The Android sample was
built locally many times while it was written, and CI builds a real APK. For iOS:

| Check | Where | What it proves |
| --- | --- | --- |
| `swiftc -parse` | everywhere, including locally | the sources are syntactically valid. It does **not** resolve `import AppAuth`, so it cannot tell you a method name is real or an argument label is right |
| `xcodebuild` for iOS | the macOS CI lane | it compiles against the actual AppAuth package, which is the check that matters |

No local build stood behind its first commit, because this machine has the Command Line Tools
and not Xcode. Read it as authored-and-CI-compiled rather than as exercised.

## What is actually verified

`scripts/mobile-verify.sh` runs in CI and does two things, each proving what the other cannot.

**The build half**: the Android sample assembles into a real APK against the real AppAuth
library, and the **merged** manifest is checked for the redirect scheme -- not the source
manifest, because the placeholder is interpolated by the library's manifest and the merge is the
only place its value is observable.

**The flow half**: an AppAuth-shaped exchange -- public client, PKCE, loopback redirect, **no
DPoP proof** -- against a real IronAuth, with a control:

| Step | Expected |
| --- | --- |
| The exchange, before any exemption | refused, `invalid_dpop_proof` |
| Grant `bearer-tokens` through the management API | `allow_bearer_tokens: true` |
| The identical exchange, after | 200, an unbound `Bearer` token |

**The control is the point.** Without it the flow half would pass just as happily against a
server that never required DPoP at all, and would prove nothing about the configuration this
page tells you to apply.

## What is not verified

- **No emulator or device run.** Neither sample is launched on a simulator, so nothing here
  proves the UI works, that Custom Tabs opens, or that the redirect reaches the app on a real
  device. What is proved is that the code builds and that the server accepts the exchange the
  library performs.
- **The iOS build is CI-only**, as above.
