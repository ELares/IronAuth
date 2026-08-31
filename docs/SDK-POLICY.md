# SDK priority policy

Which SDKs IronAuth ships, which are deferred, and the reasoning behind the order.

An integrator's first question is "is my language supported, and if not, will it be?" A
silent absence answers neither. This page answers both, and states a **revisit trigger** for
every deferral so a deferral is falsifiable rather than indefinite -- the same discipline
[Will Not Implement](WILL-NOT-IMPLEMENT.md) applies to outright refusals. The difference is
that nothing here is refused: these are ordering decisions, and the order can change.

## The priority matrix

The order is not a popularity ranking. It follows one rule: **build what removes the most
protocol risk from the integrator, first.**

| Priority | Surface | Why here |
| --- | --- | --- |
| 1 | Browser-facing session handling (Next.js, BFF) | Where tokens are most easily mishandled. A browser app that holds tokens in JavaScript is one XSS from full account takeover, so the layer that keeps them out of the browser earns the first slot. |
| 2 | Headless React hooks | Same risk surface, minus the framework. State and actions only, no bundled UI -- a component library ages faster than a protocol and would tie upgrades to a design system. |
| 3 | Server SDKs generated from the published spec (Go, Python) | Generated, so they cannot drift from the contract. A hand-written server SDK is a second implementation of the API with its own bugs; generation makes the spec the single source. |
| 4 | Step-up middleware helpers | The RFC 9470 challenge loop is fiddly and easy to get subtly wrong (comparing `acr` and `auth_time` against required values, constructing the retry request). Worth centralising once. |
| 5 | Mobile guidance over AppAuth | Documented path rather than a shipped SDK -- see the deferral reasoning below. |

## What ships today

| Surface | State |
| --- | --- |
| Go management SDK | **Generated** from `docs/openapi/management.json` (`sdks/go`) |
| Python management SDK | **Generated** from `docs/openapi/management.json` (`sdks/python`) |
| Java token verification | **Hand-written, dependency-free** (`sdks/java`) -- the JDK has had Ed25519 since Java 15, so it bundles nothing, not even a JSON parser. Verification only: there is no Java management SDK, and the generated clients remain Go and Python |
| Reference client | **Hand-written from the published spec** (`clients/reference`) -- proves the spec is sufficient to build against without reading SDK source |

The generated clients are produced by the pipeline in the [SDK contract](SDK-CONTRACT.md);
CI fails if the management API changes without regenerating them.

## Deferred, with triggers

Nothing below is refused. Each entry states what would change our mind.

- **What**: Vue, Nuxt, and Angular wrappers.
  **Why**: the session-handling substance lives in the framework-agnostic BFF helper and the
  WebCrypto core; a wrapper is thin glue over both. Shipping three more of them before the
  first is proven in production buys surface area, not safety.
  **Instead**: use the BFF helper directly. The protocol work is done; what is missing is
  idiomatic sugar.
  **Revisit trigger**: the Next.js and React surfaces are stable across a major release with
  no protocol-level changes, or a specific integrator blocks on framework glue rather than on
  the underlying flow.

- **What**: full native mobile SDKs for iOS and Android.
  **Why**: AppAuth already implements RFC 8252 correctly (system browser plus PKCE, claimed
  HTTPS or custom-scheme redirects per platform) and is maintained by people who track
  platform changes we would otherwise chase. A native SDK of our own would mostly re-wrap it,
  and would own a platform-security surface we could not maintain as well.
  **Instead**: documented AppAuth integration against IronAuth endpoints, plus documentation
  for exposing native passkey ceremonies through the headless flow API.
  **Revisit trigger**: AppAuth stops tracking a platform release, or a capability IronAuth
  needs cannot be expressed through it.

- **What**: .NET, Ruby, and PHP beyond generated management clients.
  **Why**: for a server-side integration the protocol work is token verification, and that is
  a JOSE problem those ecosystems already solve well. The generated management client covers
  administration; a bespoke SDK on top would mostly restate a verification library.
  **Instead**: the generated management client, plus the verification guidance in
  [edge verification](edge-verification.md).
  **Revisit trigger**: a verification path in one of these ecosystems proves error-prone in
  practice -- a recurring integrator mistake is evidence; an absence of one is not.
  **Java left this list**, and the reason is worth recording because it is not the trigger
  above. Nobody reported a Java integrator getting verification wrong. What changed is that
  the cost collapsed: Ed25519 landed in the JDK itself, so the artifact could be written with
  no dependencies at all rather than as glue around Nimbus and Tink. A deferral justified by
  "this would mostly restate a library" stops holding when the thing no longer needs the
  library. Note the narrow scope of what shipped -- verification, not administration; there
  is still no Java management SDK, and this entry still covers that.

## Why deferrals are published rather than implied

An unpublished deferral is indistinguishable from an oversight. An integrator choosing a
stack needs to know that Vue support is a scheduling decision with a stated trigger, not an
omission that might be fixed next week -- because those two answers lead to different
decisions. Publishing the trigger also constrains us: a deferral whose trigger has fired and
that has not been revisited is a visible contradiction rather than a quiet one.
