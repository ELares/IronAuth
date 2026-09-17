# @ironauth/sdk

TypeScript helpers for integrating with IronAuth's public authentication and
authorization contracts. The package uses WebCrypto for token verification and
proof-of-possession operations, and also includes protocol, resource-server,
session-token, diagnostic, and copyable verification utilities.

The development manifest is private (`0.0.0`). Build from this repository;
there is no published npm installation or single root export entry point in
the current package. Consumers use the compiled modules they need, or the
standalone snippets. For app setup, start with the
[integration guide](../../docs/INTEGRATIONS.md).

## Modules and capabilities

| Module | Public helpers and behavior |
| --- | --- |
| `verify.ts` | `verifyToken`, `JwksCache`, and typed `VerifyError` refusals. Checks signature, allowed algorithm, issuer, audience, and times; cache reuse and bounded unknown-key refetch. The WebCrypto implementation accepts EdDSA, ES256, and RS256, not every algorithm supported by the server. |
| `protocol.ts` | Discovery, PKCE/state generation, authorization URLs, code exchange, refresh, and UserInfo. Uses discovered endpoints instead of guessing their paths. DPoP binding can be supplied to supported requests. |
| `dpop.ts` | Proof-key generation, proof creation, URL normalization, nonce handling, and proof-aware fetch. |
| `dpop-store.ts` | Memory and IndexedDB proof-key stores, per-client/environment key slots, load-or-create helpers, and a nonce cache. Persistent proof keys do not turn the package into a browser token-storage layer. |
| `protected-resource.ts` | RFC 9728 protected-resource metadata, configuration validation, OAuth challenges, and middleware response helpers; configure the resource and trusted authorization servers explicitly. |
| `session-token.ts` | `SessionTokenClient`, server-advertised session-token mode detection, scheduled refresh, and explicit active/degraded/signed-out state. See the [session tokenizer](../../docs/session-tokenizer.md). |
| `check.ts` | A uniform authorization check using verified-token permissions, IronAuth AuthZEN, or a compatible customer PDP. All expected failures deny. |
| `debug.ts` | `diagnose` returns verification observations and suggested fixes. Its decoded claims on a refused token are diagnostic data, not authenticated identity. |

The [edge verification guide](../../docs/edge-verification.md) states the
runtime support matrix, test evidence, and latency methodology. Java and .NET
verification implementations are separate artifacts, not wrappers around this
package.

## Build and verify

Use Node 20 or newer as declared by this package's manifest. If developing
other packages in the same checkout, follow their own requirements; the admin
SPA currently requires newer supported Node 22/24/26 versions.

```sh
cd packages/ironauth-sdk
npm ci
npm run typecheck
npm run build
npm test
```

The output is under `dist/`, one compiled module per source module. Browser
proof-key reload checks have a separate `npm run test:browser` command and
runtime prerequisites. `npm run bench` measures JWT verification on the
machine running it; it is not a hosted-platform latency guarantee.

## Verify before using token claims

Create a JWKS cache from trusted discovery metadata. Pass the expected issuer,
resource audience, and the algorithms your application accepts. This example
assumes it runs next to the package's `dist/` directory and that `metadata`,
`issuer`, and `accessToken` came from your application setup:

```ts
import { JwksCache, verifyToken } from './dist/verify.js';

const keys = new JwksCache({ uri: metadata.jwks_uri });
const verified = await verifyToken(accessToken, keys, {
  issuer,
  audience: 'https://orders.example',
  algorithms: ['EdDSA'],
});
```

Reuse the cache between requests. A verified self-contained JWT can remain
valid until expiration after its grant is revoked. Use introspection when
you need the issuer's current revocation state. A DPoP-bound access token also
requires request-proof validation by its consumer; signature verification
alone does not validate that proof.

## Uniform authorization checks

One request shape can use three resolvers, selected by configuration:

| Mode | Decision source |
| --- | --- |
| `claims` | A permission slug in the access token the application has already verified. |
| `authzen` | IronAuth's configured AuthZEN evaluation endpoint. |
| `pdp` | A customer's compatible AuthZEN-shaped PDP. |

```ts
import { check } from './dist/check.js';

const allowed = await check({
  mode: 'claims',
  claims: () => verified.claims,
}, {
  subject: { type: 'user', id: String(verified.claims.sub) },
  resourceType: 'orders',
  action: 'read',
  organizationId: 'org_example',
});
```

`check()` is an authorization decision, not a JWT verifier. The claims resolver
looks for an exact permission slug such as `orders.read`; it does not itself
validate the subject or organization against your request. Enforce that
binding in your application, or use the configured PDP for contextual decisions.
Endpoint modes accept an `endpoint` and optional bearer `token`.

Network errors, non-success responses, malformed bodies, and missing permission
claims return `false`. An over-budget token with no usable permission list
also denies; choosing a PDP resolver is an explicit application decision.
See the [capability guide](../../docs/CAPABILITIES.md) for server-side
permission and AuthZEN behavior.

## Standalone snippets

- `snippets/verify-webcrypto.mjs`: copyable JWT verification with explicit
  issuer, audience, keys, and time inputs.
- `snippets/verify-log-stream.mjs`: verification of signed log-stream batches;
  see the [consumer guide](../../docs/log-stream-verification.md).

The snippet and SDK verification implementations are exercised against the
shared refusal/acceptance corpus. Copying a file means taking responsibility
for updates; keeping a source dependency follows the repository's update cycle.

## Separation from authentication pages

The [reference app](../reference-app/README.md) renders only the public flow
API. It has a route audit that keeps management and operator-configured PDP
calls outside that package. Use this SDK in your application or API, and the
reference renderer for custom authentication pages. The server remains the
security boundary for flow submissions.
