<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Machine-to-machine token caching (client-credentials, issue #23)

The `client_credentials` grant (RFC 6749 4.4) mints machine-to-machine (M2M)
access tokens for a client's own service-account principal. This document is the
SDK-facing guidance for how a client should CACHE and REUSE those tokens.

## Why caching is the client's job

IronAuth applies NO metering, counting-for-billing, or quota hook anywhere on the
M2M issuance path (a covenant of the platform; enforced in CI by
`scripts/no-m2m-metering.sh`). Issuance is not rate-limited or charged per token,
so there is no server-side incentive or penalty steering how often a client asks
for a token. That makes correct client-side caching purely a matter of efficiency
and reliability, and it is entirely the client's responsibility.

Fetching a fresh token on every outbound request is wasteful: it doubles the
request count against IronAuth and adds a signing round-trip to every call. A
well-behaved M2M client fetches ONE token and reuses it until shortly before it
expires.

## The rules

1. **Cache the token, keyed by `(client_id, scope, resource)`.** A token is
   specific to the client, the granted `scope`, and (once RFC 8707 `resource`
   lands, issue #28) the targeted audience. Cache one token per distinct
   combination; do not share a token across scopes or audiences.

2. **Reuse until an early-refresh threshold, never until the last second.**
   Read `expires_in` from the token response (seconds). Refresh when the token is
   within a small skew of expiry, for example when
   `now >= issued_at + expires_in - 60s`. Refreshing early absorbs clock skew and
   in-flight requests, so a request never leaves with a token that expires
   mid-flight.

3. **There is NO refresh token.** RFC 6749 4.4.3 forbids a refresh token on this
   grant, and IronAuth returns none. To get a new access token, re-run the
   client-credentials exchange (authenticate the client again). Do not look for or
   depend on a `refresh_token` field; it will never be present.

4. **Refresh on a `401`/`invalid_token`, once.** If a resource server rejects the
   token as expired or revoked (a client-credentials token is revocable via the
   introspection/revocation endpoints, issue #22), discard the cached token, fetch
   exactly one fresh token, and retry the request once. Do not retry-loop.

5. **Never persist the token to disk or logs.** An access token is a bearer
   credential. Keep it in memory for its short lifetime; do not write it to a log
   line, a file, or a shared cache that outlives the process without protection.

6. **Serialize concurrent refreshes.** Under concurrency, many in-flight requests
   can notice an expired token at once. Use a single-flight lock so exactly one
   refresh runs and the rest wait for its result, rather than issuing a burst of
   identical exchanges.

## A minimal cache (pseudocode)

```
token = cache.get(client_id, scope, resource)
if token is None or now >= token.expires_at - REFRESH_SKEW:
    with single_flight_lock(client_id, scope, resource):
        token = cache.get(client_id, scope, resource)          # re-check under lock
        if token is None or now >= token.expires_at - REFRESH_SKEW:
            resp  = post_token(grant_type="client_credentials",
                               client_auth=..., scope=scope, resource=resource)
            token = Token(value=resp.access_token,
                          expires_at=now + resp.expires_in)
            cache.put(client_id, scope, resource, token)
use token.value as the Bearer credential
```

`REFRESH_SKEW` is a small margin (a minute is a reasonable default) so a token is
never used in the final moments before it expires.

## What NOT to do

- Do not fetch a token per request. Cache and reuse it for its lifetime.
- Do not treat a missing `refresh_token` as an error; the grant never issues one.
- Do not pin a token past `expires_in`; it will be rejected once it expires.
- Do not assume issuance is free of side effects a meter would impose; there are
  none, but correct caching is still the client's job for efficiency and
  reliability.
