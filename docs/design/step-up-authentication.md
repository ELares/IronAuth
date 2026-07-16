# Step-up authentication: the resource-server challenge contract (RFC 9470)

IronAuth implements RFC 9470 (OAuth 2.0 Step-up Authentication Challenge Protocol)
end to end: a resource server (RS) challenges a request whose access token does not
carry a strong enough authentication context, the client re-authorizes with the
requested `acr_values` / `max_age`, the authorization server (AS) runs the required
authentication (a real second factor, never a silent session reuse), and issues
tokens whose `acr` and `auth_time` reflect what actually happened. This page is the
contract an RS implements. The authoritative behavior is exercised by the
`step_up` integration suite and the sample RS in
`crates/ironauth-oidc/tests/step_up.rs`.

The invariant that makes this safe: `acr`, `amr`, and `auth_time` are DERIVED from
the recorded authentication event (see `crates/ironauth-oidc/src/authn.rs`), never
asserted from a request parameter. A stepped-up token therefore always carries the
honest, fresh context; an RS can trust it.

## The authentication-context claims on an access token

An IronAuth JWT access token (`at+jwt`) carries:

- `acr` — the achieved authentication context class. IronAuth advertises, weakest to
  strongest: `urn:ironauth:acr:pwd` (a password), `urn:ironauth:acr:mfa` (a password
  plus a verified second factor: a TOTP code or a one-time recovery code), `phr`
  (a phishing-resistant passkey), `phrh` (a phishing-resistant, hardware-protected
  passkey). The order is per-tenant configurable (`oidc.acr_order`), so an RS should
  compare by the tenant's configured rank, not by string equality alone.
- `auth_time` — the epoch-seconds instant the authentication occurred. Present when
  the token's issuance required it (a `max_age` request, a client registered
  `require_auth_time`, or a step-up max-age policy). An RS that enforces a maximum
  authentication age needs this claim; if it is absent, treat the token as not
  meeting any max-age requirement and challenge.

`amr` is an ID-token claim (the concrete factors used); an RS keys its decision on
`acr` + `auth_time`.

## The RS decision

For a protected operation that requires a floor (an `acr` and/or a max
authentication age):

1. Verify the access token (signature, `iss`, `aud`, `exp`) as usual.
2. Read `acr` and `auth_time`.
3. Accept when `acr` satisfies the required floor (same value, or ranks at least as
   strong) AND `now - auth_time <= max_age`.
4. Otherwise return `401` with a `WWW-Authenticate: Bearer` challenge naming
   `error="insufficient_user_authentication"` and the `acr_values` / `max_age` the
   client must reach.

## The wire

### 1. The RS challenge (RFC 9470 section 3)

A request whose token is authenticated at only `urn:ironauth:acr:pwd` against an
operation that requires `urn:ironauth:acr:mfa` within 5 minutes:

```http
GET /payments HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOi...   # acr = urn:ironauth:acr:pwd
```

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_user_authentication",
  error_description="a higher authentication context is required",
  acr_values="urn:ironauth:acr:mfa", max_age=300
```

The `acr_values` and `max_age` are the values the client passes on the retry
authorization request.

### 2. The retry authorization request

The client re-authorizes, carrying the challenged parameters (RFC 9470 section 4):

```
GET /authorize?response_type=code
  &client_id=cli_...
  &redirect_uri=https%3A%2F%2Fclient.example%2Fcb
  &scope=openid%20payments
  &acr_values=urn%3Aironauth%3Aacr%3Amfa
  &max_age=300
  &code_challenge=...&code_challenge_method=S256
```

Because the current session is below the requested `acr` (or older than `max_age`),
the AS does NOT silently reuse it. It runs the required authentication: a second-
factor challenge (`/login/mfa`) when the user has a qualifying factor and the floor
is at the multi-factor level, or a full re-login for a lapsed age window or a
phishing-resistant floor. When the user has no qualifying factor, the AS surfaces an
enrollment prompt where tenant policy allows, or fails with
`unmet_authentication_requirements` (delivered through the negotiated response mode)
when the requirement can never be met.

### 3. The stepped-up token

After the real second factor completes, the AS issues tokens whose `acr` and
`auth_time` reflect it:

```json
{
  "acr": "urn:ironauth:acr:mfa",
  "amr": ["pwd", "otp", "mfa"],
  "auth_time": 1700000123
}
```

The `auth_time` is FRESH — the instant the step-up completed — never the stale
session's original `auth_time`, and the `amr` records the concrete factors actually
used. The RS re-evaluates the same operation against the new token and accepts.

## Declarative policy on the AS side

Beyond the request `acr_values` / `max_age`, the AS enforces two declarative policy
surfaces so step-up is a platform capability, not a per-app convention:

- per-CLIENT floor: `clients.step_up_acr` / `clients.step_up_max_age_secs`, applied
  to every authorization the client makes;
- per-SCOPE policy: the `scope_step_up_policies` table maps an OAuth scope token to
  an `(acr floor, max auth age)` requirement — for example scope `payments:write`
  requires `urn:ironauth:acr:mfa` within 300 seconds.

These are folded together with the request parameters (the strongest `acr` floor and
the smallest age window win) and evaluated at THREE points: at authorization, at
token issuance, and on refresh. A refresh that would mint an access token for a
scope whose auth-age window has LAPSED triggers the step-up requirement rather than
silently succeeding with a stale `acr`/`auth_time`; the token endpoint returns
`400` with `error="insufficient_user_authentication"` and the `acr_values` /
`max_age` the client re-authorizes with.

## A sample resource server

A minimal, exercised sample RS lives in `crates/ironauth-oidc/tests/step_up.rs`
(the `sample_rs` module): it reads an access token's `acr`, compares it to the
required floor under the ladder order, and returns the exact `WWW-Authenticate`
challenge above when insufficient. The `the_sample_resource_server_challenges_then_accepts_a_stepped_up_token`
test drives the full round trip: challenge, re-authorization, real TOTP step-up, and
acceptance of the stepped-up token. A standalone runnable version (a tiny
hyper/tokio server) is in `crates/ironauth-oidc/examples/step_up_resource_server.rs`.

## Out of scope

Client-side SDK middleware (a drop-in RS helper that emits the challenge and retries)
is planned for a later milestone; this delivers the server side, the documented
contract, and the sample RS.
