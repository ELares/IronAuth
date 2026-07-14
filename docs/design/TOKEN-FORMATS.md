<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Access-token formats and the scannable token-prefix scheme (issue #29)

IronAuth mints access tokens in one of two formats, chosen per resource server
(and defaulted per environment). This document records the two formats, the
scannable prefix scheme every opaque credential carries, and the detection
regexes to register with a secret scanner (for example GitHub secret scanning,
`gitleaks`, or `trufflehog`).

## The two access-token formats

| Format | Wire shape | Verification | When |
| --- | --- | --- | --- |
| `at+jwt` (RFC 9068) | A signed compact JWS with header `typ = at+jwt` | Offline, against the environment JWKS, plus the store for revocation | The default; the OIDC / `UserInfo` case |
| opaque | A scope-declaring reference token with the `ira_at_` prefix | ONLY by a store lookup (the `UserInfo` consumer, and introspection, RFC 7662, issue #22). There is no offline validation. | A resource server (or environment) that opts into digest-only tokens |

The format is selected by the resolved resource server: a token exchange that
targets a registered `resource_servers.audience` uses that resource server's
`token_format`; otherwise the environment default (`oidc.default_access_token_format`,
default `at_jwt`) applies. The RFC 8707 `resource` request-parameter wiring that
feeds the audience from the token request is issue #28.

### RFC 9068 `at+jwt` claims

An `at+jwt` carries the RFC 9068 section 2.2 claims: `iss`, `exp`, `aud`, `sub`,
`client_id`, `iat`, `jti`, and `scope` (when a scope was granted). Because the
token results from a user-authentication (code) flow it also carries `acr` and,
when the authentication instant was frozen onto the code as due, `auth_time`.
Its `aud` is the client id when no resource server is targeted (so `UserInfo`'s
`aud == client` check keeps working) or the resource server's audience when one
is. No PII beyond these protocol claims is placed in the payload; scope-derived
claims stay at `UserInfo`.

## The opaque-token prefix scheme

Every opaque credential is `<prefix><handle><delimiter><secret>`, where:

- the prefix namespaces the product (`ira`, IronAuth) and the credential class,
  and is scannable (a fixed, greppable literal);
- the handle is the token's own `jti`, a `tok_` typed scoped identifier that embeds
  the token's `(tenant, environment)`. It SELF-DECLARES the token's scope, so a
  GLOBAL consumer (the `UserInfo` endpoint, and the RFC 7662 introspection endpoint)
  can recover the scope and run the scope-bound, row-level-security store resolve,
  exactly as an `at+jwt`'s `jti` carries its scope. The handle is a NON-secret id
  (it is also the stored `jti` and the introspection handle), so it is never the
  thing that authenticates the token;
- the delimiter is `~`, a valid RFC 7235 Bearer `token68` character that appears in
  neither the Base64url alphabet nor a scoped-identifier's wire form (and is not
  `.`, so an opaque token still carries no dots and can never be mistaken for a
  compact JWS), so the split between handle and secret is unambiguous;
- the secret is the URL-safe, unpadded Base64 of 256 bits of entropy drawn from the
  ironauth-env entropy seam (never a raw OS RNG), so the token cannot be guessed or
  enumerated even by a party that knows the (non-secret) handle;
- ONLY a SHA-256 digest of the WHOLE token (handle, delimiter, and secret) is ever
  stored. The plaintext token is returned to the client once and never persisted, so
  a database dump contains no material that can be replayed as a valid token: the
  stored handle reveals the scope but not the secret.

| Prefix | Credential class | Handle | Secret | Status |
| --- | --- | --- | --- | --- |
| `ira_at_` | Opaque ACCESS token | `tok_` scoped `jti` (48 bytes, Base64url no-pad, 64 chars) | 32 random bytes (256 bits), Base64url no-pad (43 chars) | Shipped (issue #29) |
| `ira_rt_` | Opaque REFRESH token | (adopts the same scheme) | 32 random bytes (256 bits), Base64url no-pad (43 chars) | RESERVED for issue #21 (not yet issued) |

The `ira_rt_` prefix is reserved here for consistency so that the refresh-token
work (issue #21) adopts the same scope-declaring scheme; refresh-token storage and
rotation are NOT implemented in issue #29.

## Detection regexes (for secret-scanner registration)

Register these anchored regexes with your secret scanner so a leaked IronAuth
token is caught in source, logs, and history:

```
# Opaque access token (ira_at_): prefix, tok_ scoped-jti handle, ~, 256-bit secret
ira_at_tok_[A-Za-z0-9_-]{64}~[A-Za-z0-9_-]{43}

# Opaque refresh token (ira_rt_, reserved for issue #21; same scheme)
ira_rt_tok_[A-Za-z0-9_-]{64}~[A-Za-z0-9_-]{43}

# Both classes in one pattern
ira_(at|rt)_tok_[A-Za-z0-9_-]{64}~[A-Za-z0-9_-]{43}

# High-signal prefix-only match (catches any future body shape)
ira_(at|rt)_[A-Za-z0-9_~-]+
```

The handle is exactly 64 characters (a `tok_` scoped identifier's 48-byte payload
encoded as URL-safe Base64 without padding, `ceil(48 * 4 / 3) = 64`) and the secret
is exactly 43 characters (32 bytes, `ceil(32 * 4 / 3) - 1 = 43`), both drawn from
the alphabet `[A-Za-z0-9_-]` and separated by `~`. A scanner may anchor the match
with a word boundary on either side; the prefix alone (`ira_at_` / `ira_rt_`) is
already a high-signal literal, so the last pattern above catches a leaked token
regardless of the exact body shape.

## Why digest-only storage is safe under a database dump

The `opaque_access_tokens` table stores `token_digest` (SHA-256 hex) and the
token's metadata (subject, client, audience, scope, `jti`, expiry, grant), never
the token itself. Verification hashes the PRESENTED token and matches it against
`token_digest`. So an attacker who exfiltrates the table cannot present any stored
value as a token: the digest is one-way (hashing the stored digest, or any other
stored column, does not reproduce the token), and the only value that resolves is
the original high-entropy plaintext, which was never stored.

The stored `jti` equals the token's routing HANDLE, which is deliberately NOT a
secret: it declares the token's scope for routing, exactly as a scoped identifier
does everywhere else in IronAuth. Knowing the handle does not help an attacker,
because it is only the first segment of the token; the 256-bit secret segment after
the `~` is never stored, so the whole-token digest cannot be reproduced from the
handle (or any other stored column) alone.
