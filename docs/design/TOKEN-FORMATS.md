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
| opaque | A random reference token with the `ira_at_` prefix | ONLY by an authenticated store lookup (introspection, RFC 7662, issue #22). There is no offline validation. | A resource server (or environment) that opts into digest-only tokens |

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

Every opaque credential is `<prefix><body>`, where:

- the prefix namespaces the product (`ira`, IronAuth) and the credential class,
  and is scannable (a fixed, greppable literal);
- the body is the URL-safe, unpadded Base64 of at least 256 bits of entropy drawn
  from the ironauth-env entropy seam (never a raw OS RNG), so the token cannot be
  guessed or enumerated;
- ONLY a SHA-256 digest of the whole token is ever stored. The plaintext token is
  returned to the client once and never persisted, so a database dump contains no
  material that can be replayed as a valid token.

| Prefix | Credential class | Body | Status |
| --- | --- | --- | --- |
| `ira_at_` | Opaque ACCESS token | 32 random bytes (256 bits), Base64url no-pad (43 chars) | Shipped (issue #29) |
| `ira_rt_` | Opaque REFRESH token | 32 random bytes (256 bits), Base64url no-pad (43 chars) | RESERVED for issue #21 (not yet issued) |

The `ira_rt_` prefix is reserved here for consistency so that the refresh-token
work (issue #21) adopts the same scheme; refresh-token storage and rotation are
NOT implemented in issue #29.

## Detection regexes (for secret-scanner registration)

Register these anchored regexes with your secret scanner so a leaked IronAuth
token is caught in source, logs, and history:

```
# Opaque access token (ira_at_)
ira_at_[A-Za-z0-9_-]{43}

# Opaque refresh token (ira_rt_, reserved for issue #21)
ira_rt_[A-Za-z0-9_-]{43}

# Both classes in one pattern
ira_(at|rt)_[A-Za-z0-9_-]{43}
```

The body is exactly 43 characters: 32 bytes encoded as URL-safe Base64 without
padding is `ceil(32 * 4 / 3) - 1 = 43` characters, drawn from the alphabet
`[A-Za-z0-9_-]`. A scanner may anchor the match with a word boundary on either
side; the prefix alone (`ira_at_` / `ira_rt_`) is already a high-signal literal.

## Why digest-only storage is safe under a database dump

The `opaque_access_tokens` table stores `token_digest` (SHA-256 hex) and the
token's metadata (subject, client, audience, scope, `jti`, expiry, grant), never
the token itself. Verification hashes the PRESENTED token and matches it against
`token_digest`. So an attacker who exfiltrates the table cannot present any stored
value as a token: the digest is one-way (hashing the stored digest, or any other
stored column, does not reproduce the token), and the only value that resolves is
the original high-entropy plaintext, which was never stored.
