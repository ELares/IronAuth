# The session tokenizer

IronAuth sessions are opaque and database-backed. That is the right default: a session can be
revoked and the revocation takes effect on the very next request, everywhere, with no window.

Some consumers cannot pay for a database lookup. A service mesh authorizing east-west traffic, a
third-party API that needs to know who is calling, an edge worker running before your origin: each
of these wants a token it can verify from a public key and nothing else.

The session tokenizer converts one into the other, on request, under configuration you control.

## What a template is

A **tokenizer template** is a named, per-environment object with four parts:

- an **audience**, which every token minted from it carries as `aud`;
- a **TTL**, in seconds, which is how long a minted token is valid;
- a **claims mapper**, the same ordered rule list a claims mapping uses, deciding which session
  attributes reach the token and under what names;
- its **own key set**, published at its own JWKS URL.

Write one through the management API:

```
PUT /v1/tenants/{tenant}/environments/{environment}/session-token-templates?name=orders

{
  "audience": "https://orders.example",
  "ttl_seconds": 60,
  "rules": [
    {"kind": "static", "name": "tier", "value": "gold"}
  ]
}
```

Everything the template says is validated **before it is stored**. A rule that names a protected
claim, a rule this version cannot read, a TTL outside the bounds, a missing audience: each is a
`400` naming what was wrong. A template that reaches the mint has already been checked, twice.

## Minting a token

The end user's own session cookie is the credential:

```
POST /t/{tenant}/e/{environment}/session/tokenize?tokenize_as=orders
Cookie: __Host-ironauth_session=...
```

```json
{
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6InNlc3Npb24rand0Iiwia2lkIjoic3RrXy4uLiJ9...",
  "token_type": "session+jwt",
  "audience": "https://orders.example",
  "expires_in": 60
}
```

There is no other way to mint one. The endpoint resolves the session through the same guard every
other authenticated surface uses, so a session that is expired, revoked, ended, or rotated away
does not resolve and no token is minted. An **impersonated** session is refused outright: a
tokenized JWT is a credential a third party accepts for its whole lifetime, and a support operator
should not be able to create one.

## Verifying a token

Fetch the template's own key set and verify against it. No IronAuth call, no database:

```
GET /t/{tenant}/e/{environment}/session-tokens/orders/jwks.json
```

The response carries `Cache-Control` and a strong `ETag`, so a verifier caches it and refetches on
a `kid` miss.

Verification requires three things and you should assert all three:

1. the signature, against a key from **that template's** JWKS;
2. `aud`, against the audience you expect;
3. `typ`, which is `session+jwt`.

The third is not decoration. An IronAuth access token (`at+jwt`) and a tokenized session JWT can
share an issuer, a subject, and an audience, and they authorize differently: an access token was
issued through an OAuth grant a user consented to, and this one was issued because a browser
session exists. A verifier that ignores `typ` lets one stand in for the other.

## The revocation window, stated plainly

**A tokenized session JWT is verified with no database call, so revoking the underlying session
cannot reach a token that has already been minted.** Revocation stops the *minting*, immediately
and with no window. A token already in a consumer's hands stays valid until it expires.

That means:

> **The revocation window is exactly the template's `ttl_seconds`.**

A template with `ttl_seconds: 60` has a sixty-second worst case between an operator ending a
session and the last token from it ceasing to verify. This is the whole trade, and it is why the
TTL is bounded rather than free:

| | seconds |
|---|---|
| Minimum TTL | 30 |
| Recommended range | 60 to 120 |
| Maximum TTL | 900 |

The recommended range is what most deployments should use. Below it you start fighting the clock
skew verifiers tolerate, and a token that is expired on arrival for some verifiers and not others
reads as an intermittent outage rather than as a setting. Above it you are lengthening the window
in which an ended session still authorizes something, which is the one property of this feature
you cannot get back by other means.

If a shorter window than 30 seconds matters more than the network saving, the right answer is not
this feature: check the session.

## What a token carries

The claims mapper runs against the **session's** attributes, not the user's profile:

| claim | what it is |
|---|---|
| `sub` | the authenticated subject |
| `sid` | a per-template, one-way reference to the session, never the session id |
| `auth_time` | when the subject authenticated |
| `amr` | the recorded authentication methods |

Two things about `sid` are worth stating outright. It is **not the session id**: the session id is
the cookie value, a bearer credential, and a token that travels to a third party must never carry
it. And it is keyed on the template, so two audiences holding tokens for the same session cannot
compare references and discover they are looking at the same person.

`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti` and `sid` are set by the mint. A mapping rule that
tries to write one is refused when the template is written.

## Key sets are per template, and separate on purpose

A template's keys live in their own table and are published only at that template's own JWKS URL.
They never appear in the environment's `jwks.json`, and an environment signing key never appears in
a template's.

This is what stops an ID token verifying against a tokenizer template's key, or the reverse. The
separation is structural rather than a filter someone has to remember: the identifiers use
different prefixes (`stk_` against `sik_`), and no query that reads one table can see the other.

Deleting a template deletes its keys. Its JWKS URL stops answering, and every consumer verifying
against it starts failing, which is the intended blast radius of removing a template that
something still depends on.
