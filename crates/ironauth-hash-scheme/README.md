<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# ironauth-hash-scheme

Algorithm-tagged verification of **foreign** password hashes.

This is the one layer of an identity-provider migration that is useful to somebody who is
not running IronAuth. If you are importing users out of another system, you have a column
full of strings in half a dozen formats and you need to answer one question per row: does
this password match. That is all this crate does.

It depends on **no** `ironauth-*` crate, and that is deliberate rather than incidental.

## Supported schemes

| Scheme | Encodings |
| --- | --- |
| bcrypt | `$2a$`, `$2b$`, `$2x$`, `$2y$` |
| Argon2 | `$argon2i$`, `$argon2d$`, `$argon2id$` |
| scrypt | `$scrypt$` (PHC string) |
| PBKDF2 | `$pbkdf2-sha256$`, `$pbkdf2-sha512$` (PHC string) |
| Firebase | modified scrypt, with the project's base64 signer key and salt separator |
| SHA-crypt | `$5$` (SHA-256), `$6$` (SHA-512), with the optional `rounds=` |
| LDAP / RFC 2307 | `{SHA}`, `{SSHA}`, `{SHA256}`, `{SSHA256}`, `{SHA512}`, `{SSHA512}` |

The LDAP digests carry no cost parameter at all, and that is the reason
`Scheme::rehash_is_urgent` exists. They are one unsalted or lightly salted digest pass,
so there is nothing to bound and nothing an import check can do to make a stolen row
expensive to attack; the only fix is to stop storing them, which means rehashing on the
first successful login rather than eventually. The MD5 LDAP schemes (`{MD5}`, `{SMD5}`)
are deliberately NOT recognized.

The four bcrypt variants are listed separately because they are not interchangeable
prefixes: `$2x$` exists to reproduce a bug in a specific PHP implementation, and treating it
as `$2b$` silently fails to verify passwords that were valid in the source system.

## Cost bounds

Every scheme carries bounds on its cost parameters, checked at parse time. A record whose
cost is outside them is rejected with a typed per-record error rather than accepted and
verified later.

This matters more on import than anywhere else. A cost parameter is an attacker-controlled
integer when it arrives in an import file, and a bcrypt cost of 31 or an Argon2 memory
parameter of several gigabytes is a denial of service against the importing server, not a
strong password hash. The bounds are the reason an import of untrusted data cannot be turned
into a resource-exhaustion attack by editing one column.

## Usage

```rust
use ironauth_hash_scheme::{ForeignHash, HashError, Scheme};

// Parsing is where the cost bounds are enforced, so an out-of-bounds record is refused
// before anything expensive happens with it.
let hash = ForeignHash::parse("$2b$12$K3JNi5Aw17Xa9x6nHtDlKuLGrLmjbJmn0BEjKcOJ1jRfLIhs3xLtC")?;
assert_eq!(hash.scheme(), Scheme::Bcrypt);
assert_eq!(hash.tag(), "bcrypt");

// Verification dispatches on the recognized scheme and FAILS CLOSED: a wrong password and
// a corrupt stored value both answer false, and neither panics.
assert!(!hash.verify(b"not the password"));

// An out-of-bounds cost is a typed error, not a slow verification later.
assert!(matches!(
    ForeignHash::parse("$2b$99$K3JNi5Aw17Xa9x6nHtDlKuLGrLmjbJmn0BEjKcOJ1jRfLIhs3xLtC"),
    Err(HashError::OutOfBounds(_))
));
# Ok::<(), HashError>(())
```

Whether a verified hash should be REPLACED with your own scheme is deliberately not decided
here. This crate answers "does this match", and the rehash policy belongs to whatever owns
your password policy, because it depends on parameters this crate has no view of.

## Why it is a separate crate

Two reasons, and the second is the one that constrains its contents.

It is independently useful: verifying a foreign hash has nothing to do with issuing tokens,
and somebody migrating between two other providers can use this without adopting anything
else.

And it is the only part of the import path that **can** be published on its own. Everything
else in the import pipeline reaches into the store, the envelope substrate, or the audit
log. Adding an `ironauth-*` dependency here would revoke that quietly, so
`the_crate_depends_on_no_ironauth_crate` asserts the absence rather than leaving it to a
comment.

## Licence

MIT OR Apache-2.0.
