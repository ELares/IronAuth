<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Where these fixtures came from

Read this before trusting a passing run.

These assertion shapes are **derived from published specifications and vendor
documentation**, not captured from a live Okta or Entra tenant. That distinction
decides what a green suite means:

- It means the sign-in path accepts the NameID formats and attribute names the
  specs and the vendor docs describe, and maps them through per-connection
  configuration rather than through anything hardcoded.
- It does **not** mean the sign-in path accepts what Okta and Entra actually
  send.

Those differ, and SAML has more room to differ in than SCIM does: element
ordering, which of the Response and the Assertion is signed, whether a
`ds:KeyInfo` is present, namespace prefixes, and `AuthnStatement` contents all
vary by identity provider and by tenant configuration. Issue #139 asks for
*fixtures* precisely because a document the implementer writes proves the
verifier agrees with the implementer.

## What is fixture-shaped and what is not

The **signature is generated at test time**, over the fixture's own content, by
the connection's test key. It has to be: a static signature would be a signature
over bytes nobody can re-derive, and pinning a vendor's real certificate would
mean shipping a private key to match it. So these fixtures carry the parts a
vendor's document *shapes* -- the issuer, the NameID and its format, and the
attribute names -- and the harness supplies the envelope and the signature.

That is the boundary of the claim. A green run says the mapper and the JIT
provisioner handle the vendor's *attribute vocabulary*; it says nothing about
canonicalization against a vendor's real signed bytes. The signature side is
covered instead by `crates/ironauth-saml/tests/wrapping.rs`, which drives
signature wrapping, line-wrapped base64, embedded certificates, and the
algorithm allowlist directly.

Replacing a fixture with a real capture is a drop-in change: the files are data,
with no test code to touch. When that happens, change the `source` field in the
fixture and delete the corresponding caveat from the issue.

| Fixture | source |
|---|---|
| `okta_login.json` | Okta SAML app configuration reference; attribute names are Okta's default short names |
| `entra_login.json` | Microsoft Entra ID SAML token reference; attribute names are the `schemas.xmlsoap.org` / `schemas.microsoft.com` claim URIs Entra emits |
