<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# Where these fixtures came from

Read this before trusting a passing run.

These request bodies are **derived from published specifications and vendor
documentation**, not captured from a live Okta or Entra tenant. That distinction
decides what a green suite means:

- It means the parsers accept the shapes the specs and the vendor docs describe,
  and reject the malformed variants beside them.
- It does **not** mean the parsers accept what Okta and Entra actually send.

Those differ. Every provisioning connector has undocumented habits, and the whole
reason issue #135 asks for *recorded* traffic is that a fixture the implementer
writes proves the parser agrees with the implementer.

So this suite is the harness plus a spec-derived corpus. Replacing a fixture with
a real capture is a drop-in change: the files are request bodies and paths, with
no test code to touch. When that happens, change the `source` field in the
fixture and delete the corresponding caveat from the issue.

| Fixture | source |
|---|---|
| `okta_*.json` | Okta SCIM 2.0 connector documentation and RFC 7644 examples |
| `entra_*.json` | Microsoft Entra provisioning documentation and RFC 7644 examples |

RFC 7644 examples are normative for shape and are the strongest thing here; the
vendor-documented shapes are the ones a real capture would most likely contradict.
