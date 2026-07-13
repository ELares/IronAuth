# The IronAuth Covenants

These commitments are made once, publicly, at the start of the project, and
they do not move. They exist because every one of them is the documented
failure mode of a named competitor, and because a security product that
cannot be trusted on its business terms cannot be trusted at all. If a future
version of this project violates any covenant on this page, treat that as a
breaking change of the project itself.

## The three inviolable lines

1. **No paywalled security.** MFA, breached-password checks, SSO connections,
   audit logs, account lockout, and multi-tenancy are never gated behind
   licenses, editions, or plans, including when self-hosted. Any commercial
   line is drawn at hosting, scale operations, SLAs, and compliance packs,
   never at security features.

2. **No mandatory first-party infrastructure.** IronAuth runs complete on
   PostgreSQL alone, forever. IronCache and IronBus are strictly optional
   accelerators behind documented interfaces with safe defaults; they are
   never prerequisites, and CI verifies both modes.

3. **No unexportable data.** Every piece of tenant data is exportable through
   documented, self-serve interfaces, including password hashes and MFA
   enrollments. Leaving IronAuth must never require a support ticket.

## Supporting commitments

- **No two-tier security patching.** Security fixes ship to everyone at the
  same time. There is no tier that receives interim security patches while
  others wait for a quarterly release.

- **No per-unit pricing traps.** No metering of enterprise connections,
  machine-to-machine tokens, satellite domains, dashboard seats, or
  environments. No free-tier clawbacks and no retroactive monetization of
  previously free capabilities.

- **No roadmap capture.** Upvoted issues are never auto-closed as stale, and
  "contact sales to prioritize" is never the only path onto the roadmap.

- **No mid-flight relicensing.** The license is OSI-approved (MIT or
  Apache-2.0, at your option) and stays that way. The commercial line below
  is stated now precisely so that a future relicensing cannot be justified as
  "clarifying" it.

## The commercial line, stated up front

If a commercial offering ever exists, it may charge for: managed hosting,
operating the platform at scale on your behalf, support contracts and SLAs,
and compliance evidence packs. It may not charge for anything the three
inviolable lines or the supporting commitments cover. This sentence is here
so the covenant is falsifiable: if a paid feature ever appears that is not on
this list, the covenant is broken, and the community should say so.
