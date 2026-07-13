# Security Policy

IronAuth is pre-1.0 and under active foundational development; no production
deployment should exist yet. Until a stable 1.0, the latest release is the
only supported version. This policy describes how to report a suspected
vulnerability privately and what you can expect from us.

## Reporting a vulnerability

Please report suspected security issues privately. Do not open a public issue
for a vulnerability.

- Preferred: GitHub private vulnerability reporting on this repository (the
  "Report a vulnerability" button under the Security tab). This channel is
  monitored by the maintainer.
- A dedicated security inbox will be published here once project
  infrastructure exists; until then the GitHub channel is authoritative.

## What to expect (response targets)

- Acknowledgement within 3 business days.
- Initial assessment (accepted, declined, or needs more information) within
  7 business days.
- Coordinated disclosure: we ask for up to 90 days to ship a fix; we will
  agree on a timeline with you and credit you in the advisory if you wish.
  If a fix ships sooner, disclosure moves up accordingly, never later without
  your agreement.

## Safe harbor

We will not pursue or support legal action against good-faith security
research on IronAuth. Good faith means: testing against your own deployment
(not someone else's data), no service degradation of infrastructure you do
not own, no exfiltration beyond the minimum proof needed, and private
reporting per this policy. This commitment reflects the published
[covenants](COVENANTS.md), including no two-tier security patching: fixes
ship to everyone simultaneously.

## Advisories

Every advisory follows the format defined in
[docs/RELEASING.md](docs/RELEASING.md): it names the exact artifact, the
affected version range, the first patched version, and a severity with a
plain-language impact statement. Every release carries severity-rated
security notes, even when the list is empty (an explicit "no security-
relevant changes" line), so silence is never ambiguous.

## Scope

The per-surface threat model lives in
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) and is updated in the same pull
request that ships any new surface. Deliberately rejected features and
algorithms are documented with reasons in
[docs/WILL-NOT-IMPLEMENT.md](docs/WILL-NOT-IMPLEMENT.md).
