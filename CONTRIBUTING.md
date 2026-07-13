# Contributing to IronAuth

Thank you for contributing. IronAuth is pre-1.0 and moving fast along a
public plan (16 milestones in the issue tracker); the fastest way to help is
to pick an open issue in the current milestone and say so on the issue.

## Ground rules

- **One issue per PR.** Reference it with "Closes #N". PRs that drift beyond
  their issue get split.
- **Green gate before review.** Run `scripts/gate.sh` locally; it runs the
  same fmt, clippy pedantic, test, invariant-lint, dash-scan, and
  compatibility checks CI enforces.
- **Prose rule.** No em dashes and no en dashes anywhere in repo text
  (code, comments, docs, commit messages). CI enforces this.
- **Determinism seam.** All time and randomness flows through
  `crates/ironauth-env`. The invariant lints will fail your PR otherwise;
  if you believe you need a raw source, the escape marker requires a written
  reason on the same line.
- **Changelogs.** User-visible changes update the owning artifact's
  `CHANGELOG.md` (Unreleased section) in the same PR.

## The threat-model rule (mandatory)

Every PR that ships a **new surface** (a network-facing endpoint family, a
new parser over untrusted input, or a new privileged plane) must extend
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) with that surface's STRIDE
section **in the same PR**. Reviewers block merges that add a surface without
its threat-model section. If you are unsure whether your change is a new
surface, ask on the issue before opening the PR.

## Security

Never open a public issue for a suspected vulnerability; see
[SECURITY.md](SECURITY.md) for private reporting and the safe-harbor
commitment.

## Licensing

Dual-licensed MIT or Apache-2.0. Unless you explicitly state otherwise, any
contribution intentionally submitted for inclusion is dual-licensed as
described in [LICENSE](LICENSE), without any additional terms.
