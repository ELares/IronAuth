<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
## Summary

Closes #

## Checklist

- [ ] `scripts/gate.sh` is green locally.
- [ ] The owning artifact's `CHANGELOG.md` (Unreleased) is updated for user-visible changes.
- [ ] **Threat model rule**: this PR ships no new surface (network-facing endpoint family, parser over untrusted input, or privileged plane), OR `docs/THREAT-MODEL.md` gains that surface's STRIDE section in this PR. See CONTRIBUTING.md.
- [ ] No em dashes or en dashes anywhere in the diff (CI enforces).
