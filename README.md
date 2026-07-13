# IronAuth

A modern, standards-first OpenID Connect identity platform. Multi-tenant,
multi-environment, EdDSA-first. One repository holds everything: the provider
server (Rust), management APIs, SDKs, the admin SPA, hosted auth pages, and
background workers.

**Status: pre-1.0, foundations (milestone M1) in progress.** Nothing here is
ready to run in production yet. The complete plan is public: [16 milestones
and 164 issues](https://github.com/ELares/IronAuth/milestones), from the
certifiable OIDC core through multi-environment config promotion, passkeys,
organizations, SCIM, and agent-native OAuth.

## What IronAuth is building toward

- A certified OpenID Connect provider built against the final 2025-2026 spec
  wave (OAuth 2.1 posture, FAPI 2.0, Shared Signals) with the conformance
  suite wired into CI as a merge gate.
- First-class tenants, isolated environments per tenant (dev, staging, prod),
  and server-side config promotion with diff, plan, and apply.
- EdDSA (Ed25519) as the default token signing algorithm, with the full
  RS256/ES256/PS256 matrix supported and per-client negotiation so legacy
  relying parties are a config flip, never a migration.
- Single static binary on PostgreSQL. IronCache (Redis-compatible cache) and
  IronBus (durable message bus) are optional accelerators, never requirements.
- Secure by default: PKCE everywhere, exact redirect matching, one hardened
  and fuzzed JOSE verification path, tenant isolation enforced below the
  application layer.

## Principles

Three covenants, stated once and never moved: no paywalled security features,
no mandatory first-party infrastructure, no unexportable data. The full
covenant text, including the supporting commitments and the falsifiable
commercial line, is in [COVENANTS.md](COVENANTS.md). The threat model and the
"will not implement, and why" page land with the M1 security-program issue
and will be linked here.

## Repository layout

- `crates/`: the Rust workspace (server, workers, libraries). Each crate is a
  documented design seam; see the workspace `Cargo.toml`.
- `packages/`: TypeScript artifacts (SDKs, admin SPA, hosted pages); arrive
  with milestones M9 and M12.
- `docs/`: operating and contributing documentation, including
  [RELEASING.md](docs/RELEASING.md) and the generated
  [COMPATIBILITY.md](docs/COMPATIBILITY.md).
- `scripts/`: the local merge gate (`scripts/gate.sh`) and the structural
  checks CI enforces.
- `fuzz/`: the fuzzing harness (lands with the hardened JOSE core).

## Building

```
cargo build --workspace
scripts/gate.sh   # fmt, clippy pedantic, tests, invariants, supply-chain
```

The pinned toolchain is in `rust-toolchain.toml`; the MSRV is 1.85 and is
enforced in CI.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at
your option (see [LICENSE](LICENSE)), matching the sibling Iron projects.
The licensing commitments, including no mid-flight relicensing, are part of
[COVENANTS.md](COVENANTS.md).
