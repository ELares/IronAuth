# OpenID Federation 1.1 (DESIGN NOTE)

**Status:** design note only. No prototype ships.
**Pinned revision:** OpenID Federation 1.1 Final (May 2026) — the corrected final text, not the 2024 drafts.
**Feature flag:** none (no prototype).
**Trigger condition:** a concrete ecosystem engagement — a federation operator (the Italy SPID/CIE class, or a comparable national-scale program) naming IronAuth as a participant or relying party. 3-6 engineer-months budget, milestone-class.
**Graduation criteria:** leaf entity + automatic client registration shipping behind the experimental ack gate: entity statements at `/.well-known/openid-federation`, trust-chain resolution, metadata policy merge — all pinned to the 1.1 Final text, with the conformance suite's federation tests green.

## The bet

- 1.1 Final runs at national scale (10,000+ RPs in the Italian context); no OSS Rust participant.
- The cheapest hedge regardless of the trigger: keep entity metadata and trust config modular in the existing discovery/client-registration surfaces so the federation layer is an addition, not a rework.
- The registration story is the actual product: a federation participant registers through the trust chain, so the entity statement + metadata policy merge IS the DCR flow's federation arm.

## What must NOT happen

- Trust-anchor and intermediate tooling before a leaf entity exists.
- Budget before a concrete engagement (the trigger discipline is the issue's whole point).
