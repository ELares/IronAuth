# OID4VC (DESIGN NOTE)

**Status:** design note only. No prototype ships.
**Pinned revision:** OID4VCI / OID4VP as published, with HAIP conformance targeted (HAIP 1.1 planned for December 2026 — the profile-version-sensitive code is isolated because of it).
**Feature flag:** none (no prototype).
**Trigger condition:** a regulated-sector demand signal — the eIDAS 2.0 December 2026 member-state deadline passing with a concrete wallet-integration request, or an EUDI-login-style engagement (Keycloak's EUDI-login request is its second most-reacted open issue).
**Graduation criteria:** an OID4VCI issuer (SD-JWT VC, pre-authorized code and authorization code flows, issuer metadata) followed by an OID4VP verifier ("log in with EUDI wallet" via DCQL and direct_post), both targeting HAIP conformance.

## The bet

- The wallet ecosystem consolidated on OID4VP + the browser Digital Credentials API (SIOPv2 refused).
- HAIP centers on ES256 — already in the algorithm matrix — so the crypto surface is a config stance, not a new stack.
- SD-JWT VC is the credential format the EUDI ecosystem actually uses; the jose crate's JWT assembly is the seam it slots into.

## What must NOT happen

- OID4VP before OID4VCI (a verifier with no issuer ecosystem is a demo).
- Base-spec-only conformance: HAIP conformance is the acceptance bar.
