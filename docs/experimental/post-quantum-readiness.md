# Post-quantum readiness (DESIGN NOTE)

**Status:** design note only. No prototype ships.
**Pinned revision:** RFC 9964 (ML-DSA for JOSE and COSE, May 2026); FIPS 204 (final).
**Feature flag:** none (no prototype).
**Trigger condition:** ecosystem verifier support for ML-DSA JOSE broadens to the point where a tenant can actually consume an ML-DSA-issued token - OR the JOSE hybrid composite (`draft-ietf-jose-pq-composite-sigs`) reaches a stable revision and a KMS partner carries it.
**Graduation criteria:** an ML-DSA-44 signer behind the experimental ack gate, signed under a pinned RFC 9964 revision, passing the workspace's JOSE test-vector battery; then ecosystem evidence (two independent verifiers consuming the tokens) before anything leaves experimental.

## The bet

- **Priority ordering:** JWE key agreement and long-lived trust material over access-token signing. Access tokens are short-lived and rotating; trust anchors are what outlive a Shor-capable adversary.
- **The seam:** the key store stays fully polymorphic over alg/kid/key-type so RFC 9964's AKP kty (seed-only private keys) slots in as just another signer. The external-signer seam (issue #161) already keeps the backend abstract; the AKP kty is a key-shape, not a backend, and the jose crate's key material enum is the single widening point.
- **The hedge:** JOSE hybrid composites (ML-DSA plus Ed25519) tracked as the likely transition shape; nothing ships until both halves of the hybrid are verifiable in the ecosystem.
- **Cost today:** roughly 5 KB tokens break cookie limits - the constraint that makes signing readiness, not shipping, the right stance.

## What must NOT happen

- ML-DSA as a default posture: token size + verifier thinness make it a regression for everyone until the ecosystem moves.
