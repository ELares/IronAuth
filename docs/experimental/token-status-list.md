# Token status list (DESIGN NOTE)

**Status:** design note only (a watch item, not one of the five bets).
**Pinned revision:** `draft-ietf-oauth-status-list` (tracked; Janssen's Cedarling already consumes it).
**Feature flag:** none (no prototype).
**Trigger condition:** the draft reaches RFC, OR two independent ecosystem consumers are live.
**Graduation criteria:** status-list publication over the token store with NO schema change (the design constraint), behind the experimental ack gate.

## The bet

- A status list is a compact signed artifact encoding token statuses (revoked, suspended, etc.) for offline-ish validation — the revocation surface's scalable arm.
- The design constraint that makes it cheap: the token store already records revocation state per token; a status-list publication reads that state and composes the signed list. The store's revocation rows are the single source; publication is a projection.
- The jose crate's JWT assembly + the signing policy govern the list's signature exactly as they govern a token's.

## What must NOT happen

- A schema change to enable it (the constraint IS the bet: the store already holds the state).
