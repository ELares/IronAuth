# Multi-Region Replication on the Event Backbone (issue #155, EXPLORATORY)

Status: **design note** - pinned assumptions recorded before code hardens, per the
issue's own requirement. Nothing on this page is built. The `multi-region-replication`
feature is registered in the experimental ack gate (`features.rs`) and is deliberately
inert: enabling the flag today acknowledges this design note and changes nothing.

## Why this mechanism and not the incumbents'

Keycloak's multi-site guidance requires sub-10ms RTT between sites - effectively
multi-AZ, not multi-region - because its Infinispan coupling is synchronous. The
hyperscaler offerings sidestep the hard part by pinning identity data to one geography.
Cognito's June 2026 capability and Auth0's private-cloud offering set the bar this
issue targets: users, credentials, and configuration replicate across regions with
**zero forced re-authentication on failover**.

IronAuth's architecture already points at a different mechanism: the transactional
outbox produces an **ordered event stream** (every mutation is a row, every row is a
stream event, transactions and audit are one). Replicating that stream asynchronously
gives an explicit, tunable **RPO** instead of a hidden RTT ceiling - the lag bound is a
number the operator chooses and the system reports, not a physics constraint.

## The pinned assumptions

These are the assumptions the exploratory phase proceeds under. A change to any of them
bumps `MULTI_REGION_REPLICATION_VERSION` and invalidates existing acks.

1. **Single writer region per environment.** An environment's authoritative writes
   happen only in its pinned region (the per-environment pin overrides the tenant
   `home_region` when they differ); tenant-level metadata writes happen only in the
   tenant home region. Multi-writer/active-active is explicitly out of scope.
2. **Cross-region flows are asynchronous only.** No synchronous cross-region database
   call may exist on any request path. This is enforced structurally, not by
   convention: the request-path crates never construct a database connection (the
   `no-request-path-connections` lint in the gate pins that - the request path receives
   its `Store` from boot wiring, so a connection constructed in request code would be a
   new database target chosen by the request, which is the seam a synchronous
   cross-region call would have to come through).
3. **The replicated stream is the outbox's ordered event stream.** Followers apply
   events to build a complete replica of users, credentials, session-relevant state, and
   configuration for pinned tenants. The stream's ordering contract is the outbox's own;
   replication adds a carrier, never a reordering.
4. **Transport is Postgres-only first; IronBus is an optional carrier.** Replication
   must work by shipping outbox rows between regional databases. The IronBus backbone
   lowers lag when present and is never a prerequisite.
5. **Failover is operator-initiated.** A documented promotion of a follower region to
   home, targeting the Cognito bar: users, credentials, and configuration present,
   existing sessions and refresh tokens usable, zero forced re-authentication within the
   documented RPO window. Automatic failover is out of scope.
6. **Region-scoped uniqueness is preserved by the single-writer rule.** During and
   after failover, the promoted region becomes the single writer for the environment, so
   the uniqueness invariants hold by construction; the promotion procedure must drain
   the lag window before writes resume.

## What the acceptance criteria will verify (when built)

- **RPO as a first-class metric**: replication lag exported per tenant in the metric
  contract, with configurable alerting thresholds.
- **The failover demo**: a scripted, repeatable promotion that preserves logins - an
  existing session and a refresh token from before failover both work after promotion,
  with the achieved RPO documented from the run.
- **Catch-up**: users, credentials, and config created in the home region are queryable
  in the follower within the configured lag bound.
- **Dual-transport correctness**: both the Postgres-only and the IronBus-carried runs
  pass the same correctness suite; per-carrier lag is measured under netem-injected
  inter-region latency and published as CI artifacts (informational, no relative
  threshold - whether IronBus lowers lag on real hardware is a graduation-assessment
  question, not a CI gate).
- **The architectural lint** (already landed): `scripts/no-request-path-connections.sh`,
  in the gate, pins that no request-path crate constructs a connection.

## What can be lost

Inside the RPO window, in-flight state is lossy by design: events still in the lag
window when failover happens are not applied to the follower. The promotion procedure
must state the window explicitly and account for the events it covers. The single
writer region means the window contains only home-region writes, never conflicting
writes from two regions.

## Graduation trigger

The exploratory phase graduates when: the replication machinery passes the dual-transport
correctness suite, the failover demo runs end to end with a documented RPO, and the
per-tenant lag metric is exported. Graduation is a separate issue; this note records the
assumptions that issue will test.