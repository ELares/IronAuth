# ironauth-quota changelog

All notable changes to the `ironauth-quota` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- Initial per-tenant and per-environment quota fairness core (issue #50): the
  operator-plane noisy-neighbor guard.
  - `QuotaEnforcer`: single-node, process-local nested token buckets over three
    independently enforced dimensions (`Requests`, `TokenIssuance`,
    `HookSeconds`). A per-tenant bucket bounds a tenant's aggregate; a
    per-environment bucket is nested under its tenant, so an environment spend
    draws from both and can never exceed its tenant's remaining share.
  - Fairness by per-scope isolated buckets: one tenant or environment exhausting
    its quota leaves every other scope's quota fully intact (they draw from
    disjoint buckets); proven by `noisy_tenant_does_not_starve_a_quiet_tenant`.
  - Fail-closed enforcement: an over-quota spend is denied and charges nothing
    (neither the environment nor the tenant bucket), so a rejected request never
    erodes the scope's own budget.
  - Deterministic refill: every bucket refill draws "now" from the
    `ironauth-env` monotonic clock, so window refresh is testable with
    `ManualClock`.
  - `RateLimitSnapshot` produces the structured `RateLimit` and
    `RateLimit-Policy` headers, the legacy `X-RateLimit-*` triplet, a
    `Retry-After`, and a machine-readable block signal (the `x-ratelimit-block`
    header and an optional `__Host-ira-rl-block` cookie) so an edge or WAF can
    offload continued blocking without parsing bodies.
  - `UsageEvent`: usage-threshold saturation events (default 80 and 100 percent
    per dimension) carrying the scope and dimension.
  - Runtime overrides (`set_tenant_override` / `set_environment_override`) take
    effect on the next spend without a restart; unlimited is expressible with a
    burst of 0.
  - `metrics()` exports per-scope, per-dimension admitted and denied counters for
    the metrics surface.
  - Scope note: this is the process-local core. The per-IP/per-user/per-client
    layers, the IronCache-backed shared L2, the request-path middleware wiring,
    and the audited management-API surface for adjusting quotas ride M15 on top
    of this crate.
