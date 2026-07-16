# ironauth-quota changelog

All notable changes to the `ironauth-quota` crate. Format: keep a section per
released version, newest first; every release names the artifact and version
range per docs/RELEASING.md.

## Unreleased

- `PasswordHashing` quota dimension (issue #62): a fourth independently enforced
  dimension so the Argon2id hashing pool admits per tenant and per environment through
  the SAME fair-share engine (and its 429 block-signal contract) the request path uses,
  rather than a second fairness mechanism. `QuotaDimension::all()`/`as_str()`,
  `ScopeLimits`, and `ScopeLimits::from_config` all carry it; a scope's hashing-share
  bucket is disjoint from its request/token buckets, so a credential-stuffing storm that
  drains one tenant's hashing share never touches that tenant's other buckets nor
  another tenant.
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
  - A denial is attributed only to the bucket that actually lacked capacity: a
    spend rejected by the TENANT ceiling no longer increments the nested
    ENVIRONMENT bucket's denied counter (that bucket had room and denied nothing).
  - The denied `reset` header reports the time for the binding bucket to refill to
    full FROM ITS CURRENT (uncharged) level, not over-counted by the rejected
    cost; `Retry-After` still reports the time to accrue the requested cost.
  - Wired onto the data plane (NOT deferred): the OIDC provider constructs one
    `QuotaEnforcer` from the `[quota]` config and spends it on the `/authorize`
    request path, short-circuiting an over-quota `(tenant, environment)` with a
    `429` and the RateLimit headers plus block signal. See the `ironauth-oidc`
    changelog.
  - Idle-bucket reaper (defense in depth for the bounded map). A bucket untouched
    for `idle_bucket_ttl_secs` (configurable, default one hour; `0` disables) is
    evicted, driven by the same `ironauth-env` monotonic clock so it is
    deterministically testable. Reaping runs opportunistically on `admit` (amortized
    to at most one scan per window) and can be forced with `reap_idle_buckets`;
    `bucket_count` exposes the live count. Eviction is safe by construction (a
    re-created bucket starts full exactly as a never-seen scope would). This bounds
    memory under legitimate scope churn; the primary bound remains that only a
    verified, existing scope ever allocates a bucket.
  - Scope note: this crate is the process-local core. Still riding M15 on top of
    it: the per-IP/per-user/per-client layers, the IronCache-backed shared L2,
    per-scope metric export as labelled series, the usage-threshold webhook delivery
    surface (the events are produced here; there is no platform eventing surface yet
    to route them to), and the audited management-API surface for adjusting a
    tenant's quota at runtime.
