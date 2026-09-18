# The metric contract

Every series this build exports, with its type, its labels and what it means. GENERATED from
`metrics::CONTRACT` in `crates/ironauth-server/src/metrics.rs` by `scripts/metrics-doc.sh`,
which CI runs; a hand edit here fails that gate. Do not write this page, write the contract.

## What the contract promises

`crates/ironauth-server/tests/metric_contract.rs` checks the contract against the emit sites in
BOTH directions, which is what makes this page worth writing a dashboard against:

- a metric listed here and emitted nowhere fails the build, so a panel cannot render empty
  because the series it queries was quietly deleted; and
- a metric emitted and not listed here fails the build, so a series cannot appear on your
  scrape without having been reviewed.

The labels are checked the same way. A site that emits a label this page does not list, or
omits one it does, fails.

## Cardinality

NO METRIC HERE CARRIES A TENANT, CLIENT, USER OR ENVIRONMENT LABEL, and that is a deliberate
bound rather than an omission. Such a label multiplies every series it touches by the number of
distinct values a deployment has, which is unbounded from this repository's side: it is the
standard way to bring down a Prometheus instance, and it puts identifiers on a surface that is
usually scraped by something less protected than the database.

Two labels are worth reading carefully, because both are named `route` and they are not the
same quantity. On the HTTP metrics it is the route TEMPLATE, normalised before it is used as a
label for exactly this reason, so a request to an unrouted path cannot mint a series. On
`ironauth_sms_route_throttled_total` it is the destination route derived from the E.164 number,
so its domain is the set of dialling destinations rather than the set of phone numbers.

The per-tenant view is not missing, it is somewhere else. Per-tenant counts come from the
events and usage-metering API, which is authenticated, scoped, and paginated, and where a
tenant identifier is the point rather than a cardinality hazard.

`no_contract_metric_carries_a_per_principal_label` in the contract test enforces the paragraph
above, including on any label name ending in `_id`, so this page cannot go on claiming a bound
the contract has stopped keeping.

| metric | type | labels | meaning |
| --- | --- | --- | --- |
| `ironauth_connector_healthy` | gauge | `connector` | Whether an upstream connector's last probe succeeded |
| `ironauth_connector_upstream_error_total` | counter | `connector`, `kind` | Upstream connector calls that failed, by failure kind |
| `ironauth_connector_upstream_success_total` | counter | `connector` | Upstream connector calls that succeeded |
| `ironauth_factor_downgrade_recovery_permitted_total` | counter | `factor`, `surface` | Recovery flows permitted to use a weaker factor |
| `ironauth_factor_downgrade_refused_total` | counter | `factor`, `path` | Authentications refused for attempting a weaker factor than the policy allows |
| `ironauth_forward_auth_throttled_total` | counter | `layer` | Forward-auth checks refused by the request-plane limiter, by refusing layer |
| `ironauth_http_request_duration_seconds` | histogram | `method`, `route`, `status` | HTTP request duration in seconds |
| `ironauth_http_requests_total` | counter | `method`, `route`, `status` | Total HTTP requests |
| `ironauth_lazy_migration_breaker_state` | gauge | none | Lazy password-migration breaker state, as a number a dashboard can threshold |
| `ironauth_lazy_migration_breaker_transitions_total` | counter | `to` | Lazy-migration breaker transitions, by the state entered |
| `ironauth_lazy_migration_hook_latency_seconds` | histogram | none | Wall time of a lazy-migration verification hook |
| `ironauth_lazy_migration_hook_total` | counter | `outcome` | Lazy-migration hook invocations, by outcome |
| `ironauth_lazy_migration_migrated_total` | counter | none | Credentials rehashed into the current scheme by a lazy migration |
| `ironauth_log_stream_dead_letters` | gauge | `sink_type` | Log stream dead letters awaiting replay, by sink type |
| `ironauth_log_streams` | gauge | `sink_type`, `status` | Configured log streams by sink type and status |
| `ironauth_oidc_code_reuse_total` | counter | none | Authorization codes presented more than once, which is a replay signal |
| `ironauth_oidc_redeem_error_total` | counter | none | Token redemptions that failed |
| `ironauth_oidc_refresh_reuse_total` | counter | none | Refresh tokens presented after rotation, which is a theft signal |
| `ironauth_otp_funnel_total` | counter | `channel`, `result`, `stage` | One-time-code outcomes by channel and funnel stage |
| `ironauth_outbound_fetch_blocked_total` | counter | `purpose`, `reason` | Outbound fetches refused by the destination policy |
| `ironauth_outbound_fetch_requests_total` | counter | `outcome`, `purpose` | Outbound fetches attempted, by purpose and outcome |
| `ironauth_outbox_depth` | gauge | `consumer`, `state` | Outbox messages by state |
| `ironauth_outbox_messages_claimed_total` | counter | `consumer` | Outbox messages leased by a worker |
| `ironauth_outbox_messages_total` | counter | `consumer`, `outcome` | Outbox messages that reached an outcome |
| `ironauth_outbox_oldest_ready_age_seconds` | gauge | `consumer` | Age of the oldest ready outbox message in seconds |
| `ironauth_outbox_pass_failures_total` | counter | `consumer`, `kind` | Outbox drain passes that could not run |
| `ironauth_passkey_funnel_total` | counter | `result`, `stage` | Passkey ceremony outcomes by funnel stage |
| `ironauth_password_breached_at_login_total` | counter | none | Logins where the presented password matched a breach corpus |
| `ironauth_password_hash_admission_rejected_total` | counter | `reason` | Hash requests refused before reaching the pool, by reason |
| `ironauth_password_hash_duration_seconds` | histogram | `op` | Wall time of a password hash or verify |
| `ironauth_password_hash_pool_active_workers` | gauge | none | Hash pool workers currently running a job |
| `ironauth_password_hash_pool_queue_depth` | gauge | none | Hash requests waiting for a pool worker |
| `ironauth_password_hash_pool_threads` | gauge | none | Hash pool worker threads configured |
| `ironauth_password_screen_total` | counter | `outcome` | Password screening checks, by outcome |
| `ironauth_proxy_forwarding_rejected_total` | counter | `reason` | Requests whose forwarding headers were rejected and failed closed |
| `ironauth_quota_decisions_total` | counter | `decision`, `dimension` | Quota decisions, by dimension and admitted or denied |
| `ironauth_sms_route_throttled_total` | counter | `route` | SMS sends refused by a per-route throttle |
| `ironauth_sms_send_hash_rejected_total` | counter | none | SMS sends refused because the recipient hash was rejected |
| `ironauth_sms_send_refused_total` | counter | `reason` | SMS sends refused, by reason |
| `ironauth_up` | gauge | none | 1 while the process is serving |
| `ironauth_verification_send_suppressed_total` | counter | `purpose` | Verification sends suppressed, by purpose |

41 metrics, 12 of them carrying no labels at all.

## Scope

The server's own metrics. Other crates export their own (`ironauth-fetch` has two), and they
are not in this contract yet: bringing them in means moving their constants behind one
registry, which is wider than the contract this page publishes.
`the_contract_covers_every_metric_this_module_declares` holds that boundary, so a metric added
to the server's metrics module without a contract entry fails the build rather than quietly
escaping.

## Regenerating

    scripts/metrics-doc.sh
