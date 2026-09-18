# The metric contract

Every series this build exports, with its type, its labels and what it means. GENERATED from
`metrics::CONTRACT` in `crates/ironauth-server/src/metrics.rs` by `scripts/metrics-doc.sh`,
which CI runs; a hand edit here fails that gate. Do not write this page, write the contract.

## What the contract promises

`crates/ironauth-server/tests/metric_contract.rs` checks the contract against the emit sites in
BOTH directions, which is what makes this page worth writing a dashboard against:

- a metric listed here whose emit sites have all been DELETED fails the build, so a panel does
  not go quiet because the series it queries stopped existing. This is a check on the source,
  not on coverage: a site that still exists on a path nothing reaches passes it, and only a
  test that drives the path can say the series is actually produced; and
- a metric emitted and not listed here fails the build, so a series cannot appear on your
  scrape without having been reviewed.

The labels and kind are checked too: an emitted label this page does not list, a declared
label absent from every emit site, or a gauge this page calls a counter fails. An individual
site may emit a subset of the declared labels; the check compares their union across sites.

THAT SENTENCE WAS PUBLISHED BEFORE IT WAS TRUE, which is worth leaving here rather than quietly
correcting. The label check ran over emit sites resolved through one crate's constants only, so
it reached eleven of the metrics in the table below while this page told a dashboard author it
reached all of them. A `tenant` label added to any of the others left every test green. The scan
now resolves a metric named by a string literal and by a constant declared anywhere in the
workspace, `both_scans_find_the_same_emit_sites` asserts the two independently written walks
over the tree agree about what an emit site is, and the mutation above now fails.

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

`no_metric_carries_a_per_principal_label` in the contract test enforces the paragraph above,
including on any label name ending in `_id`. It reads BOTH the contract's declared labels and
the labels the emit sites actually set, which is the difference between a promise and the
behaviour: its first version read the contract alone, so adding `tenant` to an emit site put the
label on the wire with every test green.

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
| `ironauth_token_request_duration_seconds` | histogram | `grant_type` | Token endpoint request duration in seconds, by grant type |
| `ironauth_token_requests_total` | counter | `grant_type`, `outcome` | Token endpoint requests by grant type and outcome |
| `ironauth_up` | gauge | none | 1 while the process is serving |
| `ironauth_verification_send_suppressed_total` | counter | `purpose` | Verification sends suppressed, by purpose |

43 metrics, 12 of them carrying no labels at all.

## Scope

Every metric this workspace emits, wherever it is emitted from. The contract is DECLARED in the
server crate and is not limited to it: most of the table above is emitted from `ironauth-oidc`,
the rest from the binary crate, `ironauth-fetch` and the server.

An earlier version of this paragraph gave the split as a measured count, and the next change to
add a metric falsified every number in it while this page regenerated byte-identically, because
the prose travels inside the generator and only the table is derived. A count that is not
computed from the contract does not belong on a page generated from the contract.

Two tests hold that boundary from different sides.
`the_contract_covers_every_metric_this_module_declares` refuses a metric constant declared in
the server's metrics module with no contract entry, and
`the_contract_covers_every_metric_the_workspace_emits` refuses a metric emitted anywhere in the
workspace with no contract entry. So a new series cannot reach a scrape without appearing on
this page.

## Regenerating

    scripts/metrics-doc.sh
