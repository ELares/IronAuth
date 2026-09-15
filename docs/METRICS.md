# The metric contract

Every metric IronAuth exports, with the labels it carries. `scripts/metric-contract.py`
checks the code against this table and fails on drift in EITHER direction.

## Why both directions

A metric emitted and undocumented is invisible: an operator building a dashboard cannot
know it exists. That direction is the one people remember.

The other direction is the one that hurts during an incident. A metric documented and no
longer emitted leaves a dashboard panel permanently empty and an alert that never fires,
and an alert that never fires looks exactly like an alert whose condition is not met. The
first time anyone notices is when the thing it was watching goes wrong.

## This table is the contract, not a report

The script asserts the code matches this file. It does not regenerate it: a document
regenerated from the thing it describes cannot disagree with it, and so cannot fail.

**The initial table was seeded from the code as a snapshot**, and that is worth stating
plainly rather than implying the contract was derived independently. What it buys starts
now: from this point, adding a metric without a row here fails, removing a metric without
removing its row fails, and changing a label set on either side fails.

## Labels

Labels are listed as the UNION across every call site of a metric. A metric emitted from
two places with different label sets appears here with both, which is usually a defect
worth looking at rather than a fact worth recording: Prometheus treats a differing label
set as a different series.

Label VALUES are deliberately not listed. They are bounded by construction (each comes
from an `as_str` over a closed enum) and listing them would be a second statement of a
thing the type system already fixes.

## The contract

| Metric | Kind | Labels |
|---|---|---|
| `ironauth_connector_healthy` | gauge | `connector` |
| `ironauth_connector_upstream_error_total` | counter | `connector`, `kind` |
| `ironauth_connector_upstream_success_total` | counter | `connector` |
| `ironauth_factor_downgrade_recovery_permitted_total` | counter | `factor`, `surface` |
| `ironauth_factor_downgrade_refused_total` | counter | `factor`, `path` |
| `ironauth_http_request_duration_seconds` | histogram | `method`, `route`, `status` |
| `ironauth_http_requests_total` | counter | `method`, `route`, `status` |
| `ironauth_lazy_migration_breaker_state` | gauge | none |
| `ironauth_lazy_migration_breaker_transitions_total` | counter | `to` |
| `ironauth_lazy_migration_hook_latency_seconds` | histogram | none |
| `ironauth_lazy_migration_hook_total` | counter | `outcome` |
| `ironauth_lazy_migration_migrated_total` | counter | none |
| `ironauth_log_stream_dead_letters` | gauge | `sink_type` |
| `ironauth_log_streams` | gauge | `sink_type`, `status` |
| `ironauth_oidc_code_reuse_total` | counter | none |
| `ironauth_oidc_redeem_error_total` | counter | none |
| `ironauth_oidc_refresh_reuse_total` | counter | none |
| `ironauth_outbound_fetch_blocked_total` | counter | `purpose`, `reason` |
| `ironauth_outbound_fetch_requests_total` | counter | `outcome`, `purpose` |
| `ironauth_outbox_depth` | gauge | `consumer`, `state` |
| `ironauth_outbox_messages_claimed_total` | counter | `consumer` |
| `ironauth_outbox_messages_total` | counter | `consumer`, `outcome` |
| `ironauth_outbox_oldest_ready_age_seconds` | gauge | `consumer` |
| `ironauth_outbox_pass_failures_total` | counter | `consumer`, `kind` |
| `ironauth_password_breached_at_login_total` | counter | none |
| `ironauth_password_hash_admission_rejected_total` | counter | `reason` |
| `ironauth_password_hash_duration_seconds` | histogram | `op` |
| `ironauth_password_hash_pool_active_workers` | gauge | none |
| `ironauth_password_hash_pool_queue_depth` | gauge | none |
| `ironauth_password_hash_pool_threads` | gauge | none |
| `ironauth_password_screen_total` | counter | `outcome` |
| `ironauth_proxy_forwarding_rejected_total` | counter | `reason` |
| `ironauth_quota_decisions_total` | counter | `decision`, `dimension` |
| `ironauth_sms_route_throttled_total` | counter | `route` |
| `ironauth_sms_send_hash_rejected_total` | counter | none |
| `ironauth_sms_send_refused_total` | counter | `reason` |
| `ironauth_up` | gauge | none |
| `ironauth_verification_send_suppressed_total` | counter | `purpose` |

## What this check cannot see

It parses `metrics::{counter,gauge,histogram}!` invocations, resolving a name given as a
string literal or as a `const`. A metric emitted through a helper it does not recognise
would be invisible to it, and a gate that silently covers nothing is worse than no gate,
so it also refuses any `ironauth_`-prefixed string literal that is neither extracted nor
listed as a known non-metric in `NOT_METRICS`.
