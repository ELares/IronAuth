#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Diagnostics redaction corpus (issue #91, made honest and non-vacuous in #423).
#
# The admin diagnostics sink (the M9 flow inspector's client-authentication failure
# records, the policy decision traces, the token size events, the flow inspector
# projection) must not carry secret material. This gate runs the hostile corpora
# that check that, and the probes that prove the corpora can actually see a leak.
#
# WHAT IS PROVED, and in which of two tiers. The distinction matters, because the
# stronger claim was asserted here for a long time and it was false:
#
#   STRUCTURAL, provable by enumeration. A closed enum or a bounded integer cannot
#   hold a sentinel: its whole value space is finite and contains none. The
#   the_closed_*_vocabularies_cannot_express_a_sentinel tests sweep those spaces.
#   A sweep is only total if the list it walks is, so the variant lists those two
#   tests iterate are themselves checked, against the enum declarations rather than
#   against a `match` beside them; that is the ironauth-store group below, and it is
#   run HERE because the structural tier is worth exactly as much as it.
#   Separately, a field that does not exist cannot hold anything: no diagnostic
#   struct has a field for an assertion body, a client secret, a token value or a
#   JWKS private key, and the trace input type is an allowlisted PROJECTION, so a
#   raw claim set cannot be passed through without widening the enum first.
#
#   CALLER DISCIPLINE, not a property of the type. Every free-form String and &str
#   field (a client id, an auth method, a kid, an alg, a trace subject and reason,
#   an acr, a risk level and signal, a connector slug, a failure kind) WOULD record
#   a sentinel verbatim. Several are attacker influenced. Nothing in the types
#   prevents it.
#
# A corpus that builds records from SAFE literals and asserts no sentinel appears
# proves only that the safe literals contain no sentinel: it is one hardcoded list
# compared against another, and deleting its scan loop would go unnoticed. That is
# why every free-form field has a should_panic probe that routes a REAL sentinel
# through it. Those probes are run here too, deliberately: without them this gate
# could pass while proving nothing. The honest claim it makes is the weaker, TRUE
# one, that a leak through any of these fields WOULD BE SEEN.
#
# The probes are IDENTIFIED, not counted. Counting was the first attempt and it was
# not sound: with a substring filter and a `ran at least N` check, renaming the
# signing_alg probe and adding a `..._nothing_at_all` probe whose whole body is
# `panic!("a secret sentinel leaked")` restored the count and the gate printed
# clean while signing_alg had no probe at all (measured, issue #404 review). Every
# group below therefore pins the EXACT set of test names, compared against
# `--list`, so a rename, a deletion, and an addition all fail until this file is
# updated to say which field the new probe is for.
#
# Plain cargo tests, no database, so this runs in any lane.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# List the tests a filter selects, compare that set against the exact names this
# gate expects, then RUN exactly those names.
#
#   expect_exact <package> <label> <filter> <name>...
expect_exact() {
  local package="$1" label="$2" filter="$3"
  shift 3
  local expected=("$@")
  echo "diagnostics-redaction: ${label}"

  local listed
  if ! listed=$(cargo test --quiet -p "$package" --lib "$filter" -- --list 2>&1); then
    printf '%s\n' "$listed"
    return 1
  fi
  local actual_set expected_set
  actual_set=$(printf '%s\n' "$listed" | sed -n 's/: test$//p' | sort)
  expected_set=$(printf '%s\n' "${expected[@]}" | sort)
  if [ "$actual_set" != "$expected_set" ]; then
    echo "diagnostics-redaction: the tests matching '${filter}' are not the ones this"
    echo "gate claims to run. A probe was renamed, deleted, or added without saying"
    echo "which field it covers. Reconcile scripts/diagnostics-redaction-scan.sh with"
    echo "the tests, or restore the missing one."
    echo "  expected:"
    printf '    %s\n' $expected_set
    echo "  found:"
    printf '    %s\n' ${actual_set:-"(nothing)"}
    return 1
  fi

  local output passed
  if ! output=$(cargo test --quiet -p "$package" --lib -- --exact "${expected[@]}" 2>&1); then
    printf '%s\n' "$output"
    return 1
  fi
  passed=$(printf '%s\n' "$output" \
    | sed -n 's/^test result: ok\. \([0-9][0-9]*\) passed.*/\1/p' | head -1)
  passed=${passed:-0}
  if [ "$passed" -ne "${#expected[@]}" ]; then
    printf '%s\n' "$output"
    echo "diagnostics-redaction: '${label}' listed ${#expected[@]} test(s) but ran"
    echo "${passed}. A filter that matches nothing reports green while proving nothing."
    return 1
  fi
}

# 0. The variant lists the closed-vocabulary sweeps below walk, against the enum
#    declarations themselves. Without this, "the closed vocabularies cannot express
#    a sentinel" is a claim about a hand-written list, not about the enum: a variant
#    added to the enum and to the total `match` beside the list left the list short
#    and every sweep stayed green (measured, issue #404 review).
#
#    The last two entries are NOT diagnostic vocabularies, and they are listed here
#    anyway because this gate pins the module EXACTLY and that module is where the
#    `declared_variants` source parser lives. `UserState` is a LIFECYCLE vocabulary
#    (issue #241): `user_state_all_holds_every_declared_variant` pins its `ALL` against
#    the enum's own declaration, and `every_reachable_non_authenticatable_state_ends_sessions`
#    pins the three-way relation across `can_authenticate`, `ends_sessions` and
#    `can_transition_to` that the token-mint fences rest on. Measured during the #241
#    review: a state that is non-authenticatable, a valid transition target, and not
#    session-ending compiles at every one of the six match sites and silently reopens
#    four user-bound mint paths, and only that relation test catches it. So they cover a
#    mint invariant rather than a redaction one, and they belong to this list only
#    because they share the parser this gate is asserting about.
expect_exact ironauth-store "closed vocabulary lists match their enum declarations" \
  repository::variant_lists_match_the_enum_declarations:: \
  repository::variant_lists_match_the_enum_declarations::client_auth_diagnostic_reason_all_holds_every_declared_variant \
  repository::variant_lists_match_the_enum_declarations::diagnostic_expectation_all_holds_every_declared_variant \
  repository::variant_lists_match_the_enum_declarations::token_size_reason_all_holds_every_declared_variant \
  repository::variant_lists_match_the_enum_declarations::user_state_all_holds_every_declared_variant \
  repository::variant_lists_match_the_enum_declarations::every_reachable_non_authenticatable_state_ends_sessions \
  repository::variant_lists_match_the_enum_declarations::the_declaration_parser_refuses_an_enum_it_cannot_find

# 1. The client-authentication diagnostic corpus: a hostile assertion with secret,
#    token, assertion-body and JWKS-private sentinels buried in it is fed through the
#    SAME safe-field peek the record path uses, and no sentinel may come out.
expect_exact ironauth-oidc "client auth diagnostic corpus" \
  client_auth::tests::diagnostics_redaction_corpus_leaks_no_secret_sentinel \
  client_auth::tests::diagnostics_redaction_corpus_leaks_no_secret_sentinel

# 2. One probe per free-form field of `NewClientAuthDiagnostic`. The four names are
#    the four fields: client_id, auth_method, key_id, signing_alg.
expect_exact ironauth-oidc "client auth diagnostic free-form field probes" \
  client_auth::tests::the_sentinel_scan_catches_a_leak_through_ \
  client_auth::tests::the_sentinel_scan_catches_a_leak_through_the_client_id \
  client_auth::tests::the_sentinel_scan_catches_a_leak_through_the_auth_method \
  client_auth::tests::the_sentinel_scan_catches_a_leak_through_the_key_id \
  client_auth::tests::the_sentinel_scan_catches_a_leak_through_the_signing_alg

# 3. The enumeration of that record's closed vocabularies.
expect_exact ironauth-oidc "client auth diagnostic closed vocabulary sweep" \
  client_auth::tests::the_closed_diagnostic_vocabularies_cannot_express_a_sentinel \
  client_auth::tests::the_closed_diagnostic_vocabularies_cannot_express_a_sentinel

# 4. The policy decision trace and token size record corpus.
expect_exact ironauth-oidc "policy trace and token size corpus" \
  policy_trace::tests::redaction_corpus_leaks_no_secret_sentinel \
  policy_trace::tests::redaction_corpus_leaks_no_secret_sentinel

# 5. One probe per free-form field of the trace and budget records: the trace's own
#    subject and reason, the four String fields of the StepUp and Risk inputs
#    variants plus the two nested in a risk signal, the two of the ClaimMapping
#    variant, and the audience and organization of the budget event.
expect_exact ironauth-oidc "policy trace free-form field probes" \
  policy_trace::tests::the_sentinel_scan_catches_a_leak_through_ \
  policy_trace::tests::the_sentinel_scan_catches_a_leak_through_the_trace_subject \
  policy_trace::tests::the_sentinel_scan_catches_a_leak_through_the_trace_reason \
  policy_trace::tests::the_sentinel_scan_catches_a_leak_through_the_required_acr \
  policy_trace::tests::the_sentinel_scan_catches_a_leak_through_the_achieved_acr \
  policy_trace::tests::the_sentinel_scan_catches_a_leak_through_the_risk_level \
  policy_trace::tests::the_sentinel_scan_catches_a_leak_through_a_risk_signal_name \
  policy_trace::tests::the_sentinel_scan_catches_a_leak_through_a_risk_signal_level \
  policy_trace::tests::the_sentinel_scan_catches_a_leak_through_the_connector_slug \
  policy_trace::tests::the_sentinel_scan_catches_a_leak_through_the_failure_kind \
  policy_trace::tests::the_sentinel_scan_catches_a_leak_through_the_audience \
  policy_trace::tests::the_sentinel_scan_catches_a_leak_through_the_organization

# 6. The enumeration of the closed budget vocabularies.
expect_exact ironauth-oidc "policy trace closed vocabulary sweep" \
  policy_trace::tests::the_closed_budget_vocabularies_cannot_express_a_sentinel \
  policy_trace::tests::the_closed_budget_vocabularies_cannot_express_a_sentinel

# 7. The M9 flow inspector projection. Here the structural half is genuinely strong:
#    the context view has NO field for the flow submit token (it is not even on the
#    persisted state) and NO field for the recovery identifier PII (reduced to a
#    boolean), so those two cannot appear. The corpus is non-vacuous on its own,
#    because it seeds REAL sentinels into the persisted state it projects from, and
#    the probe beside it proves the scan would fire if one survived the projection.
expect_exact ironauth-oidc "flow inspector projection corpus" \
  flow::inspect::tests::redaction_corpus_leaks_no_secret_sentinel \
  flow::inspect::tests::redaction_corpus_leaks_no_secret_sentinel

expect_exact ironauth-oidc "flow inspector projection probe" \
  flow::inspect::tests::the_sentinel_scan_catches_a_leak_through_ \
  flow::inspect::tests::the_sentinel_scan_catches_a_leak_through_the_context_subject

echo "diagnostics-redaction: clean (every corpus green, every free-form field named above has its own probe, and every closed vocabulary list matches its enum declaration)"
