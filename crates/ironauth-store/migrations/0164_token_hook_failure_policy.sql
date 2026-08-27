-- SPDX-License-Identifier: MIT OR Apache-2.0
--
-- The per-client hook FAILURE POLICY (issue #114 criterion 3).
--
-- Criterion 3 asks that a fuel or deadline abort applies "the configured failure policy". The
-- dispatch had no policy to configure: every fault refused the issuance, unconditionally.
--
-- # What this does NOT cover, said here because the obvious reading is wrong
--
-- #113's `filter_hook_claims` says the per-client failure policy decides "whether a refusal is
-- fatal", meaning a hook that tried to write a PROTECTED claim. This column does not decide
-- that and cannot: the fence drops such a claim and reports it, `fence` has no error channel
-- back to the dispatch, and the invocation succeeds. So a protected-claim attempt is neither
-- fail-open nor fail-closed today -- it is dropped-and-logged, whatever this column says.
--
-- This governs a hook that DID NOT COMPLETE: a trap, exhausted fuel, a passed deadline, a
-- decline, or a component that will not load. Wiring the refusal path to it is a separate
-- change, because it needs an error channel out of the fence that does not exist yet.
--
-- # Why the default is fail-closed, and why fail-open has to be opt-in per client
--
-- A hook can REMOVE a claim as easily as add one. `claims_mapping_at_issuance` records the
-- measurement: the hook's answer REPLACES the claim set rather than merging into it, precisely
-- so a hook deployed to strip `email` actually strips it. Ignoring a hook that failed therefore
-- issues MORE than the operator deployed, not less -- a token carrying the claim they removed.
--
-- So fail-open is not "degrade gracefully", it is "issue a token the operator did not
-- authorise", and it is correct only where the operator knows the hook only ADDS. That is a
-- per-client fact nobody but the operator has, which is what makes this a column rather than a
-- constant.
--
-- EXPAND: the column has a default, so an old binary that never selects it is unaffected and
-- every existing row reads as the behaviour that shipped.
ALTER TABLE token_hooks
    ADD COLUMN failure_policy text NOT NULL DEFAULT 'fail_closed';

-- Spelled out rather than an enum type: the set is small, the values are wire-visible on the
-- management API, and a CHECK is what stops a typo becoming a silent third behaviour. A row
-- naming anything else is one no dispatch could honour, so it is refused at the write.
ALTER TABLE token_hooks
    ADD CONSTRAINT token_hooks_failure_policy_known
        CHECK (failure_policy IN ('fail_closed', 'fail_open'));
