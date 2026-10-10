# Optional hosted display names

Work in progress for #1385 and Civio onboarding #455. This document is an
implementation contract, not deployment or issue-completion evidence.

The provider owns an optional standard `name` claim. Its display label is not a
login identifier, verified mailbox, account key or authorization input. Equal
names do not merge accounts. Removing a name leaves a valid empty profile.

## Implemented backend and hosted form

- GET `/t/{tenant}/e/{environment}/account/profile` returns only `name` for the
  authenticated own account. It refuses impersonation and never returns the
  stored claim bag.
- POST at the same path accepts only `expected_name` and `name` strings, requires
  a present same-origin Origin, and binds the target to the current session.
  Names are trimmed, at most 80 Unicode characters, and contain no control
  characters. An empty name removes the standard claim.
- The store rechecks the active subject and stable human actor, locks the row,
  reads the current sealed claims and DEK version, compares the expected label,
  changes only `name`, reseals and writes the owner-attributed audit atomically.
  A different current name returns a conflict. Repeating the desired current
  value is harmless and may append a further audit record.
- GET `/t/{tenant}/e/{environment}/profile` hosts the own-name form. Its optional
  `return_to` must resolve a registered in-scope authorization request. Other
  app URLs, cross-scope requests and indirect unvalidated contexts are refused.
- The form retains input after errors, freezes uncertain saves for exact retry,
  offers an explicit reload of current state, guards navigation, and keeps a
  sessionStorage recovery copy keyed by the scoped subject. Confirmed saves or
  explicit reload clear the copy. Storage unavailability is visible.

Existing UserInfo claim selection remains authoritative. The name becomes
available on a fresh permitted profile read; a relying party may cache its own
label until reauthentication. This feature does not establish email ownership.

## Required before integrated completion

1. Connect a discoverable registration/account-settings entry and the validated
   relying-party return, including interrupted/expired sign-in. Do not require
   users to assemble provider URLs or seed their profile through management APIs.
2. Run fresh registration, name selection, later editing/removal and Civio return
   in a real browser. Inspect narrow layouts, keyboard/focus, both provider page
   styling variants as supported, retained input and lost-response reconciliation.
3. Cover wrong scope, disabled user, impersonation and persisted rollback/audit
   behavior as well as the existing positive, conflict, forged-field, same-origin,
   concurrency, HTML escaping and scoped UserInfo tests. Decide and document the
   canonical user.updated event behavior before merge.
4. Preserve names at the application boundary: Civio currently limits display
   strings to 254 UTF-8 bytes while 80 Unicode characters can exceed that. Resolve
   the mismatch explicitly, without changing account identity or grant lookup.
5. Qualify the original pairwise requirement. Current production token and
   UserInfo code calls `resolve_public_subject`; the separate generic pairwise
   helper is not an integrated pairwise registration/token/UserInfo path. Do not
   check this criterion from public-subject tests.
6. Run the required local gate and one fixed-head review, fix blockers with
   targeted validation, deploy a reviewed candidate, qualify the connected
   browser journey and merge a regular PR. Preserve all remaining original
   #1385 and Civio U01/U02/U04/U07 criteria until their evidence is complete.
